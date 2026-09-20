//! Durable automatic validation, Ghidra writeback, and bounded reanalysis.
use crate::{
    ai::Analysis, config::Config, db::Db, decisions::Choice, ghidra, knowledge, types::TypePlan,
};
use anyhow::{Context, Result};
use serde_json::{Value, json};
use sqlx::Row;
use std::{
    collections::{BTreeMap, HashSet},
    sync::Arc,
    time::Duration,
};
use tokio::sync::Semaphore;
use tokio_util::sync::CancellationToken;

fn supported(answers: &Value, field: &str) -> bool {
    serde_json::from_value::<Choice>(answers[field].clone())
        .is_ok_and(|answer| answer.kind == "choice" && answer.choice == "supported")
}

// Conflicting plans are deferred as whole plans. Do not pick a winner by row order.
fn compatible(plans: &[(String, TypePlan)]) -> HashSet<String> {
    let mut definitions = BTreeMap::new();
    let mut signatures = BTreeMap::new();
    let mut conflicts = HashSet::new();
    for (index, (id, plan)) in plans.iter().enumerate() {
        for (other, other_plan) in &plans[..index] {
            let mut merged = plan.cpp.clone();
            if merged.merge(other_plan.cpp.clone()).is_err() {
                conflicts.insert(id.clone());
                conflicts.insert(other.clone());
            }
        }
        for definition in &plan.definitions {
            let values: &mut Vec<(&String, &crate::types::Definition)> =
                definitions.entry(definition.name()).or_default();
            for (other, value) in values.iter() {
                if *value != definition {
                    conflicts.insert((*other).clone());
                    conflicts.insert(id.clone());
                }
            }
            values.push((id, definition));
        }
        for signature in &plan.signatures {
            let values: &mut Vec<(&String, &crate::types::Signature)> =
                signatures.entry(&signature.address).or_default();
            for (other, value) in values.iter() {
                if *value != signature {
                    conflicts.insert((*other).clone());
                    conflicts.insert(id.clone());
                }
            }
            values.push((id, signature));
        }
    }
    plans
        .iter()
        .filter(|(id, _)| !conflicts.contains(id))
        .map(|(id, _)| id.clone())
        .collect()
}

pub async fn work(db: Db, config: Arc<Config>, gate: Arc<Semaphore>, cancel: CancellationToken) {
    loop {
        if cancel.is_cancelled() {
            break;
        }
        let binaries: Vec<String> =
            sqlx::query_scalar("SELECT id FROM binaries WHERE paused=0 AND status='indexed'")
                .fetch_all(&db.pool)
                .await
                .unwrap_or_default();
        for binary in binaries {
            if cancel.is_cancelled() {
                break;
            }
            let Ok(_permit) = gate.try_acquire() else {
                break;
            };
            if let Err(error) = advance(&db, &config, &binary, 3).await {
                tracing::error!(%error, %binary, "Automatic recovery failed");
            }
        }
        tokio::select! { () = cancel.cancelled() => break, () = tokio::time::sleep(Duration::from_secs(2)) => {} }
    }
}

/// Runs one durable phase only after all requests in the active scope drain.
/// The writer flag and job claims share SQLite's write lock.
pub async fn advance(db: &Db, config: &Config, binary: &str, max_passes: u32) -> Result<bool> {
    let claimed = sqlx::query("UPDATE binaries SET recovery_writer=1 WHERE id=? AND paused=0 AND recovery_writer=0 AND NOT EXISTS(SELECT 1 FROM jobs j WHERE j.binary_id=binaries.id AND (j.status IN ('running','batched','uncertain') OR (j.status='queued' AND (binaries.active_run_id IS NULL OR j.run_id=binaries.active_run_id))))")
        .bind(binary).execute(&db.pool).await?.rows_affected();
    if claimed == 0 {
        return Ok(false);
    }
    let outcome = advance_locked(db, config, binary, max_passes).await;
    sqlx::query("UPDATE binaries SET recovery_writer=0 WHERE id=?")
        .bind(binary)
        .execute(&db.pool)
        .await?;
    outcome
}

async fn advance_locked(db: &Db, config: &Config, binary: &str, max_passes: u32) -> Result<bool> {
    let run: String =
        sqlx::query_scalar("SELECT COALESCE(active_run_id,'all') FROM binaries WHERE id=?")
            .bind(binary)
            .fetch_one(&db.pool)
            .await?;
    sqlx::query(
        "INSERT OR IGNORE INTO automatic_recovery(id,binary_id,run_id,max_passes) VALUES(?,?,?,?)",
    )
    .bind(knowledge::id())
    .bind(binary)
    .bind(&run)
    .bind(max_passes)
    .execute(&db.pool)
    .await?;
    let cycle = sqlx::query("SELECT * FROM automatic_recovery WHERE binary_id=? AND run_id=?")
        .bind(binary)
        .bind(&run)
        .fetch_one(&db.pool)
        .await?;
    let id: String = cycle.get("id");
    let phase: String = cycle.get("status");
    if matches!(phase.as_str(), "completed" | "deferred" | "failed") {
        return Ok(true);
    }
    let pass: i64 = cycle.get("pass");
    let limit: i64 = cycle.get("max_passes");
    sqlx::query("INSERT OR IGNORE INTO recovery_passes(cycle_id,run_id,pass,selected,reason) SELECT ?,?,?,COUNT(DISTINCT function_id),'Initial analysis' FROM jobs WHERE binary_id=? AND (run_id=? OR ?='all')")
        .bind(&id).bind(&run).bind(pass+1).bind(binary).bind(&run).bind(&run).execute(&db.pool).await?;
    let outcome: Result<()> = async {
        match phase.as_str() {
            "assessing" => {
                let proposals = assess(db, binary).await?;
                sqlx::query("UPDATE automatic_recovery SET type_results=?,status='names',updated_at=unixepoch() WHERE id=?")
                    .bind(serde_json::to_string(&proposals)?).bind(&id).execute(&db.pool).await?;
            }
            "names" => {
                let operation: String = match cycle.get::<Option<String>, _>("name_operation") {
                    Some(operation) => operation,
                    None => {
                        let operation = knowledge::preview_apply(db, binary).await?;
                        sqlx::query("UPDATE automatic_recovery SET name_operation=? WHERE id=?").bind(&operation.id).bind(&id).execute(&db.pool).await?;
                        operation.id
                    }
                };
                let current = knowledge::apply_operation(db, &operation).await?;
                if !current.items.is_empty() && matches!(current.status.as_str(), "preview" | "uncertain") {
                    ghidra::execute_apply(db, config, &operation, None).await?;
                }
                set_phase(db, &id, "types", "").await?;
            }
            "types" => {
                let mut proposals: Vec<String> = serde_json::from_str(&cycle.get::<String, _>("type_results"))?;
                if !proposals.is_empty() {
                    let operation = match cycle.get::<Option<String>, _>("type_operation") {
                        Some(operation) => Some(operation),
                        None => match preview_types(db, config, &id, &mut proposals).await {
                            Ok(Some(preview)) => {
                                let operation = preview["id"].as_str().context("Missing type operation")?.to_owned();
                                sqlx::query("UPDATE automatic_recovery SET type_operation=? WHERE id=?").bind(&operation).bind(&id).execute(&db.pool).await?;
                                Some(operation)
                            }
                            Ok(None) => None,
                            Err(error) => {
                                for result in &proposals { type_outcome(db, result, "deferred", &format!("Ghidra preview rejected the plan: {error:#}")).await?; }
                                db.event(binary, "warn", &format!("Automatic type validation deferred incompatible proposals: {error:#}")).await?;
                                None
                            }
                        }
                    };
                    if let Some(operation) = operation {
                        let status: String = sqlx::query_scalar("SELECT status FROM type_operations WHERE id=?").bind(&operation).fetch_one(&db.pool).await?;
                        if !matches!(status.as_str(), "applied" | "unchanged") { crate::types::apply(db, config, &operation).await?; }
                        for result in proposals { type_outcome(db, &result, if status == "unchanged" { "unchanged" } else { "applied" }, "Saved in the Ghidra project").await?; }
                    }
                }
                set_phase(db, &id, "refreshing", "").await?;
            }
            "refreshing" => {
                let parameters_changed = if config.ghidra_home.is_some() {
                    crate::parameters::recover(db, config, binary, &id, pass).await?
                } else { false };
                // Type apply already exports; name-only changes also need fresh pseudocode.
                let name_changed: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM apply_items WHERE operation_id=? AND status='applied')")
                    .bind(cycle.get::<Option<String>, _>("name_operation")).fetch_one(&db.pool).await?;
                let types_refreshed: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM type_operations WHERE id=? AND status='applied')")
                    .bind(cycle.get::<Option<String>, _>("type_operation")).fetch_one(&db.pool).await?;
                if parameters_changed || (name_changed && !types_refreshed) {
                    ghidra::refresh(db, config, binary).await?;
                }
                sqlx::query("UPDATE results SET automation_json=json_set(automation_json,'$.name',CASE WHEN name_review='accepted' THEN 'applied' ELSE name_review END,'$.summary',CASE WHEN summary_review='accepted' THEN 'applied' ELSE summary_review END) WHERE id IN (SELECT result_id FROM apply_items WHERE operation_id=? AND status='applied')")
                    .bind(cycle.get::<Option<String>, _>("name_operation")).execute(&db.pool).await?;
                sqlx::query("UPDATE results SET automation_json=json_set(automation_json,'$.reason','Ghidra changed since validation; conflicting writeback was deferred') WHERE id IN (SELECT result_id FROM apply_items WHERE operation_id=? AND status='conflict')")
                    .bind(cycle.get::<Option<String>, _>("name_operation")).execute(&db.pool).await?;
                set_phase(db, &id, "reanalysis", "").await?;
            }
            "reanalysis" => {
                let functions: Vec<String> = sqlx::query_scalar("SELECT f.id FROM functions f JOIN results r ON r.id=f.current_result_id WHERE f.binary_id=? AND f.skip_reason='' AND (r.stale=1 OR r.name_review='deferred' OR r.summary_review='deferred' OR json_extract(r.automation_json,'$.types')='deferred' OR json_array_length(r.raw_json,'$.context_requests')>0) AND r.author<>'human' AND NOT EXISTS(SELECT 1 FROM review_decisions WHERE result_id=r.id) ORDER BY f.id")
                    .bind(binary).fetch_all(&db.pool).await?;
                let mut prompts = Vec::new();
                if pass + 1 < limit && config.ai.configured() {
                    let ai = crate::ai::Ai::new(config.ai.clone())?;
                    let stage = "map";
                    for function in functions {
                        let mut prompt = ai.recovery_prompt(db, &function, stage).await?;
                        let previous: Option<String> = sqlx::query_scalar("SELECT j.input_json FROM functions f JOIN results r ON r.id=f.current_result_id JOIN jobs j ON j.id=r.job_id WHERE f.id=?").bind(&function).fetch_optional(&db.pool).await?;
                        let previous = previous.and_then(|raw| serde_json::from_str::<crate::ai::Prompt>(&raw).ok());
                        let changed = previous.as_ref().is_some_and(|old| !old.source_fingerprints.is_empty() && old.source_fingerprints != prompt.source_fingerprints);
                        let mut reason = "Type, execution, or runtime evidence changed".to_owned();
                        if !changed {
                            let raw: String = sqlx::query_scalar("SELECT raw_json FROM results WHERE id=(SELECT current_result_id FROM functions WHERE id=?)").bind(&function).fetch_one(&db.pool).await?;
                            let analysis: Analysis = serde_json::from_str(&raw)?;
                            let requested = if let Some(old) = &previous { ai.requested_context(db, &function, old, &analysis.context_requests).await? } else { None };
                            if let Some((targeted, question)) = requested {
                                prompt = targeted;
                                reason = format!("Model requested available missing evidence: {question}");
                            } else {
                                sqlx::query("UPDATE results SET automation_json=json_set(automation_json,'$.reason','Stopped automatically: no changed or available requested evidence. Retained the best supported result; no user action required.') WHERE id=(SELECT current_result_id FROM functions WHERE id=?)").bind(&function).execute(&db.pool).await?;
                                continue;
                            }
                        } else if let Some(old) = &previous {
                            prompt.context_history = old.context_history.clone();
                        }
                        sqlx::query("UPDATE results SET automation_json=json_set(automation_json,'$.followup_reason',?,'$.followup_sources',json(?)) WHERE id=(SELECT current_result_id FROM functions WHERE id=?)")
                            .bind(&reason).bind(serde_json::to_string(&prompt.source_fingerprints)?).bind(&function).execute(&db.pool).await?;
                        prompts.push((function, prompt));
                    }
                }
                if !prompts.is_empty() {
                    let run = knowledge::id();
                    let mut tx = db.pool.begin().await?;
                    sqlx::query("INSERT INTO analysis_runs(id,binary_id,reason,config_json) VALUES(?,?,?,?)")
                        .bind(&run).bind(binary).bind(format!("Automatic recovery pass {}", pass + 2)).bind(serde_json::to_string(&config.ai)?).execute(&mut *tx).await?;
                    let stage = "map";
                    for (function, prompt) in &prompts {
                        sqlx::query("INSERT INTO jobs(id,binary_id,function_id,stage,run_id,input_json) VALUES(?,?,?,?,?,?)")
                            .bind(knowledge::id()).bind(binary).bind(function).bind(stage).bind(&run).bind(serde_json::to_string(prompt)?).execute(&mut *tx).await?;
                    }
                    sqlx::query("INSERT INTO recovery_passes(cycle_id,run_id,pass,selected,reason) VALUES(?,?,?,?,?)")
                        .bind(&id).bind(&run).bind(pass+2).bind(prompts.len() as i64).bind("Changed or explicitly requested missing evidence").execute(&mut *tx).await?;
                    sqlx::query("UPDATE binaries SET active_run_id=? WHERE id=?").bind(&run).bind(binary).execute(&mut *tx).await?;
                    sqlx::query("UPDATE automatic_recovery SET run_id=?,pass=pass+1,status='assessing',name_operation=NULL,type_operation=NULL,type_results='[]',attempts=0,updated_at=unixepoch() WHERE id=?")
                        .bind(&run).bind(&id).execute(&mut *tx).await?;
                    tx.commit().await?;
                    db.event(binary, "info", &format!("Automatic recovery selected {} functions with changed or explicitly requested evidence in pass {} of {limit}.", prompts.len(), pass + 2)).await?;
                } else {
                    let deferred: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM functions f JOIN results r ON r.id=f.current_result_id WHERE f.binary_id=? AND (r.stale=1 OR r.name_review='deferred' OR r.summary_review='deferred' OR json_extract(r.automation_json,'$.types')='deferred')")
                        .bind(binary).fetch_one(&db.pool).await?;
                    let status = if deferred > 0 { "deferred" } else { "completed" };
                    let reason = format!("Automatic recovery finished after {} total passes. {deferred} functions retain deferred fields. No manual review is required.", pass + 1);
                    set_phase(db, &id, status, &reason).await?;
                    db.event(binary, "info", &reason).await?;
                }
            }
            _ => anyhow::bail!("Unknown automatic recovery phase {phase}"),
        }
        Ok(())
    }.await;
    if let Err(error) = outcome {
        sqlx::query("UPDATE automatic_recovery SET attempts=attempts+1,status=CASE WHEN attempts>=2 THEN 'failed' ELSE status END,error=?,updated_at=unixepoch() WHERE id=?")
            .bind(format!("{error:#}")).bind(&id).execute(&db.pool).await?;
        db.event(
            binary,
            "error",
            &format!("Automatic recovery could not finish {phase}: {error:#}"),
        )
        .await?;
        return Err(error);
    }
    Ok(false)
}

// Local identities can change during signature application inside the native
// preview. Preserve independent layouts and signatures when locals cannot apply.
async fn preview_types(
    db: &Db,
    config: &Config,
    cycle: &str,
    proposals: &mut Vec<String>,
) -> Result<Option<Value>> {
    match crate::types::preview_many(db, config, proposals).await {
        Ok(preview) => return Ok(Some(preview)),
        Err(error) => {
            let message = format!("{error:#}");
            if ![
                "Local name changed",
                "Local variable identity changed",
                "Ambiguous local identity",
                "Cannot resolve local variables",
            ]
            .iter()
            .any(|reason| message.contains(reason))
            {
                return Err(error);
            }
        }
    }
    let mut retained = Vec::new();
    for result in proposals.iter() {
        let row = sqlx::query("SELECT automation_json,raw_json FROM results WHERE id=?")
            .bind(result)
            .fetch_one(&db.pool)
            .await?;
        let mut audit: Value = serde_json::from_str(&row.get::<String, _>("automation_json"))?;
        let analysis: Analysis = serde_json::from_str(&row.get::<String, _>("raw_json"))?;
        let mut plan: TypePlan = audit
            .get("accepted_plan")
            .map(|v| serde_json::from_value(v.clone()))
            .transpose()?
            .unwrap_or(analysis.type_plan);
        if !plan.cpp.locals.is_empty() {
            plan.cpp.locals.clear();
            audit["accepted_plan"] = serde_json::to_value(&plan)?;
            audit["locals"] = json!("deferred");
            audit["reason"] = json!(
                "Native local identities changed; retained independently validated layouts and signatures without another model request"
            );
            if plan.is_empty() {
                audit["types"] = json!("deferred");
            }
            sqlx::query("UPDATE results SET automation_json=? WHERE id=?")
                .bind(audit.to_string())
                .bind(result)
                .execute(&db.pool)
                .await?;
        }
        if !plan.is_empty() {
            retained.push(result.clone());
        }
    }
    *proposals = retained;
    sqlx::query("UPDATE automatic_recovery SET type_results=? WHERE id=?")
        .bind(serde_json::to_string(proposals)?)
        .bind(cycle)
        .execute(&db.pool)
        .await?;
    if proposals.is_empty() {
        Ok(None)
    } else {
        crate::types::preview_many(db, config, proposals)
            .await
            .map(Some)
    }
}

async fn set_phase(db: &Db, id: &str, status: &str, reason: &str) -> Result<()> {
    sqlx::query("UPDATE automatic_recovery SET status=?,error=?,attempts=0,updated_at=unixepoch() WHERE id=?")
        .bind(status).bind(reason).bind(id).execute(&db.pool).await?;
    Ok(())
}
async fn type_outcome(db: &Db, result: &str, status: &str, reason: &str) -> Result<()> {
    sqlx::query("UPDATE results SET automation_json=json_set(automation_json,'$.types',?,'$.reason',?) WHERE id=?")
        .bind(status).bind(reason).bind(result).execute(&db.pool).await?;
    Ok(())
}

async fn assess(db: &Db, binary: &str) -> Result<Vec<String>> {
    let rows = sqlx::query("SELECT r.*,f.name current_name,f.comment current_comment FROM functions f JOIN results r ON r.id=f.current_result_id WHERE f.binary_id=? AND r.author<>'human' AND r.automation_json='{}' AND NOT EXISTS(SELECT 1 FROM review_decisions WHERE result_id=r.id) ORDER BY f.address")
        .bind(binary).fetch_all(&db.pool).await?;
    let mut plans = Vec::new();
    for row in rows {
        let id: String = row.get("id");
        let decision: Option<String> = sqlx::query_scalar("SELECT response_json FROM decisions WHERE json_extract(request_json,'$.state.candidate.result_id')=? AND json_extract(request_json,'$.state.candidate.revision')=? AND route<>'superseded' ORDER BY rowid DESC LIMIT 1")
            .bind(&id).bind(row.get::<i64,_>("revision")).fetch_optional(&db.pool).await?;
        let answers = decision
            .and_then(|raw| serde_json::from_str::<Value>(&raw).ok())
            .unwrap_or_default();
        let analysis: Analysis = serde_json::from_str(&row.get::<String, _>("raw_json"))?;
        let valid = !row.get::<bool, _>("stale") && analysis.validate().is_ok();
        let name = if valid && supported(&answers["answers"], "name") {
            "accepted"
        } else {
            "deferred"
        };
        let summary = if valid && supported(&answers["answers"], "summary") {
            "accepted"
        } else {
            "deferred"
        };
        let accepted_plan = if valid {
            crate::refinement::accepted_plan(&analysis.type_plan, &answers["answers"])
        } else {
            Default::default()
        };
        let types = if analysis.type_plan.is_empty() {
            "none"
        } else if !accepted_plan.is_empty() {
            "validated"
        } else {
            "deferred"
        };
        let reason = "Fields use independent evidence verdicts and structural validation; confidence scores do not trigger retries";
        let name_status = if name == "accepted"
            && analysis.proposed_name == row.get::<String, _>("current_name")
        {
            "unchanged"
        } else {
            name
        };
        let summary_status = if summary == "accepted"
            && analysis.summary == row.get::<String, _>("current_comment")
        {
            "unchanged"
        } else {
            summary
        };
        let audit = json!({"name":name_status,"summary":summary_status,"types":types,"reason":reason,"verdicts":answers["answers"],"accepted_plan":accepted_plan});
        sqlx::query("UPDATE results SET name_review=?,summary_review=?,review=CASE WHEN ?='accepted' OR ?='accepted' THEN 'accepted' ELSE 'deferred' END,automation_json=? WHERE id=? AND revision=?")
            .bind(name).bind(summary).bind(name).bind(summary).bind(audit.to_string()).bind(&id).bind(row.get::<i64,_>("revision")).execute(&db.pool).await?;
        if types == "validated" {
            plans.push((id, analysis.type_plan));
        }
    }
    // Recover a partially completed assessment after a process restart.
    plans.clear();
    let ready = sqlx::query("SELECT r.id,r.raw_json,r.automation_json FROM functions f JOIN results r ON r.id=f.current_result_id WHERE f.binary_id=? AND r.stale=0 AND json_extract(r.automation_json,'$.types')='validated'")
        .bind(binary).fetch_all(&db.pool).await?;
    for row in ready {
        let analysis: Analysis = serde_json::from_str(&row.get::<String, _>("raw_json"))?;
        let audit: Value = serde_json::from_str(&row.get::<String, _>("automation_json"))?;
        let plan = audit
            .get("accepted_plan")
            .map(|v| serde_json::from_value(v.clone()))
            .transpose()?
            .unwrap_or(analysis.type_plan);
        plans.push((row.get("id"), plan));
    }
    let allowed = compatible(&plans);
    let mut results = Vec::new();
    for (id, _) in plans {
        if allowed.contains(&id) {
            results.push(id);
        } else {
            type_outcome(
                db,
                &id,
                "deferred",
                "Conflicting type definitions or signatures were deferred automatically",
            )
            .await?;
        }
    }
    Ok(results)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        ai::{Ai, Completion},
        pipeline,
    };

    async fn fixture() -> (tempfile::TempDir, Db, Config, String) {
        let dir = tempfile::tempdir().unwrap();
        let db = Db::open(&dir.path().join("db")).await.unwrap();
        sqlx::query("INSERT INTO binaries(id,name,sha256,size,architecture,format,path,paused,status) VALUES('b','fixture','sha',1,'x86','ELF','unused',0,'indexed')").execute(&db.pool).await.unwrap();
        let file = dir.path().join("export.jsonl");
        std::fs::write(&file, json!({"address":"1000","name":"value","size":30,"pseudocode":"int value(int x) { return x + 1; }"}).to_string()).unwrap();
        ghidra::import_export(&db, "b", &file).await.unwrap();
        let config = Config::default();
        let ai = Ai::new(config.ai.clone()).unwrap();
        let job = pipeline::claim(&db, &ai, Some("b"), false)
            .await
            .unwrap()
            .unwrap();
        pipeline::finish(&db,&ai,&job,Completion {
            analysis: serde_json::from_value(json!({"proposed_name":"increment","summary":"Adds one.","confidence":0.99,"evidence":["addition"],"claims":[],"parameter_types":[],"side_effects":[],"uncertainties":[]})).unwrap(),
            input_tokens:1,output_tokens:1,cost:None,latency_ms:1,prompt_hash:"fixture".into(),model:"fixture".into(),
        }).await.unwrap();
        let result: String =
            sqlx::query_scalar("SELECT current_result_id FROM functions WHERE id='b:1000'")
                .fetch_one(&db.pool)
                .await
                .unwrap();
        (dir, db, config, result)
    }

    #[tokio::test]
    async fn independent_fields_defer_without_manual_review_and_resume_idempotently() {
        let (_dir, db, _config, result) = fixture().await;
        let response = json!({"answers":{
            "name":{"type":"choice","choice":"supported","confidence":0.6,"probabilities":{"supported":0.6}},
            "summary":{"type":"choice","choice":"uncertain","confidence":1.0,"probabilities":{"uncertain":1.0}}
        }});
        sqlx::query("INSERT INTO decisions(id,job_id,function_id,stage,model,prompt_hash,extraction_id,request_json,response_json,route,input_tokens,output_tokens,cost_usd,latency_ms) SELECT 'assessment',job_id,function_id,'verify_map','fixture','hash','',?,?,'deferred',1,1,NULL,1 FROM results WHERE id=?")
            .bind(json!({"state":{"candidate":{"result_id":result,"revision":0}}}).to_string()).bind(response.to_string()).bind(&result).execute(&db.pool).await.unwrap();
        assert!(assess(&db, "b").await.unwrap().is_empty());
        let row = knowledge::result(&db, &result).await.unwrap();
        assert_eq!(row.name_review, "accepted");
        assert_eq!(row.summary_review, "deferred");
        assert!(assess(&db, "b").await.unwrap().is_empty());
        let preview = knowledge::preview_apply(&db, "b").await.unwrap();
        assert_eq!(preview.items.len(), 1);
        assert_eq!(preview.items[0].summary, preview.items[0].expected_comment);
        assert_eq!(preview.items[0].name, row.proposed_name);
    }

    #[tokio::test]
    async fn unavailable_assessment_finishes_without_writeback_or_review_and_survives_restart() {
        let (_dir, db, config, result) = fixture().await;
        assert!(!advance(&db, &config, "b", 3).await.unwrap());
        sqlx::query("UPDATE binaries SET recovery_writer=1")
            .execute(&db.pool)
            .await
            .unwrap();
        db.recover().await.unwrap();
        for _ in 0..6 {
            advance(&db, &config, "b", 3).await.unwrap();
        }
        let count: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM automatic_recovery WHERE status='deferred'")
                .fetch_one(&db.pool)
                .await
                .unwrap();
        assert_eq!(count, 1);
        assert_eq!(
            knowledge::result(&db, &result).await.unwrap().name_review,
            "deferred"
        );
        let items: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM apply_items")
            .fetch_one(&db.pool)
            .await
            .unwrap();
        assert_eq!(items, 0);
    }

    #[tokio::test]
    async fn automatic_writer_and_provider_claims_are_mutually_exclusive() {
        let (_dir, db, config, _) = fixture().await;
        sqlx::query("UPDATE jobs SET status='queued'")
            .execute(&db.pool)
            .await
            .unwrap();
        assert!(!advance(&db, &config, "b", 3).await.unwrap());
        sqlx::query("UPDATE binaries SET recovery_writer=1")
            .execute(&db.pool)
            .await
            .unwrap();
        assert!(
            pipeline::claim(&db, &Ai::new(config.ai).unwrap(), Some("b"), false)
                .await
                .unwrap()
                .is_none()
        );
    }

    #[tokio::test]
    async fn unchanged_evidence_stops_reanalysis_and_preserves_budget() {
        let (_dir, db, mut config, _) = fixture().await;
        config.ai.model = "fixture".into();
        config.ai.api_key_env = "USER".into();
        sqlx::query("INSERT INTO functions(id,binary_id,address,name,size,pseudocode) VALUES('b:2000','b','2000','neighbor',30,'return x * 2;')").execute(&db.pool).await.unwrap();
        sqlx::query("INSERT INTO edges(caller,callee) VALUES('b:1000','b:2000')")
            .execute(&db.pool)
            .await
            .unwrap();
        sqlx::query("INSERT INTO artifacts(id,extraction_id,function_id,kind,content,sha256) SELECT 'neighbor-code',id,'b:2000','pseudocode','return x * 2;','fixture' FROM extractions LIMIT 1").execute(&db.pool).await.unwrap();
        let ai = Ai::new(config.ai.clone()).unwrap();
        let initial = ai.prompt(&db, "b:1000", "map").await.unwrap();
        let second = ai.recovery_prompt(&db, "b:1000", "map").await.unwrap();
        let third = ai.recovery_prompt(&db, "b:1000", "map").await.unwrap();
        assert_eq!(
            second.config.max_input_bytes,
            initial.config.max_input_bytes
        );
        assert_eq!(third.config.max_input_bytes, initial.config.max_input_bytes);
        assert_eq!(second.source_fingerprints, third.source_fingerprints);
        assert!(second.source_fingerprints.contains_key("b:2000"));
        sqlx::query("UPDATE jobs SET status='completed'")
            .execute(&db.pool)
            .await
            .unwrap();
        advance(&db, &config, "b", 3).await.unwrap();
        sqlx::query("UPDATE automatic_recovery SET status='reanalysis',pass=2")
            .execute(&db.pool)
            .await
            .unwrap();
        advance(&db, &config, "b", 3).await.unwrap();
        let queued: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM jobs WHERE status='queued'")
            .fetch_one(&db.pool)
            .await
            .unwrap();
        assert_eq!(queued, 0);
        let status: String = sqlx::query_scalar("SELECT status FROM automatic_recovery")
            .fetch_one(&db.pool)
            .await
            .unwrap();
        assert_eq!(status, "deferred");
        // Identical evidence ends recovery before the pass cap, despite new feedback.
        sqlx::query("UPDATE jobs SET input_json=? WHERE id=(SELECT job_id FROM results WHERE id=(SELECT current_result_id FROM functions WHERE id='b:1000'))")
            .bind(serde_json::to_string(&second).unwrap()).execute(&db.pool).await.unwrap();
        sqlx::query("UPDATE automatic_recovery SET status='reanalysis',pass=0")
            .execute(&db.pool)
            .await
            .unwrap();
        advance(&db, &config, "b", 3).await.unwrap();
        let queued: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM jobs WHERE status='queued'")
            .fetch_one(&db.pool)
            .await
            .unwrap();
        assert_eq!(queued, 0);
        let status: String = sqlx::query_scalar("SELECT status FROM automatic_recovery")
            .fetch_one(&db.pool)
            .await
            .unwrap();
        assert_eq!(status, "deferred");
    }

    #[tokio::test]
    async fn changed_native_types_schedule_one_bounded_followup_without_preprocessing() {
        let (_dir, db, mut config, _) = fixture().await;
        config.ai.model = "fixture".into();
        config.ai.api_key_env = "USER".into();
        let ai = Ai::new(config.ai.clone()).unwrap();
        let prompt = ai.prompt(&db, "b:1000", "map").await.unwrap();
        sqlx::query("UPDATE jobs SET input_json=?")
            .bind(serde_json::to_string(&prompt).unwrap())
            .execute(&db.pool)
            .await
            .unwrap();
        advance(&db, &config, "b", 3).await.unwrap();
        sqlx::query("UPDATE functions SET type_context=? WHERE id='b:1000'")
            .bind(json!({"return_type":"uint64"}).to_string())
            .execute(&db.pool)
            .await
            .unwrap();
        sqlx::query("UPDATE automatic_recovery SET status='reanalysis'")
            .execute(&db.pool)
            .await
            .unwrap();
        advance(&db, &config, "b", 3).await.unwrap();
        let (stage, input): (String, String) =
            sqlx::query_as("SELECT stage,input_json FROM jobs WHERE status='queued'")
                .fetch_one(&db.pool)
                .await
                .unwrap();
        assert_eq!(stage, "map");
        let followup: crate::ai::Prompt = serde_json::from_str(&input).unwrap();
        assert_eq!(
            followup.config.max_input_bytes,
            prompt.config.max_input_bytes
        );
        assert_ne!(followup.source_fingerprints, prompt.source_fingerprints);
        let selected: i64 = sqlx::query_scalar("SELECT selected FROM recovery_passes WHERE pass=2")
            .fetch_one(&db.pool)
            .await
            .unwrap();
        assert_eq!(selected, 1);
    }

    #[tokio::test]
    async fn explicit_context_requests_fetch_missing_excerpts_once_without_manual_work() {
        let (_dir, db, config, _) = fixture().await;
        sqlx::query("INSERT INTO functions(id,binary_id,address,name,size,pseudocode) VALUES('b:2000','b','2000','callee',30,'code')").execute(&db.pool).await.unwrap();
        sqlx::query("INSERT INTO edges(caller,callee) VALUES('b:1000','b:2000')")
            .execute(&db.pool)
            .await
            .unwrap();
        sqlx::query("INSERT INTO artifacts(id,extraction_id,function_id,kind,content,sha256) SELECT 'callee-code',id,'b:2000','pseudocode',?,'fixture' FROM extractions LIMIT 1")
            .bind("header\nbranch\nreturn value;\nfooter").execute(&db.pool).await.unwrap();
        let ai = Ai::new(config.ai).unwrap();
        let original = ai.prompt(&db, "b:1000", "map").await.unwrap();
        let mut request = crate::ai::ContextRequest {
            question: "What value does the callee return?".into(),
            address: "2000".into(),
            kind: "pseudocode".into(),
            start_line: 2,
            end_line: 3,
        };
        let (prompt, _) = ai
            .requested_context(&db, "b:1000", &original, &[request.clone()])
            .await
            .unwrap()
            .unwrap();
        let snippet = prompt
            .evidence
            .iter()
            .find(|e| e.artifact_id == "callee-code")
            .unwrap();
        assert_eq!(snippet.start_line, 2);
        assert_eq!(snippet.content.lines().count(), 2);
        assert!(
            serde_json::to_vec(&prompt.messages).unwrap().len() <= prompt.config.max_input_bytes
        );
        assert!(
            ai.requested_context(&db, "b:1000", &prompt, &[request.clone()])
                .await
                .unwrap()
                .is_none()
        );
        let mut tail = request.clone();
        tail.start_line = 4;
        tail.end_line = 4;
        let (windows, _) = ai
            .requested_context(&db, "b:1000", &original, &[request.clone(), tail])
            .await
            .unwrap()
            .unwrap();
        let mut analysis: Analysis = serde_json::from_value(json!({"proposed_name":"value","summary":"Returns a value.","confidence":0.5,"evidence":["code"],"claims":[{"text":"Tail inspected","references":[{"artifact_id":"callee-code","start_line":4,"end_line":4}]}],"parameter_types":[],"side_effects":[],"uncertainties":[]})).unwrap();
        assert!(Ai::validate_evidence(&analysis, &windows).is_ok());
        analysis.claims[0].references[0].start_line = 1;
        assert!(Ai::validate_evidence(&analysis, &windows).is_err());
        request.kind = "recording".into();
        assert!(
            ai.requested_context(&db, "b:1000", &original, &[request.clone()])
                .await
                .unwrap()
                .is_none()
        );
        request.kind = "pseudocode".into();
        request.address = "9999".into();
        assert!(
            ai.requested_context(&db, "b:1000", &original, &[request])
                .await
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn conflicting_types_defer_both_sources_but_keep_independent_plans() {
        let plan = |size| TypePlan {
            definitions: vec![crate::types::Definition::Structure {
                name: "Record".into(),
                size,
                fields: vec![],
            }],
            signatures: vec![],
            ..Default::default()
        };
        let plans = vec![
            ("one".into(), plan(4)),
            ("two".into(), plan(8)),
            ("independent".into(), TypePlan::default()),
        ];
        assert_eq!(
            compatible(&plans),
            HashSet::from(["independent".to_owned()])
        );
        assert_eq!(
            compatible(&plans.into_iter().rev().collect::<Vec<_>>()),
            HashSet::from(["independent".to_owned()])
        );
    }
}
