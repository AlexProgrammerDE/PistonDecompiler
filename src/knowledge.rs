//! Durable evidence, result revisions, review decisions, and investigation scope.
use crate::{config::AiConfig, db::Db, proto};
use anyhow::{Result, ensure};
use sha2::{Digest, Sha256};
use sqlx::{Row, Sqlite, Transaction};

pub fn id() -> String {
    uuid::Uuid::new_v4().to_string()
}

pub async fn result(db: &Db, id: &str) -> Result<proto::AnalysisResult> {
    let r = sqlx::query("SELECT r.*,COALESCE(j.input_json,'') input_json,COALESCE(j.transcript_json,'[]') transcript_json FROM results r LEFT JOIN jobs j ON j.id=r.job_id WHERE r.id=?").bind(id).fetch_one(&db.pool).await?;
    let dependencies = sqlx::query_scalar(
        "SELECT dependency_id FROM result_dependencies WHERE result_id=? ORDER BY dependency_id",
    )
    .bind(id)
    .fetch_all(&db.pool)
    .await?;
    Ok(proto::AnalysisResult {
        id: r.get("id"),
        function_id: r.get("function_id"),
        proposed_name: r.get("proposed_name"),
        summary: r.get("summary"),
        author: r.get("author"),
        model: r.get("model"),
        stage: r.get("stage"),
        stale: r.get("stale"),
        revision: r.get::<i64, _>("revision") as u32,
        name_review: r.get("name_review"),
        summary_review: r.get("summary_review"),
        analysis_json: r.get("raw_json"),
        extraction_id: r.get("extraction_id"),
        created_at: r.get("created_at"),
        parent_id: r.get::<Option<String>, _>("parent_id").unwrap_or_default(),
        dependencies,
        input_json: r.get("input_json"),
        transcript_json: r.get("transcript_json"),
    })
}
pub async fn history(db: &Db, function: &str) -> Result<proto::ResultList> {
    let ids: Vec<String> = sqlx::query_scalar(
        "SELECT id FROM results WHERE function_id=? ORDER BY rowid DESC LIMIT 100",
    )
    .bind(function)
    .fetch_all(&db.pool)
    .await?;
    let mut results = Vec::new();
    for id in ids {
        results.push(result(db, &id).await?);
    }
    Ok(proto::ResultList { results })
}
pub async fn artifact(db: &Db, id: &str) -> Result<proto::Artifact> {
    let r=sqlx::query("SELECT a.*,e.metadata_json FROM artifacts a JOIN extractions e ON e.id=a.extraction_id WHERE a.id=?").bind(id).fetch_one(&db.pool).await?;
    Ok(proto::Artifact {
        id: r.get("id"),
        extraction_id: r.get("extraction_id"),
        function_id: r.get("function_id"),
        kind: r.get("kind"),
        content: r.get("content"),
        sha256: r.get("sha256"),
        metadata_json: r.get("metadata_json"),
    })
}
/// Called inside the extraction transaction, before any worker can see the evidence.
pub async fn snapshot(
    tx: &mut Transaction<'_, Sqlite>,
    binary: &str,
    metadata: &str,
) -> Result<String> {
    let extraction = id();
    sqlx::query("INSERT INTO extractions(id,binary_id,metadata_json) VALUES(?,?,?)")
        .bind(&extraction)
        .bind(binary)
        .bind(metadata)
        .execute(&mut **tx)
        .await?;
    let functions: Vec<String> = sqlx::query_scalar("SELECT id FROM functions WHERE binary_id=?")
        .bind(binary)
        .fetch_all(&mut **tx)
        .await?;
    for function in &functions {
        let r=sqlx::query("SELECT id,pseudocode,disassembly,pcode,strings_json,imports_json FROM functions WHERE id=?").bind(function).fetch_one(&mut **tx).await?;
        for kind in [
            "pseudocode",
            "disassembly",
            "pcode",
            "strings_json",
            "imports_json",
        ] {
            let content: String = r.get(kind);
            sqlx::query("INSERT INTO artifacts(id,extraction_id,function_id,kind,content,sha256) VALUES(?,?,?,?,?,?)")
            .bind(id()).bind(&extraction).bind(r.get::<String,_>("id")).bind(kind).bind(&content).bind(hex::encode(Sha256::digest(content.as_bytes()))).execute(&mut **tx).await?;
        }
    }
    let functions: Vec<String> = sqlx::query_scalar("SELECT id FROM functions WHERE binary_id=?")
        .bind(binary)
        .fetch_all(&mut **tx)
        .await?;
    for function in functions {
        let callees:Vec<String>=sqlx::query_scalar("SELECT f.address FROM edges e JOIN functions f ON f.id=e.callee WHERE e.caller=? ORDER BY f.address").bind(&function).fetch_all(&mut **tx).await?;
        let callers:Vec<String>=sqlx::query_scalar("SELECT f.address FROM edges e JOIN functions f ON f.id=e.caller WHERE e.callee=? ORDER BY f.address").bind(&function).fetch_all(&mut **tx).await?;
        let content = serde_json::to_string_pretty(
            &serde_json::json!({"callers":callers,"callees":callees}),
        )?;
        sqlx::query("INSERT INTO artifacts(id,extraction_id,function_id,kind,content,sha256) VALUES(?,?,?,'references',?,?)").bind(id()).bind(&extraction).bind(&function).bind(&content).bind(hex::encode(Sha256::digest(content.as_bytes()))).execute(&mut **tx).await?;
    }
    Ok(extraction)
}
/// Materialize an honest legacy snapshot rather than claiming historical tool versions.
pub async fn backfill(db: &Db) -> Result<()> {
    let mut tx = db.pool.begin().await?;
    let binaries:Vec<String>=sqlx::query_scalar("SELECT DISTINCT binary_id FROM functions WHERE binary_id NOT IN (SELECT binary_id FROM extractions)").fetch_all(&mut *tx).await?;
    for binary in binaries {
        snapshot(
            &mut tx,
            &binary,
            r#"{"source":"legacy index","ghidra_version":"unknown","exporter_version":"unknown"}"#,
        )
        .await?;
    }
    tx.commit().await?;
    Ok(())
}

pub async fn invalidate(tx: &mut Transaction<'_, Sqlite>, old: &str) -> Result<()> {
    sqlx::query("WITH RECURSIVE affected(id) AS (SELECT result_id FROM result_dependencies WHERE dependency_id=? UNION SELECT d.result_id FROM result_dependencies d JOIN affected a ON d.dependency_id=a.id) UPDATE results SET stale=1 WHERE id IN (SELECT id FROM affected)")
        .bind(old).execute(&mut **tx).await?;
    Ok(())
}
pub async fn review(db: &Db, request: &proto::ReviewRequest) -> Result<()> {
    ensure!(
        ["name", "summary", "both"].contains(&request.field.as_str()),
        "Choose name, summary, or both"
    );
    ensure!(
        ["accepted", "rejected"].contains(&request.decision.as_str()),
        "Choose accepted or rejected"
    );
    ensure!(request.reason.len() <= 8000, "Review reason is too long");
    let mut tx = db.pool.begin().await?;
    let changed=sqlx::query("UPDATE results SET name_review=CASE WHEN ? IN ('name','both') THEN ? ELSE name_review END,summary_review=CASE WHEN ? IN ('summary','both') THEN ? ELSE summary_review END,revision=revision+1 WHERE id=? AND revision=? AND stale=0 AND NOT EXISTS(SELECT 1 FROM apply_items i JOIN apply_operations o ON o.id=i.operation_id WHERE i.result_id=results.id AND o.status IN ('applying','uncertain'))")
        .bind(&request.field).bind(&request.decision).bind(&request.field).bind(&request.decision).bind(&request.result_id).bind(i64::from(request.expected_revision)).execute(&mut *tx).await?.rows_affected();
    ensure!(
        changed == 1,
        "Result changed, is stale, or has an unresolved apply operation. Refresh before reviewing."
    );
    sqlx::query("UPDATE results SET review=CASE WHEN name_review='accepted' OR summary_review='accepted' THEN 'accepted' WHEN name_review='rejected' AND summary_review='rejected' THEN 'rejected' ELSE 'pending' END WHERE id=?").bind(&request.result_id).execute(&mut *tx).await?;
    sqlx::query("INSERT INTO review_decisions(id,result_id,field,decision,reason,revision) VALUES(?,?,?,?,?,?)").bind(id()).bind(&request.result_id).bind(&request.field).bind(&request.decision).bind(&request.reason).bind(i64::from(request.expected_revision)+1).execute(&mut *tx).await?;
    // Rejection changes the meaning of context already consumed by callers.
    if request.decision == "rejected" {
        invalidate(&mut tx, &request.result_id).await?;
    }
    if request.decision == "accepted" {
        let old:Option<String>=sqlx::query_scalar("SELECT current_result_id FROM functions WHERE id=(SELECT function_id FROM results WHERE id=?)").bind(&request.result_id).fetch_one(&mut *tx).await?;
        if let Some(old) = old
            && old != request.result_id
        {
            invalidate(&mut tx, &old).await?;
        }
        sqlx::query("UPDATE functions SET current_result_id=? WHERE id=(SELECT function_id FROM results WHERE id=?)").bind(&request.result_id).bind(&request.result_id).execute(&mut *tx).await?;
        sqlx::query("UPDATE function_search SET summary=(SELECT proposed_name||' '||summary FROM results WHERE id=?) WHERE function_id=(SELECT function_id FROM results WHERE id=?)").bind(&request.result_id).bind(&request.result_id).execute(&mut *tx).await?;
    }
    tx.commit().await?;
    Ok(())
}
pub async fn correct(db: &Db, r: &proto::CorrectionRequest) -> Result<proto::AnalysisResult> {
    ensure!(
        !r.proposed_name.is_empty()
            && r.proposed_name.len() <= 160
            && r.proposed_name.bytes().enumerate().all(|(i, c)| c == b'_'
                || c.is_ascii_alphabetic()
                || (i > 0 && c.is_ascii_digit())),
        "Invalid C identifier"
    );
    ensure!(
        !r.summary.trim().is_empty()
            && r.summary.len() <= 8000
            && !r.reason.trim().is_empty()
            && r.reason.len() <= 8000,
        "Provide a summary and correction reason (at most 8000 bytes each)"
    );
    let new = id();
    let mut tx = db.pool.begin().await?;
    let changed=sqlx::query("UPDATE results SET revision=revision+1 WHERE id=? AND revision=? AND id=(SELECT current_result_id FROM functions WHERE id=results.function_id) AND NOT EXISTS(SELECT 1 FROM apply_items i JOIN apply_operations o ON o.id=i.operation_id WHERE i.result_id=results.id AND o.status IN ('applying','uncertain'))")
        .bind(&r.result_id).bind(i64::from(r.expected_revision)).execute(&mut *tx).await?.rows_affected();
    ensure!(
        changed == 1,
        "Result changed or is being applied. Refresh before correcting."
    );
    sqlx::query("INSERT INTO results(id,function_id,stage,model,prompt_hash,raw_json,proposed_name,summary,confidence,review,input_tokens,output_tokens,cost_usd,latency_ms,parent_id,author,name_review,summary_review,extraction_id) SELECT ?,function_id,'human','','',?, ?,?,0,'accepted',0,0,0,0,id,'human','accepted','accepted',extraction_id FROM results WHERE id=?")
        .bind(&new).bind(serde_json::json!({"correction_reason":r.reason,"evidence_status":"Review the parent result for original evidence; this correction is human-authored."}).to_string()).bind(&r.proposed_name).bind(&r.summary).bind(&r.result_id).execute(&mut *tx).await?;
    sqlx::query("INSERT INTO result_dependencies SELECT ?,dependency_id FROM result_dependencies WHERE result_id=?").bind(&new).bind(&r.result_id).execute(&mut *tx).await?;
    invalidate(&mut tx, &r.result_id).await?;
    sqlx::query("UPDATE functions SET current_result_id=? WHERE current_result_id=?")
        .bind(&new)
        .bind(&r.result_id)
        .execute(&mut *tx)
        .await?;
    sqlx::query("UPDATE function_search SET summary=? WHERE function_id=(SELECT function_id FROM results WHERE id=?)").bind(format!("{} {}",r.proposed_name,r.summary)).bind(&new).execute(&mut *tx).await?;
    tx.commit().await?;
    result(db, &new).await
}

pub async fn reanalyze(
    db: &Db,
    config: &AiConfig,
    r: &proto::ReanalysisRequest,
) -> Result<proto::RunResponse> {
    ensure!(r.function_ids.len() <= 200, "Select at most 200 functions");
    let stage = if r.stage.is_empty() {
        "map"
    } else {
        r.stage.as_str()
    };
    ensure!(
        ["map", "escalate"].contains(&stage),
        "Choose map or escalate"
    );
    ensure!(
        stage != "escalate" || !config.escalation_model.is_empty(),
        "Configure an escalation model first"
    );
    let stage = if stage == "map" && config.decisions.is_some() {
        "preprocess"
    } else {
        stage
    };
    let run = id();
    let mut tx = db.pool.begin().await?;
    let investigation = if r.investigation_id.is_empty() {
        None
    } else {
        Some(r.investigation_id.as_str())
    };
    if let Some(i) = investigation {
        let binary: String = sqlx::query_scalar("SELECT binary_id FROM investigations WHERE id=?")
            .bind(i)
            .fetch_one(&mut *tx)
            .await?;
        ensure!(
            binary == r.binary_id,
            "Investigation belongs to another binary"
        );
    }
    sqlx::query("INSERT INTO analysis_runs(id,binary_id,investigation_id,reason,config_json) VALUES(?,?,?,?,?)").bind(&run).bind(&r.binary_id).bind(investigation).bind(if r.stale_only{"Reconsider stale conclusions"}else{"Analyze selected scope"}).bind(serde_json::to_string(config)?).execute(&mut *tx).await?;
    let functions: Vec<String> = if r.function_ids.is_empty() {
        ensure!(
            r.stale_only || investigation.is_some(),
            "Select functions or an investigation"
        );
        sqlx::query_scalar("SELECT f.id FROM functions f LEFT JOIN results r ON r.id=f.current_result_id WHERE f.binary_id=? AND (?=0 OR r.stale=1) AND (? IS NULL OR f.id IN (SELECT function_id FROM investigation_functions WHERE investigation_id=?)) ORDER BY f.address LIMIT 200")
            .bind(&r.binary_id).bind(r.stale_only).bind(investigation).bind(investigation).fetch_all(&mut *tx).await?
    } else {
        r.function_ids.clone()
    };
    let question: String = if let Some(i) = investigation {
        sqlx::query_scalar("SELECT question FROM investigations WHERE id=?")
            .bind(i)
            .fetch_one(&mut *tx)
            .await?
    } else {
        String::new()
    };
    let mut queued = 0;
    for f in functions {
        let belongs: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM functions WHERE id=? AND binary_id=?")
                .bind(&f)
                .bind(&r.binary_id)
                .fetch_one(&mut *tx)
                .await?;
        ensure!(belongs == 1, "Function belongs to another binary");
        if let Some(i) = investigation {
            let member:i64=sqlx::query_scalar("SELECT COUNT(*) FROM investigation_functions WHERE investigation_id=? AND function_id=?").bind(i).bind(&f).fetch_one(&mut *tx).await?;
            ensure!(member == 1, "Function is outside investigation scope");
        }
        queued+=sqlx::query("INSERT OR IGNORE INTO jobs(id,binary_id,function_id,stage,run_id) SELECT ?,?,f.id,?,? FROM functions f LEFT JOIN results r ON r.id=f.current_result_id WHERE f.id=? AND (?=0 OR r.stale=1) AND NOT EXISTS(SELECT 1 FROM jobs WHERE function_id=f.id AND status IN ('running','batched','uncertain'))")
            .bind(id()).bind(&r.binary_id).bind(stage).bind(&run).bind(&f).bind(r.stale_only).execute(&mut *tx).await?.rows_affected() as u32;
    }
    ensure!(
        queued > 0,
        "No eligible functions to queue. Selected functions may already be running or have no stale results."
    );
    let ai = crate::ai::Ai::new(config.clone())?;
    let jobs = sqlx::query("SELECT id,function_id,stage FROM jobs WHERE run_id=?")
        .bind(&run)
        .fetch_all(&mut *tx)
        .await?;
    for job in jobs {
        let prompt = ai
            .investigation_prompt(
                db,
                &job.get::<String, _>("function_id"),
                &job.get::<String, _>("stage"),
                &question,
            )
            .await?;
        sqlx::query("UPDATE jobs SET input_json=? WHERE id=?")
            .bind(serde_json::to_string(&prompt)?)
            .bind(job.get::<String, _>("id"))
            .execute(&mut *tx)
            .await?;
    }
    sqlx::query("UPDATE binaries SET active_run_id=?,paused=1 WHERE id=?")
        .bind(&run)
        .bind(&r.binary_id)
        .execute(&mut *tx)
        .await?;
    tx.commit().await?;
    Ok(proto::RunResponse { id: run, queued })
}

pub async fn investigations(db: &Db, binary: &str) -> Result<proto::InvestigationList> {
    let rows = sqlx::query("SELECT * FROM investigations WHERE binary_id=? ORDER BY created_at,id")
        .bind(binary)
        .fetch_all(&db.pool)
        .await?;
    let mut investigations = Vec::new();
    for r in rows {
        let id: String = r.get("id");
        let function_ids=sqlx::query_scalar("SELECT function_id FROM investigation_functions WHERE investigation_id=? ORDER BY function_id").bind(&id).fetch_all(&db.pool).await?;
        let result_ids=sqlx::query_scalar("SELECT result_id FROM investigation_findings WHERE investigation_id=? ORDER BY result_id").bind(&id).fetch_all(&db.pool).await?;
        investigations.push(proto::Investigation {
            id,
            binary_id: r.get("binary_id"),
            question: r.get("question"),
            notes: r.get("notes"),
            budget_usd: r.get("budget_usd"),
            revision: r.get::<i64, _>("revision") as u32,
            function_ids,
            result_ids,
        });
    }
    Ok(proto::InvestigationList { investigations })
}
pub async fn save_investigation(db: &Db, r: &proto::Investigation) -> Result<proto::Investigation> {
    ensure!(
        !r.question.trim().is_empty() && r.question.len() <= 4000 && r.notes.len() <= 32000,
        "Provide a question and keep notes below 32000 bytes"
    );
    ensure!(
        r.budget_usd.is_finite()
            && r.budget_usd > 0.0
            && r.function_ids.len() <= 200
            && r.result_ids.len() <= 200,
        "Invalid budget or scope (maximum 200 functions and findings)"
    );
    let mut saved = r.clone();
    let mut tx = db.pool.begin().await?;
    if r.id.is_empty() {
        saved.id = id();
        saved.revision = 0;
        sqlx::query(
            "INSERT INTO investigations(id,binary_id,question,notes,budget_usd) VALUES(?,?,?,?,?)",
        )
        .bind(&saved.id)
        .bind(&r.binary_id)
        .bind(&r.question)
        .bind(&r.notes)
        .bind(r.budget_usd)
        .execute(&mut *tx)
        .await?;
    } else {
        let changed=sqlx::query("UPDATE investigations SET question=?,notes=?,budget_usd=?,revision=revision+1 WHERE id=? AND binary_id=? AND revision=?").bind(&r.question).bind(&r.notes).bind(r.budget_usd).bind(&r.id).bind(&r.binary_id).bind(i64::from(r.revision)).execute(&mut *tx).await?.rows_affected();
        ensure!(changed == 1, "Investigation changed. Reload before saving.");
        saved.revision += 1;
    }
    for table in ["investigation_functions", "investigation_findings"] {
        sqlx::query(&format!("DELETE FROM {table} WHERE investigation_id=?"))
            .bind(&saved.id)
            .execute(&mut *tx)
            .await?;
    }
    for f in &r.function_ids {
        let n=sqlx::query("INSERT OR IGNORE INTO investigation_functions SELECT ?,id FROM functions WHERE id=? AND binary_id=?").bind(&saved.id).bind(f).bind(&r.binary_id).execute(&mut *tx).await?.rows_affected();
        ensure!(n == 1, "Invalid or duplicate function in scope");
    }
    for result in &r.result_ids {
        let n=sqlx::query("INSERT OR IGNORE INTO investigation_findings SELECT ?,r.id FROM results r JOIN functions f ON f.id=r.function_id WHERE r.id=? AND f.binary_id=?").bind(&saved.id).bind(result).bind(&r.binary_id).execute(&mut *tx).await?.rows_affected();
        ensure!(n == 1, "Invalid or duplicate finding");
    }
    tx.commit().await?;
    Ok(saved)
}

pub async fn apply_operation(db: &Db, id: &str) -> Result<proto::ApplyOperation> {
    let r = sqlx::query("SELECT * FROM apply_operations WHERE id=?")
        .bind(id)
        .fetch_one(&db.pool)
        .await?;
    let rows = sqlx::query("SELECT * FROM apply_items WHERE operation_id=? ORDER BY address")
        .bind(id)
        .fetch_all(&db.pool)
        .await?;
    let items = rows
        .iter()
        .map(|r| proto::ApplyItem {
            result_id: r.get("result_id"),
            revision: r.get::<i64, _>("revision") as u32,
            address: r.get("address"),
            expected_name: r.get("expected_name"),
            expected_comment: r.get("expected_comment"),
            name: r.get("name"),
            summary: r.get("summary"),
            status: r.get("status"),
            error: r.get("error"),
        })
        .collect();
    Ok(proto::ApplyOperation {
        id: r.get("id"),
        binary_id: r.get("binary_id"),
        status: r.get("status"),
        error: r.get("error"),
        items,
    })
}
pub async fn preview_apply(db: &Db, binary: &str) -> Result<proto::ApplyOperation> {
    let operation = id();
    let mut tx = db.pool.begin().await?;
    sqlx::query("INSERT INTO apply_operations(id,binary_id) VALUES(?,?)")
        .bind(&operation)
        .bind(binary)
        .execute(&mut *tx)
        .await?;
    sqlx::query("INSERT INTO apply_items(operation_id,result_id,revision,address,expected_name,expected_comment,name,summary) SELECT ?,r.id,r.revision,f.address,f.name,f.comment,CASE WHEN r.name_review='accepted' THEN r.proposed_name ELSE f.name END,CASE WHEN r.summary_review='accepted' THEN r.summary ELSE f.comment END FROM functions f JOIN results r ON r.id=f.current_result_id WHERE f.binary_id=? AND r.stale=0 AND (r.name_review='accepted' OR r.summary_review='accepted') AND ((r.name_review='accepted' AND r.proposed_name<>f.name) OR (r.summary_review='accepted' AND r.summary<>f.comment))").bind(&operation).bind(binary).execute(&mut *tx).await?;
    tx.commit().await?;
    apply_operation(db, &operation).await
}
