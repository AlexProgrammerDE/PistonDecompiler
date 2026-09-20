//! Explicit, bounded orchestration of analysis, type writeback, and fresh decompilation.
use crate::{ai::Ai, config::Config, db::Db, pipeline, types};
use anyhow::{Context, Result, ensure};
use sha2::{Digest, Sha256};
use sqlx::Row;
use std::collections::{BTreeMap, HashSet};

pub async fn run(
    db: &Db,
    config: &Config,
    ai: &Ai,
    binary: &str,
    max_iterations: u32,
    apply_types: bool,
) -> Result<()> {
    ensure!(
        (1..=5).contains(&max_iterations),
        "Recovery requires 1 to 5 iterations"
    );
    ensure!(ai.config.configured(), "Configure the model and key first");
    let active:i64=sqlx::query_scalar("SELECT COUNT(*) FROM jobs WHERE binary_id=? AND status IN ('running','batched','uncertain')").bind(binary).fetch_one(&db.pool).await?;
    ensure!(
        active == 0,
        "Resolve active or uncertain jobs before recovery"
    );
    let prior_run: Option<String> =
        sqlx::query_scalar("SELECT active_run_id FROM binaries WHERE id=?")
            .bind(binary)
            .fetch_one(&db.pool)
            .await?;
    // The CLI owns the data-directory lock. Pause between iterations before any writer runs.
    sqlx::query("UPDATE binaries SET paused=1 WHERE id=?")
        .bind(binary)
        .execute(&db.pool)
        .await?;
    let result = async {
        for _ in 0..5 {
            if run_components(db, config, ai, binary, max_iterations, apply_types).await? {
                return Ok(());
            }
        }
        anyhow::bail!(
            "Call graph changed five times during recovery; inspect the recorded iterations"
        )
    }
    .await;
    sqlx::query("UPDATE binaries SET paused=1,active_run_id=? WHERE id=?")
        .bind(prior_run)
        .bind(binary)
        .execute(&db.pool)
        .await?;
    result
}
async fn run_components(
    db: &Db,
    config: &Config,
    ai: &Ai,
    binary: &str,
    max_iterations: u32,
    apply_types: bool,
) -> Result<bool> {
    let ids: Vec<String> =
        sqlx::query_scalar("SELECT id FROM functions WHERE binary_id=? ORDER BY id")
            .bind(binary)
            .fetch_all(&db.pool)
            .await?;
    let edges: Vec<(String, String)> = sqlx::query_as(
        "SELECT caller,callee FROM edges JOIN functions f ON f.id=caller WHERE f.binary_id=?",
    )
    .bind(binary)
    .fetch_all(&db.pool)
    .await?;
    let graph_edges: HashSet<_> = edges.iter().cloned().collect();
    let ranks = crate::graph::dependency_ranks(&ids, &edges);
    let rows=sqlx::query("SELECT c.component_id,f.id FROM functions f JOIN function_components c ON c.function_id=f.id WHERE f.binary_id=? AND f.skip_reason='' ORDER BY f.id").bind(binary).fetch_all(&db.pool).await?;
    let mut components: BTreeMap<(usize, String), Vec<String>> = BTreeMap::new();
    for row in rows {
        let id: String = row.get("id");
        components
            .entry((ranks[&id], row.get("component_id")))
            .or_default()
            .push(id);
    }
    for ((_, component), functions) in components {
        let mut hashes = HashSet::new();
        let mut previous = None;
        for iteration in 1..=max_iterations {
            let run = crate::knowledge::id();
            let record = crate::knowledge::id();
            let stage = if ai.config.decisions.is_some() {
                "preprocess"
            } else {
                "map"
            };
            // Pin every SCC member before any member publishes this iteration's result.
            let mut prompts = Vec::new();
            for function in &functions {
                prompts.push((function, ai.prompt(db, function, stage).await?));
            }
            let mut tx = db.pool.begin().await?;
            sqlx::query(
                "INSERT INTO analysis_runs(id,binary_id,reason,config_json) VALUES(?,?,?,?)",
            )
            .bind(&run)
            .bind(binary)
            .bind(format!(
                "Recovery component {component}, iteration {iteration}"
            ))
            .bind(serde_json::to_string(&ai.config)?)
            .execute(&mut *tx)
            .await?;
            sqlx::query("INSERT INTO recovery_iterations(id,binary_id,component_id,iteration,run_id) VALUES(?,?,?,?,?)").bind(&record).bind(binary).bind(&component).bind(iteration).bind(&run).execute(&mut *tx).await?;
            for (function, prompt) in prompts {
                sqlx::query("INSERT INTO jobs(id,binary_id,function_id,stage,run_id,input_json) VALUES(?,?,?,?,?,?)").bind(crate::knowledge::id()).bind(binary).bind(function).bind(stage).bind(&run).bind(serde_json::to_string(&prompt)?).execute(&mut *tx).await?;
            }
            sqlx::query("UPDATE binaries SET active_run_id=?,paused=0 WHERE id=?")
                .bind(&run)
                .bind(binary)
                .execute(&mut *tx)
                .await?;
            tx.commit().await?;
            let outcome = analyze_run(db, ai, binary, &run).await;
            sqlx::query("UPDATE binaries SET paused=1 WHERE id=?")
                .bind(binary)
                .execute(&db.pool)
                .await?;
            if let Err(error) = outcome {
                set_status(db, &record, "blocked", &format!("{error:#}")).await?;
                return Err(error);
            }
            let rows=sqlx::query("SELECT r.id,r.raw_json,r.confidence FROM functions f JOIN results r ON r.id=f.current_result_id JOIN jobs j ON j.id=r.job_id WHERE j.run_id=? ORDER BY f.id").bind(&run).fetch_all(&db.pool).await?;
            if rows.len() != functions.len() {
                set_status(
                    db,
                    &record,
                    "needs_review",
                    "Some functions were deferred or retain protected human results",
                )
                .await?;
                anyhow::bail!(
                    "Component {component} has deferred evidence or protected results; review it before recovery continues"
                );
            }
            let mut proposals = Vec::new();
            let mut plans = Vec::new();
            for row in rows {
                let analysis: crate::ai::Analysis =
                    serde_json::from_str(&row.get::<String, _>("raw_json"))?;
                if analysis.type_plan.is_empty() {
                    continue;
                }
                let id: String = row.get("id");
                let supported: bool = sqlx::query_scalar(
                    "SELECT EXISTS(SELECT 1 FROM decisions WHERE json_extract(request_json,'$.state.candidate.result_id')=? AND route='review')",
                )
                .bind(&id)
                .fetch_one(&db.pool)
                .await?;
                if !supported || row.get::<f64, _>("confidence") < 0.95 {
                    set_status(
                        db,
                        &record,
                        "needs_review",
                        "Type proposal lacks high-confidence assessment",
                    )
                    .await?;
                    anyhow::bail!(
                        "Component {component} needs type review before callers can proceed"
                    );
                }
                let mut plan = analysis.type_plan;
                plan.definitions.sort_by(|a, b| a.name().cmp(b.name()));
                for definition in &mut plan.definitions {
                    if let crate::types::Definition::Structure { fields, .. } = definition {
                        fields.sort_by_key(|f| f.offset);
                    }
                }
                plan.signatures.sort_by(|a, b| a.address.cmp(&b.address));
                plans.push(plan);
                proposals.push(id);
            }
            let hash = hex::encode(Sha256::digest(serde_json::to_vec(&plans)?));
            sqlx::query("UPDATE recovery_iterations SET plan_hash=? WHERE id=?")
                .bind(&hash)
                .bind(&record)
                .execute(&db.pool)
                .await?;
            if proposals.is_empty() || previous.as_ref() == Some(&hash) {
                set_status(db, &record, "stable", "").await?;
                break;
            }
            if !hashes.insert(hash.clone()) {
                set_status(
                    db,
                    &record,
                    "oscillation",
                    "Type plans repeated without convergence",
                )
                .await?;
                anyhow::bail!("Component {component} oscillated between type plans");
            }
            previous = Some(hash);
            let operation = match types::preview_many(db, config, &proposals).await {
                Ok(operation) => operation,
                Err(error) => {
                    set_status(db, &record, "blocked", &format!("{error:#}")).await?;
                    return Err(error);
                }
            };
            let operation_id = operation["id"]
                .as_str()
                .context("Missing type operation ID")?;
            if !apply_types {
                set_status(
                    db,
                    &record,
                    "needs_review",
                    &format!("Apply type operation {operation_id}"),
                )
                .await?;
                anyhow::bail!(
                    "Type preview {operation_id} is ready. Apply it or run recovery with --apply-types to authorize assessed changes"
                );
            }
            set_status(db, &record, "applying", operation_id).await?;
            if let Err(error) = types::apply(db, config, operation_id).await {
                set_status(db, &record, "blocked", &format!("{error:#}")).await?;
                return Err(error);
            }
            set_status(db, &record, "applied", "").await?;
            let current:Vec<(String,String)>=sqlx::query_as("SELECT caller,callee FROM edges JOIN functions f ON f.id=caller WHERE f.binary_id=?").bind(binary).fetch_all(&db.pool).await?;
            if current.into_iter().collect::<HashSet<_>>() != graph_edges {
                set_status(
                    db,
                    &record,
                    "graph_changed",
                    "Rebuild SCC order before continuing",
                )
                .await?;
                return Ok(false);
            }
            if iteration == max_iterations {
                set_status(
                    db,
                    &record,
                    "iteration_limit",
                    "Fresh evidence exists but convergence is unverified",
                )
                .await?;
                anyhow::bail!(
                    "Component {component} reached its iteration limit; callers remain unprocessed"
                );
            }
        }
    }
    Ok(true)
}
async fn set_status(db: &Db, id: &str, status: &str, error: &str) -> Result<()> {
    sqlx::query("UPDATE recovery_iterations SET status=?,error=? WHERE id=?")
        .bind(status)
        .bind(error)
        .bind(id)
        .execute(&db.pool)
        .await?;
    Ok(())
}
async fn analyze_run(db: &Db, ai: &Ai, binary: &str, run: &str) -> Result<()> {
    loop {
        ensure!(
            !db.overview(binary).await?.paused,
            "Recovery paused. Check pipeline status before resuming."
        );
        let mut jobs = Vec::new();
        for _ in 0..ai.config.concurrency {
            if let Some(job) = pipeline::claim(db, ai, Some(binary), false).await? {
                jobs.push(job);
            } else {
                break;
            }
        }
        if jobs.is_empty() {
            let unfinished: i64 = sqlx::query_scalar(
                "SELECT COUNT(*) FROM jobs WHERE run_id=? AND status<>'completed'",
            )
            .bind(run)
            .fetch_one(&db.pool)
            .await?;
            if unfinished == 0 {
                return Ok(());
            }
            let failed:i64=sqlx::query_scalar("SELECT COUNT(*) FROM jobs WHERE run_id=? AND status IN ('failed','uncertain','batched')").bind(run).fetch_one(&db.pool).await?;
            ensure!(
                failed == 0,
                "Recovery has failed, uncertain, or batched jobs"
            );
            tokio::time::sleep(std::time::Duration::from_secs(1)).await;
            continue;
        }
        let outcomes = futures::future::join_all(jobs.iter().map(|job| async move {
            if crate::decisions::is_decision_stage(&job.stage) {
                match crate::decisions::analyze(ai, db, job).await {
                    Ok(c) => crate::decisions::finish(db, job, c).await,
                    Err(e) => pipeline::fail(db, ai, job, &format!("{e:#}")).await,
                }
            } else {
                match ai.analyze_job(db, job).await {
                    Ok(c) => pipeline::finish(db, ai, job, c).await,
                    Err(e) => pipeline::fail(db, ai, job, &format!("{e:#}")).await,
                }
            }
        }))
        .await;
        for outcome in outcomes {
            outcome?;
        }
    }
}
