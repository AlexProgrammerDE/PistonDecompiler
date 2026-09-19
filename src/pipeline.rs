use crate::{
    ai::{Ai, Completion},
    db::Db,
};
use anyhow::{Result, ensure};
use sqlx::{FromRow, Row};
use std::{sync::Arc, time::Duration};
use tokio_util::sync::CancellationToken;

#[derive(Clone, Debug, FromRow)]
pub struct Job {
    pub id: String,
    pub binary_id: String,
    pub function_id: String,
    pub stage: String,
    pub attempts: i64,
    pub reserved_usd: f64,
}

pub async fn claim(db: &Db, ai: &Ai, binary: Option<&str>, batch: bool) -> Result<Option<Job>> {
    claim_inner(db, ai, binary, batch, None).await
}
pub async fn claim_batch(db: &Db, ai: &Ai, binary: &str, batch_id: &str) -> Result<Option<Job>> {
    claim_inner(db, ai, Some(binary), true, Some(batch_id)).await
}
async fn claim_inner(
    db: &Db,
    ai: &Ai,
    binary: Option<&str>,
    batch: bool,
    batch_id: Option<&str>,
) -> Result<Option<Job>> {
    // One write statement claims a row. SQLite serializes competing writers.
    let mut tx = db.pool.begin().await?;
    let stage_filter = if batch { "AND j.stage='map'" } else { "" };
    let row = sqlx::query_as::<_,Job>(&format!("UPDATE jobs SET status='running',attempts=attempts+1,updated_at=unixepoch() WHERE id=(SELECT j.id FROM jobs j JOIN binaries b ON b.id=j.binary_id WHERE j.status='queued' AND j.available_at<=unixepoch() AND b.paused=0 AND (? IS NULL OR j.binary_id=?) {stage_filter} AND (j.stage='map' OR NOT EXISTS(SELECT 1 FROM jobs earlier WHERE earlier.binary_id=j.binary_id AND earlier.stage='map' AND earlier.status IN ('queued','running','batched'))) ORDER BY j.priority DESC,j.id LIMIT 1) RETURNING id,binary_id,function_id,stage,attempts,reserved_usd"))
        .bind(binary).bind(binary).fetch_optional(&mut *tx).await?;
    let Some(mut job) = row else {
        return Ok(None);
    };
    let reservation = ai.reservation(&job.stage, batch);
    let changed = sqlx::query("UPDATE binaries SET reserved_usd=reserved_usd+? WHERE id=? AND spent_usd+reserved_usd+?<=budget_usd")
        .bind(reservation).bind(&job.binary_id).bind(reservation).execute(&mut *tx).await?.rows_affected();
    if changed == 0 {
        tx.rollback().await?;
        sqlx::query("UPDATE binaries SET paused=1 WHERE id=?")
            .bind(&job.binary_id)
            .execute(&db.pool)
            .await?;
        db.event(
            &job.binary_id,
            "warning",
            "Budget cannot cover the next request reservation. Pipeline paused.",
        )
        .await?;
        return Ok(None);
    }
    job.reserved_usd = reservation;
    sqlx::query("UPDATE jobs SET reserved_usd=? WHERE id=?")
        .bind(reservation)
        .bind(&job.id)
        .execute(&mut *tx)
        .await?;
    if let Some(batch_id) = batch_id {
        sqlx::query("UPDATE jobs SET status='batched',batch_id=? WHERE id=?")
            .bind(batch_id)
            .bind(&job.id)
            .execute(&mut *tx)
            .await?;
    }
    tx.commit().await?;
    Ok(Some(job))
}
pub async fn fail_before_dispatch(db: &Db, ai: &Ai, job: &Job, error: &str) -> Result<()> {
    let mut tx = db.pool.begin().await?;
    let changed = sqlx::query("UPDATE jobs SET status=?,error=?,reserved_usd=0,batch_id=NULL,available_at=unixepoch(),updated_at=unixepoch() WHERE id=? AND status IN ('running','batched')")
        .bind(if job.attempts < i64::from(ai.config.max_attempts) { "queued" } else { "failed" })
        .bind(error)
        .bind(&job.id)
        .execute(&mut *tx)
        .await?
        .rows_affected();
    if changed > 0 {
        sqlx::query("UPDATE binaries SET reserved_usd=MAX(0,reserved_usd-?) WHERE id=?")
            .bind(job.reserved_usd)
            .bind(&job.binary_id)
            .execute(&mut *tx)
            .await?;
    }
    tx.commit().await?;
    Ok(())
}
pub async fn finish(db: &Db, ai: &Ai, job: &Job, completion: Completion) -> Result<()> {
    completion.analysis.validate()?;
    ensure!(
        completion.cost.is_finite() && completion.cost >= 0.0,
        "invalid provider cost"
    );
    let mut tx = db.pool.begin().await?;
    let changed = sqlx::query("UPDATE jobs SET status='completed',reserved_usd=0,error='',updated_at=unixepoch() WHERE id=? AND status IN ('running','batched')")
        .bind(&job.id).execute(&mut *tx).await?.rows_affected();
    if changed == 0 {
        return Ok(());
    } // Repeated batch collection is idempotent.
    sqlx::query("UPDATE binaries SET reserved_usd=MAX(0,reserved_usd-?),spent_usd=spent_usd+?,paused=CASE WHEN spent_usd+?+reserved_usd-?>=budget_usd THEN 1 ELSE paused END WHERE id=?")
        .bind(job.reserved_usd).bind(completion.cost).bind(completion.cost).bind(job.reserved_usd).bind(&job.binary_id).execute(&mut *tx).await?;
    let a = &completion.analysis;
    sqlx::query("INSERT INTO results(id,job_id,function_id,stage,model,prompt_hash,raw_json,proposed_name,summary,confidence,input_tokens,output_tokens,cost_usd,latency_ms) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)")
        .bind(uuid::Uuid::new_v4().to_string()).bind(&job.id).bind(&job.function_id).bind(&job.stage).bind(&completion.model).bind(&completion.prompt_hash)
        .bind(serde_json::to_string(a)?).bind(&a.proposed_name).bind(&a.summary).bind(a.confidence).bind(completion.input_tokens as i64).bind(completion.output_tokens as i64).bind(completion.cost).bind(completion.latency_ms).execute(&mut *tx).await?;
    sqlx::query("UPDATE function_search SET summary=? WHERE function_id=?")
        .bind(format!("{} {}", a.proposed_name, a.summary))
        .bind(&job.function_id)
        .execute(&mut *tx)
        .await?;
    // Low confidence or large functions receive one bounded evidence-gathering pass.
    let size: i64 = sqlx::query_scalar("SELECT size FROM functions WHERE id=?")
        .bind(&job.function_id)
        .fetch_one(&mut *tx)
        .await?;
    let next = if job.stage == "map" {
        Some("propagate")
    } else if job.stage == "propagate"
        && (a.confidence < ai.config.confidence_threshold || size > 2000)
        && !ai.config.escalation_model.is_empty()
    {
        Some("escalate")
    } else {
        None
    };
    if let Some(stage) = next {
        sqlx::query("INSERT OR IGNORE INTO jobs(id,binary_id,function_id,stage,priority) SELECT ?,?,?,?,priority-100000 FROM jobs WHERE id=?")
            .bind(uuid::Uuid::new_v4().to_string()).bind(&job.binary_id).bind(&job.function_id).bind(stage).bind(&job.id).execute(&mut *tx).await?;
    }
    tx.commit().await?;
    Ok(())
}
pub async fn fail(db: &Db, ai: &Ai, job: &Job, error: &str) -> Result<()> {
    // Conservatively charge the reservation when delivery or usage is uncertain.
    // Never automatically release it and risk crossing the configured ceiling.
    let mut tx = db.pool.begin().await?;
    let changed = sqlx::query("UPDATE jobs SET status=?,error=?,reserved_usd=0,available_at=unixepoch()+?,updated_at=unixepoch() WHERE id=? AND status IN ('running','batched')")
        .bind(if job.attempts < i64::from(ai.config.max_attempts) { "queued" } else { "failed" }).bind(error)
        .bind(5_i64 * 2_i64.pow(job.attempts.min(10) as u32)).bind(&job.id).execute(&mut *tx).await?.rows_affected();
    if changed > 0 {
        sqlx::query("UPDATE binaries SET reserved_usd=MAX(0,reserved_usd-?),spent_usd=spent_usd+? WHERE id=?")
            .bind(job.reserved_usd).bind(job.reserved_usd).bind(&job.binary_id).execute(&mut *tx).await?;
    }
    tx.commit().await?;
    db.event(
        &job.binary_id,
        "error",
        &format!(
            "{} request failed: {error}. Reserved cost accounted conservatively.",
            job.stage
        ),
    )
    .await?;
    Ok(())
}
pub async fn work(db: Db, ai: Arc<Ai>, cancel: CancellationToken) {
    let mut workers = tokio::task::JoinSet::new();
    for _ in 0..ai.config.concurrency {
        let db = db.clone();
        let ai = ai.clone();
        let cancel = cancel.clone();
        workers.spawn(async move {
            loop {
                if cancel.is_cancelled() { break; }
                match claim(&db,&ai,None,false).await {
                    Ok(Some(job)) => {
                        let result = ai.analyze(&db,&job.binary_id,&job.function_id,&job.stage).await;
                        let saved = match result { Ok(completion) => finish(&db,&ai,&job,completion).await, Err(error) => fail(&db,&ai,&job,&format!("{error:#}")).await };
                        if let Err(error) = saved { tracing::error!(%error,job=job.id,"Could not persist job outcome"); }
                    }
                    Ok(None) => { tokio::select! { () = cancel.cancelled() => break, () = tokio::time::sleep(Duration::from_secs(1)) => {} } }
                    Err(error) => { tracing::error!(%error,"Queue claim failed"); tokio::time::sleep(Duration::from_secs(2)).await; }
                }
            }
        });
    }
    while let Some(result) = workers.join_next().await {
        if let Err(error) = result {
            tracing::error!(%error,"Worker stopped");
        }
    }
}
pub async fn control(db: &Db, ai: &Ai, binary: &str, action: &str) -> Result<()> {
    db.binary(binary).await?;
    match action {
        "resume" => {
            ensure!(
                ai.config.configured(),
                "Configure an AI model, API key and nonzero token prices first"
            );
            if !ai.config.escalation_model.is_empty() {
                ensure!(
                    ai.config.escalation_input_usd_per_million > 0.0
                        && ai.config.escalation_output_usd_per_million > 0.0,
                    "Configure escalation prices first"
                );
            }
            sqlx::query("UPDATE binaries SET paused=0 WHERE id=?")
                .bind(binary)
                .execute(&db.pool)
                .await?;
        }
        "pause" => {
            sqlx::query("UPDATE binaries SET paused=1 WHERE id=?")
                .bind(binary)
                .execute(&db.pool)
                .await?;
        }
        "retry" => {
            let mut tx = db.pool.begin().await?;
            let reserved: f64 = sqlx::query_scalar("SELECT COALESCE(SUM(reserved_usd),0.0) FROM jobs WHERE binary_id=? AND status='uncertain'").bind(binary).fetch_one(&mut *tx).await?;
            sqlx::query("UPDATE binaries SET spent_usd=spent_usd+?,reserved_usd=MAX(0,reserved_usd-?) WHERE id=?").bind(reserved).bind(reserved).bind(binary).execute(&mut *tx).await?;
            sqlx::query("UPDATE jobs SET status='queued',attempts=0,reserved_usd=0,available_at=0,error='',updated_at=unixepoch() WHERE binary_id=? AND status IN ('failed','uncertain')").bind(binary).execute(&mut *tx).await?;
            tx.commit().await?;
        }
        _ => anyhow::bail!("unknown pipeline action"),
    }
    db.event(binary, "info", &format!("Pipeline action: {action}."))
        .await?;
    Ok(())
}
pub async fn review(db: &Db, function: &str, accept: bool) -> Result<()> {
    let row = sqlx::query("SELECT id,review FROM results WHERE function_id=? ORDER BY CASE stage WHEN 'escalate' THEN 3 WHEN 'propagate' THEN 2 ELSE 1 END DESC LIMIT 1").bind(function).fetch_one(&db.pool).await?;
    ensure!(
        row.get::<String, _>("review") != "applied",
        "proposal is already applied"
    );
    sqlx::query("UPDATE results SET review=? WHERE id=?")
        .bind(if accept { "accepted" } else { "rejected" })
        .bind(row.get::<String, _>("id"))
        .execute(&db.pool)
        .await?;
    Ok(())
}
