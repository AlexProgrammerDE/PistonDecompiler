use crate::{
    ai::{Ai, Analysis, Completion, usage},
    config::Config,
    db::Db,
    pipeline::{self, Job},
};
use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sqlx::Row;
use std::{collections::HashMap, path::PathBuf};

#[derive(Serialize, Deserialize)]
struct Manifest {
    input_rate: f64,
    output_rate: f64,
    model: String,
    hashes: HashMap<String, String>,
}
/// OpenAI-compatible asynchronous batch endpoints. No provider discount is assumed.
pub async fn submit(db: &Db, ai: &Ai, config: &Config, binary: &str) -> Result<String> {
    ensure!(
        ai.config.batch_enabled,
        "enable ai.batch_enabled for a provider that supports /files and /batches"
    );
    pipeline::control(db, ai, binary, "resume").await?;
    let id = uuid::Uuid::new_v4().to_string();
    let dir = config.data_dir.join("batches");
    tokio::fs::create_dir_all(&dir).await?;
    let path = tokio::fs::canonicalize(dir)
        .await?
        .join(format!("{id}.jsonl"));
    sqlx::query("INSERT INTO batches(id,binary_id,status,path,model,provider_url) VALUES(?,?,'preparing',?,?,?)")
        .bind(&id).bind(binary).bind(path.to_string_lossy().as_ref()).bind(&ai.config.model).bind(&ai.config.base_url).execute(&db.pool).await?;
    let mut lines = String::new();
    let (ir, or) = ai.config.rates("map");
    let mut manifest = Manifest {
        input_rate: ir * ai.config.batch_price_multiplier,
        output_rate: or * ai.config.batch_price_multiplier,
        model: ai.config.model.clone(),
        hashes: HashMap::new(),
    };
    for _ in 0..ai.config.batch_size {
        let Some(job) = pipeline::claim_batch(db, ai, binary, &id).await? else {
            break;
        };
        match ai.prompt(db, &job.function_id, "map").await {
            Ok(prompt) => {
                lines.push_str(&serde_json::to_string(&json!({"custom_id":job.id,"method":"POST","url":"/v1/chat/completions","body":ai.body(&prompt.messages,"map",false)}))?);
                lines.push('\n');
                manifest.hashes.insert(job.id.clone(), prompt.hash);
            }
            Err(error) => {
                pipeline::fail_before_dispatch(
                    db,
                    ai,
                    &job,
                    &format!("Cannot prepare batch prompt: {error:#}"),
                )
                .await?;
            }
        }
    }
    pipeline::control(db, ai, binary, "pause").await?;
    if manifest.hashes.is_empty() {
        sqlx::query("UPDATE batches SET status='abandoned' WHERE id=?")
            .bind(&id)
            .execute(&db.pool)
            .await?;
        anyhow::bail!("no eligible map jobs fit the remaining budget");
    }
    tokio::fs::write(&path, lines.as_bytes()).await?;
    tokio::fs::write(
        path.with_extension("manifest.json"),
        serde_json::to_vec_pretty(&manifest)?,
    )
    .await?;
    sqlx::query("UPDATE batches SET status='uploading' WHERE id=?")
        .bind(&id)
        .execute(&db.pool)
        .await?;
    let result = async {
        let form = reqwest::multipart::Form::new().text("purpose","batch")
            .part("file",reqwest::multipart::Part::bytes(lines.into_bytes()).file_name(format!("{id}.jsonl")).mime_str("application/jsonl")?);
        let response = ai.client.post(ai.endpoint("files")).bearer_auth(ai.key()?).multipart(form).send().await?;
        ensure!(response.status().is_success(), "batch file upload returned HTTP {}",response.status());
        let file: Value = response.json().await?;
        let file_id = file["id"].as_str().context("file upload omitted ID")?;
        // Persist submission intent immediately before the request that can create
        // paid work. A lost response requires provider inspection, not a retry.
        sqlx::query("UPDATE batches SET status='submitting' WHERE id=?")
            .bind(&id)
            .execute(&db.pool)
            .await?;
        let response = ai.client.post(ai.endpoint("batches")).bearer_auth(ai.key()?).json(&json!({"input_file_id":file_id,"endpoint":"/v1/chat/completions","completion_window":"24h","metadata":{"piston_batch_id":id}})).send().await?;
        ensure!(response.status().is_success(), "batch submission returned HTTP {}",response.status());
        let value: Value = response.json().await?;
        let remote = value["id"].as_str().context("batch response omitted ID")?;
        sqlx::query("UPDATE batches SET status='submitted',remote_id=? WHERE id=?").bind(remote).bind(&id).execute(&db.pool).await?;
        db.event(binary,"info",&format!("Submitted asynchronous batch {id} ({} requests).",manifest.hashes.len())).await?;
        Ok(id.clone())
    }.await;
    if result.is_err() {
        let status: String = sqlx::query_scalar("SELECT status FROM batches WHERE id=?")
            .bind(&id)
            .fetch_one(&db.pool)
            .await?;
        let message = if status == "submitting" {
            format!(
                "Batch {id} submission is uncertain. Inspect provider metadata before attaching a remote ID or abandoning it."
            )
        } else {
            format!("Batch {id} stopped before submission. It can be abandoned safely.")
        };
        db.event(binary, "error", &message).await?;
    }
    result
}
pub async fn attach(db: &Db, id: &str, remote: &str) -> Result<()> {
    ensure!(
        !remote.is_empty()
            && remote
                .bytes()
                .all(|c| c.is_ascii_alphanumeric() || c == b'_' || c == b'-'),
        "invalid remote batch ID"
    );
    let changed = sqlx::query("UPDATE batches SET remote_id=?,status='submitted' WHERE id=? AND status='submitting' AND remote_id=''").bind(remote).bind(id).execute(&db.pool).await?.rows_affected();
    ensure!(
        changed == 1,
        "only uncertain submissions can attach a remote batch ID"
    );
    Ok(())
}
pub async fn abandon(db: &Db, id: &str, confirmed_not_submitted: bool) -> Result<()> {
    let mut tx = db.pool.begin().await?;
    let row = sqlx::query("SELECT binary_id,status,remote_id FROM batches WHERE id=?")
        .bind(id)
        .fetch_one(&mut *tx)
        .await?;
    let binary: String = row.get("binary_id");
    let status: String = row.get("status");
    let remote: String = row.get("remote_id");
    ensure!(
        remote.is_empty() && matches!(status.as_str(), "preparing" | "uploading" | "submitting"),
        "only an unsubmitted local batch or uncertain submitting batch can be abandoned"
    );
    ensure!(
        matches!(status.as_str(), "preparing" | "uploading") || confirmed_not_submitted,
        "inspect the provider first, then pass --confirmed-not-submitted for an uncertain submission"
    );
    let reserved: f64 = sqlx::query_scalar(
        "SELECT COALESCE(SUM(reserved_usd),0.0) FROM jobs WHERE batch_id=? AND status IN ('running','batched','uncertain')",
    )
    .bind(id)
    .fetch_one(&mut *tx)
    .await?;
    sqlx::query("UPDATE jobs SET status='queued',attempts=MAX(0,attempts-1),reserved_usd=0,batch_id=NULL,available_at=0,error='',updated_at=unixepoch() WHERE batch_id=? AND status IN ('running','batched','uncertain')")
        .bind(id)
        .execute(&mut *tx)
        .await?;
    sqlx::query("UPDATE binaries SET reserved_usd=MAX(0,reserved_usd-?) WHERE id=?")
        .bind(reserved)
        .bind(&binary)
        .execute(&mut *tx)
        .await?;
    sqlx::query("UPDATE batches SET status='abandoned' WHERE id=?")
        .bind(id)
        .execute(&mut *tx)
        .await?;
    tx.commit().await?;
    db.event(
        &binary,
        "warning",
        &format!("Abandoned batch {id}. Its jobs returned to the queue."),
    )
    .await?;
    Ok(())
}
pub async fn collect(db: &Db, ai: &Ai, id: &str) -> Result<String> {
    let row = sqlx::query("SELECT * FROM batches WHERE id=?")
        .bind(id)
        .fetch_one(&db.pool)
        .await?;
    let status: String = row.get("status");
    if status == "collected" {
        return Ok(status);
    }
    let remote: String = row.get("remote_id");
    ensure!(
        !remote.is_empty(),
        "no remote ID recorded; inspect the provider and use batch attach if submission succeeded"
    );
    ensure!(
        row.get::<String, _>("provider_url") == ai.config.base_url,
        "provider URL differs from the submitting provider"
    );
    let path = PathBuf::from(row.get::<String, _>("path"));
    let manifest: Manifest =
        serde_json::from_slice(&tokio::fs::read(path.with_extension("manifest.json")).await?)?;
    let response = ai
        .client
        .get(ai.endpoint(&format!("batches/{remote}")))
        .bearer_auth(ai.key()?)
        .send()
        .await?
        .error_for_status()?;
    let value: Value = response.json().await?;
    let remote_status = value["status"].as_str().context("batch omitted status")?;
    if !["completed", "failed", "expired", "cancelled"].contains(&remote_status) {
        return Ok(remote_status.into());
    }
    let mut results = HashMap::new();
    for field in ["output_file_id", "error_file_id"] {
        if let Some(file) = value[field].as_str() {
            ensure!(
                file.bytes()
                    .all(|c| c.is_ascii_alphanumeric() || c == b'_' || c == b'-'),
                "invalid output file ID"
            );
            let content = ai
                .client
                .get(ai.endpoint(&format!("files/{file}/content")))
                .bearer_auth(ai.key()?)
                .send()
                .await?
                .error_for_status()?
                .text()
                .await?;
            tokio::fs::write(path.with_extension(format!("{field}.jsonl")), &content).await?;
            for line in content.lines().filter(|l| !l.trim().is_empty()) {
                let item: Value = serde_json::from_str(line)?;
                let custom = item["custom_id"]
                    .as_str()
                    .context("batch result omitted custom_id")?;
                ensure!(
                    manifest.hashes.contains_key(custom),
                    "batch returned an unknown custom_id"
                );
                ensure!(
                    !results.contains_key(custom),
                    "batch returned duplicate custom_id"
                );
                results.insert(custom.to_owned(), item);
            }
        }
    }
    let jobs = sqlx::query_as::<_,Job>("SELECT id,binary_id,function_id,stage,attempts,reserved_usd FROM jobs WHERE batch_id=? AND status='batched'").bind(id).fetch_all(&db.pool).await?;
    for job in jobs {
        let result = (|| -> Result<Completion> {
            let item = results
                .get(&job.id)
                .context("batch returned no result for this job")?;
            ensure!(
                item.pointer("/response/status_code")
                    .and_then(Value::as_u64)
                    == Some(200),
                "batch request failed"
            );
            let body = &item["response"]["body"];
            let (input, output) = usage(body)?;
            let analysis: Analysis = serde_json::from_str(
                body.pointer("/choices/0/message/content")
                    .and_then(Value::as_str)
                    .context("batch returned no content")?,
            )?;
            analysis.validate()?;
            Ok(Completion {
                analysis,
                input_tokens: input,
                output_tokens: output,
                cost: (input as f64 * manifest.input_rate + output as f64 * manifest.output_rate)
                    / 1_000_000.0,
                latency_ms: 0,
                prompt_hash: manifest
                    .hashes
                    .get(&job.id)
                    .context("manifest missing job")?
                    .clone(),
                model: manifest.model.clone(),
            })
        })();
        match result {
            Ok(c) => pipeline::finish(db, ai, &job, c).await?,
            Err(error) => pipeline::fail(db, ai, &job, &format!("{error:#}")).await?,
        }
    }
    sqlx::query("UPDATE batches SET status='collected' WHERE id=?")
        .bind(id)
        .execute(&db.pool)
        .await?;
    Ok("collected".into())
}
