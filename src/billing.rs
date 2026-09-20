use anyhow::{Result, bail};
use serde_json::Value;

pub async fn dispatch(db: &crate::db::Db, job: &str) -> Result<String> {
    let id = crate::knowledge::id();
    sqlx::query("INSERT INTO provider_requests(id,job_id,dispatch_id) SELECT ?,id,dispatch_id FROM jobs WHERE id=?")
        .bind(&id).bind(job).execute(&db.pool).await?;
    Ok(id)
}

pub fn reported_cost(response: &Value) -> Option<f64> {
    response
        .pointer("/usage/cost")
        .and_then(Value::as_f64)
        .filter(|cost| cost.is_finite() && *cost >= 0.0)
}

/// Persist the unmodified receipt before semantic validation can reject it.
pub async fn record(db: &crate::db::Db, id: Option<&str>, response: &Value) -> Result<Option<f64>> {
    let cost = reported_cost(response);
    if let Some(id) = id {
        sqlx::query("UPDATE provider_requests SET response_json=?,cost_usd=? WHERE id=?")
            .bind(response.to_string())
            .bind(cost)
            .bind(id)
            .execute(&db.pool)
            .await?;
    }
    Ok(cost)
}

pub async fn response(response: reqwest::Response) -> Result<Value> {
    if response.status() == reqwest::StatusCode::PAYMENT_REQUIRED {
        bail!(
            "Provider spending limit reached (HTTP 402). Check provider billing before resuming."
        );
    }
    Ok(response.error_for_status()?.json().await?)
}
