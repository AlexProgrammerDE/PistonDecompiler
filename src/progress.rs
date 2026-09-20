//! Progress reports use measured phase work, never fabricated whole-program percentages.
use crate::{db::Db, proto::ProgressReport};
use anyhow::Result;
use sqlx::Row;

pub fn estimate(completed: i64, total: i64, elapsed: i64) -> i64 {
    if completed < 3 || elapsed < 2 || total <= completed {
        return -1;
    }
    ((total - completed) as f64 * elapsed as f64 / completed as f64).ceil() as i64
}

pub async fn reports(db: &Db, binary: &str) -> Result<Vec<ProgressReport>> {
    let mut reports = Vec::new();
    if let Some(r) = sqlx::query("SELECT status,scenario,created_at,COALESCE(finished_at,unixepoch())-created_at elapsed,unixepoch() now FROM recordings WHERE binary_id=? ORDER BY rowid DESC LIMIT 1").bind(binary).fetch_optional(&db.pool).await? {
        reports.push(ProgressReport {phase:"Runtime recording".into(),status:r.get("status"),completed:0,total:0,elapsed_seconds:r.get("elapsed"),eta_seconds:-1,detail:format!("Scenario: {}. Open Recordings for observations, markers, and the capture time limit.",r.get::<String,_>("scenario")),updated_at:r.get("now")});
    }
    if let Some(r) = sqlx::query("SELECT p.*,b.status,unixepoch()-p.started_at elapsed,unixepoch()-p.phase_started_at phase_elapsed FROM extraction_progress p JOIN binaries b ON b.id=p.binary_id WHERE binary_id=?")
        .bind(binary).fetch_optional(&db.pool).await? {
        let active = r.get::<String,_>("status") == "extracting";
        let done: i64 = r.get("completed"); let total: i64 = r.get("total");
        reports.push(ProgressReport {
            phase: r.get("phase"), status: if active { "running".into() } else { r.get("status") },
            completed: done as u32, total: total as u32,
            elapsed_seconds: if active { r.get("elapsed") } else { r.get::<i64,_>("updated_at") - r.get::<i64,_>("started_at") },
            eta_seconds: if active { estimate(done,total,r.get("phase_elapsed")) } else { -1 },
            detail: r.get("detail"), updated_at: r.get("updated_at"),
        });
    }
    let rows = sqlx::query("SELECT j.stage,COUNT(*) total,SUM(j.status='completed') completed,SUM(j.status IN ('failed','uncertain')) blocked,SUM(j.status IN ('running','batched')) running,MIN(j.started_at) started,MAX(COALESCE(j.finished_at,j.updated_at)) updated,b.paused,SUM(j.status='completed' AND j.finished_at>=unixepoch()-300) recent,MIN(CASE WHEN j.status='completed' AND j.finished_at>=unixepoch()-300 THEN j.started_at END) recent_start,unixepoch() now FROM jobs j JOIN binaries b ON b.id=j.binary_id WHERE j.binary_id=? AND (b.active_run_id IS NULL OR j.run_id=b.active_run_id) GROUP BY j.stage ORDER BY MIN(j.rowid)")
        .bind(binary).fetch_all(&db.pool).await?;
    for r in rows {
        let done: i64 = r.get("completed");
        let total: i64 = r.get("total");
        let paused: bool = r.get("paused");
        let blocked: i64 = r.get("blocked");
        let running: i64 = r.get("running");
        let now: i64 = r.get("now");
        let status = if done == total {
            "completed"
        } else if running > 0 {
            "running"
        } else if blocked > 0 {
            "needs attention"
        } else if paused {
            "paused"
        } else {
            "queued"
        };
        let sample: i64 = r.get("recent");
        let eta = if !paused && blocked == 0 && running > 0 {
            estimate(
                sample,
                sample + total - done,
                now - r.get::<Option<i64>, _>("recent_start").unwrap_or(now),
            )
        } else {
            -1
        };
        reports.push(ProgressReport { phase:r.get("stage"),status:status.into(),completed:done as u32,total:total as u32,
            elapsed_seconds:r.get::<Option<i64>,_>("started").map(|start| (if done==total {r.get("updated")} else {now})-start).unwrap_or(0),
            eta_seconds:eta,detail:format!("{running} active · {blocked} need attention. ETA covers currently queued work; later passes can add jobs. Elapsed includes pauses."),updated_at:r.get("updated") });
    }
    for (table, label) in [
        ("apply_operations", "Ghidra names and comments"),
        ("type_operations", "Ghidra types and signatures"),
        ("recovery_iterations", "Recovery iteration"),
    ] {
        // Table names come exclusively from the fixed list above.
        if let Some(r) = sqlx::query(&format!(
            "SELECT *,unixepoch() now FROM {table} WHERE binary_id=? ORDER BY rowid DESC LIMIT 1"
        ))
        .bind(binary)
        .fetch_optional(&db.pool)
        .await?
        {
            let status: String = r.get("status");
            let active = matches!(status.as_str(), "applying" | "analyzing");
            let updated = r
                .get::<Option<i64>, _>("updated_at")
                .unwrap_or(r.get("created_at"));
            reports.push(ProgressReport {
                phase: label.into(),
                status,
                completed: 0,
                total: 0,
                elapsed_seconds: if active {
                    r.get::<i64, _>("now") - r.get::<i64, _>("created_at")
                } else {
                    updated - r.get::<i64, _>("created_at")
                },
                eta_seconds: -1,
                detail: r.get("error"),
                updated_at: updated,
            });
        }
    }
    if let Some(r) = sqlx::query("SELECT *,unixepoch() now FROM automatic_recovery WHERE binary_id=? ORDER BY rowid DESC LIMIT 1").bind(binary).fetch_optional(&db.pool).await? {
        let status: String = r.get("status");
        let done = matches!(status.as_str(), "completed" | "deferred" | "failed");
        reports.push(ProgressReport {
            phase: "Automatic Ghidra recovery".into(), status,
            completed: (r.get::<i64,_>("pass") + 1) as u32, total: r.get::<i64,_>("max_passes") as u32,
            elapsed_seconds: (if done {r.get::<i64,_>("updated_at")} else {r.get::<i64,_>("now")}) - r.get::<i64,_>("created_at"), eta_seconds: -1,
            detail: if r.get::<String,_>("error").is_empty() { "Validates fields, saves supported changes in Ghidra, and reanalyzes affected functions automatically. Pass count is a limit, not an estimate.".into() } else {r.get("error")}, updated_at: r.get("updated_at"),
        });
    }
    Ok(reports)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn estimates_require_samples_and_remaining_work() {
        assert_eq!(estimate(2, 100, 10), -1);
        assert_eq!(estimate(5, 5, 10), -1);
        assert_eq!(estimate(5, 20, 10), 30);
        assert_eq!(estimate(5, 20, 0), -1);
    }
}
