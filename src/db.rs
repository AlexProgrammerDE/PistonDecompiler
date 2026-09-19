use crate::{config::Config, proto};
use anyhow::Result;
use sqlx::{
    Row, SqlitePool,
    sqlite::{SqliteConnectOptions, SqliteJournalMode, SqlitePoolOptions},
};
use std::{path::Path, time::Duration};

#[derive(Clone)]
pub struct Db {
    pub pool: SqlitePool,
}
impl Db {
    pub async fn open(path: &Path) -> Result<Self> {
        let options = SqliteConnectOptions::new()
            .filename(path)
            .create_if_missing(true)
            .journal_mode(SqliteJournalMode::Wal)
            .foreign_keys(true)
            .busy_timeout(Duration::from_secs(30));
        let pool = SqlitePoolOptions::new()
            .max_connections(8)
            .connect_with(options)
            .await?;
        sqlx::migrate!().run(&pool).await?;
        let db = Self { pool };
        crate::knowledge::backfill(&db).await?;
        Ok(db)
    }
    pub async fn event(&self, binary: &str, level: &str, message: &str) -> Result<()> {
        tracing::info!(binary, level, message, "Analysis event");
        sqlx::query("INSERT INTO events(binary_id,level,message) VALUES(?,?,?)")
            .bind(binary)
            .bind(level)
            .bind(message)
            .execute(&self.pool)
            .await?;
        Ok(())
    }
    pub async fn recover(&self) -> Result<()> {
        // A lost HTTP response can still incur a charge. Retain its reservation.
        let mut tx = self.pool.begin().await?;
        sqlx::query("UPDATE jobs SET status='uncertain',error='Process stopped during a provider request. Reservation retained.',updated_at=unixepoch() WHERE status='running'").execute(&mut *tx).await?;
        sqlx::query("UPDATE binaries SET status='interrupted',error='Extraction was interrupted. Resume to extract again.' WHERE status='extracting'").execute(&mut *tx).await?;
        sqlx::query("UPDATE apply_operations SET status='uncertain',error='Process stopped during writeback. Retry this exact change set to reconcile.' WHERE status='applying'").execute(&mut *tx).await?;
        sqlx::query("UPDATE binaries SET paused=1 WHERE id IN (SELECT binary_id FROM jobs WHERE status='uncertain')").execute(&mut *tx).await?;
        tx.commit().await?;
        Ok(())
    }
    pub async fn import(&self, path: &Path, config: &Config) -> Result<proto::Binary> {
        let source = path.to_owned();
        let root = config.data_dir.join("binaries");
        let snapshot =
            tokio::task::spawn_blocking(move || crate::snapshot::create(&source, &root)).await??;
        let id = snapshot.id;
        let mut tx = self.pool.begin().await?;
        let inserted = sqlx::query("INSERT INTO binaries(id,name,sha256,size,architecture,format,path,budget_usd) VALUES(?,?,?,?,?,?,?,?) ON CONFLICT(sha256) DO NOTHING")
            .bind(&id).bind(path.file_name().unwrap_or_default().to_string_lossy().as_ref()).bind(&snapshot.sha256)
            .bind(snapshot.size).bind(&snapshot.architecture).bind(&snapshot.format)
            .bind(snapshot.path.to_string_lossy().as_ref()).bind(config.ai.budget_usd).execute(&mut *tx).await?.rows_affected() == 1;
        let row = sqlx::query("SELECT * FROM binaries WHERE sha256=?")
            .bind(&snapshot.sha256)
            .fetch_one(&mut *tx)
            .await?;
        if inserted {
            sqlx::query("INSERT INTO events(binary_id,level,message) VALUES(?,'info','Binary imported. Immutable snapshot stored.')")
                .bind(&id).execute(&mut *tx).await?;
            // Keep the durable file before COMMIT. Cancellation or an ambiguous
            // commit must never delete a snapshot that SQLite may reference.
            let _ = snapshot.directory.keep();
        }
        tx.commit().await?;
        // A duplicate's temporary directory is removed automatically.
        Ok(binary_row(&row))
    }
    pub async fn binary(&self, id: &str) -> Result<proto::Binary> {
        let row = sqlx::query("SELECT * FROM binaries WHERE id=?")
            .bind(id)
            .fetch_one(&self.pool)
            .await?;
        Ok(binary_row(&row))
    }
    pub async fn binaries(&self) -> Result<Vec<proto::Binary>> {
        Ok(
            sqlx::query("SELECT * FROM binaries ORDER BY created_at DESC,id")
                .fetch_all(&self.pool)
                .await?
                .iter()
                .map(binary_row)
                .collect(),
        )
    }
    pub async fn functions(&self, query: &proto::FunctionQuery) -> Result<proto::FunctionList> {
        let search = query.search.trim();
        let fts = search
            .split_whitespace()
            .map(|s| format!("\"{}\"*", s.replace('"', "\"\"")))
            .collect::<Vec<_>>()
            .join(" AND ");
        let filter = match query.filter.as_str() {
            "" | "all" => "1=1",
            "eligible" => "f.skip_reason=''",
            "skipped" => "f.skip_reason<>''",
            "review" => "r.review='pending'",
            "accepted" => "r.review='accepted'",
            "stale" => "r.stale=1",
            _ => anyhow::bail!("unknown function filter"),
        };
        let where_sql = format!(
            "f.binary_id=? AND ({filter}) AND (?='' OR f.id IN (SELECT function_id FROM function_search WHERE function_search MATCH ?))"
        );
        let join = "FROM functions f LEFT JOIN results r ON r.id=f.current_result_id";
        let count: i64 = sqlx::query_scalar(&format!("SELECT COUNT(*) {join} WHERE {where_sql}"))
            .bind(&query.binary_id)
            .bind(search)
            .bind(if fts.is_empty() { "\"\"" } else { &fts })
            .fetch_one(&self.pool)
            .await?;
        let rows = sqlx::query(&format!(
            "{FUNCTION_SELECT} {join} WHERE {where_sql} ORDER BY f.address LIMIT ? OFFSET ?"
        ))
        .bind(&query.binary_id)
        .bind(search)
        .bind(if fts.is_empty() { "\"\"" } else { &fts })
        .bind(i64::from(query.limit.clamp(1, 200)))
        .bind(i64::from(query.offset))
        .fetch_all(&self.pool)
        .await?;
        Ok(proto::FunctionList {
            functions: rows.iter().map(function_row).collect(),
            total: count as u32,
        })
    }
    pub async fn function(&self, id: &str) -> Result<proto::FunctionDetail> {
        let row = sqlx::query(&format!("{FUNCTION_SELECT},f.pseudocode,f.strings_json,f.imports_json,f.disassembly,f.pcode,COALESCE(r.raw_json,'') AS analysis_json,COALESCE(r.model,'') AS model,COALESCE(r.prompt_hash,'') AS prompt_hash FROM functions f LEFT JOIN results r ON r.id=f.current_result_id WHERE f.id=?"))
            .bind(id).fetch_one(&self.pool).await?;
        let mut detail = proto::FunctionDetail {
            function: Some(function_row(&row)),
            pseudocode: row.get("pseudocode"),
            strings: serde_json::from_str(row.get("strings_json"))?,
            imports: serde_json::from_str(row.get("imports_json"))?,
            analysis_json: row.get("analysis_json"),
            model: row.get("model"),
            prompt_hash: row.get("prompt_hash"),
            disassembly: row.get("disassembly"),
            pcode: row.get("pcode"),
            ..Default::default()
        };
        for (incoming, target) in [(true, &mut detail.callers), (false, &mut detail.callees)] {
            let condition = if incoming {
                "f.id IN (SELECT caller FROM edges WHERE callee=?)"
            } else {
                "f.id IN (SELECT callee FROM edges WHERE caller=?)"
            };
            let rows = sqlx::query(&format!("{FUNCTION_SELECT} FROM functions f LEFT JOIN results r ON r.id=f.current_result_id WHERE {condition} ORDER BY f.address LIMIT 100"))
                .bind(id).fetch_all(&self.pool).await?;
            *target = rows.iter().map(function_row).collect();
        }
        if let Some(f) = &detail.function
            && !f.result_id.is_empty()
        {
            detail.result = Some(crate::knowledge::result(self, &f.result_id).await?);
        }
        Ok(detail)
    }
    pub async fn overview(&self, id: &str) -> Result<proto::Overview> {
        let binary = self.binary(id).await?;
        let b =
            sqlx::query("SELECT spent_usd,reserved_usd,budget_usd,paused,active_run_id FROM binaries WHERE id=?")
                .bind(id)
                .fetch_one(&self.pool)
                .await?;
        let f = sqlx::query("SELECT COUNT(*) AS total,COUNT(CASE WHEN skip_reason='' THEN 1 END) AS eligible,COUNT(DISTINCT NULLIF(module,'')) AS modules FROM functions WHERE binary_id=?").bind(id).fetch_one(&self.pool).await?;
        let totals = sqlx::query("SELECT COUNT(DISTINCT r.function_id) AS analyzed,COALESCE(SUM(input_tokens),0) AS input_tokens,COALESCE(SUM(output_tokens),0) AS output_tokens FROM results r JOIN functions f ON f.id=r.function_id WHERE f.binary_id=?").bind(id).fetch_one(&self.pool).await?;
        let edges: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM edges e JOIN functions f ON f.id=e.caller WHERE f.binary_id=?",
        )
        .bind(id)
        .fetch_one(&self.pool)
        .await?;
        let proposals: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM results r JOIN functions f ON f.id=r.function_id WHERE f.binary_id=? AND r.review='pending' AND r.id=f.current_result_id").bind(id).fetch_one(&self.pool).await?;
        let rows = sqlx::query(
            "SELECT stage,status,COUNT(*) AS n FROM jobs WHERE binary_id=? GROUP BY stage,status",
        )
        .bind(id)
        .fetch_all(&self.pool)
        .await?;
        let mut overview = proto::Overview {
            binary: Some(binary),
            functions: f.get::<i64, _>("total") as u32,
            eligible: f.get::<i64, _>("eligible") as u32,
            modules: f.get::<i64, _>("modules") as u32,
            analyzed: totals.get::<i64, _>("analyzed") as u32,
            input_tokens: totals.get::<i64, _>("input_tokens") as u64,
            output_tokens: totals.get::<i64, _>("output_tokens") as u64,
            edges: edges as u32,
            proposals: proposals as u32,
            cost_usd: b.get("spent_usd"),
            reserved_usd: b.get("reserved_usd"),
            budget_usd: b.get("budget_usd"),
            paused: b.get("paused"),
            active_run_id: b
                .get::<Option<String>, _>("active_run_id")
                .unwrap_or_default(),
            ..Default::default()
        };
        for stage in ["map", "propagate", "escalate"] {
            let mut s = proto::Stage {
                name: stage.into(),
                ..Default::default()
            };
            for row in rows.iter().filter(|r| r.get::<String, _>("stage") == stage) {
                let n = row.get::<i64, _>("n") as u32;
                match row.get::<String, _>("status").as_str() {
                    "queued" => s.queued += n,
                    "completed" => s.completed += n,
                    "running" | "batched" => s.running += n,
                    _ => s.failed += n,
                }
            }
            overview.queued += s.queued;
            overview.running += s.running;
            overview.failed += s.failed;
            overview.stages.push(s);
        }
        overview.usage = sqlx::query("SELECT strftime('%Y-%m-%d %H:00',r.created_at,'unixepoch') AS bucket,SUM(input_tokens) AS input_tokens,SUM(output_tokens) AS output_tokens,SUM(cost_usd) AS cost_usd,COUNT(*) AS requests FROM results r JOIN functions f ON f.id=r.function_id WHERE f.binary_id=? GROUP BY bucket ORDER BY bucket DESC LIMIT 48")
            .bind(id).fetch_all(&self.pool).await?.iter().map(|r| proto::UsagePoint { bucket: r.get("bucket"), input_tokens: r.get::<i64,_>("input_tokens") as u64, output_tokens: r.get::<i64,_>("output_tokens") as u64, cost_usd: r.get("cost_usd"), requests: r.get::<i64,_>("requests") as u32 }).collect();
        overview.usage.reverse();
        overview.provider_breakdowns = sqlx::query("SELECT r.model,r.stage,COUNT(*) requests,SUM(input_tokens) input_tokens,SUM(output_tokens) output_tokens,SUM(cost_usd) cost_usd,AVG(latency_ms) average_latency_ms FROM results r JOIN functions f ON f.id=r.function_id WHERE f.binary_id=? GROUP BY r.model,r.stage ORDER BY cost_usd DESC,r.model,r.stage")
            .bind(id)
            .fetch_all(&self.pool)
            .await?
            .iter()
            .map(|r| proto::ProviderBreakdown {
                model: r.get("model"),
                stage: r.get("stage"),
                requests: r.get::<i64, _>("requests") as u32,
                input_tokens: r.get::<i64, _>("input_tokens") as u64,
                output_tokens: r.get::<i64, _>("output_tokens") as u64,
                cost_usd: r.get("cost_usd"),
                average_latency_ms: r.get("average_latency_ms"),
            })
            .collect();
        Ok(overview)
    }
}
fn binary_row(r: &sqlx::sqlite::SqliteRow) -> proto::Binary {
    proto::Binary {
        id: r.get("id"),
        name: r.get("name"),
        sha256: r.get("sha256"),
        size: r.get::<i64, _>("size") as u64,
        architecture: r.get("architecture"),
        format: r.get("format"),
        status: r.get("status"),
        created_at: r.get("created_at"),
        error: r.get("error"),
    }
}
const FUNCTION_SELECT: &str = "SELECT f.id,f.address,f.name,f.size,f.skip_reason,f.module,(SELECT COUNT(*) FROM edges WHERE callee=f.id) AS callers,(SELECT COUNT(*) FROM edges WHERE caller=f.id) AS callees,COALESCE(r.id,'') AS result_id,COALESCE(r.stale,0) AS stale,COALESCE(r.summary,'') AS summary,COALESCE(r.proposed_name,'') AS proposed_name,COALESCE(r.confidence,0.0) AS confidence,COALESCE(r.review,'') AS review,COALESCE((SELECT status FROM jobs WHERE function_id=f.id ORDER BY rowid DESC LIMIT 1),'indexed') AS status";
fn function_row(r: &sqlx::sqlite::SqliteRow) -> proto::Function {
    proto::Function {
        id: r.get("id"),
        address: r.get("address"),
        name: r.get("name"),
        size: r.get::<i64, _>("size") as u64,
        callers: r.get::<i64, _>("callers") as u32,
        callees: r.get::<i64, _>("callees") as u32,
        skip_reason: r.get("skip_reason"),
        summary: r.get("summary"),
        proposed_name: r.get("proposed_name"),
        confidence: r.get("confidence"),
        module: r.get("module"),
        review: r.get("review"),
        status: r.get("status"),
        result_id: r.get("result_id"),
        stale: r.get("stale"),
    }
}
