use axum::{
    Json, Router,
    extract::State,
    routing::{get, post},
};
use piston_decompiler::{
    ai::{Ai, Analysis},
    batch,
    config::{AiConfig, Config},
    db::Db,
    ghidra, pipeline,
};
use serde_json::json;
use sqlx::Row;
use std::sync::{Arc, RwLock};

async fn fixture(batch_size: usize) -> (tempfile::TempDir, Db, Ai, Config) {
    let dir = tempfile::tempdir().unwrap();
    let db = Db::open(&dir.path().join("test.db")).await.unwrap();
    sqlx::query("INSERT INTO binaries(id,name,sha256,size,architecture,format,path,paused) VALUES('b','fixture','sha',10,'x86','ELF','unused',1)")
        .execute(&db.pool)
        .await
        .unwrap();
    let export = (0..3)
        .map(|index| {
            json!({
                "address": format!("{index:08x}"),
                "name": format!("fn_{index}"),
                "size": 32,
                "pseudocode": format!("int fn_{index}(void) {{ return {index}; }}")
            })
            .to_string()
        })
        .collect::<Vec<_>>()
        .join("\n");
    let path = dir.path().join("functions.jsonl");
    std::fs::write(&path, export).unwrap();
    ghidra::import_export(&db, "b", &path).await.unwrap();
    let ai_config = AiConfig {
        api_key_env: "PATH".into(),
        model: "fixture".into(),
        batch_enabled: true,
        batch_size,
        ..Default::default()
    };
    let ai = Ai::new(ai_config.clone()).unwrap();
    let config = Config {
        data_dir: dir.path().into(),
        ai: ai_config,
        ..Default::default()
    };
    (dir, db, ai, config)
}

#[tokio::test]
async fn batch_submit_and_partial_collection_preserve_jobs_and_unknown_costs() {
    let (_dir, db, mut ai, mut config) = fixture(2).await;
    let output = Arc::new(RwLock::new(String::new()));
    let app = Router::new()
        .route(
            "/files",
            post(|| async { Json(json!({"id": "file-input"})) }),
        )
        .route(
            "/batches",
            post(|| async { Json(json!({"id": "batch-remote"})) }),
        )
        .route(
            "/batches/batch-remote",
            get(|| async { Json(json!({"status": "completed", "output_file_id": "file-output"})) }),
        )
        .route(
            "/files/file-output/content",
            get(|State(output): State<Arc<RwLock<String>>>| async move {
                output.read().unwrap().clone()
            }),
        )
        .with_state(output.clone());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let base_url = format!("http://{}", listener.local_addr().unwrap());
    ai.config.base_url = base_url.clone();
    config.ai.base_url = base_url;
    let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });

    let id = batch::submit(&db, &ai, &config, "b").await.unwrap();
    let jobs = sqlx::query("SELECT id FROM jobs WHERE batch_id=? ORDER BY id")
        .bind(&id)
        .fetch_all(&db.pool)
        .await
        .unwrap();
    assert_eq!(jobs.len(), 2);
    let pinned: String = sqlx::query_scalar("SELECT input_json FROM jobs WHERE id=?")
        .bind(jobs[0].get::<String, _>("id"))
        .fetch_one(&db.pool)
        .await
        .unwrap();
    let pinned: piston_decompiler::ai::Prompt = serde_json::from_str(&pinned).unwrap();
    let analysis = Analysis {
        proposed_name: "return_constant".into(),
        summary: "Returns a constant integer.".into(),
        confidence: 0.9,
        claims: vec![piston_decompiler::ai::Claim {
            text: "Returns an integer.".into(),
            references: vec![piston_decompiler::ai::EvidenceReference {
                artifact_id: pinned.evidence[0].artifact_id.clone(),
                start_line: 1,
                end_line: 1,
            }],
        }],
        evidence: vec!["The return statement contains a constant.".into()],
        parameter_types: vec![],
        side_effects: vec![],
        uncertainties: vec![],
        type_plan: Default::default(),
    };
    *output.write().unwrap() = json!({
        "custom_id": jobs[0].get::<String, _>("id"),
        "response": {
            "status_code": 200,
            "body": {
                "choices": [{"message": {"content": serde_json::to_string(&analysis).unwrap()}}],
                "usage": {"prompt_tokens": 100, "completion_tokens": 20}
            }
        }
    })
    .to_string()
        + "\n";

    assert_eq!(batch::collect(&db, &ai, &id).await.unwrap(), "collected");
    assert_eq!(batch::collect(&db, &ai, &id).await.unwrap(), "collected");
    let counts = sqlx::query(
        "SELECT SUM(status='completed') completed,SUM(status='queued') queued FROM jobs WHERE batch_id=?",
    )
    .bind(&id)
    .fetch_one(&db.pool)
    .await
    .unwrap();
    assert_eq!(counts.get::<i64, _>("completed"), 1);
    assert_eq!(counts.get::<i64, _>("queued"), 1);
    let overview = db.overview("b").await.unwrap();
    assert_eq!(overview.cost_usd, None);
    assert_eq!(overview.unreported_cost_requests, 2);
    server.abort();
}

#[tokio::test]
async fn abandoning_local_and_uncertain_batches_requires_the_right_evidence() {
    for (status, confirmed) in [
        ("preparing", false),
        ("uploading", false),
        ("submitting", true),
    ] {
        let (_dir, db, ai, _config) = fixture(1).await;
        pipeline::control(&db, &ai, "b", "resume").await.unwrap();
        let job = pipeline::claim(&db, &ai, Some("b"), true)
            .await
            .unwrap()
            .unwrap();
        sqlx::query("INSERT INTO batches(id,binary_id,status,path,model,provider_url) VALUES('batch','b',?,'unused','fixture','fixture')")
            .bind(status)
            .execute(&db.pool)
            .await
            .unwrap();
        sqlx::query("UPDATE jobs SET status='batched',batch_id='batch' WHERE id=?")
            .bind(&job.id)
            .execute(&db.pool)
            .await
            .unwrap();
        if status == "submitting" {
            assert!(batch::abandon(&db, "batch", false).await.is_err());
        }
        batch::abandon(&db, "batch", confirmed).await.unwrap();
        let row = sqlx::query("SELECT status,attempts,batch_id FROM jobs WHERE id=?")
            .bind(&job.id)
            .fetch_one(&db.pool)
            .await
            .unwrap();
        assert_eq!(row.get::<String, _>("status"), "queued");
        assert_eq!(row.get::<i64, _>("attempts"), 0);
        assert!(row.get::<Option<String>, _>("batch_id").is_none());
    }
}
