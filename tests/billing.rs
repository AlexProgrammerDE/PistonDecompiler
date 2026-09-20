use axum::{Json, Router, http::StatusCode, routing::post};
use piston_decompiler::{ai::Ai, billing, config::AiConfig, db::Db, ghidra, pipeline};
use serde_json::{Value, json};
use sqlx::Row;

#[tokio::test]
async fn invalid_outputs_keep_native_receipts_without_estimates_or_duplicate_charges() {
    for cost in [Some(0.0037), Some(0.0), None] {
        let dir = tempfile::tempdir().unwrap();
        let db = Db::open(&dir.path().join("test.db")).await.unwrap();
        sqlx::query("INSERT INTO binaries(id,name,sha256,size,architecture,format,path,paused) VALUES('b','fixture','sha',1,'x86','ELF','unused',0)").execute(&db.pool).await.unwrap();
        let export = dir.path().join("export.jsonl");
        std::fs::write(
            &export,
            json!({"address":"1000","name":"f","size":32,"pseudocode":"int f() { return 1; }"})
                .to_string(),
        )
        .unwrap();
        ghidra::import_export(&db, "b", &export).await.unwrap();
        let mut raw = json!({"id":"generation-fixture","model":"fixture","choices":[{"message":{"content":"invalid JSON"}}],"usage":{"prompt_tokens":42,"completion_tokens":7}});
        if let Some(cost) = cost {
            raw["usage"]["cost"] = json!(cost);
        }
        let response = raw.clone();
        let app = Router::new().route(
            "/chat/completions",
            post(move || {
                let response = response.clone();
                async move { Json(response) }
            }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let ai = Ai::new(AiConfig {
            base_url: format!("http://{}", listener.local_addr().unwrap()),
            api_key_env: "USER".into(),
            model: "fixture".into(),
            ..Default::default()
        })
        .unwrap();
        let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        let job = pipeline::claim(&db, &ai, Some("b"), false)
            .await
            .unwrap()
            .unwrap();
        assert!(ai.analyze_job(&db, &job).await.is_err());
        pipeline::fail(&db, &ai, &job, "invalid analysis")
            .await
            .unwrap();
        pipeline::fail(&db, &ai, &job, "duplicate failure delivery")
            .await
            .unwrap();
        let receipt = sqlx::query("SELECT response_json,cost_usd FROM provider_requests")
            .fetch_one(&db.pool)
            .await
            .unwrap();
        assert_eq!(
            serde_json::from_str::<Value>(receipt.get("response_json")).unwrap(),
            raw
        );
        assert_eq!(receipt.get::<Option<f64>, _>("cost_usd"), cost);
        let overview = db.overview("b").await.unwrap();
        assert_eq!(overview.cost_usd, cost);
        assert_eq!(overview.unreported_cost_requests, u32::from(cost.is_none()));
        assert_eq!(overview.input_tokens, 42);
        assert_eq!(overview.output_tokens, 7);
        assert!(!overview.paused);
        db.recover().await.unwrap();
        assert_eq!(db.overview("b").await.unwrap().cost_usd, cost);
        server.abort();
    }
}

#[tokio::test]
async fn native_payment_rejection_pauses_without_manufacturing_a_charge() {
    let dir = tempfile::tempdir().unwrap();
    let db = Db::open(&dir.path().join("test.db")).await.unwrap();
    sqlx::query("INSERT INTO binaries(id,name,sha256,size,architecture,format,path,paused) VALUES('b','fixture','sha',1,'x86','ELF','unused',0)").execute(&db.pool).await.unwrap();
    sqlx::query(
        "INSERT INTO functions(id,binary_id,address,name,size) VALUES('f','b','1000','f',1)",
    )
    .execute(&db.pool)
    .await
    .unwrap();
    sqlx::query("INSERT INTO jobs(id,binary_id,function_id,stage) VALUES('j','b','f','map')")
        .execute(&db.pool)
        .await
        .unwrap();
    let app = Router::new().route("/", post(|| async { StatusCode::PAYMENT_REQUIRED }));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    let ai = Ai::new(AiConfig::default()).unwrap();
    let job = pipeline::claim(&db, &ai, Some("b"), false)
        .await
        .unwrap()
        .unwrap();
    let error = billing::response(reqwest::Client::new().post(url).send().await.unwrap())
        .await
        .unwrap_err();
    pipeline::fail(&db, &ai, &job, &error.to_string())
        .await
        .unwrap();
    let overview = db.overview("b").await.unwrap();
    assert!(overview.paused);
    assert_eq!(overview.queued, 1);
    assert_eq!(overview.cost_usd, None);
    assert!(
        pipeline::claim(&db, &ai, Some("b"), false)
            .await
            .unwrap()
            .is_none()
    );
    server.abort();
}

#[test]
fn only_numeric_nonnegative_native_cost_is_reported() {
    for value in [
        json!({}),
        json!({"usage":{"cost":null}}),
        json!({"usage":{"cost":"0.1"}}),
        json!({"usage":{"cost":-1}}),
    ] {
        assert_eq!(billing::reported_cost(&value), None);
    }
    assert_eq!(
        billing::reported_cost(&json!({"usage":{"cost":0}})),
        Some(0.0)
    );
}
