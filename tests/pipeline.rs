use piston_decompiler::{
    ai::{Ai, Analysis, Completion},
    config::AiConfig,
    db::Db,
    ghidra, pipeline, proto,
};
use serde_json::json;
use sqlx::Row;

async fn fixture() -> (tempfile::TempDir, Db, Ai) {
    let dir = tempfile::tempdir().unwrap();
    let db = Db::open(&dir.path().join("test.db")).await.unwrap();
    sqlx::query("INSERT INTO binaries(id,name,sha256,size,architecture,format,path,budget_usd,paused) VALUES('b','fixture','sha',10,'x86','ELF','unused',1.0,0)").execute(&db.pool).await.unwrap();
    let functions = (0..8).map(|i|json!({"address":format!("{i:08x}"),"name":format!("fn_{i}"),"size":32,"pseudocode":format!("int fn_{i}(int n) {{ return n + {i}; }}"),"callees":if i>0 {vec![format!("{:08x}",i-1)]} else {vec![]}}).to_string()).collect::<Vec<_>>().join("\n");
    let path = dir.path().join("functions.jsonl");
    std::fs::write(&path, functions).unwrap();
    ghidra::import_export(&db, "b", &path).await.unwrap();
    let ai = Ai::new(AiConfig {
        model: "fixture".into(),
        input_usd_per_million: 1.0,
        output_usd_per_million: 2.0,
        ..Default::default()
    })
    .unwrap();
    (dir, db, ai)
}
fn completion() -> Completion {
    Completion {
        analysis: Analysis {
            proposed_name: "increment_value".into(),
            summary: "Adds a constant to the input.".into(),
            confidence: 0.9,
            evidence: vec!["One integer addition".into()],
            parameter_types: vec![],
            side_effects: vec![],
            uncertainties: vec![],
        },
        input_tokens: 100,
        output_tokens: 20,
        cost: 0.00014,
        latency_ms: 10,
        prompt_hash: "hash".into(),
        model: "fixture".into(),
    }
}
#[tokio::test]
async fn concurrent_claims_are_unique_and_reservations_bound_spend() {
    let (_dir, db, ai) = fixture().await;
    let reservation = ai.reservation("map", false);
    sqlx::query("UPDATE binaries SET budget_usd=? WHERE id='b'")
        .bind(reservation * 3.1)
        .execute(&db.pool)
        .await
        .unwrap();
    let claims =
        futures::future::join_all((0..8).map(|_| pipeline::claim(&db, &ai, None, false))).await;
    let jobs: Vec<_> = claims.into_iter().filter_map(Result::unwrap).collect();
    assert_eq!(jobs.len(), 3);
    assert_eq!(
        jobs.iter()
            .map(|j| &j.id)
            .collect::<std::collections::HashSet<_>>()
            .len(),
        3
    );
    let overview = db.overview("b").await.unwrap();
    assert!(overview.reserved_usd + overview.cost_usd <= overview.budget_usd);
    assert!(overview.paused);
}
#[tokio::test]
async fn completion_is_idempotent_and_propagation_waits_for_map() {
    let (_dir, db, ai) = fixture().await;
    let job = pipeline::claim(&db, &ai, None, false)
        .await
        .unwrap()
        .unwrap();
    pipeline::finish(&db, &ai, &job, completion())
        .await
        .unwrap();
    pipeline::finish(&db, &ai, &job, completion())
        .await
        .unwrap();
    let overview = db.overview("b").await.unwrap();
    assert_eq!(overview.analyzed, 1);
    assert_eq!(overview.input_tokens, 100);
    assert!(overview.reserved_usd.abs() < 1e-9);
    assert_eq!(overview.provider_breakdowns.len(), 1);
    assert_eq!(overview.provider_breakdowns[0].model, "fixture");
    assert_eq!(overview.provider_breakdowns[0].stage, "map");
    assert_eq!(overview.provider_breakdowns[0].requests, 1);
    assert_eq!(overview.provider_breakdowns[0].average_latency_ms, 10.0);
    let next = pipeline::claim(&db, &ai, None, false)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(next.stage, job.stage);
    let result = db
        .functions(&proto::FunctionQuery {
            binary_id: "b".into(),
            search: "increment".into(),
            limit: 50,
            ..Default::default()
        })
        .await
        .unwrap();
    assert_eq!(result.total, 1);
    assert_eq!(result.functions[0].id, job.function_id);
}
#[tokio::test]
async fn restart_preserves_uncertain_spend_and_explicit_retry_accounts_for_it() {
    let (_dir, db, ai) = fixture().await;
    let job = pipeline::claim(&db, &ai, None, false)
        .await
        .unwrap()
        .unwrap();
    db.recover().await.unwrap();
    let recovered = db.overview("b").await.unwrap();
    assert!(recovered.paused);
    assert_eq!(recovered.failed, 1);
    assert_eq!(recovered.reserved_usd, job.reserved_usd);
    pipeline::control(&db, &ai, "b", "retry").await.unwrap();
    let retried = db.overview("b").await.unwrap();
    assert_eq!(retried.reserved_usd, 0.0);
    assert_eq!(retried.cost_usd, job.reserved_usd);
    assert_eq!(retried.queued, 8);
}
#[tokio::test]
async fn failed_request_retains_conservative_charge_and_backoff() {
    let (_dir, db, ai) = fixture().await;
    let job = pipeline::claim(&db, &ai, None, false)
        .await
        .unwrap()
        .unwrap();
    pipeline::fail(&db, &ai, &job, "simulated timeout")
        .await
        .unwrap();
    pipeline::fail(&db, &ai, &job, "duplicate delivery")
        .await
        .unwrap();
    let overview = db.overview("b").await.unwrap();
    assert_eq!(overview.cost_usd, job.reserved_usd);
    assert_eq!(overview.reserved_usd, 0.0);
    let row = sqlx::query("SELECT available_at>unixepoch() AS delayed FROM jobs WHERE id=?")
        .bind(job.id)
        .fetch_one(&db.pool)
        .await
        .unwrap();
    assert!(row.get::<bool, _>("delayed"));
}
#[tokio::test]
async fn export_is_transactional_and_search_handles_user_syntax() {
    let (dir, db, _ai) = fixture().await;
    for search in ["\" OR *", "fn_", "fn_1", ""] {
        let result = db
            .functions(&proto::FunctionQuery {
                binary_id: "b".into(),
                search: search.into(),
                limit: 50,
                ..Default::default()
            })
            .await;
        assert!(result.is_ok(), "{result:?}");
    }
    assert!(
        ghidra::import_export(&db, "b", &dir.path().join("functions.jsonl"))
            .await
            .is_err()
    );
    assert_eq!(db.overview("b").await.unwrap().functions, 8);
}
#[tokio::test]
async fn evidence_agent_uses_bounded_tools_and_accounts_all_rounds() {
    use axum::{Json, Router, routing::post};
    use std::sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    };
    let (_dir, db, mut ai) = fixture().await;
    let calls = Arc::new(AtomicUsize::new(0));
    let seen = calls.clone();
    let app=Router::new().route("/chat/completions",post(move |Json(body):Json<serde_json::Value>|{
        let seen=seen.clone();async move {
            let index=seen.fetch_add(1,Ordering::SeqCst);
            assert!(body["messages"].as_array().unwrap().len()>=2);
            let message=if index==0 {json!({"role":"assistant","content":null,"tool_calls":[{"id":"t1","type":"function","function":{"name":"inspect_function","arguments":"{\"address\":\"00000000\",\"kind\":\"pseudocode\"}"}}]})} else {json!({"role":"assistant","content":serde_json::to_string(&completion().analysis).unwrap()})};
            Json(json!({"choices":[{"message":message}],"usage":{"prompt_tokens":100,"completion_tokens":20}}))
        }
    }));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    ai.config.base_url = format!("http://{}", listener.local_addr().unwrap());
    // An existing nonsecret environment variable exercises bearer-key loading without global mutation.
    ai.config.api_key_env = "USER".into();
    ai.config.escalation_model = "fixture".into();
    ai.config.escalation_input_usd_per_million = 1.0;
    ai.config.escalation_output_usd_per_million = 2.0;
    let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    let result = ai
        .analyze(&db, "b", "b:00000001", "escalate")
        .await
        .unwrap();
    assert_eq!(calls.load(Ordering::SeqCst), 2);
    assert_eq!(result.input_tokens, 200);
    assert_eq!(result.output_tokens, 40);
    assert!(result.cost < ai.reservation("escalate", false));
    server.abort();
}

#[tokio::test]
async fn prompt_packing_keeps_structured_evidence_within_escaped_budget() {
    let (_dir, db, mut ai) = fixture().await;
    let hostile = "\"\\\n\t\u{0001}日é".repeat(2_000);
    sqlx::query("UPDATE functions SET pseudocode=?,name=?,strings_json=?,imports_json=?")
        .bind(&hostile)
        .bind(&hostile)
        .bind(serde_json::to_string(&vec![&hostile; 30]).unwrap())
        .bind(serde_json::to_string(&vec![&hostile; 30]).unwrap())
        .execute(&db.pool)
        .await
        .unwrap();
    for budget in [4096, 4097, 8192, 24000, 100000] {
        ai.config.max_input_bytes = budget;
        let prompt = ai.prompt(&db, "b:00000001", "map").await.unwrap();
        assert!(serde_json::to_vec(&prompt.messages).unwrap().len() <= budget - 1024);
        let context: serde_json::Value =
            serde_json::from_str(prompt.messages[1]["content"].as_str().unwrap()).unwrap();
        assert_eq!(context["address"], "00000001");
        let code = context["pseudocode"].as_str().unwrap();
        assert!(!code.is_empty());
        assert!(hostile.starts_with(code));
        assert!(context["strings"].is_array());
        assert!(context["callees"].is_array());
        assert_eq!(
            prompt.hash,
            ai.prompt(&db, "b:00000001", "map").await.unwrap().hash
        );
    }
    ai.config.max_input_bytes = 1;
    assert!(ai.prompt(&db, "b:00000001", "map").await.is_err());
}

#[tokio::test]
async fn run_state_reports_remote_batch_blockers_without_hanging() {
    let (_dir, db, _ai) = fixture().await;
    assert_eq!(
        pipeline::run_state(&db, "b").await.unwrap(),
        pipeline::RunState::Work
    );
    sqlx::query("UPDATE jobs SET status='batched',batch_id='remote'")
        .execute(&db.pool)
        .await
        .unwrap();
    sqlx::query("INSERT INTO jobs(id,binary_id,function_id,stage,status) VALUES('propagate','b','b:00000000','propagate','queued')")
        .execute(&db.pool)
        .await
        .unwrap();
    assert_eq!(
        pipeline::run_state(&db, "b").await.unwrap(),
        pipeline::RunState::BatchBlocked
    );
    sqlx::query("UPDATE jobs SET status='completed'")
        .execute(&db.pool)
        .await
        .unwrap();
    assert_eq!(
        pipeline::run_state(&db, "b").await.unwrap(),
        pipeline::RunState::Complete
    );
}
