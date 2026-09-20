use axum::{Json, Router, routing::post};
use piston_decompiler::{
    ai::{Ai, Prompt},
    config::{AiConfig, DecisionConfig},
    db::Db,
    decisions, ghidra, pipeline, proto,
};
use serde_json::{Value, json};
use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};

struct Fixture {
    _dir: tempfile::TempDir,
    db: Db,
    ai: Ai,
    requests: Arc<AtomicUsize>,
    server: tokio::task::JoinHandle<()>,
}
impl Drop for Fixture {
    fn drop(&mut self) {
        self.server.abort();
    }
}
async fn fixture(
    insufficient: bool,
    supported: bool,
    missing_confidence: bool,
    strong: bool,
) -> Fixture {
    let requests = Arc::new(AtomicUsize::new(0));
    let observed = requests.clone();
    let app = Router::new().route("/api/alpha/decisions", post(move |Json(body): Json<Value>| {
        let observed = observed.clone();
        async move {
            observed.fetch_add(1, Ordering::SeqCst);
            let mut answers = serde_json::Map::new();
            for (name, q) in body["questions"].as_object().unwrap() {
                let label = match name.as_str() {
                    "role" => "computation",
                    "evidence" => if insufficient { "insufficient" } else { "sufficient" },
                    "complexity" => "routine",
                    _ => if supported { "supported" } else { "unsupported" },
                };
                let probabilities: serde_json::Map<String, Value> = q["criteria"].as_object().unwrap().keys()
                    .map(|k| (k.clone(),json!(if k==label {1.0} else {0.0}))).collect();
                let mut answer=json!({"type":"choice","choice":label,"probabilities":probabilities});
                if !missing_confidence {answer["confidence"]=json!(1.0);}
                answers.insert(name.clone(),answer);
            }
            Json(json!({"model":"decision-fixture","answers":answers,"usage":{"input_tokens":100,"output_tokens":10,"cost":0.0000042}}))
        }
    })).route("/chat/completions", post(|Json(body): Json<Value>| async move {
        let user=body["messages"].as_array().unwrap().iter().find(|m|m["role"]=="user").unwrap();
        let content=user["content"].as_str().unwrap_or_else(||user["content"][0]["text"].as_str().unwrap());
        let context:Value=serde_json::from_str(content).unwrap();
        let analysis=json!({"proposed_name":"increment_value","summary":"Adds one to the argument.","confidence":0.8,
            "evidence":["Addition in return expression"],"claims":[{"text":"Adds one.","references":[{"artifact_id":context["evidence"][0]["artifact_id"],"start_line":1,"end_line":1}]}],
            "parameter_types":["int"],"side_effects":[],"uncertainties":[]});
        Json(json!({"id":"fixture","object":"chat.completion","created":0,"model":"generator",
            "choices":[{"index":0,"finish_reason":"stop","message":{"role":"assistant","content":analysis.to_string()}}],
            "usage":{"prompt_tokens":100,"completion_tokens":50,"total_tokens":150}}))
    }));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    let dir = tempfile::tempdir().unwrap();
    let db = Db::open(&dir.path().join("test.db")).await.unwrap();
    sqlx::query("INSERT INTO binaries(id,name,sha256,size,architecture,format,path,budget_usd,paused) VALUES('b','fixture','sha',1,'x86','ELF','unused',1,0)").execute(&db.pool).await.unwrap();
    let path = dir.path().join("export.jsonl");
    std::fs::write(&path,json!({"address":"1000","name":"FUN_1000","size":4,"pseudocode":"int f(int x) { return x + 1; }"}).to_string()).unwrap();
    ghidra::import_export(&db, "b", &path).await.unwrap();
    let ai = Ai::new(AiConfig {
        base_url: format!("http://{address}"),
        api_key_env: "USER".into(),
        model: "generator".into(),
        escalation_model: if strong {
            "strong".into()
        } else {
            String::new()
        },
        input_usd_per_million: 1.0,
        output_usd_per_million: 2.0,
        escalation_input_usd_per_million: 2.0,
        escalation_output_usd_per_million: 4.0,
        decisions: Some(DecisionConfig {
            endpoint: format!("http://{address}/api/alpha/decisions"),
            ..Default::default()
        }),
        ..Default::default()
    })
    .unwrap();
    decisions::prepare(&db, &ai, "b").await.unwrap();
    Fixture {
        _dir: dir,
        db,
        ai,
        requests,
        server,
    }
}
async fn decision(f: &Fixture, expected: &str) -> (pipeline::Job, decisions::DecisionCompletion) {
    let job = pipeline::claim(&f.db, &f.ai, Some("b"), false)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(job.stage, expected);
    let result = decisions::analyze(&f.ai, &f.db, &job).await.unwrap();
    (job, result)
}
async fn generate(f: &Fixture, expected: &str) {
    let job = pipeline::claim(&f.db, &f.ai, Some("b"), false)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(job.stage, expected);
    let result = f.ai.analyze_job(&f.db, &job).await.unwrap();
    pipeline::finish(&f.db, &f.ai, &job, result).await.unwrap();
}
#[tokio::test]
async fn preprocessing_generation_and_verification_preserve_review_and_accounting() {
    let f = fixture(false, true, false, false).await;
    let (job, c) = decision(&f, "preprocess").await;
    assert_eq!(c.route, "map");
    decisions::finish(&f.db, &job, c).await.unwrap();
    decisions::prepare(&f.db, &f.ai, "b").await.unwrap();
    generate(&f, "map").await;
    let (job, c) = decision(&f, "verify_map").await;
    assert_eq!(c.route, "review");
    assert!(c.prompt.candidate.is_some());
    decisions::finish(&f.db, &job, c).await.unwrap();
    let detail = f.db.function("b:1000").await.unwrap();
    assert_eq!(detail.decisions.len(), 2);
    assert_eq!(detail.result.unwrap().name_review, "pending");
    let o = f.db.overview("b").await.unwrap();
    assert_eq!(o.input_tokens, 300);
    assert_eq!(o.output_tokens, 70);
    assert_eq!(o.provider_breakdowns.len(), 3);
    assert!((o.cost_usd - 0.0002084).abs() < 1e-10);
    assert_eq!(o.reserved_usd, 0.0);
    assert_eq!(f.requests.load(Ordering::SeqCst), 2);
    assert_eq!(
        pipeline::run_state(&f.db, "b").await.unwrap(),
        pipeline::RunState::Complete
    );
}
#[tokio::test]
async fn missing_confidence_cannot_defer_and_double_finish_is_idempotent() {
    let f = fixture(true, true, true, false).await;
    let (job, c) = decision(&f, "preprocess").await;
    assert_eq!(c.route, "map");
    // Simulate delivery of the same successful completion twice without another provider call.
    let duplicate = decisions::DecisionCompletion {
        request: c.request.clone(),
        response: c.response.clone(),
        route: c.route.clone(),
        model: c.model.clone(),
        hash: c.hash.clone(),
        input_tokens: c.input_tokens,
        output_tokens: c.output_tokens,
        cost: c.cost,
        latency_ms: c.latency_ms,
        prompt: c.prompt.clone(),
    };
    decisions::finish(&f.db, &job, c).await.unwrap();
    decisions::finish(&f.db, &job, duplicate).await.unwrap();
    assert_eq!(f.db.function("b:1000").await.unwrap().decisions.len(), 1);
    let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM jobs WHERE stage='map'")
        .fetch_one(&f.db.pool)
        .await
        .unwrap();
    assert_eq!(count, 1);
    assert!((f.db.overview("b").await.unwrap().cost_usd - 0.0000042).abs() < 1e-10);
}
#[tokio::test]
async fn insufficient_evidence_defers_without_inventing_a_result() {
    let f = fixture(true, true, false, false).await;
    let (job, c) = decision(&f, "preprocess").await;
    assert_eq!(c.route, "defer");
    decisions::finish(&f.db, &job, c).await.unwrap();
    assert!(f.db.function("b:1000").await.unwrap().result.is_none());
    assert!(
        pipeline::claim(&f.db, &f.ai, Some("b"), false)
            .await
            .unwrap()
            .is_none()
    );
    // Explicit reanalysis creates a fresh, pinned preprocessing pass.
    let run = piston_decompiler::knowledge::reanalyze(
        &f.db,
        &f.ai.config,
        &proto::ReanalysisRequest {
            binary_id: "b".into(),
            function_ids: vec!["b:1000".into()],
            ..Default::default()
        },
    )
    .await
    .unwrap();
    let (stage, input): (String, String) =
        sqlx::query_as("SELECT stage,input_json FROM jobs WHERE run_id=?")
            .bind(run.id)
            .fetch_one(&f.db.pool)
            .await
            .unwrap();
    assert_eq!(stage, "preprocess");
    assert!(
        serde_json::from_str::<Prompt>(&input)
            .unwrap()
            .config
            .decisions
            .is_some()
    );
}
#[tokio::test]
async fn unsupported_candidates_escalate_once_and_remain_pending() {
    let f = fixture(false, false, false, true).await;
    let (job, c) = decision(&f, "preprocess").await;
    decisions::finish(&f.db, &job, c).await.unwrap();
    generate(&f, "map").await;
    let (job, c) = decision(&f, "verify_map").await;
    assert_eq!(c.route, "escalate");
    decisions::finish(&f.db, &job, c).await.unwrap();
    generate(&f, "escalate").await;
    let (job, c) = decision(&f, "verify_escalate").await;
    assert_eq!(c.route, "needs_review");
    decisions::finish(&f.db, &job, c).await.unwrap();
    assert!(
        pipeline::claim(&f.db, &f.ai, Some("b"), false)
            .await
            .unwrap()
            .is_none()
    );
    assert_eq!(
        f.db.function("b:1000")
            .await
            .unwrap()
            .result
            .unwrap()
            .name_review,
        "pending"
    );
}
#[tokio::test]
async fn human_review_during_verification_prevents_paid_escalation() {
    let f = fixture(false, false, false, true).await;
    let (job, c) = decision(&f, "preprocess").await;
    decisions::finish(&f.db, &job, c).await.unwrap();
    generate(&f, "map").await;
    let (job, c) = decision(&f, "verify_map").await;
    let result = f.db.function("b:1000").await.unwrap().result.unwrap();
    pipeline::review(
        &f.db,
        &proto::ReviewRequest {
            result_id: result.id,
            expected_revision: result.revision,
            field: "both".into(),
            decision: "accepted".into(),
            reason: String::new(),
        },
    )
    .await
    .unwrap();
    decisions::finish(&f.db, &job, c).await.unwrap();
    assert!(
        pipeline::claim(&f.db, &f.ai, Some("b"), false)
            .await
            .unwrap()
            .is_none()
    );
}
#[tokio::test]
async fn decision_budget_is_reserved_before_dispatch() {
    let f = fixture(false, true, false, false).await;
    sqlx::query("UPDATE binaries SET budget_usd=? WHERE id='b'")
        .bind(f.ai.reservation("preprocess", false) * 0.5)
        .execute(&f.db.pool)
        .await
        .unwrap();
    assert!(
        pipeline::claim(&f.db, &f.ai, Some("b"), false)
            .await
            .unwrap()
            .is_none()
    );
    assert_eq!(f.requests.load(Ordering::SeqCst), 0);
    assert!(f.db.overview("b").await.unwrap().paused);
}

#[tokio::test]
async fn pinned_decision_provider_and_prices_survive_configuration_changes() {
    let mut f = fixture(false, true, false, false).await;
    let id: String = sqlx::query_scalar("SELECT id FROM jobs WHERE stage='preprocess'")
        .fetch_one(&f.db.pool)
        .await
        .unwrap();
    let prompt = f.ai.prompt(&f.db, "b:1000", "preprocess").await.unwrap();
    sqlx::query("UPDATE jobs SET input_json=? WHERE id=?")
        .bind(serde_json::to_string(&prompt).unwrap())
        .bind(id)
        .execute(&f.db.pool)
        .await
        .unwrap();
    let reserved = f.ai.reservation("preprocess", false);
    f.ai.config.decisions.as_mut().unwrap().endpoint = "http://127.0.0.1:1/unavailable".into();
    f.ai.config
        .decisions
        .as_mut()
        .unwrap()
        .input_usd_per_million = 1000.0;
    let (job, c) = decision(&f, "preprocess").await;
    assert_eq!(job.reserved_usd, reserved);
    assert_eq!(c.route, "map");
    decisions::finish(&f.db, &job, c).await.unwrap();
    assert_eq!(f.requests.load(Ordering::SeqCst), 1);
}
