use piston_decompiler::{
    ai::{Ai, Analysis, Claim, Completion, EvidenceReference},
    config::AiConfig,
    db::Db,
    ghidra, knowledge, pipeline, proto,
};
use serde_json::json;

async fn fixture() -> (tempfile::TempDir, Db, Ai) {
    let dir = tempfile::tempdir().unwrap();
    let db = Db::open(&dir.path().join("state.db")).await.unwrap();
    sqlx::query("INSERT INTO binaries(id,name,sha256,size,architecture,format,path,budget_usd,paused) VALUES('b','test','hash',1,'x86','ELF','unused',10,0)").execute(&db.pool).await.unwrap();
    let path = dir.path().join("export.jsonl");
    std::fs::write(&path,[json!({"address":"1000","name":"leaf","size":30,"pseudocode":"int leaf(int n) {\n return n + 1;\n}"}),json!({"address":"2000","name":"caller","size":30,"pseudocode":"int caller(int n) {\n return leaf(n);\n}","callees":["1000"]})].iter().map(|v|v.to_string()).collect::<Vec<_>>().join("\n")).unwrap();
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
            proposed_name: "increment".into(),
            summary: "Adds one.".into(),
            confidence: 0.7,
            evidence: vec!["addition".into()],
            claims: vec![],
            parameter_types: vec![],
            side_effects: vec![],
            uncertainties: vec![],
        },
        input_tokens: 10,
        output_tokens: 10,
        cost: 0.001,
        latency_ms: 1,
        prompt_hash: "fixture".into(),
        model: "fixture".into(),
    }
}
async fn finish_next(db: &Db, ai: &Ai) -> proto::AnalysisResult {
    sqlx::query("UPDATE binaries SET paused=0")
        .execute(&db.pool)
        .await
        .unwrap();
    let job = pipeline::claim(db, ai, Some("b"), false)
        .await
        .unwrap()
        .unwrap();
    ai.pin_prompt(db, &job).await.unwrap();
    pipeline::finish(db, ai, &job, completion()).await.unwrap();
    db.function(&job.function_id).await.unwrap().result.unwrap()
}
#[tokio::test]
async fn corrections_invalidate_only_dependencies_and_survive_restart() {
    let (dir, db, ai) = fixture().await;
    let leaf = finish_next(&db, &ai).await;
    assert_eq!(leaf.function_id, "b:1000");
    let caller = finish_next(&db, &ai).await;
    assert_eq!(caller.dependencies, vec![leaf.id.clone()]);
    let corrected = knowledge::correct(
        &db,
        &proto::CorrectionRequest {
            result_id: leaf.id.clone(),
            expected_revision: 0,
            proposed_name: "add_one".into(),
            summary: "Adds one to its integer input.".into(),
            reason: "Checked the arithmetic.".into(),
        },
    )
    .await
    .unwrap();
    assert!(knowledge::result(&db, &caller.id).await.unwrap().stale);
    assert!(!corrected.stale);
    assert_eq!(
        knowledge::history(&db, &leaf.function_id)
            .await
            .unwrap()
            .results
            .len(),
        2
    );
    let run = knowledge::reanalyze(
        &db,
        &ai.config,
        &proto::ReanalysisRequest {
            binary_id: "b".into(),
            stale_only: true,
            ..Default::default()
        },
    )
    .await
    .unwrap();
    assert_eq!(run.queued, 1);
    let new = finish_next(&db, &ai).await;
    assert_ne!(new.id, caller.id);
    assert!(!new.stale);
    assert_eq!(new.dependencies, vec![corrected.id.clone()]);
    db.pool.close().await;
    let reopened = Db::open(&dir.path().join("state.db")).await.unwrap();
    assert_eq!(
        reopened
            .function(&leaf.function_id)
            .await
            .unwrap()
            .result
            .unwrap()
            .id,
        corrected.id
    );
}
#[tokio::test]
async fn exact_review_rejects_concurrent_updates_and_preserves_human_decisions() {
    let (_dir, db, ai) = fixture().await;
    let first = finish_next(&db, &ai).await;
    let request = proto::ReviewRequest {
        result_id: first.id.clone(),
        expected_revision: 0,
        field: "name".into(),
        decision: "accepted".into(),
        reason: String::new(),
    };
    let (a, b) = tokio::join!(
        knowledge::review(&db, &request),
        knowledge::review(&db, &request)
    );
    assert_ne!(a.is_ok(), b.is_ok());
    finish_next(&db, &ai).await;
    let run = knowledge::reanalyze(
        &db,
        &ai.config,
        &proto::ReanalysisRequest {
            binary_id: "b".into(),
            function_ids: vec![first.function_id.clone()],
            ..Default::default()
        },
    )
    .await
    .unwrap();
    assert_eq!(run.queued, 1);
    finish_next(&db, &ai).await;
    assert_eq!(
        db.function(&first.function_id)
            .await
            .unwrap()
            .result
            .unwrap()
            .id,
        first.id
    );
    assert_eq!(
        knowledge::history(&db, &first.function_id)
            .await
            .unwrap()
            .results
            .len(),
        2
    );
}
#[tokio::test]
async fn evidence_references_must_point_inside_supplied_artifacts() {
    let (_dir, db, ai) = fixture().await;
    let prompt = ai.prompt(&db, "b:1000", "map").await.unwrap();
    let artifact = &prompt.evidence[0];
    let mut a = completion().analysis;
    a.claims = vec![Claim {
        text: "Adds one.".into(),
        references: vec![EvidenceReference {
            artifact_id: artifact.artifact_id.clone(),
            start_line: 2,
            end_line: 2,
        }],
    }];
    Ai::validate_evidence(&a, &prompt).unwrap();
    a.claims[0].references[0].end_line = 100;
    assert!(Ai::validate_evidence(&a, &prompt).is_err());
    a.claims[0].references[0].end_line = 2;
    a.claims[0].references[0].artifact_id = "invented".into();
    assert!(Ai::validate_evidence(&a, &prompt).is_err());
    let evidence = knowledge::artifact(&db, &artifact.artifact_id)
        .await
        .unwrap();
    assert!(evidence.content.contains("return n + 1"));
}
#[tokio::test]
async fn investigation_scope_budget_and_revision_are_enforced() {
    let (_dir, db, ai) = fixture().await;
    finish_next(&db, &ai).await;
    finish_next(&db, &ai).await;
    let mut i = knowledge::save_investigation(
        &db,
        &proto::Investigation {
            binary_id: "b".into(),
            question: "Where is arithmetic performed?".into(),
            budget_usd: 0.000001,
            function_ids: vec!["b:1000".into()],
            ..Default::default()
        },
    )
    .await
    .unwrap();
    let stale = i.clone();
    i.notes = "Inspect the addition.".into();
    i = knowledge::save_investigation(&db, &i).await.unwrap();
    assert!(knowledge::save_investigation(&db, &stale).await.is_err());
    assert!(
        knowledge::reanalyze(
            &db,
            &ai.config,
            &proto::ReanalysisRequest {
                binary_id: "b".into(),
                investigation_id: i.id.clone(),
                function_ids: vec!["b:2000".into()],
                ..Default::default()
            }
        )
        .await
        .is_err()
    );
    let run = knowledge::reanalyze(
        &db,
        &ai.config,
        &proto::ReanalysisRequest {
            binary_id: "b".into(),
            investigation_id: i.id.clone(),
            ..Default::default()
        },
    )
    .await
    .unwrap();
    assert_eq!(run.queued, 1);
    let input: String = sqlx::query_scalar("SELECT input_json FROM jobs WHERE run_id=?")
        .bind(&run.id)
        .fetch_one(&db.pool)
        .await
        .unwrap();
    let prompt: piston_decompiler::ai::Prompt = serde_json::from_str(&input).unwrap();
    let context: serde_json::Value =
        serde_json::from_str(prompt.messages[1]["content"].as_str().unwrap()).unwrap();
    assert_eq!(context["investigation_question"], i.question);
    assert!(
        pipeline::claim(&db, &ai, Some("b"), false)
            .await
            .unwrap()
            .is_none()
    );
    assert!(db.overview("b").await.unwrap().paused);
    assert_eq!(
        knowledge::investigations(&db, "b")
            .await
            .unwrap()
            .investigations[0]
            .notes,
        i.notes
    );
}
#[tokio::test]
async fn preview_becomes_invalid_when_review_changes() {
    let (_dir, db, ai) = fixture().await;
    let result = finish_next(&db, &ai).await;
    knowledge::review(
        &db,
        &proto::ReviewRequest {
            result_id: result.id.clone(),
            expected_revision: 0,
            field: "both".into(),
            decision: "accepted".into(),
            reason: String::new(),
        },
    )
    .await
    .unwrap();
    let preview = knowledge::preview_apply(&db, "b").await.unwrap();
    assert_eq!(preview.items.len(), 1);
    knowledge::review(
        &db,
        &proto::ReviewRequest {
            result_id: result.id,
            expected_revision: 1,
            field: "both".into(),
            decision: "rejected".into(),
            reason: String::new(),
        },
    )
    .await
    .unwrap();
    assert!(
        ghidra::execute_apply(&db, &Default::default(), &preview.id, None)
            .await
            .is_err()
    );
    assert_eq!(
        knowledge::apply_operation(&db, &preview.id)
            .await
            .unwrap()
            .status,
        "preview"
    );
}

#[tokio::test]
async fn selected_scope_holds_unrelated_background_jobs() {
    let (_dir, db, ai) = fixture().await;
    let run = knowledge::reanalyze(
        &db,
        &ai.config,
        &proto::ReanalysisRequest {
            binary_id: "b".into(),
            function_ids: vec!["b:2000".into()],
            ..Default::default()
        },
    )
    .await
    .unwrap();
    assert_eq!(run.queued, 1);
    sqlx::query("UPDATE binaries SET paused=0")
        .execute(&db.pool)
        .await
        .unwrap();
    let job = pipeline::claim(&db, &ai, Some("b"), false)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(job.function_id, "b:2000");
    pipeline::finish(&db, &ai, &job, completion())
        .await
        .unwrap();
    assert!(
        pipeline::claim(&db, &ai, Some("b"), false)
            .await
            .unwrap()
            .is_none()
    );
    assert_eq!(
        pipeline::run_state(&db, "b").await.unwrap(),
        pipeline::RunState::Complete
    );
}

#[tokio::test]
async fn original_database_migrates_without_losing_results() {
    use sqlx::sqlite::{SqliteConnectOptions, SqlitePoolOptions};
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("old.db");
    let migrations = dir.path().join("migrations");
    std::fs::create_dir(&migrations).unwrap();
    std::fs::write(
        migrations.join("0001_initial.sql"),
        include_str!("../migrations/0001_initial.sql"),
    )
    .unwrap();
    let pool = SqlitePoolOptions::new()
        .connect_with(
            SqliteConnectOptions::new()
                .filename(&path)
                .create_if_missing(true)
                .foreign_keys(true),
        )
        .await
        .unwrap();
    sqlx::migrate::Migrator::new(migrations.as_path())
        .await
        .unwrap()
        .run(&pool)
        .await
        .unwrap();
    sqlx::raw_sql("INSERT INTO binaries(id,name,sha256,size,architecture,format,path,budget_usd) VALUES('b','old','hash',1,'x86','ELF','unused',1); INSERT INTO functions(id,binary_id,address,name,size,pseudocode) VALUES('f','b','1000','original',1,'return 1;'); INSERT INTO jobs(id,binary_id,function_id,stage,status) VALUES('j','b','f','map','completed'); INSERT INTO results(id,job_id,function_id,stage,model,prompt_hash,raw_json,proposed_name,summary,confidence,review,input_tokens,output_tokens,cost_usd,latency_ms) VALUES('r','j','f','map','old','hash','{}','one','Returns one.',0.7,'applied',10,10,0.1,1);").execute(&pool).await.unwrap();
    pool.close().await;
    let db = Db::open(&path).await.unwrap();
    let detail = db.function("f").await.unwrap();
    assert_eq!(detail.result.unwrap().id, "r");
    assert_eq!(
        knowledge::result(&db, "r").await.unwrap().name_review,
        "accepted"
    );
    let check: Vec<(String, i64, String, i64)> = sqlx::query_as("PRAGMA foreign_key_check")
        .fetch_all(&db.pool)
        .await
        .unwrap();
    assert!(check.is_empty());
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM artifacts")
            .fetch_one(&db.pool)
            .await
            .unwrap(),
        6
    );
}

#[tokio::test]
async fn rejected_summary_is_not_reused_and_invalidates_inflight_dependents() {
    let (_dir, db, ai) = fixture().await;
    let leaf = finish_next(&db, &ai).await;
    let job = pipeline::claim(&db, &ai, Some("b"), false)
        .await
        .unwrap()
        .unwrap();
    let prompt = ai.pin_prompt(&db, &job).await.unwrap();
    assert_eq!(prompt.dependencies, vec![leaf.id.clone()]);
    knowledge::review(
        &db,
        &proto::ReviewRequest {
            result_id: leaf.id.clone(),
            expected_revision: 0,
            field: "name".into(),
            decision: "accepted".into(),
            ..Default::default()
        },
    )
    .await
    .unwrap();
    knowledge::review(
        &db,
        &proto::ReviewRequest {
            result_id: leaf.id,
            expected_revision: 1,
            field: "summary".into(),
            decision: "rejected".into(),
            ..Default::default()
        },
    )
    .await
    .unwrap();
    assert!(
        ai.prompt(&db, &job.function_id, "map")
            .await
            .unwrap()
            .dependencies
            .is_empty()
    );
    pipeline::finish(&db, &ai, &job, completion())
        .await
        .unwrap();
    assert!(
        db.function(&job.function_id)
            .await
            .unwrap()
            .result
            .unwrap()
            .stale
    );
}
