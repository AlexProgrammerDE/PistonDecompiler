use piston_decompiler::{
    ai::Ai,
    config::AiConfig,
    db::Db,
    ghidra,
    runtime::{self, Trace},
};
use serde_json::json;

fn trace() -> serde_json::Value {
    json!({"version":1,"id":"session","binary_sha256":"sha","scenario":"inventory","image_base":4096,"pointer_width":8,"collector":"fixture","dropped_events":0,"events":[
{"sequence":1,"thread":1,"function_rva":0,"kind":"allocation","allocation":"object-1","address":8192,"size":16},
{"sequence":2,"thread":1,"function_rva":0,"kind":"memory","allocation":"object-1","offset":8,"width":4,"write":false,"value":"100","instruction_rva":2},
{"sequence":3,"thread":1,"function_rva":0,"kind":"call","target_rva":16,"site_rva":4},
{"sequence":4,"thread":1,"function_rva":0,"kind":"free","allocation":"object-1"}]})
}
#[test]
fn allocation_lifetimes_and_bounds_are_enforced() {
    let base = trace();
    serde_json::from_value::<Trace>(base.clone())
        .unwrap()
        .validate()
        .unwrap();
    for invalid in [json!(20), json!(u64::MAX)] {
        let mut t = base.clone();
        t["events"][1]["offset"] = invalid;
        assert!(
            serde_json::from_value::<Trace>(t)
                .unwrap()
                .validate()
                .is_err()
        );
    }
    let mut t = base.clone();
    t["events"][1]["allocation"] = json!("unknown");
    assert!(
        serde_json::from_value::<Trace>(t)
            .unwrap()
            .validate()
            .is_err()
    );
    let mut t = base;
    t["events"].as_array_mut().unwrap().push(json!({"sequence":5,"thread":1,"function_rva":0,"kind":"allocation","allocation":"object-1","address":8192,"size":16}));
    assert!(
        serde_json::from_value::<Trace>(t)
            .unwrap()
            .validate()
            .is_err()
    );
}
#[tokio::test]
async fn import_is_atomic_idempotent_and_reaches_model_evidence() {
    let dir = tempfile::tempdir().unwrap();
    let db = Db::open(&dir.path().join("db")).await.unwrap();
    sqlx::query("INSERT INTO binaries(id,name,sha256,size,architecture,format,path) VALUES('b','fixture','sha',10,'x86_64','ELF','unused')").execute(&db.pool).await.unwrap();
    let export = dir.path().join("export.jsonl");
    std::fs::write(
        &export,
        [
            json!({"address":"1000","name":"root","size":16,"pseudocode":"return child();"}),
            json!({"address":"1010","name":"child","size":16,"pseudocode":"return 1;"}),
        ]
        .map(|v| v.to_string())
        .join("\n"),
    )
    .unwrap();
    ghidra::import_export(&db, "b", &export).await.unwrap();
    let path = dir.path().join("trace.json");
    std::fs::write(&path, trace().to_string()).unwrap();
    runtime::import(&db, "b", &path).await.unwrap();
    runtime::import(&db, "b", &path).await.unwrap();
    let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM runtime_sessions")
        .fetch_one(&db.pool)
        .await
        .unwrap();
    assert_eq!(count, 1);
    let edges: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM edges")
        .fetch_one(&db.pool)
        .await
        .unwrap();
    assert_eq!(edges, 1);
    let ai = Ai::new(AiConfig::default()).unwrap();
    let prompt = ai.prompt(&db, "b:1000", "map").await.unwrap();
    assert!(prompt.evidence.iter().any(|e| e.kind == "runtime"));
    let mut conflicting = trace();
    conflicting["scenario"] = json!("other");
    std::fs::write(&path, conflicting.to_string()).unwrap();
    assert!(runtime::import(&db, "b", &path).await.is_err());
    let coverage = runtime::coverage(&db, "b").await.unwrap();
    assert_eq!(coverage["observed_functions"], 1);
}
