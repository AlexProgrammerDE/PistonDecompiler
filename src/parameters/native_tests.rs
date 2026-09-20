use crate::{config::Config, db::Db, ghidra};
use serde_json::{Value, json};

#[tokio::test]
#[ignore = "requires PISTON_TEST_GHIDRA_HOME, a JDK, and cc"]
async fn native_parameter_trials_preserve_return_and_reconcile_saved_winners() {
    let dir = tempfile::tempdir().unwrap();
    let source = dir.path().join("sample.c");
    let binary = dir.path().join("sample");
    std::fs::write(&source,"#include <string.h>\n__attribute__((noinline)) unsigned long measure(const char *p, unsigned long n) { return strnlen(p,n); }\nint main(int argc,char **argv) { return measure(argv[0],argc+10); }").unwrap();
    assert!(
        std::process::Command::new("cc")
            .args(["-O1", "-fno-inline", "-o"])
            .arg(&binary)
            .arg(&source)
            .status()
            .unwrap()
            .success()
    );
    let config = Config {
        ghidra_gui: false,
        data_dir: dir.path().join("data"),
        ghidra_home: Some(std::env::var_os("PISTON_TEST_GHIDRA_HOME").unwrap().into()),
        ..Default::default()
    };
    std::fs::create_dir_all(&config.data_dir).unwrap();
    let db = Db::open(&config.data_dir.join("piston.db")).await.unwrap();
    let b = db.import(&binary, &config).await.unwrap();
    ghidra::extract(&db, &config, &b.id).await.unwrap();
    let (address, before): (String, String) = sqlx::query_as(
        "SELECT address,type_context FROM functions WHERE binary_id=? AND name='measure'",
    )
    .bind(&b.id)
    .fetch_one(&db.pool)
    .await
    .unwrap();
    let input = dir.path().join("input.json");
    let report = dir.path().join("report.json");
    std::fs::write(&input,json!({"address":address,"candidates":[{"index":0,"name":"text","data_type":{"kind":"primitive","name":"f64"}},{"index":1,"name":"limit","data_type":null},{"index":1,"name":"alternative","data_type":null},{"index":63,"name":"outside","data_type":null}]}).to_string()).unwrap();
    let args = vec![
        "-process".into(),
        "program.bin".into(),
        "-noanalysis".into(),
        "-postScript".into(),
        "PistonParameters.java".into(),
        "test-parameters".into(),
        input.to_string_lossy().into_owned(),
        report.to_string_lossy().into_owned(),
    ];
    ghidra::headless(&config, &b.id, &args, None).await.unwrap();
    assert!(
        report.exists(),
        "{}",
        std::fs::read_to_string(
            config
                .data_dir
                .join("binaries")
                .join(&b.id)
                .join("ghidra/headless.log")
        )
        .unwrap()
    );
    let first: Value = serde_json::from_slice(&std::fs::read(&report).unwrap()).unwrap();
    assert_eq!(first["status"], "completed");
    assert_eq!(first["changed"], true, "{first:#}");
    assert_eq!(first["coverage_before"]["named"], 0);
    assert_eq!(first["coverage_after"]["named"], 2);
    assert!(
        first["propagated_candidates"].as_u64().unwrap() > 0,
        "{first:#}"
    );
    let trials = first["trials"].as_array().unwrap();
    assert!(
        trials
            .iter()
            .any(|t| t["source"] == "ai_name" && t["accepted"] == true)
    );
    assert!(
        trials
            .iter()
            .any(|t| t["source"] == "ai_type" && t["accepted"] == false)
    );
    ghidra::refresh(&db, &config, &b.id).await.unwrap();
    let after: String =
        sqlx::query_scalar("SELECT type_context FROM functions WHERE binary_id=? AND address=?")
            .bind(&b.id)
            .bind(&address)
            .fetch_one(&db.pool)
            .await
            .unwrap();
    let before: Value = serde_json::from_str(&before).unwrap();
    let after: Value = serde_json::from_str(&after).unwrap();
    assert_eq!(before["return_type"], after["return_type"]);
    assert_eq!(before["calling_convention"], after["calling_convention"]);
    // A new process reopens the saved project and returns the same audit without trials.
    ghidra::headless(&config, &b.id, &args, None).await.unwrap();
    let second: Value = serde_json::from_slice(&std::fs::read(&report).unwrap()).unwrap();
    assert_eq!(first, second);
}
