use piston_decompiler::{config::Config, db::Db, ghidra, proto::StartRecordingRequest, recording};
use serde_json::json;
async fn fixture() -> (tempfile::TempDir, Db, Config, StartRecordingRequest) {
    let dir = tempfile::tempdir().unwrap();
    let config = Config {
        data_dir: dir.path().into(),
        ..Default::default()
    };
    let db = Db::open(&dir.path().join("db")).await.unwrap();
    sqlx::query("INSERT INTO binaries(id,name,sha256,size,architecture,format,path) VALUES('b','fixture','sha',10,'x86_64','ELF','unused')").execute(&db.pool).await.unwrap();
    let export = dir.path().join("export.jsonl");
    std::fs::write(
        &export,
        json!({"address":"001000","name":"root","size":16,"pseudocode":"return 1;"}).to_string(),
    )
    .unwrap();
    ghidra::import_export(&db, "b", &export).await.unwrap();
    sqlx::query("INSERT INTO extractions(id,binary_id,metadata_json) VALUES('metadata','b',?)")
        .bind(json!({"image_base":4096,"pointer_width":8}).to_string())
        .execute(&db.pool)
        .await
        .unwrap();
    let request = StartRecordingRequest {
        binary_id: "b".into(),
        scenario: "damage".into(),
        executable: "/bin/true".into(),
        mode: "investigate".into(),
        seconds: 30,
        function_ids: vec!["b:001000".into()],
        argument_count: 2,
        snapshot_bytes: 32,
        ..Default::default()
    };
    (dir, db, config, request)
}
#[tokio::test]
async fn recording_excludes_workers_and_other_recordings_and_retains_stop() {
    let (_dir, db, config, request) = fixture().await;
    let id = recording::start(&db, &config, &request).await.unwrap();
    assert!(recording::start(&db, &config, &request).await.is_err());
    assert!(
        sqlx::query("UPDATE binaries SET paused=0 WHERE id='b'")
            .execute(&db.pool)
            .await
            .is_err()
    );
    recording::command(&db, &config, &id, "marker", "Before damage")
        .await
        .unwrap();
    recording::command(&db, &config, &id, "stop", "")
        .await
        .unwrap();
    assert_eq!(
        recording::get(&db, &config, &id).await.unwrap().status,
        "stopping"
    );
    db.recover().await.unwrap();
    assert_eq!(
        recording::get(&db, &config, &id).await.unwrap().status,
        "interrupted"
    );
    assert!(
        recording::directory(&config, &id)
            .join("plan.json")
            .exists()
    );
    assert!(
        recording::command(&db, &config, &id, "marker", "late")
            .await
            .is_err()
    );
}
#[tokio::test]
async fn stop_import_is_idempotent_and_preserves_unknown_region_provenance() {
    let (_dir, db, config, request) = fixture().await;
    let id = recording::start(&db, &config, &request).await.unwrap();
    let trace = json!({"version":1,"id":id,"binary_sha256":"sha","scenario":"damage","image_base":4096,"pointer_width":8,"collector":"test","dropped_events":0,"events":[
        {"sequence":1,"timestamp_us":1,"thread":1,"kind":"marker","label":"Before damage"},
        {"sequence":2,"timestamp_us":2,"thread":1,"function_rva":0,"kind":"region","allocation":"unknown","address":8192,"size":8},
        {"sequence":3,"timestamp_us":3,"thread":1,"function_rva":0,"kind":"snapshot","allocation":"unknown","offset":0,"bytes":"64000000","invocation":1,"phase":"entry","argument_index":0}
    ]});
    tokio::fs::write(
        recording::directory(&config, &id).join("trace.json"),
        trace.to_string(),
    )
    .await
    .unwrap();
    recording::import_saved(&db, &config, &id).await.unwrap();
    recording::import_saved(&db, &config, &id).await.unwrap();
    let record = recording::get(&db, &config, &id).await.unwrap();
    assert_eq!(record.status, "ready");
    assert_eq!(
        serde_json::from_str::<serde_json::Value>(&record.coverage_json).unwrap()["new_functions"],
        1
    );
    let ai = piston_decompiler::ai::Ai::new(Default::default()).unwrap();
    let prompt = ai.prompt(&db, "b:001000", "map").await.unwrap();
    let artifact = prompt
        .evidence
        .iter()
        .find(|e| e.kind == "runtime")
        .unwrap();
    let content: String = sqlx::query_scalar("SELECT content FROM artifacts WHERE id=?")
        .bind(&artifact.artifact_id)
        .fetch_one(&db.pool)
        .await
        .unwrap();
    let events: Vec<serde_json::Value> = content
        .lines()
        .filter_map(|line| serde_json::from_str(line).ok())
        .collect();
    assert!(events.iter().any(|v| v["kind"] == "region"));
    assert!(events.iter().any(|v| v["kind"] == "marker"));
    assert!(
        events
            .iter()
            .any(|v| v["invocation"] == 1 && v["phase"] == "entry")
    );
    let ai = piston_decompiler::ai::Ai::new(piston_decompiler::config::AiConfig {
        model: "fixture".into(),
        api_key_env: "USER".into(),
        ..Default::default()
    })
    .unwrap();
    recording::analyze(&db, &ai, &id).await.unwrap();
    let first = recording::get(&db, &config, &id)
        .await
        .unwrap()
        .analysis_run_id;
    recording::analyze(&db, &ai, &id).await.unwrap();
    assert_eq!(
        first,
        recording::get(&db, &config, &id)
            .await
            .unwrap()
            .analysis_run_id
    );
}

#[tokio::test]
#[ignore = "requires a C compiler, Frida, and optionally Ghidra"]
async fn real_capture_stop_import_and_ghidra_save() {
    let python =
        std::env::var_os("PISTON_TEST_RUNTIME_PYTHON").expect("Set PISTON_TEST_RUNTIME_PYTHON");
    let dir = tempfile::tempdir().unwrap();
    let source = dir.path().join("fixture.c");
    std::fs::write(&source,r#"
#include <stdlib.h>
#include <unistd.h>
struct Player { int health; int armor; };
__attribute__((noinline)) int damage(struct Player *p, int n) {p->health-=n;return p->health;}
int main(void){struct Player*p=malloc(sizeof(*p));p->health=100;p->armor=5;for(int i=0;i<30;i++){damage(p,1);usleep(100000);}free(p);return 0;}
"#).unwrap();
    let executable = dir.path().join("fixture");
    assert!(
        std::process::Command::new("cc")
            .args(["-g", "-O0", "-fno-pie", "-no-pie"])
            .arg(&source)
            .arg("-o")
            .arg(&executable)
            .status()
            .unwrap()
            .success()
    );
    let config = Config {
        data_dir: dir.path().join("data"),
        runtime_python: python.into(),
        ghidra_home: std::env::var_os("PISTON_TEST_GHIDRA_HOME").map(Into::into),
        ..Default::default()
    };
    tokio::fs::create_dir_all(&config.data_dir).await.unwrap();
    let db = Db::open(&config.data_dir.join("piston.db")).await.unwrap();
    let binary = db.import(&executable, &config).await.unwrap();
    // This integration test uses Ghidra's real instruction map, rather than fake RVAs.
    ghidra::extract(&db, &config, &binary.id).await.unwrap();
    let function_ids: Vec<String> = sqlx::query_scalar(
        "SELECT id FROM functions WHERE binary_id=? AND name IN ('damage','main')",
    )
    .bind(&binary.id)
    .fetch_all(&db.pool)
    .await
    .unwrap();
    assert_eq!(function_ids.len(), 2);
    let id = recording::start(
        &db,
        &config,
        &StartRecordingRequest {
            binary_id: binary.id.clone(),
            scenario: "damage".into(),
            executable: executable.display().to_string(),
            mode: "investigate".into(),
            seconds: 30,
            function_ids: function_ids.clone(),
            argument_count: 2,
            snapshot_bytes: 8,
            trace_memory: true,
            ..Default::default()
        },
    )
    .await
    .unwrap();
    let runner = tokio::spawn({
        let db = db.clone();
        let config = config.clone();
        let id = id.clone();
        async move {
            recording::run(
                &db,
                &config,
                &id,
                tokio_util::sync::CancellationToken::new(),
            )
            .await
        }
    });
    tokio::time::timeout(std::time::Duration::from_secs(20), async {
        loop {
            if recording::get(&db, &config, &id).await.unwrap().status == "recording" {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        }
    })
    .await
    .unwrap();
    recording::command(&db, &config, &id, "marker", "After damage")
        .await
        .unwrap();
    tokio::time::sleep(std::time::Duration::from_millis(200)).await;
    recording::command(&db, &config, &id, "stop", "")
        .await
        .unwrap();
    runner.await.unwrap().unwrap();
    let trace: serde_json::Value = serde_json::from_slice(
        &tokio::fs::read(recording::directory(&config, &id).join("trace.json"))
            .await
            .unwrap(),
    )
    .unwrap();
    let events = trace["events"].as_array().unwrap();
    assert!(events.iter().any(|e| e["kind"] == "marker"));
    assert!(
        events
            .iter()
            .any(|e| e["kind"] == "snapshot" && e["phase"] == "entry")
    );
    assert!(
        events
            .iter()
            .any(|e| e["kind"] == "snapshot" && e["phase"] == "return")
    );
    assert!(
        events
            .iter()
            .any(|e| e["kind"] == "memory" && e["write"] == true)
    );
    recording::publish(&db, &config, &id).await.unwrap();
    assert_eq!(
        recording::get(&db, &config, &id)
            .await
            .unwrap()
            .ghidra_status,
        "saved"
    );
    let crash_id = recording::start(
        &db,
        &config,
        &StartRecordingRequest {
            binary_id: binary.id.clone(),
            scenario: "interrupted damage".into(),
            executable: executable.display().to_string(),
            mode: "investigate".into(),
            seconds: 30,
            function_ids,
            argument_count: 2,
            snapshot_bytes: 8,
            ..Default::default()
        },
    )
    .await
    .unwrap();
    let runner = tokio::spawn({
        let db = db.clone();
        let config = config.clone();
        let id = crash_id.clone();
        async move {
            recording::run(
                &db,
                &config,
                &id,
                tokio_util::sync::CancellationToken::new(),
            )
            .await
        }
    });
    let progress = tokio::time::timeout(std::time::Duration::from_secs(20), async {
        loop {
            let r = recording::get(&db, &config, &crash_id).await.unwrap();
            let p: serde_json::Value = serde_json::from_str(&r.progress_json).unwrap();
            if r.status == "recording" && p["events"].as_u64().unwrap_or(0) > 0 {
                break p;
            }
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        }
    })
    .await
    .unwrap();
    assert!(
        std::process::Command::new("kill")
            .args(["-KILL", &progress["recorder_pid"].to_string()])
            .status()
            .unwrap()
            .success()
    );
    assert!(runner.await.unwrap().is_err());
    db.recover().await.unwrap();
    recording::recover(&db, &config, &crash_id).await.unwrap();
    assert_eq!(
        recording::get(&db, &config, &crash_id)
            .await
            .unwrap()
            .status,
        "ready"
    );
    // Reopen and verify the same native project. Publishing again remains idempotent.
    recording::publish(&db, &config, &id).await.unwrap();
}

#[tokio::test]
async fn refresh_removes_non_executable_entries_from_capture_and_work_queue() {
    for flags in [
        json!({"executable":false}),
        json!({"executable":true,"external_thunk":true}),
    ] {
        let (dir, db, config, request) = fixture().await;
        let export = dir.path().join("data-entry.jsonl");
        let mut entry =
            json!({"address":"001000","name":"root","size":1,"pseudocode":"halt_baddata();"});
        entry
            .as_object_mut()
            .unwrap()
            .extend(flags.as_object().unwrap().clone());
        std::fs::write(&export, entry.to_string()).unwrap();
        std::fs::write(
            export.with_extension("metadata.json"),
            json!({"image_base":4096,"pointer_width":8}).to_string(),
        )
        .unwrap();
        ghidra::refresh_export(&db, "b", &export).await.unwrap();
        let plan = piston_decompiler::runtime::capture_plan(&db, "b")
            .await
            .unwrap();
        assert!(plan["functions"].as_array().unwrap().is_empty());
        let queued: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM jobs WHERE binary_id='b' AND status='queued'")
                .fetch_one(&db.pool)
                .await
                .unwrap();
        assert_eq!(queued, 0);
        assert!(recording::start(&db, &config, &request).await.is_err());
    }
}
