#![cfg(unix)]

use piston_decompiler::{config::Config, db::Db, ghidra, knowledge, pipeline, proto};
use std::{os::unix::fs::PermissionsExt, path::Path};
use tokio_util::sync::CancellationToken;

async fn fixture(script: &str) -> (tempfile::TempDir, Db, Config) {
    let directory = tempfile::tempdir().unwrap();
    let data = directory.path().join("data");
    let binary = data.join("binaries/b");
    std::fs::create_dir_all(&binary).unwrap();
    std::fs::write(binary.join("program.bin"), b"fixture").unwrap();
    let home = directory.path().join("ghidra");
    let support = home.join("support");
    std::fs::create_dir_all(&support).unwrap();
    let executable = support.join("analyzeHeadless");
    std::fs::write(&executable, script).unwrap();
    std::fs::set_permissions(&executable, std::fs::Permissions::from_mode(0o755)).unwrap();
    let db = Db::open(&data.join("piston.db")).await.unwrap();
    sqlx::query("INSERT INTO binaries(id,name,sha256,size,architecture,format,path,budget_usd) VALUES('b','fixture','sha',7,'x86','ELF',?,1.0)")
        .bind(binary.join("program.bin").to_string_lossy().as_ref())
        .execute(&db.pool)
        .await
        .unwrap();
    sqlx::query("INSERT INTO functions(id,binary_id,address,name,size) VALUES('b:1000','b','1000','FUN_1000',10)")
        .execute(&db.pool)
        .await
        .unwrap();
    sqlx::query("INSERT INTO jobs(id,binary_id,function_id,stage,status) VALUES('job','b','b:1000','map','completed')")
        .execute(&db.pool)
        .await
        .unwrap();
    sqlx::query("INSERT INTO results(id,job_id,function_id,stage,model,prompt_hash,raw_json,proposed_name,summary,confidence,review,input_tokens,output_tokens,cost_usd,latency_ms) VALUES('result','job','b:1000','map','fixture','hash','{}','read_header','Reads the file header.',0.9,'accepted',1,1,0.0,1)")
        .execute(&db.pool)
        .await
        .unwrap();
    sqlx::query("UPDATE results SET name_review='accepted',summary_review='accepted'")
        .execute(&db.pool)
        .await
        .unwrap();
    sqlx::query("UPDATE functions SET current_result_id='result'")
        .execute(&db.pool)
        .await
        .unwrap();
    let config = Config {
        data_dir: data,
        ghidra_home: Some(home),
        ghidra_timeout_secs: 60,
        ..Default::default()
    };
    (directory, db, config)
}

fn reject() -> proto::ReviewRequest {
    proto::ReviewRequest {
        result_id: "result".into(),
        expected_revision: 0,
        field: "both".into(),
        decision: "rejected".into(),
        reason: String::new(),
    }
}
#[tokio::test]
async fn successful_writeback_is_idempotent() {
    let (_directory,db,config)=fixture("#!/bin/sh\nfor arg in \"$@\"; do prev=$last; last=$arg; done\npython3 - \"$prev\" \"$last\" <<'PYREPORT'\nimport json,sys\nitems=json.load(open(sys.argv[1]))\nfor item in items: item['status']='applied'; item['error']=''\njson.dump(items,open(sys.argv[2],'w'))\nPYREPORT\n").await;
    let preview = knowledge::preview_apply(&db, "b").await.unwrap();
    assert_eq!(preview.items.len(), 1);
    let applied = ghidra::execute_apply(&db, &config, &preview.id, None)
        .await
        .unwrap();
    assert_eq!(applied.status, "applied");
    assert!(
        ghidra::execute_apply(&db, &config, &preview.id, None)
            .await
            .is_err()
    );
    assert!(
        knowledge::preview_apply(&db, "b")
            .await
            .unwrap()
            .items
            .is_empty()
    );
    assert_eq!(
        knowledge::result(&db, "result").await.unwrap().name_review,
        "accepted"
    );
}
#[tokio::test]
async fn cancellation_blocks_review_and_retains_uncertain_operation() {
    let (_directory, db, config) = fixture("#!/bin/sh\ntouch \"$1/started\"\nsleep 300\n").await;
    let started = config.data_dir.join("binaries/b/ghidra/started");
    let preview = knowledge::preview_apply(&db, "b").await.unwrap();
    let cancel = CancellationToken::new();
    let task_cancel = cancel.clone();
    let task_db = db.clone();
    let id = preview.id.clone();
    let task = tokio::spawn(async move {
        ghidra::execute_apply(&task_db, &config, &id, Some(task_cancel)).await
    });
    for _ in 0..100 {
        if started.is_file() {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
    assert!(Path::new(&started).is_file());
    assert!(pipeline::review(&db, &reject()).await.is_err());
    cancel.cancel();
    assert!(task.await.unwrap().is_err());
    assert_eq!(
        knowledge::apply_operation(&db, &preview.id)
            .await
            .unwrap()
            .status,
        "uncertain"
    );
    db.recover().await.unwrap();
    assert!(pipeline::review(&db, &reject()).await.is_err());
}
