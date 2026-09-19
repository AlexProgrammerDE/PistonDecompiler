#![cfg(unix)]

use piston_decompiler::{config::Config, db::Db, ghidra, pipeline};
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
    let config = Config {
        data_dir: data,
        ghidra_home: Some(home),
        ghidra_timeout_secs: 60,
        ..Default::default()
    };
    (directory, db, config)
}

async fn review(db: &Db) -> String {
    sqlx::query_scalar("SELECT review FROM results WHERE id='result'")
        .fetch_one(&db.pool)
        .await
        .unwrap()
}

#[tokio::test]
async fn successful_writeback_is_idempotent() {
    let (_directory, db, config) = fixture("#!/bin/sh\nexit 0\n").await;
    assert_eq!(ghidra::apply(&db, &config, "b").await.unwrap(), 1);
    assert_eq!(review(&db).await, "applied");
    assert_eq!(ghidra::apply(&db, &config, "b").await.unwrap(), 0);
    assert!(pipeline::review(&db, "b:1000", false).await.is_err());
}

#[tokio::test]
async fn cancellation_blocks_concurrent_review_and_restores_acceptance() {
    let (_directory, db, config) = fixture("#!/bin/sh\ntouch \"$1/started\"\nsleep 300\n").await;
    let started = config.data_dir.join("binaries/b/ghidra/started");
    let cancel = CancellationToken::new();
    let task_db = db.clone();
    let task_cancel = cancel.clone();
    let task = tokio::spawn(async move {
        ghidra::apply_cancellable(&task_db, &config, "b", task_cancel).await
    });
    for _ in 0..100 {
        if started.is_file() {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
    assert!(Path::new(&started).is_file());
    assert_eq!(review(&db).await, "applying");
    assert!(pipeline::review(&db, "b:1000", false).await.is_err());
    cancel.cancel();
    assert!(task.await.unwrap().is_err());
    assert_eq!(review(&db).await, "accepted");

    sqlx::query("UPDATE results SET review='applying' WHERE id='result'")
        .execute(&db.pool)
        .await
        .unwrap();
    db.recover().await.unwrap();
    assert_eq!(review(&db).await, "accepted");
}
