use piston_decompiler::{db::Db, ghidra, progress};

#[tokio::test]
async fn reports_scope_runs_and_suppress_paused_estimates() {
    let dir = tempfile::tempdir().unwrap();
    let db = Db::open(&dir.path().join("db")).await.unwrap();
    sqlx::query("INSERT INTO binaries(id,name,sha256,size,architecture,format,path,budget_usd) VALUES('b','fixture','sha',10,'x86_64','ELF','unused',1)").execute(&db.pool).await.unwrap();
    let export = dir.path().join("export.jsonl");
    std::fs::write(
        &export,
        r#"{"address":"1000","name":"root","size":16,"pseudocode":"return 1;"}"#,
    )
    .unwrap();
    ghidra::import_export(&db, "b", &export).await.unwrap();
    sqlx::query("UPDATE jobs SET status='running'")
        .execute(&db.pool)
        .await
        .unwrap();
    let started: Option<i64> = sqlx::query_scalar("SELECT started_at FROM jobs LIMIT 1")
        .fetch_one(&db.pool)
        .await
        .unwrap();
    assert!(started.is_some());
    sqlx::query("UPDATE jobs SET status='completed'")
        .execute(&db.pool)
        .await
        .unwrap();
    let finished: Option<i64> = sqlx::query_scalar("SELECT finished_at FROM jobs LIMIT 1")
        .fetch_one(&db.pool)
        .await
        .unwrap();
    assert!(finished >= started);
    sqlx::query("UPDATE jobs SET status='queued'")
        .execute(&db.pool)
        .await
        .unwrap();
    sqlx::query("UPDATE jobs SET status='running'")
        .execute(&db.pool)
        .await
        .unwrap();
    let cleared: Option<i64> = sqlx::query_scalar("SELECT finished_at FROM jobs LIMIT 1")
        .fetch_one(&db.pool)
        .await
        .unwrap();
    assert!(cleared.is_none());
    for n in 0..3 {
        sqlx::query("INSERT INTO jobs(id,binary_id,function_id,stage,status,run_id,started_at,finished_at) SELECT ?,binary_id,function_id,stage,'completed',?,unixepoch()-30,unixepoch()-5 FROM jobs LIMIT 1")
            .bind(format!("sample-{n}")).bind(format!("run-{n}")).execute(&db.pool).await.unwrap();
    }
    sqlx::query("UPDATE binaries SET paused=0 WHERE id='b'")
        .execute(&db.pool)
        .await
        .unwrap();
    let measured = progress::reports(&db, "b").await.unwrap();
    assert_eq!(measured[0].completed, 3);
    assert_eq!(measured[0].total, 4);
    assert!(measured[0].eta_seconds >= 10);
    sqlx::query("UPDATE binaries SET paused=1 WHERE id='b'")
        .execute(&db.pool)
        .await
        .unwrap();
    let reports = progress::reports(&db, "b").await.unwrap();
    assert!(!reports.is_empty());
    assert!(reports.iter().all(|r| r.eta_seconds < 0));
    sqlx::query("UPDATE binaries SET active_run_id='other' WHERE id='b'")
        .execute(&db.pool)
        .await
        .unwrap();
    assert!(progress::reports(&db, "b").await.unwrap().is_empty());
}
