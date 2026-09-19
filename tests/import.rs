use piston_decompiler::{config::Config, db::Db};
use sha2::{Digest, Sha256};
use std::{io::Read, path::Path};

fn sha256(path: &Path) -> String {
    let mut source = std::fs::File::open(path).unwrap();
    let mut digest = Sha256::new();
    let mut buffer = [0u8; 32768];
    loop {
        let count = source.read(&mut buffer).unwrap();
        if count == 0 {
            break;
        }
        digest.update(&buffer[..count]);
    }
    hex::encode(digest.finalize())
}

#[tokio::test]
async fn concurrent_imports_share_one_durable_snapshot() {
    let dir = tempfile::tempdir().unwrap();
    let config = Config {
        data_dir: dir.path().into(),
        ..Default::default()
    };
    let db = Db::open(&dir.path().join("test.db")).await.unwrap();
    let source = dir.path().join("source");
    std::fs::copy(std::env::current_exe().unwrap(), &source).unwrap();
    let expected = sha256(&source);
    let imports = futures::future::join_all((0..4).map(|_| db.import(&source, &config))).await;
    let imports: Vec<_> = imports.into_iter().map(Result::unwrap).collect();
    assert!(imports.iter().all(|b| b.id == imports[0].id));
    assert_eq!(db.binaries().await.unwrap().len(), 1);
    assert_eq!(
        std::fs::read_dir(dir.path().join("binaries"))
            .unwrap()
            .count(),
        1
    );
    let snapshot_path: String = sqlx::query_scalar("SELECT path FROM binaries WHERE id=?")
        .bind(&imports[0].id)
        .fetch_one(&db.pool)
        .await
        .unwrap();
    let snapshot = Path::new(&snapshot_path);
    assert_eq!(
        snapshot
            .parent()
            .unwrap()
            .file_name()
            .unwrap()
            .to_str()
            .unwrap(),
        imports[0].id
    );
    assert_eq!(sha256(snapshot), expected);
    assert_eq!(imports[0].sha256, expected);
    assert_eq!(imports[0].size, std::fs::metadata(snapshot).unwrap().len());
    assert!(
        std::fs::metadata(snapshot)
            .unwrap()
            .permissions()
            .readonly()
    );
    std::fs::write(&source, "source was replaced").unwrap();
    assert_eq!(sha256(snapshot), expected);
    let events: i64 = sqlx::query_scalar("SELECT count(*) FROM events")
        .fetch_one(&db.pool)
        .await
        .unwrap();
    assert_eq!(events, 1);
}

#[tokio::test]
async fn failed_imports_remove_uncommitted_snapshots() {
    let dir = tempfile::tempdir().unwrap();
    let config = Config {
        data_dir: dir.path().into(),
        ..Default::default()
    };
    let db = Db::open(&dir.path().join("test.db")).await.unwrap();
    let source = dir.path().join("invalid");
    std::fs::write(&source, b"not an executable").unwrap();
    assert!(db.import(&source, &config).await.is_err());
    assert!(db.import(dir.path(), &config).await.is_err());
    assert_eq!(
        std::fs::read_dir(dir.path().join("binaries"))
            .unwrap()
            .count(),
        0
    );
    sqlx::query("CREATE TRIGGER reject_import BEFORE INSERT ON binaries BEGIN SELECT RAISE(ABORT, 'test failure'); END").execute(&db.pool).await.unwrap();
    assert!(
        db.import(&std::env::current_exe().unwrap(), &config)
            .await
            .is_err()
    );
    assert!(db.binaries().await.unwrap().is_empty());
    assert_eq!(
        std::fs::read_dir(dir.path().join("binaries"))
            .unwrap()
            .count(),
        0
    );
}
