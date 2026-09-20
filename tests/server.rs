use axum::{
    body::Body,
    http::{Request, StatusCode},
};
use piston_decompiler::{
    ai::Ai,
    config::Config,
    db::Db,
    server::{self, Service},
};
use std::sync::Arc;
use tokio_util::sync::CancellationToken;
use tower::ServiceExt;

#[tokio::test]
async fn browser_metadata_does_not_block_static_or_rpc_requests() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(
        dir.path().join("index.html"),
        "<!doctype html><title>Piston</title>",
    )
    .unwrap();
    let db = Db::open(&dir.path().join("test.db")).await.unwrap();
    let config = Config {
        web_dir: dir.path().into(),
        ..Default::default()
    };
    let app = server::router(
        Service {
            db,
            ai: Arc::new(Ai::new(config.ai.clone()).unwrap()),
            config: Arc::new(config),
            ghidra_gate: Arc::new(tokio::sync::Semaphore::new(1)),
            shutdown: CancellationToken::new(),
        },
        "127.0.0.1:7070".parse().unwrap(),
    )
    .unwrap();
    for path in ["/", "/healthz", "/piston.v1.PistonService/ListBinaries"] {
        for origin in [None, Some("null"), Some("https://browser.example")] {
            let rpc = path.starts_with("/piston.");
            let mut request = Request::builder()
                .uri(path)
                .header("host", "proxy.example:9000")
                .header("sec-fetch-site", "cross-site");
            if let Some(origin) = origin {
                request = request.header("origin", origin);
            }
            let body = if rpc {
                request = request
                    .method("POST")
                    .header("content-type", "application/grpc-web+proto");
                Body::from(vec![0u8; 5])
            } else {
                Body::empty()
            };
            let response = app
                .clone()
                .oneshot(request.body(body).unwrap())
                .await
                .unwrap();
            assert_eq!(
                response.status(),
                if path == "/healthz" {
                    StatusCode::NO_CONTENT
                } else {
                    StatusCode::OK
                }
            );
            assert_eq!(response.headers()["x-content-type-options"], "nosniff");
            if rpc {
                assert_eq!(
                    response.headers()["content-type"],
                    "application/grpc-web+proto"
                );
            }
        }
    }
}

#[tokio::test]
async fn event_stream_replays_only_events_after_cursor() {
    use piston_decompiler::{
        ai::Ai,
        config::Config,
        db::Db,
        server::{self, Service},
    };
    use std::sync::Arc;
    use tokio_util::sync::CancellationToken;
    let directory = tempfile::tempdir().unwrap();
    let db = Db::open(&directory.path().join("events.db")).await.unwrap();
    sqlx::query("INSERT INTO binaries(id,name,sha256,size,architecture,format,path) VALUES('b','test','hash',1,'x86','ELF','unused')").execute(&db.pool).await.unwrap();
    db.event("b", "info", "First operation").await.unwrap();
    let cursor: i64 = sqlx::query_scalar("SELECT MAX(id) FROM events")
        .fetch_one(&db.pool)
        .await
        .unwrap();
    db.event("b", "info", "Second operation").await.unwrap();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let config = Arc::new(Config::default());
    let cancel = CancellationToken::new();
    let service = Service {
        db,
        ai: Arc::new(Ai::new(config.ai.clone()).unwrap()),
        config,
        ghidra_gate: Arc::new(tokio::sync::Semaphore::new(1)),
        shutdown: cancel.clone(),
    };
    let router = server::router(service, address).unwrap();
    let task = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
    let mut response = reqwest::Client::new()
        .get(format!("http://{address}/events/b"))
        .header("last-event-id", cursor)
        .send()
        .await
        .unwrap();
    assert_eq!(response.headers()["content-type"], "text/event-stream");
    let chunk = tokio::time::timeout(std::time::Duration::from_secs(3), response.chunk())
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    let text = String::from_utf8(chunk.to_vec()).unwrap();
    let payload = text
        .lines()
        .find_map(|line| line.strip_prefix("data: "))
        .unwrap();
    let events: Vec<piston_decompiler::proto::Event> = serde_json::from_str(payload).unwrap();
    assert_eq!(events.len(), 1);
    assert!(events[0].id > cursor);
    cancel.cancel();
    task.abort();
}
