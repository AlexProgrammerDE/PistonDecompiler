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

#[tokio::test]
async fn mcp_negotiates_tools_and_shares_the_writer_gate() {
    let dir = tempfile::tempdir().unwrap();
    let db = Db::open(&dir.path().join("mcp.db")).await.unwrap();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let config = Arc::new(Config::default());
    let gate = Arc::new(tokio::sync::Semaphore::new(1));
    let service = Service {
        db,
        ai: Arc::new(Ai::new(config.ai.clone()).unwrap()),
        config,
        ghidra_gate: gate.clone(),
        shutdown: CancellationToken::new(),
    };
    let router = server::router(service, address).unwrap();
    let server = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
    let client = reqwest::Client::new();
    let url = format!("http://{address}/mcp");
    let initialize=client.post(&url).header("accept","application/json, text/event-stream").json(&serde_json::json!({"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"test","version":"1"}}})).send().await.unwrap();
    assert_eq!(initialize.status(), reqwest::StatusCode::OK);
    let session = initialize.headers()["mcp-session-id"]
        .to_str()
        .unwrap()
        .to_owned();
    async fn post(
        client: &reqwest::Client,
        url: &str,
        session: &str,
        value: serde_json::Value,
    ) -> serde_json::Value {
        let text = client
            .post(url)
            .header("accept", "application/json, text/event-stream")
            .header("mcp-session-id", session)
            .header("mcp-protocol-version", "2025-11-25")
            .json(&value)
            .send()
            .await
            .unwrap()
            .text()
            .await
            .unwrap();
        let data = text
            .lines()
            .filter_map(|line| line.strip_prefix("data: "))
            .find(|data| !data.is_empty())
            .unwrap_or(&text);
        serde_json::from_str(data).unwrap()
    }
    client
        .post(&url)
        .header("accept", "application/json, text/event-stream")
        .header("mcp-session-id", &session)
        .json(&serde_json::json!({"jsonrpc":"2.0","method":"notifications/initialized"}))
        .send()
        .await
        .unwrap();
    let tools = post(
        &client,
        &url,
        &session,
        serde_json::json!({"jsonrpc":"2.0","id":2,"method":"tools/list"}),
    )
    .await;
    let tools = tools["result"]["tools"].as_array().unwrap();
    assert_eq!(tools.len(), 7);
    let query = tools
        .iter()
        .find(|tool| tool["name"] == "query_program")
        .unwrap();
    assert_eq!(query["annotations"]["readOnlyHint"], true);
    let _permit = gate.acquire().await.unwrap();
    let blocked=post(&client,&url,&session,serde_json::json!({"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"query_program","arguments":{"binary_id":"missing","queries":[{"kind":"function","address":"140000000"}]}}})).await;
    assert!(blocked["error"].is_object(), "{blocked}");
    let hostile = client
        .post(&url)
        .header("origin", "https://untrusted.example")
        .header("accept", "application/json, text/event-stream")
        .json(&serde_json::json!({"jsonrpc":"2.0","id":4,"method":"tools/list"}))
        .send()
        .await
        .unwrap();
    assert_eq!(hostile.status(), reqwest::StatusCode::FORBIDDEN);
    server.abort();
}
