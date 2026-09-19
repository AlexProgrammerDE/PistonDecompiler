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
async fn browser_boundary_protects_rpc_and_static_content() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(
        dir.path().join("index.html"),
        "<!doctype html><title>Piston</title>",
    )
    .unwrap();
    let db = Db::open(&dir.path().join("test.db")).await.unwrap();
    let config = Config {
        web_dir: dir.path().into(),
        browser_origins: vec!["http://localhost:3000".into()],
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

    for path in ["/healthz", "/", "/piston.v1.PistonService/ListBinaries"] {
        for (host, origin, site, permitted) in [
            ("127.0.0.1:7070", None, None, true),
            (
                "localhost:7070",
                Some("http://localhost:7070"),
                Some("same-origin"),
                true,
            ),
            (
                "127.0.0.1:7070",
                Some("http://localhost:3000"),
                Some("same-site"),
                true,
            ),
            ("attacker.example:7070", None, None, false),
            ("localhost:9999", None, None, false),
            (
                "localhost:7070",
                Some("https://attacker.example"),
                Some("cross-site"),
                false,
            ),
            ("localhost:7070", Some("null"), None, false),
            (
                "localhost:7070",
                Some("http://localhost:4000"),
                Some("same-site"),
                false,
            ),
            ("localhost:7070", None, Some("cross-site"), false),
            ("localhost:7070", None, Some("same-site"), false),
        ] {
            let mut request = Request::builder().uri(path).header("host", host);
            if let Some(origin) = origin {
                request = request.header("origin", origin);
            }
            if let Some(site) = site {
                request = request.header("sec-fetch-site", site);
            }
            let rpc = path.starts_with("/piston.");
            if rpc {
                request = request
                    .method("POST")
                    .header("content-type", "application/grpc-web+proto");
            }
            let body = if rpc {
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
                if permitted {
                    if path == "/healthz" {
                        StatusCode::NO_CONTENT
                    } else {
                        StatusCode::OK
                    }
                } else {
                    StatusCode::FORBIDDEN
                },
                "{path} {host} {origin:?} {site:?}"
            );
            if rpc && permitted {
                assert_eq!(
                    response.headers()["content-type"],
                    "application/grpc-web+proto"
                );
                let body = axum::body::to_bytes(response.into_body(), 1024)
                    .await
                    .unwrap();
                assert!(!body.is_empty());
            }
        }
    }
    for request in [
        Request::builder().uri("/").body(Body::empty()).unwrap(),
        Request::builder()
            .uri("/")
            .header("host", "localhost:7070")
            .header("host", "attacker.example")
            .body(Body::empty())
            .unwrap(),
        Request::builder()
            .uri("/")
            .header("host", "localhost:7070")
            .header("origin", "http://localhost:7070")
            .header("origin", "https://attacker.example")
            .body(Body::empty())
            .unwrap(),
        Request::builder()
            .uri("http://attacker.example/")
            .header("host", "localhost:7070")
            .body(Body::empty())
            .unwrap(),
    ] {
        assert_eq!(
            app.clone().oneshot(request).await.unwrap().status(),
            StatusCode::FORBIDDEN
        );
    }
}
