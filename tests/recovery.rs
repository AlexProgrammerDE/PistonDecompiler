use axum::{Json, Router, routing::post};
use piston_decompiler::{
    ai::Ai,
    config::{AiConfig, Config},
    db::Db,
    ghidra, recovery,
};
use serde_json::json;
use std::sync::{Arc, Mutex};

#[tokio::test]
async fn recovery_analyzes_callees_before_callers_and_pins_each_component() {
    let dir = tempfile::tempdir().unwrap();
    let db = Db::open(&dir.path().join("db")).await.unwrap();
    sqlx::query("INSERT INTO binaries(id,name,sha256,size,architecture,format,path,budget_usd) VALUES('b','fixture','sha',10,'x86_64','ELF','unused',10)").execute(&db.pool).await.unwrap();
    let path = dir.path().join("export.jsonl");
    std::fs::write(&path,[json!({"address":"1000","name":"root","size":16,"pseudocode":"return child();","callees":["1010"]}),json!({"address":"1010","name":"child","size":16,"pseudocode":"return 1;"})].map(|v|v.to_string()).join("\n")).unwrap();
    ghidra::import_export(&db, "b", &path).await.unwrap();
    let seen = Arc::new(Mutex::new(Vec::new()));
    let requests = seen.clone();
    let app=Router::new().route("/chat/completions",post(move |Json(body):Json<serde_json::Value>| {let requests=requests.clone();async move {
        let user=body["messages"].as_array().unwrap().iter().find(|m|m["role"]=="user").unwrap();
        let text=user["content"].as_str().unwrap_or_else(||user["content"][0]["text"].as_str().unwrap());
        let context:serde_json::Value=serde_json::from_str(text).unwrap();
        requests.lock().unwrap().push(context["address"].as_str().unwrap().to_owned());
        let analysis=json!({"proposed_name":"read_value","summary":"Returns a value.","confidence":0.9,"evidence":["return"],"claims":[{"text":"Returns a value.","references":[{"artifact_id":context["evidence"][0]["artifact_id"],"start_line":1,"end_line":1}]}],"parameter_types":[],"side_effects":[],"uncertainties":[],"type_plan":{"definitions":[],"signatures":[]}});
        Json(json!({"id":"fixture","object":"chat.completion","created":1,"model":"fixture","choices":[{"index":0,"finish_reason":"stop","message":{"role":"assistant","content":analysis.to_string()}}],"usage":{"prompt_tokens":100,"completion_tokens":100,"total_tokens":200}}))
    }}));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    let ai = Ai::new(AiConfig {
        model: "fixture".into(),
        base_url: format!("http://{address}"),
        api_key_env: "USER".into(),
        input_usd_per_million: 1.0,
        output_usd_per_million: 1.0,
        ..Default::default()
    })
    .unwrap();
    recovery::run(&db, &Config::default(), &ai, "b", 3, false)
        .await
        .unwrap();
    assert_eq!(*seen.lock().unwrap(), vec!["1010", "1000"]);
    let stable: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM recovery_iterations WHERE status='stable'")
            .fetch_one(&db.pool)
            .await
            .unwrap();
    assert_eq!(stable, 2);
    assert!(db.overview("b").await.unwrap().paused);
    sqlx::query("INSERT INTO edges(caller,callee) VALUES('b:1010','b:1000')")
        .execute(&db.pool)
        .await
        .unwrap();
    let mut tx = db.pool.begin().await.unwrap();
    piston_decompiler::graph::rebuild(&mut tx, "b")
        .await
        .unwrap();
    tx.commit().await.unwrap();
    recovery::run(&db, &Config::default(), &ai, "b", 3, false)
        .await
        .unwrap();
    let stale:i64=sqlx::query_scalar("SELECT COUNT(*) FROM functions f JOIN results r ON r.id=f.current_result_id WHERE r.stale=1").fetch_one(&db.pool).await.unwrap();
    assert_eq!(stale, 0);
    server.abort();
}

#[tokio::test]
#[ignore = "requires PISTON_TEST_GHIDRA_HOME, a JDK, and cc"]
async fn real_ghidra_recovery_applies_types_then_converges_with_fresh_evidence() {
    use piston_decompiler::config::DecisionConfig;
    let directory = tempfile::tempdir().unwrap();
    let source = directory.path().join("fixture.c");
    let binary = directory.path().join("fixture");
    std::fs::write(&source,"struct Player { int health; int armor; }; __attribute__((noinline)) int damage(struct Player *p,int n){p->health-=n;return p->health;} int main(void){struct Player p={100,10};return damage(&p,1);}").unwrap();
    assert!(
        std::process::Command::new("cc")
            .args(["-O0", "-fno-inline", "-o"])
            .arg(&binary)
            .arg(&source)
            .status()
            .unwrap()
            .success()
    );
    let mut config = Config {
        ghidra_gui: std::env::var("PISTON_TEST_GHIDRA_DESKTOP").as_deref() == Ok("1"),
        data_dir: directory.path().join("data"),
        ghidra_home: Some(
            std::env::var_os("PISTON_TEST_GHIDRA_HOME")
                .expect("Set PISTON_TEST_GHIDRA_HOME")
                .into(),
        ),
        ..Default::default()
    };
    std::fs::create_dir_all(&config.data_dir).unwrap();
    let db = Db::open(&config.data_dir.join("piston.db")).await.unwrap();
    let b = db.import(&binary, &config).await.unwrap();
    ghidra::extract(&db, &config, &b.id).await.unwrap();
    struct DesktopGuard(Option<u64>);
    impl Drop for DesktopGuard {
        fn drop(&mut self) {
            if let Some(pid) = self.0 {
                let _ = std::process::Command::new("kill")
                    .args(["-TERM", &pid.to_string()])
                    .status();
            }
        }
    }
    let mut desktop = DesktopGuard(if config.ghidra_gui {
        let state: serde_json::Value = serde_json::from_slice(
            &std::fs::read(
                config
                    .data_dir
                    .join("binaries")
                    .join(&b.id)
                    .join("desktop/session.json"),
            )
            .unwrap(),
        )
        .unwrap();
        assert_eq!(state["ready"], true);
        state["pid"].as_u64()
    } else {
        None
    });
    let address: String = sqlx::query_scalar("SELECT address FROM functions WHERE name='damage'")
        .fetch_one(&db.pool)
        .await
        .unwrap();
    let plans = Arc::new(Mutex::new(Vec::new()));
    let observed = plans.clone();
    let model = move |Json(body): Json<serde_json::Value>| {
        let address = address.clone();
        let observed = observed.clone();
        async move {
            let user = body["messages"]
                .as_array()
                .unwrap()
                .iter()
                .find(|m| m["role"] == "user")
                .unwrap();
            let text = user["content"]
                .as_str()
                .unwrap_or_else(|| user["content"][0]["text"].as_str().unwrap());
            let context: serde_json::Value = serde_json::from_str(text).unwrap();
            let plan = if context["address"] == address {
                observed.lock().unwrap().push(text.to_owned());
                json!({"definitions":[{"kind":"structure","name":"RecoveredPlayer","size":8,"fields":[{"name":"health","offset":0,"data_type":{"kind":"primitive","name":"i32"}},{"name":"armor","offset":4,"data_type":{"kind":"primitive","name":"i32"}}]}],"signatures":[{"address":address,"name":"take_damage","namespace":["Player"],"return_type":{"kind":"primitive","name":"i32"},"parameters":[{"name":"player","data_type":{"kind":"pointer","to":{"kind":"named","name":"RecoveredPlayer"}}},{"name":"amount","data_type":{"kind":"primitive","name":"i32"}}],"calling_convention":"","variadic":false}]})
            } else {
                json!({"definitions":[],"signatures":[]})
            };
            let analysis = json!({"proposed_name":"read_value","summary":"Returns a value.","confidence":0.99,"evidence":["fixture"],"claims":[{"text":"Fixture interpretation.","references":[{"artifact_id":context["evidence"][0]["artifact_id"],"start_line":1,"end_line":1}]}],"parameter_types":[],"side_effects":[],"uncertainties":[],"type_plan":plan});
            Json(
                json!({"id":"fixture","object":"chat.completion","created":1,"model":"fixture","choices":[{"index":0,"finish_reason":"stop","message":{"role":"assistant","content":analysis.to_string()}}],"usage":{"prompt_tokens":100,"completion_tokens":100,"total_tokens":200}}),
            )
        }
    };
    let decisions = |Json(body): Json<serde_json::Value>| async move {
        let answers:serde_json::Map<String,serde_json::Value>=body["questions"].as_object().unwrap().iter().map(|(name,q)| {
            let choice=match name.as_str(){"role"=>"computation","evidence"=>"sufficient","complexity"=>"routine",_=>"supported"};
            let probabilities:serde_json::Map<String,serde_json::Value>=q["criteria"].as_object().unwrap().keys().map(|key|(key.clone(),json!(if key==choice{1.0}else{0.0}))).collect();
            (name.clone(),json!({"type":"choice","choice":choice,"confidence":1.0,"probabilities":probabilities}))
        }).collect();
        Json(
            json!({"model":"fixture","answers":answers,"usage":{"input_tokens":100,"output_tokens":10,"cost":0.0000042}}),
        )
    };
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let endpoint = format!("http://{}", listener.local_addr().unwrap());
    let app = Router::new()
        .route("/chat/completions", post(model))
        .route("/decisions", post(decisions));
    let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    config.ai = AiConfig {
        base_url: endpoint.clone(),
        model: "fixture".into(),
        api_key_env: "USER".into(),
        input_usd_per_million: 1.0,
        output_usd_per_million: 1.0,
        decisions: Some(DecisionConfig {
            endpoint: format!("{endpoint}/decisions"),
            ..Default::default()
        }),
        ..Default::default()
    };
    let ai = Ai::new(config.ai.clone()).unwrap();
    let result = recovery::run(&db, &config, &ai, &b.id, 3, true).await;
    if result.is_err() && config.ghidra_gui {
        let log = std::fs::read_to_string(
            config
                .data_dir
                .join("binaries")
                .join(&b.id)
                .join("desktop/desktop.log"),
        )
        .unwrap();
        eprintln!(
            "{}",
            log.lines()
                .rev()
                .take(60)
                .collect::<Vec<_>>()
                .into_iter()
                .rev()
                .collect::<Vec<_>>()
                .join("\n")
        );
    }
    result.unwrap();
    assert_eq!(plans.lock().unwrap().len(), 2);
    let code: String =
        sqlx::query_scalar("SELECT pseudocode FROM functions WHERE name='take_damage'")
            .fetch_one(&db.pool)
            .await
            .unwrap();
    assert!(code.contains("player->health"));
    let applied: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM type_operations WHERE status='applied'")
            .fetch_one(&db.pool)
            .await
            .unwrap();
    assert_eq!(applied, 1);
    if config.ghidra_gui {
        let pid = desktop.0.take().unwrap();
        std::process::Command::new("kill")
            .args(["-TERM", &pid.to_string()])
            .status()
            .unwrap();
        for _ in 0..100 {
            if !std::path::Path::new("/proc").join(pid.to_string()).exists() {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        }
        assert!(!std::path::Path::new("/proc").join(pid.to_string()).exists());
        // A new GUI process must read the saved project, without importing or replaying plans.
        piston_decompiler::desktop::open(&config, &b.id)
            .await
            .unwrap();
        let state: serde_json::Value = serde_json::from_slice(
            &std::fs::read(
                config
                    .data_dir
                    .join("binaries")
                    .join(&b.id)
                    .join("desktop/session.json"),
            )
            .unwrap(),
        )
        .unwrap();
        desktop.0 = state["pid"].as_u64();
        assert_ne!(desktop.0, Some(pid));
        ghidra::refresh(&db, &config, &b.id).await.unwrap();
        let reopened: String =
            sqlx::query_scalar("SELECT pseudocode FROM functions WHERE name='take_damage'")
                .fetch_one(&db.pool)
                .await
                .unwrap();
        assert!(reopened.contains("player->health"));
        let context: String =
            sqlx::query_scalar("SELECT type_context FROM functions WHERE name='take_damage'")
                .fetch_one(&db.pool)
                .await
                .unwrap();
        let context: serde_json::Value = serde_json::from_str(&context).unwrap();
        assert_eq!(context["namespace"], "Player");
        let count: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM type_operations WHERE status='applied'")
                .fetch_one(&db.pool)
                .await
                .unwrap();
        assert_eq!(count, 1);
    }
    server.abort();
}
