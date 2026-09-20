use crate::{config::Config, db::Db, ghidra};
use serde_json::{Value, json};

#[tokio::test]
#[ignore = "requires PISTON_TEST_GHIDRA_HOME, a JDK, and cc"]
async fn native_partial_layouts_accumulate_and_trials_leave_saved_program_untouched() {
    let dir = tempfile::tempdir().unwrap();
    let source = dir.path().join("fixture.c");
    let binary = dir.path().join("fixture");
    std::fs::write(&source, "struct Payload { long a,b,c; }; __attribute__((noinline)) long first(struct Payload *p){return p->a;} __attribute__((noinline)) long last(struct Payload *p){return p->c;} __attribute__((noinline)) long relay(struct Payload *p){return p->a+last(p);} int main(int argc,char **argv){struct Payload p={argc,2,3};return relay(&p);}").unwrap();
    assert!(
        std::process::Command::new("cc")
            .args(["-O1", "-fno-inline", "-fno-optimize-sibling-calls", "-o"])
            .arg(&binary)
            .arg(source)
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
    let functions: Vec<(String, String, String)> =
        sqlx::query_as("SELECT id,name,type_context FROM functions WHERE binary_id=?")
            .bind(&b.id)
            .fetch_all(&db.pool)
            .await
            .unwrap();
    let first = functions
        .iter()
        .find(|(_, name, _)| name == "first")
        .unwrap();
    let last = functions
        .iter()
        .find(|(_, name, _)| name == "last")
        .unwrap();
    let relay = functions
        .iter()
        .find(|(_, name, _)| name == "relay")
        .unwrap();
    let context: Value = serde_json::from_str(&last.2).unwrap();
    assert!(
        context["objects"]["accesses"]
            .as_array()
            .unwrap()
            .iter()
            .any(|access| access["offset"] == 16 && access["width"] == 8)
    );
    let field = |name: &str, offset| json!({"name":name,"offset":offset,"data_type":{"kind":"primitive","name":"i64"}});
    let make_plan = |size, fields: Value| json!({"definitions":[{"kind":"structure","name":"RecoveredPayload","size":size,"extent":{"kind":"minimum"},"fields":fields}],"signatures":[]});
    let call = |mode: &'static str, id: &'static str, plan: Value, expected: Value| {
        let dir = &dir;
        let config = &config;
        let b = &b;
        async move {
            let input = dir.path().join(format!("{id}-{mode}-input.json"));
            let report = dir.path().join(format!("{id}-{mode}-report.json"));
            let expect = dir.path().join(format!("{id}-{mode}-expected.json"));
            std::fs::write(&input, plan.to_string()).unwrap();
            std::fs::write(&expect, expected.to_string()).unwrap();
            ghidra::headless(
                config,
                &b.id,
                &[
                    "-process".into(),
                    "program.bin".into(),
                    "-noanalysis".into(),
                    "-postScript".into(),
                    "PistonTypes.java".into(),
                    mode.into(),
                    id.into(),
                    input.to_string_lossy().into_owned(),
                    expect.to_string_lossy().into_owned(),
                    report.to_string_lossy().into_owned(),
                ],
                None,
            )
            .await
            .unwrap();
            serde_json::from_slice::<Value>(&std::fs::read(report).unwrap()).unwrap()
        }
    };
    let mut prefix = make_plan(8, json!([field("first", 0)]));
    prefix["signatures"] = json!([{"address":last.0.split_once(':').unwrap().1,"name":"last","namespace":[],"return_type":{"kind":"primitive","name":"i64"},"parameters":[{"name":"object","data_type":{"kind":"pointer","to":{"kind":"named","name":"RecoveredPayload"}}}],"calling_convention":"","variadic":false}]);
    let preview = call("preview", "prefix", prefix.clone(), Value::Null).await;
    assert_eq!(preview["status"], "validated");
    let repeated = call("preview", "prefix", prefix.clone(), Value::Null).await;
    assert_eq!(preview["expected"], repeated["expected"]);
    assert!(repeated["expected"]["definitions"]["RecoveredPayload"].is_null());
    assert_eq!(
        call(
            "apply",
            "prefix",
            prefix.clone(),
            preview["expected"].clone()
        )
        .await["status"],
        "applied"
    );
    let tail = make_plan(24, json!([field("last", 16)]));
    let preview = call("preview", "tail", tail.clone(), Value::Null).await;
    assert_eq!(preview["status"], "validated");
    let applied = call("apply", "tail", tail, preview["expected"].clone()).await;
    let layout = &applied["actual"]["definitions"]["RecoveredPayload"];
    assert_eq!(layout["size"], 24);
    assert_eq!(layout["fields"].as_array().unwrap().len(), 2);
    ghidra::refresh(&db, &config, &b.id).await.unwrap();
    let related = crate::objects::related_functions(&db, &last.0)
        .await
        .unwrap();
    assert!(related.contains(&relay.0));
    // Matching field offsets in another function do not establish identity.
    assert!(!related.contains(&first.0));
    let narrower = call("preview", "narrow", prefix, Value::Null).await;
    assert_eq!(narrower["status"], "validated");
    assert_eq!(narrower["unchanged"], true);
    let conflict = call(
        "preview",
        "overlap",
        make_plan(24, json!([field("overlap", 4)])),
        Value::Null,
    )
    .await;
    assert_eq!(conflict["status"], "rejected");
    let final_state = call(
        "preview",
        "final",
        make_plan(24, json!([field("last", 16)])),
        Value::Null,
    )
    .await;
    assert_eq!(
        final_state["expected"]["definitions"]["RecoveredPayload"],
        *layout
    );
}
