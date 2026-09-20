use piston_decompiler::{
    config::Config, cpp::CppPlan, db::Db, ghidra, recording, runtime::Trace, types::TypePlan,
};
use serde_json::{Value, json};

#[test]
fn cpp_layout_validation_rejects_unrepresented_bases_and_wrong_slots() {
    let mut plan: TypePlan=serde_json::from_value(json!({"definitions":[
        {"kind":"structure","name":"Base","size":8,"fields":[]},
        {"kind":"structure","name":"Derived","size":16,"fields":[{"name":"base","offset":0,"data_type":{"kind":"named","name":"Base"}}]}
    ],"cpp":{"classes":[{"name":"Derived","bases":[{"name":"Base","offset":0,"virtual_base":false}],"vptrs":[]}]}})).unwrap();
    plan.validate(8).unwrap();
    plan.cpp.classes[0].bases[0].offset = 8;
    assert!(plan.validate(8).is_err());
    plan.cpp.classes.clear();
    plan.cpp.vtables =
        serde_json::from_value(json!([{"address":"1000","table_type":"Base","targets":["2000"]}]))
            .unwrap();
    assert!(plan.validate(8).is_err());
    let mut copy = CppPlan::default();
    copy.merge(plan.cpp.clone()).unwrap();
    plan.cpp.vtables[0].targets[0] = "3000".into();
    assert!(copy.merge(plan.cpp).is_err());
}

#[test]
fn dispatch_requires_live_objects_and_matching_adjustments() {
    let mut value = json!({"version":1,"id":"dispatch","binary_sha256":"fixture","scenario":"virtual","image_base":4096,"pointer_width":8,"collector":"test","dropped_events":0,"events":[
        {"sequence":1,"thread":1,"function_rva":null,"kind":"allocation","allocation":"a","address":8192,"size":32},
        {"sequence":2,"thread":1,"function_rva":16,"kind":"virtual_dispatch","invocation":1,"allocation":"a","object_offset":16,"receiver":8208,"vtable_rva":256,"slot_offset":8,"site_rva":20,"target_rva":64},
        {"sequence":3,"thread":1,"function_rva":16,"kind":"this_adjustment","invocation":1,"allocation":"a","receiver_before":8208,"receiver_after":8192,"adjustment":-16,"target_rva":64}
    ]});
    serde_json::from_value::<Trace>(value.clone())
        .unwrap()
        .validate()
        .unwrap();
    value["events"][2]["thread"] = json!(2);
    assert!(
        serde_json::from_value::<Trace>(value.clone())
            .unwrap()
            .validate()
            .is_err()
    );
    value["events"][2]["thread"] = json!(1);
    value["events"][1]["slot_offset"] = json!(3);
    assert!(
        serde_json::from_value::<Trace>(value)
            .unwrap()
            .validate()
            .is_err()
    );
}

#[tokio::test]
#[ignore = "requires Ghidra, g++, and Frida in PISTON_TEST_PYTHON"]
async fn native_cpp_evidence_capture_and_saved_writeback() {
    let dir = tempfile::tempdir().unwrap();
    let executable = dir.path().join("dispatch");
    assert!(
        std::process::Command::new("g++")
            .args(["-O0", "-fno-inline", "-o"])
            .arg(&executable)
            .arg("fixtures/cpp/dispatch.cpp")
            .status()
            .unwrap()
            .success()
    );
    let config = Config {
        data_dir: dir.path().join("data"),
        ghidra_home: Some(
            std::env::var_os("PISTON_TEST_GHIDRA_HOME")
                .expect("Ghidra required")
                .into(),
        ),
        runtime_python: std::env::var_os("PISTON_TEST_PYTHON")
            .unwrap_or_else(|| "python3".into())
            .into(),
        ..Default::default()
    };
    std::fs::create_dir_all(&config.data_dir).unwrap();
    let db = Db::open(&config.data_dir.join("piston.db")).await.unwrap();
    let binary = db.import(&executable, &config).await.unwrap();
    if let Err(error) = ghidra::extract(&db, &config, &binary.id).await {
        panic!(
            "{error:#}\n{}",
            std::fs::read_to_string(
                config
                    .data_dir
                    .join("binaries")
                    .join(&binary.id)
                    .join("ghidra/headless.log")
            )
            .unwrap_or_default()
        );
    }
    let contexts: Vec<String> = sqlx::query_scalar("SELECT type_context FROM functions")
        .fetch_all(&db.pool)
        .await
        .unwrap();
    let contexts: Vec<Value> = contexts
        .iter()
        .map(|s| serde_json::from_str(s).unwrap())
        .collect();
    assert!(
        contexts
            .iter()
            .any(|v| !v["cpp"]["indirect_calls"].as_array().unwrap().is_empty())
    );
    assert!(
        contexts
            .iter()
            .flat_map(|v| v["cpp"]["vtables"].as_array().unwrap())
            .any(|table| table["rtti"]["bases"]
                .as_array()
                .is_some_and(|bases| bases.len() >= 2)),
        "Multiple-inheritance RTTI descriptors were not exported: {:?}",
        contexts
            .iter()
            .flat_map(|v| v["cpp"]["vtables"].as_array().unwrap())
            .map(|table| table.get("rtti"))
            .collect::<Vec<_>>()
    );
    let table = contexts
        .iter()
        .flat_map(|v| v["cpp"]["vtables"].as_array().unwrap())
        .find(|v| v["slots"].as_array().unwrap().len() >= 2)
        .unwrap()
        .clone();
    let selected: Vec<String> = sqlx::query_scalar(
        "SELECT id FROM functions WHERE skip_reason='' AND name IN ('exercise','update','state')",
    )
    .fetch_all(&db.pool)
    .await
    .unwrap();
    let id = recording::start(
        &db,
        &config,
        &piston_decompiler::proto::StartRecordingRequest {
            binary_id: binary.id.clone(),
            scenario: "C++ multiple inheritance".into(),
            function_ids: selected.clone(),
            executable: executable.display().to_string(),
            mode: "investigate".into(),
            seconds: 10,
            argument_count: 2,
            snapshot_bytes: 32,
            ..Default::default()
        },
    )
    .await
    .unwrap();
    recording::run(
        &db,
        &config,
        &id,
        tokio_util::sync::CancellationToken::new(),
    )
    .await
    .unwrap();
    let trace: Trace = serde_json::from_slice(
        &std::fs::read(recording::directory(&config, &id).join("trace.json")).unwrap(),
    )
    .unwrap();
    trace.validate().unwrap();
    let dispatches: Vec<_> = trace
        .events
        .iter()
        .filter(|e| {
            matches!(
                e.observation,
                piston_decompiler::runtime::Observation::VirtualDispatch { .. }
            )
        })
        .collect();
    assert!(
        !dispatches.is_empty(),
        "No dispatch captured: {}",
        serde_json::to_string(&trace).unwrap()
    );
    assert!(
        trace.events.iter().any(|event| matches!(
            event.observation,
            piston_decompiler::runtime::Observation::VirtualDispatch {
                object_offset: 16,
                ..
            }
        )),
        "Secondary base receiver was not captured"
    );
    assert!(
        trace.events.iter().any(|event| matches!(
            event.observation,
            piston_decompiler::runtime::Observation::ThisAdjustment {
                adjustment: -16,
                ..
            }
        )),
        "Adjustor thunk was not captured"
    );
    recording::publish(&db, &config, &id).await.unwrap();
    assert_eq!(
        recording::get(&db, &config, &id)
            .await
            .unwrap()
            .ghidra_status,
        "saved"
    );
    let slots = table["slots"].as_array().unwrap();
    let (function, context): (String, String) =
        sqlx::query_as("SELECT address,type_context FROM functions WHERE name='exercise'")
            .fetch_one(&db.pool)
            .await
            .unwrap();
    let context: Value = serde_json::from_str(&context).unwrap();
    let local = context["cpp"]["locals"]
        .as_array()
        .unwrap()
        .iter()
        .find(|local| local["type"] == "int")
        .unwrap();
    let fields:Vec<_>=slots.iter().map(|s|json!({"name":format!("slot_{}",s["offset"]),"offset":s["offset"],"data_type":{"kind":"pointer","to":{"kind":"function","return_type":{"kind":"primitive","name":"i32"},"parameters":[{"kind":"pointer","to":{"kind":"primitive","name":"void"}}]}}})).collect();
    let mut plan = json!({"definitions":[{"kind":"structure","name":"ObservedVtable","size":slots.len()*8,"fields":fields}],"signatures":[],"cpp":{"classes":[],"locals":[],"vtables":[{"address":table["address"],"table_type":"ObservedVtable","targets":slots.iter().map(|s|s["target"].clone()).collect::<Vec<_>>()}]}});
    plan["definitions"].as_array_mut().unwrap().extend([
        json!({"kind":"structure","name":"ObservedBase","size":16,"fields":[{"name":"vptr","offset":0,"data_type":{"kind":"pointer","to":{"kind":"named","name":"ObservedVtable"}}}]}),
        json!({"kind":"structure","name":"ObservedObject","size":32,"fields":[{"name":"left","offset":0,"data_type":{"kind":"named","name":"ObservedBase"}},{"name":"right","offset":16,"data_type":{"kind":"named","name":"ObservedBase"}}]}),
        json!({"kind":"enumeration","name":"ObservedState","size":4,"values":{"Alive":1,"Dead":2}}),
    ]);
    plan["cpp"]["classes"] = json!([{"name":"ObservedObject","bases":[{"name":"ObservedBase","offset":0,"virtual_base":false},{"name":"ObservedBase","offset":16,"virtual_base":false}],"vptrs":[{"offset":0,"table_type":"ObservedVtable"},{"offset":16,"table_type":"ObservedVtable"}]}]);
    plan["cpp"]["locals"] = json!([{"function":function,"storage":local["storage"],"first_use":local["first_use"],"expected_name":local["name"],"name":"remaining_health","data_type":{"kind":"primitive","name":"i32"}}]);
    let typed: TypePlan = serde_json::from_value(plan.clone()).unwrap();
    typed.validate(8).unwrap();
    let analysis = json!({"proposed_name":"observed_method","summary":"Observed virtual method.","confidence":1.0,"evidence":["fixture"],"claims":[],"parameter_types":[],"side_effects":[],"uncertainties":[],"type_plan":plan});
    sqlx::query("UPDATE jobs SET status='completed'")
        .execute(&db.pool)
        .await
        .unwrap();
    let job: String = sqlx::query_scalar("SELECT id FROM jobs WHERE function_id=? LIMIT 1")
        .bind(format!("{}:{function}", binary.id))
        .fetch_one(&db.pool)
        .await
        .unwrap();
    sqlx::query("UPDATE jobs SET status='running' WHERE id=?")
        .bind(&job)
        .execute(&db.pool)
        .await
        .unwrap();
    let ai = piston_decompiler::ai::Ai::new(Default::default()).unwrap();
    piston_decompiler::pipeline::finish(
        &db,
        &ai,
        &piston_decompiler::pipeline::Job {
            id: job,
            binary_id: binary.id.clone(),
            function_id: format!("{}:{function}", binary.id),
            stage: "map".into(),
            attempts: 1,
        },
        piston_decompiler::ai::Completion {
            analysis: serde_json::from_value(analysis).unwrap(),
            input_tokens: 1,
            output_tokens: 1,
            cost: None,
            latency_ms: 1,
            prompt_hash: "fixture".into(),
            model: "fixture".into(),
        },
    )
    .await
    .unwrap();
    let result: String = sqlx::query_scalar("SELECT current_result_id FROM functions WHERE id=?")
        .bind(format!("{}:{function}", binary.id))
        .fetch_one(&db.pool)
        .await
        .unwrap();
    let preview = piston_decompiler::types::preview(&db, &config, &result)
        .await
        .unwrap();
    piston_decompiler::types::apply(&db, &config, preview["id"].as_str().unwrap())
        .await
        .unwrap();
    // Each headless invocation reopens the saved project. An unchanged dry run proves persistence.
    sqlx::query("UPDATE results SET stale=0 WHERE id=?")
        .bind(&result)
        .execute(&db.pool)
        .await
        .unwrap();
    let again = piston_decompiler::types::preview(&db, &config, &result)
        .await
        .unwrap();
    assert_eq!(again["unchanged"], true);
    let stripped = dir.path().join("dispatch-stripped");
    std::fs::copy(&executable, &stripped).unwrap();
    assert!(
        std::process::Command::new("strip")
            .arg("--strip-all")
            .arg(&stripped)
            .status()
            .unwrap()
            .success()
    );
    let stripped_binary = db.import(&stripped, &config).await.unwrap();
    ghidra::extract(&db, &config, &stripped_binary.id)
        .await
        .unwrap();
    let stripped_contexts: Vec<String> =
        sqlx::query_scalar("SELECT type_context FROM functions WHERE binary_id=?")
            .bind(&stripped_binary.id)
            .fetch_all(&db.pool)
            .await
            .unwrap();
    assert!(stripped_contexts.iter().any(|value| {
        serde_json::from_str::<Value>(value).unwrap()["cpp"]["vtables"]
            .as_array()
            .is_some_and(|tables| !tables.is_empty())
    }));
    let selected = selected
        .iter()
        .map(|id| format!("{}:{}", stripped_binary.id, id.rsplit(':').next().unwrap()))
        .collect();
    let recording = recording::start(
        &db,
        &config,
        &piston_decompiler::proto::StartRecordingRequest {
            binary_id: stripped_binary.id.clone(),
            scenario: "Stripped C++ dispatch".into(),
            executable: stripped.display().to_string(),
            mode: "investigate".into(),
            seconds: 10,
            function_ids: selected,
            argument_count: 2,
            snapshot_bytes: 32,
            ..Default::default()
        },
    )
    .await
    .unwrap();
    recording::run(
        &db,
        &config,
        &recording,
        tokio_util::sync::CancellationToken::new(),
    )
    .await
    .unwrap();
    let trace: Trace = serde_json::from_slice(
        &std::fs::read(recording::directory(&config, &recording).join("trace.json")).unwrap(),
    )
    .unwrap();
    trace.validate().unwrap();
    assert!(trace.events.iter().any(|event| matches!(
        event.observation,
        piston_decompiler::runtime::Observation::VirtualDispatch {
            object_offset: 16,
            ..
        }
    )));
    assert!(trace.events.iter().any(|event| matches!(
        event.observation,
        piston_decompiler::runtime::Observation::ThisAdjustment {
            adjustment: -16,
            ..
        }
    )));
}
