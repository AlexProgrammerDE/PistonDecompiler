//! Shared layout context from binary SSA argument flow, never reference source.
use crate::db::Db;
use anyhow::Result;
use serde_json::Value;
use sqlx::Row;
use std::collections::{BTreeMap, BTreeSet, VecDeque};

type Node = (String, u64);

/// Zero-offset argument flow shares a layout. Nonzero offsets denote subobjects
/// and remain evidence for the model, but never unify the enclosing objects.
fn related(contexts: &[(String, Value)], root: &str) -> BTreeSet<String> {
    let mut graph: BTreeMap<Node, BTreeSet<Node>> = BTreeMap::new();
    let mut types: BTreeMap<String, Vec<Node>> = BTreeMap::new();
    let addresses: BTreeMap<_, _> = contexts
        .iter()
        .map(|(id, _)| {
            (
                id.split_once(':')
                    .map_or(id.as_str(), |(_, address)| address),
                id,
            )
        })
        .collect();
    for (id, context) in contexts {
        if let Some(parameters) = context["objects"]["parameters"].as_array() {
            for parameter in parameters {
                let Some(index) = parameter["index"].as_u64() else {
                    continue;
                };
                let node = (id.clone(), index);
                graph.entry(node.clone()).or_default();
                if let Some(name) = parameter["object_type"].as_str().filter(|s| !s.is_empty()) {
                    types.entry(name.to_owned()).or_default().push(node);
                }
            }
        }
    }
    let connect = |graph: &mut BTreeMap<Node, BTreeSet<Node>>, a: Node, b: Node| {
        if graph.contains_key(&a) && graph.contains_key(&b) {
            graph.entry(a.clone()).or_default().insert(b.clone());
            graph.entry(b).or_default().insert(a);
        }
    };
    for (id, context) in contexts {
        if let Some(flows) = context["objects"]["flows"].as_array() {
            for flow in flows {
                if flow["offset"].as_i64() != Some(0) {
                    continue;
                }
                if let (Some(index), Some(target), Some(parameter)) = (
                    flow["parameter"].as_u64(),
                    flow["target"].as_str().and_then(|a| addresses.get(a)),
                    flow["target_parameter"].as_u64(),
                ) {
                    connect(
                        &mut graph,
                        (id.clone(), index),
                        ((*target).clone(), parameter),
                    );
                }
            }
        }
    }
    for nodes in types.values() {
        for pair in nodes.windows(2) {
            connect(&mut graph, pair[0].clone(), pair[1].clone());
        }
    }
    let mut queue: VecDeque<_> = graph.keys().filter(|(id, _)| id == root).cloned().collect();
    let mut visited = BTreeSet::new();
    while let Some(node) = queue.pop_front() {
        if !visited.insert(node.clone()) {
            continue;
        }
        if visited.len() >= 4096 {
            break;
        }
        if let Some(next) = graph.get(&node) {
            queue.extend(next.iter().filter(|n| !visited.contains(*n)).cloned());
        }
    }
    visited
        .into_iter()
        .map(|(id, _)| id)
        .filter(|id| id != root)
        .take(64)
        .collect()
}

pub async fn related_functions(db: &Db, function: &str) -> Result<BTreeSet<String>> {
    let rows = sqlx::query("SELECT id,type_context FROM functions WHERE binary_id=(SELECT binary_id FROM functions WHERE id=?) ORDER BY id")
        .bind(function).fetch_all(&db.pool).await?;
    let contexts: Vec<_> = rows
        .into_iter()
        .map(|row| {
            (
                row.get::<String, _>("id"),
                serde_json::from_str(&row.get::<String, _>("type_context")).unwrap_or(Value::Null),
            )
        })
        .collect();
    Ok(related(&contexts, function))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    #[test]
    fn follows_parameter_identity_without_crossing_subobjects_or_unrelated_parameters() {
        let context = |flows: Value| json!({"objects":{"parameters":[{"index":0},{"index":1}],"flows":flows}});
        let data = vec![
            (
                "b:1000".into(),
                context(
                    json!([{"parameter":0,"offset":0,"target":"2000","target_parameter":1},{"parameter":0,"offset":8,"target":"4000","target_parameter":0}]),
                ),
            ),
            (
                "b:2000".into(),
                context(json!([{"parameter":0,"offset":0,"target":"3000","target_parameter":0}])),
            ),
            ("b:3000".into(), context(json!([]))),
            ("b:4000".into(), context(json!([]))),
        ];
        assert_eq!(related(&data, "b:1000"), BTreeSet::from(["b:2000".into()]));
        assert!(related(&data, "b:4000").is_empty());
    }
    #[tokio::test]
    async fn shared_binary_evidence_reaches_prompts_and_invalidates_related_results() {
        let dir = tempfile::tempdir().unwrap();
        let db = Db::open(&dir.path().join("db")).await.unwrap();
        sqlx::query("INSERT INTO binaries(id,name,sha256,size,architecture,format,path) VALUES('b','fixture','sha',1,'x86','ELF','unused')").execute(&db.pool).await.unwrap();
        let file = dir.path().join("export.jsonl");
        let function = |address: &str, flows: Value| json!({"address":address,"name":format!("f_{address}"),"size":1,"pseudocode":"return;","type_context":json!({"address":address,"objects":{"parameters":[{"index":0}],"flows":flows,"accesses":[]}}).to_string()});
        let rows = [
            function("1000", json!([])),
            function(
                "2000",
                json!([{"parameter":0,"offset":0,"target":"1000","target_parameter":0},{"parameter":0,"offset":0,"target":"3000","target_parameter":0}]),
            ),
            function("3000", json!([])),
            function("4000", json!([])),
        ];
        std::fs::write(
            &file,
            rows.iter()
                .map(Value::to_string)
                .collect::<Vec<_>>()
                .join("\n"),
        )
        .unwrap();
        crate::ghidra::import_export(&db, "b", &file).await.unwrap();
        let before = crate::refinement::sources(&db, "b:1000").await.unwrap();
        assert!(before.contains_key("b:3000"));
        assert!(!before.contains_key("b:4000"));
        let ai = crate::ai::Ai::new(Default::default()).unwrap();
        let prompt = ai.prompt(&db, "b:1000", "map").await.unwrap();
        assert!(prompt.evidence.iter().any(|e| {
            serde_json::from_str::<Value>(&e.content).is_ok_and(|v| v["address"] == "3000")
        }));
        sqlx::query("UPDATE functions SET type_context=json_set(type_context,'$.objects.accesses',json('[{\"parameter\":0,\"offset\":16,\"width\":8}]')) WHERE id='b:3000'").execute(&db.pool).await.unwrap();
        let changed = crate::refinement::sources(&db, "b:1000").await.unwrap();
        assert_ne!(before["b:3000"], changed["b:3000"]);
        assert_eq!(before["b:1000"], changed["b:1000"]);
    }
}
