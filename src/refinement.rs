//! Semantic evidence identity for selective reanalysis.
use crate::db::Db;
use anyhow::Result;
use serde_json::Value;
use sha2::{Digest, Sha256};
use sqlx::Row;
use std::collections::BTreeMap;

/// Ignore presentation edits while preserving layout, storage, and call-target facts.
pub fn types(raw: &str) -> Value {
    fn clean(value: &mut Value) {
        match value {
            Value::Object(map) => {
                for key in [
                    "name",
                    "symbol",
                    "qualified_symbol",
                    "symbol_aliases",
                    "namespace",
                    "prototype",
                    "expected_name",
                ] {
                    map.remove(key);
                }
                for child in map.values_mut() {
                    clean(child);
                }
            }
            Value::Array(items) => {
                for item in items {
                    clean(item);
                }
            }
            _ => {}
        }
    }
    let mut value = serde_json::from_str(raw).unwrap_or(Value::String(raw.into()));
    // The exporter includes parameter names in the prototype. Retain declarator
    // shape (including pointer depth) while removing ordinary parameter names.
    if let Some(prototype) = value.get("prototype").and_then(Value::as_str)
        && let Some((_, tail)) = prototype.split_once('(')
    {
        let parameters: Vec<String> = tail
            .trim_end_matches(')')
            .split(',')
            .map(|parameter| {
                let text = parameter.trim();
                let end = text.rfind(|c: char| !c.is_alphanumeric() && c != '_');
                match end {
                    Some(index) if !text[index + 1..].is_empty() => {
                        text[..=index].trim().to_owned()
                    }
                    _ => text.to_owned(),
                }
            })
            .collect();
        value["parameter_declarators"] = serde_json::json!(parameters);
    }
    clean(&mut value);
    value
}

/// Include direct callees even if their summaries did not fit in the prompt.
pub async fn sources(db: &Db, function: &str) -> Result<BTreeMap<String, String>> {
    let rows = sqlx::query("SELECT id,pcode,type_context FROM functions WHERE id=? OR id IN (SELECT callee FROM edges WHERE caller=?) ORDER BY id")
        .bind(function).bind(function).fetch_all(&db.pool).await?;
    let mut stamps = BTreeMap::new();
    for row in rows {
        let id: String = row.get("id");
        let runtime: Vec<String> = sqlx::query_scalar("SELECT DISTINCT sha256 FROM artifacts WHERE function_id=? AND kind='runtime' ORDER BY sha256")
            .bind(&id).fetch_all(&db.pool).await?;
        let facts = serde_json::json!({"pcode":row.get::<String,_>("pcode"),"types":types(&row.get::<String,_>("type_context")),"runtime":runtime});
        stamps.insert(id, hex::encode(Sha256::digest(serde_json::to_vec(&facts)?)));
    }
    Ok(stamps)
}

/// Keep independently supported signature/local changes when the combined plan is rejected.
pub fn accepted_plan(plan: &crate::types::TypePlan, answers: &Value) -> crate::types::TypePlan {
    let supported =
        |key: &str| answers.get(key).unwrap_or(&answers["types"])["choice"] == "supported";
    let mut selected = crate::types::TypePlan::default();
    if supported("layouts") {
        selected.definitions = plan.definitions.clone();
        selected.cpp.classes = plan.cpp.classes.clone();
        selected.cpp.vtables = plan.cpp.vtables.clone();
        if selected.validate(8).is_err() && selected.validate(4).is_err() {
            selected = Default::default();
        }
    }
    for (index, signature) in plan.signatures.iter().enumerate() {
        if supported(&format!("signature_{index}")) {
            let mut candidate = selected.clone();
            candidate.signatures.push(signature.clone());
            if candidate.validate(8).is_ok() || candidate.validate(4).is_ok() {
                selected = candidate;
            }
        }
    }
    for (index, local) in plan.cpp.locals.iter().enumerate() {
        if supported(&format!("local_{index}")) {
            let mut candidate = selected.clone();
            candidate.cpp.locals.push(local.clone());
            if candidate.validate(8).is_ok() || candidate.validate(4).is_ok() {
                selected = candidate;
            }
        }
    }
    selected
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn presentation_changes_do_not_invalidate_but_layout_changes_do() {
        let a = r#"{"prototype":"int old()","cpp":{"locals":[{"name":"v1","type":"int","storage":"RAX:8"}],"vtables":[{"symbol":"old","slots":[{"offset":8,"target":"1000"}]}]}}"#;
        let renamed = a.replace("old", "descriptive").replace("v1", "count");
        assert_eq!(types(a), types(&renamed));
        assert_ne!(types(a), types(&a.replace("RAX:8", "RAX:4")));
        assert_ne!(types(a), types(&a.replace("1000", "2000")));
    }
    #[test]
    fn partial_type_acceptance_preserves_independent_supported_signatures() {
        let signature = |address: &str| crate::types::Signature {
            address: address.into(),
            name: "value".into(),
            namespace: vec![],
            return_type: crate::types::TypeRef::Primitive { name: "i32".into() },
            parameters: vec![],
            calling_convention: String::new(),
            variadic: false,
        };
        let plan = crate::types::TypePlan {
            signatures: vec![signature("1000"), signature("2000")],
            ..Default::default()
        };
        let verdicts = serde_json::json!({"types":{"choice":"supported"},"signature_0":{"choice":"unsupported"},"signature_1":{"choice":"supported"}});
        let accepted = accepted_plan(&plan, &verdicts);
        assert_eq!(accepted.signatures, vec![plan.signatures[1].clone()]);
    }
}
