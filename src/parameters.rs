//! Bounded native experiments for AI and call-site parameter candidates.
use crate::{ai::Analysis, config::Config, db::Db, types::TypeRef};
use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sqlx::Row;

#[derive(Clone, Debug, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Candidate {
    /// Zero-based parameter ordinal in the current native prototype.
    pub index: u32,
    pub name: String,
    /// None tests only a name, preserving the native type.
    #[serde(default)]
    pub data_type: Option<TypeRef>,
}

fn candidates(analysis: &Analysis, address: &str) -> Vec<Candidate> {
    let mut candidates = analysis.parameter_candidates.clone();
    for signature in &analysis.type_plan.signatures {
        if crate::cpp::address(&signature.address).ok() == crate::cpp::address(address).ok() {
            candidates.extend(signature.parameters.iter().enumerate().map(|(index, p)| {
                Candidate {
                    index: index as u32,
                    name: p.name.clone(),
                    data_type: Some(p.data_type.clone()),
                }
            }));
        }
    }
    candidates.retain(|c| c.index < 64 && crate::types::identifier(&c.name));
    candidates.truncate(192);
    candidates
}

/// Each function has a durable operation, including rejected trials. A restart
/// reconciles the native marker before doing any additional work.
pub async fn recover(
    db: &Db,
    config: &Config,
    binary: &str,
    cycle: &str,
    pass: i64,
) -> Result<bool> {
    let mut rows = sqlx::query("SELECT f.id,f.address,r.raw_json,EXISTS(SELECT 1 FROM edges WHERE caller=f.id) has_calls FROM functions f JOIN results r ON r.id=f.current_result_id WHERE f.binary_id=? AND f.skip_reason='' AND r.author<>'human' AND NOT EXISTS(SELECT 1 FROM review_decisions WHERE result_id=r.id) ORDER BY f.address")
        .bind(binary).fetch_all(&db.pool).await?;
    rows.retain(|row| {
        row.get::<bool, _>("has_calls")
            || serde_json::from_str::<Analysis>(&row.get::<String, _>("raw_json"))
                .is_ok_and(|a| !candidates(&a, &row.get::<String, _>("address")).is_empty())
    });
    let ids: Vec<String> = rows.iter().map(|r| r.get("id")).collect();
    let edges: Vec<(String, String)> = sqlx::query_as(
        "SELECT caller,callee FROM edges JOIN functions f ON f.id=caller WHERE f.binary_id=?",
    )
    .bind(binary)
    .fetch_all(&db.pool)
    .await?;
    let ranks = crate::graph::dependency_ranks(&ids, &edges);
    rows.sort_by_key(|row| {
        (
            ranks.get(&row.get::<String, _>("id")).copied().unwrap_or(0),
            row.get::<String, _>("address"),
        )
    });
    let total = rows.len();
    let mut changed = false;
    for (index, row) in rows.iter().enumerate() {
        let function: String = row.get("id");
        let analysis: Analysis = serde_json::from_str(&row.get::<String, _>("raw_json"))?;
        let address: String = row.get("address");
        let input = json!({"address":address,"candidates":candidates(&analysis,&address)});
        let operation = format!("parameters-{cycle}-{pass}-{address}");
        sqlx::query("INSERT OR IGNORE INTO parameter_operations(id,binary_id,function_id,input_json) VALUES(?,?,?,?)")
            .bind(&operation).bind(binary).bind(&function).bind(input.to_string()).execute(&db.pool).await?;
        let stored = sqlx::query(
            "SELECT status,input_json,report_json FROM parameter_operations WHERE id=?",
        )
        .bind(&operation)
        .fetch_one(&db.pool)
        .await?;
        if stored.get::<String, _>("status") == "completed" {
            let report: Value = serde_json::from_str(&stored.get::<String, _>("report_json"))?;
            changed |= report["changed"].as_bool().unwrap_or(false);
            continue;
        }
        db.event(
            binary,
            "info",
            &format!(
                "Parameter experiments: {}/{} functions; testing {address}",
                index + 1,
                total
            ),
        )
        .await?;
        let folder = tokio::fs::canonicalize(config.data_dir.join("binaries").join(binary)).await?;
        let input_path = folder.join(format!("{operation}.json"));
        let report_path = folder.join(format!("{operation}-report.json"));
        tokio::fs::write(&input_path, stored.get::<String, _>("input_json")).await?;
        crate::ghidra::headless(
            config,
            binary,
            &[
                "-process".into(),
                "program.bin".into(),
                "-noanalysis".into(),
                "-postScript".into(),
                "PistonParameters.java".into(),
                operation.clone(),
                input_path.to_string_lossy().into_owned(),
                report_path.to_string_lossy().into_owned(),
            ],
            None,
        )
        .await?;
        let report: Value =
            serde_json::from_slice(&tokio::fs::read(&report_path).await.with_context(|| {
                let log =
                    std::fs::read_to_string(folder.join("ghidra/headless.log")).unwrap_or_default();
                let lines: Vec<_> = log.lines().rev().take(24).collect();
                format!(
                    "Missing native parameter experiment report for {address}: {}",
                    lines.into_iter().rev().collect::<Vec<_>>().join("\n")
                )
            })?)?;
        ensure!(
            report["status"] == "completed",
            "Native parameter experiments did not finish"
        );
        changed |= report["changed"].as_bool().unwrap_or(false);
        sqlx::query("UPDATE parameter_operations SET status='completed',report_json=?,updated_at=unixepoch() WHERE id=?")
            .bind(report.to_string()).bind(&operation).execute(&db.pool).await?;
    }
    Ok(changed)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn preserves_name_only_and_uncertain_candidates_without_cross_function_signatures() {
        let mut analysis: Analysis = serde_json::from_value(json!({"proposed_name":"f","summary":"x","confidence":0.2,"evidence":["x"],"parameter_types":[],"side_effects":[],"uncertainties":[],"parameter_candidates":[{"index":0,"name":"buffer","data_type":null},{"index":64,"name":"outside","data_type":null}]})).unwrap();
        assert_eq!(candidates(&analysis, "1000").len(), 1);
        analysis.type_plan.signatures.push(crate::types::Signature {
            address: "2000".into(),
            name: "other".into(),
            namespace: vec![],
            return_type: TypeRef::Primitive {
                name: "void".into(),
            },
            parameters: vec![crate::types::Parameter {
                name: "wrong".into(),
                data_type: TypeRef::Primitive { name: "u64".into() },
            }],
            calling_convention: String::new(),
            variadic: false,
        });
        let selected = candidates(&analysis, "1000");
        assert_eq!(selected.len(), 1);
        assert!(selected[0].data_type.is_none());
    }
}

#[cfg(test)]
#[path = "parameters/native_tests.rs"]
mod native_tests;
