//! Focused live-program research and durable, exact-operation annotation writeback.
use crate::{config::Config, db::Db, ghidra, types::TypePlan};
use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sqlx::Row;
use tokio_util::sync::CancellationToken;

#[derive(Clone, Debug, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum Query {
    Function {
        address: String,
        #[serde(default = "yes")]
        decompile: bool,
        #[serde(default = "timeout")]
        timeout_secs: u32,
        #[serde(default = "max_chars")]
        max_chars: u32,
    },
    References {
        address: String,
        direction: Direction,
        #[serde(default)]
        offset: u32,
        #[serde(default = "limit")]
        limit: u32,
    },
    Functions {
        #[serde(default)]
        name_contains: String,
        #[serde(default)]
        offset: u32,
        #[serde(default = "limit")]
        limit: u32,
    },
    Memory {
        address: String,
        length: u32,
        #[serde(default)]
        disassemble: bool,
        #[serde(default = "limit")]
        limit: u32,
    },
    Vtable {
        address: String,
        count: u32,
    },
}
#[derive(Clone, Debug, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum Direction {
    To,
    From,
    Callers,
}
fn yes() -> bool {
    true
}
fn timeout() -> u32 {
    30
}
fn max_chars() -> u32 {
    32768
}
fn limit() -> u32 {
    100
}
fn valid_address(address: &str) -> bool {
    let hex = address.strip_prefix("0x").unwrap_or(address);
    !hex.is_empty() && hex.len() <= 16 && hex.bytes().all(|byte| byte.is_ascii_hexdigit())
}
impl Query {
    pub fn validate(&self) -> Result<()> {
        let (address, offset, count) = match self {
            Self::Function {
                address,
                timeout_secs,
                max_chars,
                ..
            } => {
                ensure!(
                    (1..=120).contains(timeout_secs) && (1..=262144).contains(max_chars),
                    "Invalid decompilation bounds"
                );
                (Some(address), 0, 1)
            }
            Self::References {
                address,
                offset,
                limit,
                ..
            } => (Some(address), *offset, *limit),
            Self::Functions {
                name_contains,
                offset,
                limit,
            } => {
                ensure!(
                    name_contains.len() <= 160,
                    "Function search exceeds 160 bytes"
                );
                (None, *offset, *limit)
            }
            Self::Memory {
                address,
                length,
                limit,
                ..
            } => {
                ensure!(
                    (1..=65536).contains(length),
                    "Memory length must be 1 to 65536"
                );
                (Some(address), 0, *limit)
            }
            Self::Vtable { address, count } => {
                ensure!((1..=512).contains(count), "Table length must be 1 to 512");
                (Some(address), 0, *count)
            }
        };
        ensure!(
            address.is_none_or(|address| valid_address(address)),
            "Use a hexadecimal address in the default address space"
        );
        ensure!(
            offset <= 100000 && (1..=1024).contains(&count),
            "Invalid query pagination"
        );
        Ok(())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Annotation {
    pub address: String,
    /// Local function name returned by inspection, without its namespace prefix.
    pub expected_name: String,
    pub expected_comment: String,
    pub name: String,
    pub comment: String,
}

async fn folder(db: &Db, config: &Config, binary: &str) -> Result<std::path::PathBuf> {
    db.binary(binary).await?;
    let folder = tokio::fs::canonicalize(config.data_dir.join("binaries").join(binary)).await?;
    ensure!(
        folder.join("ghidra/piston.gpr").is_file(),
        "Extract this binary before querying Ghidra"
    );
    Ok(folder)
}
async fn script(
    config: &Config,
    binary: &str,
    name: &str,
    args: Vec<String>,
    cancel: CancellationToken,
) -> Result<()> {
    let mut command = vec![
        "-process".into(),
        "program.bin".into(),
        "-noanalysis".into(),
        "-postScript".into(),
        name.into(),
    ];
    command.extend(args);
    ghidra::headless(config, binary, &command, Some(cancel)).await
}
async fn report(path: &std::path::Path) -> Result<Value> {
    ensure!(
        tokio::fs::metadata(path)
            .await
            .context("Ghidra did not produce a report")?
            .len()
            <= 16 * 1024 * 1024,
        "Ghidra report exceeds 16 MiB"
    );
    Ok(serde_json::from_slice(&tokio::fs::read(path).await?)?)
}

pub async fn query(
    db: &Db,
    config: &Config,
    binary: &str,
    queries: Vec<Query>,
    cancel: CancellationToken,
) -> Result<Value> {
    ensure!(
        (1..=32).contains(&queries.len()),
        "Use 1 to 32 queries per batch"
    );
    for query in &queries {
        query.validate()?;
    }
    let folder = folder(db, config, binary).await?;
    let id = uuid::Uuid::new_v4();
    let input = folder.join(format!("query-{id}.json"));
    let output = folder.join(format!("query-{id}-report.json"));
    let mut encoded = serde_json::to_value(&queries)?;
    for item in encoded.as_array_mut().context("Invalid query batch")? {
        if let Some(address) = item.get_mut("address") {
            *address = Value::String(
                address
                    .as_str()
                    .context("Invalid query address")?
                    .trim_start_matches("0x")
                    .to_owned(),
            );
        }
    }
    tokio::fs::write(&input, serde_json::to_vec(&encoded)?).await?;
    let result = async {
        script(
            config,
            binary,
            "PistonQuery.java",
            vec![input.display().to_string(), output.display().to_string()],
            cancel,
        )
        .await?;
        let report = report(&output).await?;
        ensure!(
            report["results"]
                .as_array()
                .is_some_and(|results| results.len() == queries.len()),
            "Ghidra returned an incomplete query batch"
        );
        ensure!(
            report["sha256"] == db.binary(binary).await?.sha256,
            "The open Ghidra program belongs to another binary build"
        );
        Ok(report)
    }
    .await;
    // On cancellation, the desktop can still be reading its input. Retain it for reconciliation.
    if result.is_ok() {
        tokio::fs::remove_file(input).await?;
        tokio::fs::remove_file(output).await?;
    }
    result
}

async fn writer_ready(db: &Db, binary: &str, operation: &str) -> Result<()> {
    let busy: i64 = sqlx::query_scalar("SELECT (SELECT COUNT(*) FROM research_operations WHERE binary_id=? AND id<>? AND status IN ('applying','uncertain')) + (SELECT COUNT(*) FROM type_operations WHERE binary_id=? AND status IN ('applying','uncertain')) + (SELECT COUNT(*) FROM apply_operations WHERE binary_id=? AND status IN ('applying','uncertain')) + (SELECT COUNT(*) FROM jobs WHERE binary_id=? AND status IN ('running','batched','uncertain')) + (SELECT recovery_writer FROM binaries WHERE id=?)")
        .bind(binary).bind(operation).bind(binary).bind(binary).bind(binary).bind(binary).fetch_one(&db.pool).await?;
    ensure!(
        busy == 0,
        "Another writer or an uncertain operation owns this binary; reconcile it first"
    );
    let paused: bool = sqlx::query_scalar("SELECT paused FROM binaries WHERE id=?")
        .bind(binary)
        .fetch_one(&db.pool)
        .await?;
    ensure!(
        paused,
        "Pause binary analysis before changing Ghidra annotations or types"
    );
    Ok(())
}
pub async fn operation(db: &Db, id: &str) -> Result<Value> {
    let row = sqlx::query("SELECT * FROM research_operations WHERE id=?")
        .bind(id)
        .fetch_one(&db.pool)
        .await?;
    Ok(
        json!({"id":id,"binary_id":row.get::<String,_>("binary_id"),"kind":row.get::<String,_>("kind"),"status":row.get::<String,_>("status"),"input":serde_json::from_str::<Value>(&row.get::<String,_>("input_json"))?,"report":serde_json::from_str::<Value>(&row.get::<String,_>("report_json"))?,"error":row.get::<String,_>("error")}),
    )
}

pub async fn preview_annotations(
    db: &Db,
    config: &Config,
    binary: &str,
    mut items: Vec<Annotation>,
    cancel: CancellationToken,
) -> Result<Value> {
    ensure!((1..=128).contains(&items.len()), "Use 1 to 128 annotations");
    let mut addresses = std::collections::HashSet::new();
    for item in &items {
        ensure!(
            valid_address(&item.address)
                && crate::types::identifier(&item.name)
                && item.comment.len() <= 32768
                && item.expected_comment.len() <= 32768,
            "Invalid annotation address, name or comment length"
        );
        let normalized = u64::from_str_radix(item.address.trim_start_matches("0x"), 16)?;
        ensure!(addresses.insert(normalized), "Duplicate annotation address");
    }
    writer_ready(db, binary, "").await?;
    // Inspect in batches without decompiling. Applying repeats the comparison inside the transaction.
    for chunk in items.chunks_mut(32) {
        let current = query(
            db,
            config,
            binary,
            chunk
                .iter()
                .map(|item| Query::Function {
                    address: item.address.clone(),
                    decompile: false,
                    timeout_secs: 30,
                    max_chars: 32768,
                })
                .collect(),
            cancel.clone(),
        )
        .await?;
        for (item, result) in chunk.iter_mut().zip(
            current["results"]
                .as_array()
                .context("Invalid query report")?,
        ) {
            ensure!(
                result["ok"] == true
                    && result["result"]["local_name"] == item.expected_name
                    && result["result"]["comment"] == item.expected_comment,
                "Function changed or is missing: {}",
                item.address
            );
            ensure!(
                u64::from_str_radix(
                    result["result"]["address"]
                        .as_str()
                        .context("Missing entry address")?,
                    16
                )? == u64::from_str_radix(item.address.trim_start_matches("0x"), 16)?,
                "Annotation address must be a function entry"
            );
            item.address = result["result"]["address"]
                .as_str()
                .context("Missing entry address")?
                .to_string();
        }
    }
    let id = uuid::Uuid::new_v4().to_string();
    sqlx::query("INSERT INTO research_operations(id,binary_id,kind,input_json,status) VALUES(?,?,'annotations',?,'preview')").bind(&id).bind(binary).bind(serde_json::to_string(&items)?).execute(&db.pool).await?;
    operation(db, &id).await
}

pub async fn preview_types(
    db: &Db,
    config: &Config,
    binary: &str,
    plan: TypePlan,
    cancel: CancellationToken,
) -> Result<Value> {
    writer_ready(db, binary, "").await?;
    ensure!(!plan.is_empty(), "Type plan is empty");
    let pointer = query(
        db,
        config,
        binary,
        vec![Query::Functions {
            name_contains: String::new(),
            offset: 0,
            limit: 1,
        }],
        cancel.clone(),
    )
    .await?;
    plan.validate(
        pointer["pointer_width"]
            .as_u64()
            .context("Missing pointer width")? as u32,
    )?;
    let folder = folder(db, config, binary).await?;
    let id = uuid::Uuid::new_v4().to_string();
    let input = folder.join(format!("research-{id}.json"));
    let expected = folder.join(format!("research-{id}-expected.json"));
    let output = folder.join(format!("research-{id}-preview.json"));
    let encoded = serde_json::to_string(&plan)?;
    tokio::fs::write(&input, &encoded).await?;
    tokio::fs::write(&expected, "null").await?;
    script(
        config,
        binary,
        "PistonTypes.java",
        vec![
            "preview".into(),
            format!("research-{id}"),
            input.display().to_string(),
            expected.display().to_string(),
            output.display().to_string(),
        ],
        cancel,
    )
    .await?;
    let report = report(&output).await?;
    let status = if report["status"] == "validated" {
        "preview"
    } else {
        "rejected"
    };
    sqlx::query("INSERT INTO research_operations(id,binary_id,kind,input_json,report_json,status) VALUES(?,?,'types',?,?,?)").bind(&id).bind(binary).bind(encoded).bind(report.to_string()).bind(status).execute(&db.pool).await?;
    operation(db, &id).await
}

pub async fn apply(db: &Db, config: &Config, id: &str, cancel: CancellationToken) -> Result<Value> {
    let op = operation(db, id).await?;
    let binary = op["binary_id"].as_str().context("Missing binary")?;
    writer_ready(db, binary, id).await?;
    ensure!(
        matches!(
            op["status"].as_str(),
            Some("preview" | "uncertain" | "applied")
        ),
        "Operation is not ready to apply"
    );
    let folder = folder(db, config, binary).await?;
    let input = folder.join(format!("research-{id}.json"));
    let output = folder.join(format!("research-{id}-applied.json"));
    let expected = folder.join(format!("research-{id}-expected.json"));
    tokio::fs::write(&input, op["input"].to_string()).await?;
    tokio::fs::write(&expected, op["report"]["expected"].to_string()).await?;
    if output.exists() {
        tokio::fs::remove_file(&output).await?;
    }
    let claimed = sqlx::query("UPDATE research_operations SET status='applying',error='',updated_at=unixepoch() WHERE id=? AND status IN ('preview','uncertain','applied') AND EXISTS(SELECT 1 FROM binaries WHERE id=research_operations.binary_id AND paused=1 AND recovery_writer=0) AND NOT EXISTS(SELECT 1 FROM jobs WHERE binary_id=research_operations.binary_id AND status IN ('running','batched','uncertain'))").bind(id).execute(&db.pool).await?.rows_affected();
    ensure!(
        claimed == 1,
        "Binary analysis resumed or another writer changed this operation before writeback"
    );
    let result = async {
        let (script_name,args) = if op["kind"] == "types" {
            ("PistonTypes.java",vec!["apply".into(),format!("research-{id}"),input.display().to_string(),expected.display().to_string(),output.display().to_string()])
        } else {
            ("PistonAnnotate.java",vec![id.to_string(),input.display().to_string(),output.display().to_string()])
        };
        script(config,binary,script_name,args,cancel.clone()).await?;
        let report = report(&output).await?;
        if report["status"] == "conflict" && op["kind"] == "annotations" {
            sqlx::query("UPDATE research_operations SET status='rejected',report_json=?,error='',updated_at=unixepoch() WHERE id=?").bind(report.to_string()).bind(id).execute(&db.pool).await?;
            return Ok(());
        }
        ensure!(report["status"] == "applied", "Ghidra did not confirm writeback");
        if op["kind"] == "types" {
            ghidra::refresh_cancellable(db,config,binary,Some(cancel)).await?;
        } else {
            let mut tx = db.pool.begin().await?;
            for item in serde_json::from_value::<Vec<Annotation>>(op["input"].clone())? {
                let id = format!("{binary}:{}",item.address);
                let old: Option<String> = sqlx::query_scalar("SELECT current_result_id FROM functions WHERE id=?").bind(&id).fetch_optional(&mut *tx).await?.flatten();
                sqlx::query("UPDATE functions SET name=?,comment=? WHERE id=?").bind(&item.name).bind(&item.comment).bind(&id).execute(&mut *tx).await?;
                sqlx::query("UPDATE function_search SET name=?,summary='' WHERE function_id=?").bind(&item.name).bind(&id).execute(&mut *tx).await?;
                if let Some(old) = old {
                    sqlx::query("UPDATE results SET stale=1 WHERE id=?").bind(&old).execute(&mut *tx).await?;
                    crate::knowledge::invalidate(&mut tx,&old).await?;
                }
            }
            tx.commit().await?;
        }
        // Preserve type preview expectations for exact-operation retries.
        let mut stored = op["report"].clone();
        stored["applied"] = report;
        sqlx::query("UPDATE research_operations SET status='applied',report_json=?,updated_at=unixepoch() WHERE id=?").bind(stored.to_string()).bind(id).execute(&db.pool).await?;
        Ok::<(),anyhow::Error>(())
    }.await;
    if let Err(error) = result {
        sqlx::query("UPDATE research_operations SET status='uncertain',error=?,updated_at=unixepoch() WHERE id=?").bind(format!("{error:#}")).bind(id).execute(&db.pool).await?;
        return Err(error);
    }
    db.event(
        binary,
        "info",
        &format!("Ghidra research operation {id} finished; inspect its outcome"),
    )
    .await?;
    operation(db, id).await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reject_unbounded_queries_and_unknown_fields() {
        for value in [
            json!({"kind":"memory","address":"140000000","length":65537}),
            json!({"kind":"vtable","address":"140000000","count":0}),
            json!({"kind":"references","address":"140000000","direction":"to","offset":100001}),
            json!({"kind":"function","address":"../file"}),
            json!({"kind":"function","address":"140000000","timeout_secs":121}),
        ] {
            assert!(
                serde_json::from_value::<Query>(value)
                    .unwrap()
                    .validate()
                    .is_err()
            );
        }
        assert!(
            serde_json::from_value::<Query>(
                json!({"kind":"function","address":"140000000","script":"bad"})
            )
            .is_err()
        );
    }

    #[tokio::test]
    #[ignore = "requires PISTON_TEST_GHIDRA_HOME, a JDK, and cc"]
    async fn native_focused_queries_and_annotations_persist_and_reject_stale_batches() {
        let dir = tempfile::tempdir().unwrap();
        let source = dir.path().join("fixture.c");
        let binary = dir.path().join("fixture");
        std::fs::write(&source,"__attribute__((noinline)) long add(long a,long b){return a+b;} __attribute__((noinline)) long relay(long a){return add(a,7);} void *table[]={add,relay}; int main(int argc,char **argv){return relay(argc);}").unwrap();
        assert!(
            std::process::Command::new("cc")
                .args([
                    "-O1",
                    "-fno-inline",
                    "-fno-optimize-sibling-calls",
                    "-no-pie",
                    "-o"
                ])
                .arg(&binary)
                .arg(source)
                .status()
                .unwrap()
                .success()
        );
        let config = Config {
            data_dir: dir.path().join("data"),
            ghidra_home: Some(std::env::var_os("PISTON_TEST_GHIDRA_HOME").unwrap().into()),
            ..Default::default()
        };
        std::fs::create_dir_all(&config.data_dir).unwrap();
        let db = Db::open(&config.data_dir.join("piston.db")).await.unwrap();
        let imported = db.import(&binary, &config).await.unwrap();
        ghidra::extract(&db, &config, &imported.id).await.unwrap();
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
        let mut desktop = DesktopGuard(None);
        if std::env::var_os("PISTON_TEST_GHIDRA_DESKTOP").is_some() {
            crate::desktop::open(&config, &imported.id).await.unwrap();
            let launch: Value = serde_json::from_slice(
                &std::fs::read(
                    config
                        .data_dir
                        .join("binaries")
                        .join(&imported.id)
                        .join("desktop/launch.json"),
                )
                .unwrap(),
            )
            .unwrap();
            desktop.0 = launch["pid"].as_u64();
            for _ in 0..120 {
                if crate::desktop::status(&config, &imported.id).await == "connected" {
                    break;
                }
                tokio::time::sleep(std::time::Duration::from_millis(500)).await;
            }
            assert_eq!(
                crate::desktop::status(&config, &imported.id).await,
                "connected"
            );
        }
        let q = |queries| {
            query(
                &db,
                &config,
                &imported.id,
                queries,
                CancellationToken::new(),
            )
        };
        let found = q(vec![Query::Functions {
            name_contains: "add".into(),
            offset: 0,
            limit: 100,
        }])
        .await
        .unwrap();
        let add = found["results"][0]["result"]["entries"]
            .as_array()
            .unwrap()
            .iter()
            .find(|f| f["local_name"] == "add")
            .unwrap();
        let address = add["address"].as_str().unwrap().to_owned();
        let nm = std::process::Command::new("nm")
            .arg(&binary)
            .output()
            .unwrap();
        let nm = String::from_utf8(nm.stdout).unwrap();
        let table = nm
            .lines()
            .find(|l| l.ends_with(" table"))
            .unwrap()
            .split_whitespace()
            .next()
            .unwrap()
            .to_owned();
        let results = q(vec![
            Query::Function {
                address: address.clone(),
                decompile: true,
                timeout_secs: 30,
                max_chars: 32768,
            },
            Query::References {
                address: address.clone(),
                direction: Direction::Callers,
                offset: 0,
                limit: 1,
            },
            Query::Memory {
                address: address.clone(),
                length: 16,
                disassemble: true,
                limit: 10,
            },
            Query::Vtable {
                address: table,
                count: 2,
            },
            Query::Function {
                address: "1".into(),
                decompile: true,
                timeout_secs: 30,
                max_chars: 32768,
            },
        ])
        .await
        .unwrap();
        assert_eq!(
            results["results"][0]["result"]["decompiled"], true,
            "{results}"
        );
        assert!(
            !results["results"][1]["result"]["entries"]
                .as_array()
                .unwrap()
                .is_empty()
        );
        assert_eq!(results["results"][2]["result"]["read"], 16);
        assert_eq!(
            results["results"][3]["result"]["slots"][0]["function"]["local_name"],
            "add"
        );
        assert_eq!(results["results"][4]["ok"], false);
        let item = Annotation {
            address: address.clone(),
            expected_name: "add".into(),
            expected_comment: String::new(),
            name: "verified_add".into(),
            comment: "Verified against fixture instructions".into(),
        };
        let stale = preview_annotations(
            &db,
            &config,
            &imported.id,
            vec![item.clone()],
            CancellationToken::new(),
        )
        .await
        .unwrap();
        let change = preview_annotations(
            &db,
            &config,
            &imported.id,
            vec![Annotation {
                name: "changed_add".into(),
                ..item.clone()
            }],
            CancellationToken::new(),
        )
        .await
        .unwrap();
        assert_eq!(
            apply(
                &db,
                &config,
                change["id"].as_str().unwrap(),
                CancellationToken::new()
            )
            .await
            .unwrap()["status"],
            "applied"
        );
        assert_eq!(
            apply(
                &db,
                &config,
                stale["id"].as_str().unwrap(),
                CancellationToken::new()
            )
            .await
            .unwrap()["status"],
            "rejected"
        );
        let again = q(vec![Query::Function {
            address: address.clone(),
            decompile: false,
            timeout_secs: 30,
            max_chars: 32768,
        }])
        .await
        .unwrap();
        assert_eq!(again["results"][0]["result"]["local_name"], "changed_add");
        assert_eq!(
            apply(
                &db,
                &config,
                change["id"].as_str().unwrap(),
                CancellationToken::new()
            )
            .await
            .unwrap()["status"],
            "applied"
        );
        let plan:TypePlan=serde_json::from_value(json!({"definitions":[{"kind":"structure","name":"ResearchPair","size":16,"fields":[{"name":"first","offset":0,"data_type":{"kind":"primitive","name":"i64"}}]}]})).unwrap();
        let preview = preview_types(&db, &config, &imported.id, plan, CancellationToken::new())
            .await
            .unwrap();
        assert_eq!(preview["status"], "preview", "{preview}");
        assert_eq!(
            apply(
                &db,
                &config,
                preview["id"].as_str().unwrap(),
                CancellationToken::new()
            )
            .await
            .unwrap()["status"],
            "applied"
        );
        assert_eq!(
            apply(
                &db,
                &config,
                preview["id"].as_str().unwrap(),
                CancellationToken::new()
            )
            .await
            .unwrap()["status"],
            "applied"
        );
    }
}
