use crate::{config::Config, db::Db, graph};
use anyhow::{Context, Result, ensure};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use sqlx::Row;
use std::{
    collections::{HashMap, HashSet},
    path::{Path, PathBuf},
    process::Stdio,
    time::Duration,
};
use tokio::io::{AsyncBufReadExt, BufReader};

#[derive(Debug, Default, Deserialize)]
#[serde(default)]
pub struct ExportFunction {
    pub address: String,
    pub name: String,
    pub size: i64,
    pub pseudocode: String,
    pub disassembly: String,
    pub pcode: String,
    pub strings: Vec<String>,
    pub imports: Vec<String>,
    pub callees: Vec<String>,
    pub thunk: bool,
    pub external: bool,
}
pub async fn install_scripts(config: &Config) -> Result<PathBuf> {
    let dir = config.data_dir.join("scripts");
    tokio::fs::create_dir_all(&dir).await?;
    tokio::fs::write(
        dir.join("PistonExport.java"),
        include_str!("../ghidra/PistonExport.java"),
    )
    .await?;
    tokio::fs::write(
        dir.join("PistonApply.java"),
        include_str!("../ghidra/PistonApply.java"),
    )
    .await?;
    Ok(tokio::fs::canonicalize(dir).await?)
}
async fn headless(config: &Config, binary: &str, args: &[String]) -> Result<()> {
    let home = config
        .ghidra_home
        .as_ref()
        .context("Set GHIDRA_HOME or ghidra_home in piston.toml")?;
    let executable = home.join("support/analyzeHeadless");
    ensure!(
        executable.is_file(),
        "analyzeHeadless is missing from GHIDRA_HOME/support"
    );
    let project = config.data_dir.join("binaries").join(binary).join("ghidra");
    tokio::fs::create_dir_all(&project).await?;
    let scripts = install_scripts(config).await?;
    let log = std::fs::File::create(project.join("headless.log"))?;
    let mut command = tokio::process::Command::new(executable);
    command
        .arg(&project)
        .arg("piston")
        .arg("-scriptPath")
        .arg(scripts)
        .args(args)
        .stdin(Stdio::null())
        .stdout(log.try_clone()?)
        .stderr(log)
        .kill_on_drop(true);
    #[cfg(unix)]
    command.process_group(0);
    let mut child = command.spawn().context("cannot start Ghidra")?;
    let pid = child.id();
    let status = tokio::time::timeout(
        Duration::from_secs(config.ghidra_timeout_secs),
        child.wait(),
    )
    .await;
    if status.is_err() {
        // analyzeHeadless is a launcher. Terminate its process group, including Java.
        #[cfg(unix)]
        if let Some(pid) = pid {
            let _ = tokio::process::Command::new("kill")
                .args(["-TERM", "--", &format!("-{pid}")])
                .status()
                .await;
        }
        child.kill().await.ok();
        anyhow::bail!(
            "Ghidra exceeded its time limit; see {}",
            project.join("headless.log").display()
        );
    }
    ensure!(
        status??.success(),
        "Ghidra failed; see {}",
        project.join("headless.log").display()
    );
    Ok(())
}
pub async fn extract(db: &Db, config: &Config, binary: &str) -> Result<()> {
    let row = sqlx::query("SELECT path,status FROM binaries WHERE id=?")
        .bind(binary)
        .fetch_one(&db.pool)
        .await?;
    let status: String = row.get("status");
    ensure!(
        ["imported", "interrupted", "failed"].contains(&status.as_str()),
        "binary is already indexed or extracting"
    );
    sqlx::query("UPDATE binaries SET status='extracting',error='' WHERE id=?")
        .bind(binary)
        .execute(&db.pool)
        .await?;
    db.event(binary, "info", "Ghidra extraction started.")
        .await?;
    let output = tokio::fs::canonicalize(config.data_dir.join("binaries").join(binary))
        .await?
        .join("functions.jsonl");
    let result = async {
        headless(
            config,
            binary,
            &[
                "-import".into(),
                row.get("path"),
                "-overwrite".into(),
                "-postScript".into(),
                "PistonExport.java".into(),
                output.to_string_lossy().into_owned(),
            ],
        )
        .await?;
        import_export(db, binary, &output).await
    }
    .await;
    if let Err(error) = &result {
        sqlx::query("UPDATE binaries SET status='failed',error=? WHERE id=?")
            .bind(format!("{error:#}"))
            .bind(binary)
            .execute(&db.pool)
            .await?;
        db.event(binary, "error", &format!("Extraction failed: {error:#}"))
            .await?;
    }
    result
}
pub async fn import_export(db: &Db, binary: &str, path: &Path) -> Result<()> {
    let mut lines = BufReader::new(tokio::fs::File::open(path).await?).lines();
    let mut tx = db.pool.begin().await?;
    let existing: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM functions WHERE binary_id=?")
        .bind(binary)
        .fetch_one(&mut *tx)
        .await?;
    ensure!(existing == 0, "binary already has indexed functions");
    let mut addresses = HashMap::new();
    let mut pending_edges = Vec::new();
    let mut fingerprints = HashSet::new();
    while let Some(line) = lines.next_line().await? {
        if line.trim().is_empty() {
            continue;
        }
        let f: ExportFunction = serde_json::from_str(&line).context("invalid Ghidra JSONL row")?;
        ensure!(
            !f.address.is_empty() && !f.name.is_empty() && f.size >= 0,
            "invalid function identity or size"
        );
        let id = format!("{binary}:{}", f.address);
        let fingerprint = hex::encode(Sha256::digest(f.pseudocode.as_bytes()));
        let skip = if f.external {
            "external"
        } else if f.thunk {
            "thunk"
        } else if f.pseudocode.is_empty() {
            "decompilation unavailable"
        } else if f.size < 8 {
            "tiny function"
        } else if !fingerprints.insert(fingerprint.clone()) {
            "identical pseudocode"
        } else {
            ""
        };
        sqlx::query("INSERT INTO functions(id,binary_id,address,name,size,pseudocode,disassembly,pcode,strings_json,imports_json,skip_reason,fingerprint) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)")
            .bind(&id).bind(binary).bind(&f.address).bind(&f.name).bind(f.size).bind(&f.pseudocode).bind(&f.disassembly).bind(&f.pcode)
            .bind(serde_json::to_string(&f.strings)?).bind(serde_json::to_string(&f.imports)?).bind(skip).bind(fingerprint).execute(&mut *tx).await?;
        sqlx::query(
            "INSERT INTO function_search(function_id,name,pseudocode,summary) VALUES(?,?,?,'')",
        )
        .bind(&id)
        .bind(&f.name)
        .bind(&f.pseudocode)
        .execute(&mut *tx)
        .await?;
        for callee in f.callees {
            pending_edges.push((id.clone(), callee));
        }
        addresses.insert(f.address, id);
    }
    ensure!(!addresses.is_empty(), "Ghidra export contains no functions");
    let mut edges = Vec::new();
    for (caller, address) in pending_edges {
        if let Some(callee) = addresses.get(&address) {
            sqlx::query("INSERT OR IGNORE INTO edges(caller,callee) VALUES(?,?)")
                .bind(&caller)
                .bind(callee)
                .execute(&mut *tx)
                .await?;
            edges.push((caller, callee.clone()));
        }
    }
    let mut ids: Vec<_> = addresses.into_values().collect();
    ids.sort();
    let ranks = graph::dependency_ranks(&ids, &edges);
    let modules = graph::modules(&ids, &edges);
    for id in &ids {
        sqlx::query("UPDATE functions SET module=? WHERE id=?")
            .bind(&modules[id])
            .bind(id)
            .execute(&mut *tx)
            .await?;
        sqlx::query("INSERT INTO jobs(id,binary_id,function_id,stage,priority) SELECT ?,?,id,'map',? FROM functions WHERE id=? AND skip_reason=''")
            .bind(uuid::Uuid::new_v4().to_string()).bind(binary).bind(-(ranks[id] as i64)).bind(id).execute(&mut *tx).await?;
    }
    sqlx::query("UPDATE binaries SET status='indexed',error='' WHERE id=?")
        .bind(binary)
        .execute(&mut *tx)
        .await?;
    tx.commit().await?;
    db.event(
        binary,
        "info",
        &format!(
            "Indexed {} functions and {} call edges.",
            ids.len(),
            edges.len()
        ),
    )
    .await?;
    Ok(())
}
pub async fn apply(db: &Db, config: &Config, binary: &str) -> Result<usize> {
    let rows = sqlx::query("SELECT r.id,f.address,r.proposed_name,r.summary FROM results r JOIN functions f ON f.id=r.function_id WHERE f.binary_id=? AND r.review='accepted' AND r.id=(SELECT id FROM results WHERE function_id=f.id ORDER BY CASE stage WHEN 'escalate' THEN 3 WHEN 'propagate' THEN 2 ELSE 1 END DESC LIMIT 1)").bind(binary).fetch_all(&db.pool).await?;
    ensure!(!rows.is_empty(), "no accepted proposals to apply");
    let proposals: Vec<_> = rows.iter().map(|r| serde_json::json!({"address":r.get::<String,_>("address"),"name":r.get::<String,_>("proposed_name"),"summary":r.get::<String,_>("summary")})).collect();
    let folder = tokio::fs::canonicalize(config.data_dir.join("binaries").join(binary)).await?;
    let path = folder.join("accepted.json");
    tokio::fs::write(&path, serde_json::to_vec_pretty(&proposals)?).await?;
    headless(
        config,
        binary,
        &[
            "-process".into(),
            "program.bin".into(),
            "-noanalysis".into(),
            "-postScript".into(),
            "PistonApply.java".into(),
            path.to_string_lossy().into_owned(),
        ],
    )
    .await?;
    let mut tx = db.pool.begin().await?;
    for row in &rows {
        sqlx::query("UPDATE results SET review='applied' WHERE id=?")
            .bind(row.get::<String, _>("id"))
            .execute(&mut *tx)
            .await?;
    }
    tx.commit().await?;
    db.event(
        binary,
        "info",
        &format!("Applied {} reviewed proposals in Ghidra.", rows.len()),
    )
    .await?;
    Ok(rows.len())
}
