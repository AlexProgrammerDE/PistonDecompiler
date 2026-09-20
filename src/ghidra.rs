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
use tokio_util::sync::CancellationToken;

#[derive(Debug, Default, Deserialize)]
#[serde(default)]
pub struct ExportFunction {
    pub address: String,
    pub name: String,
    pub size: i64,
    pub comment: String,
    pub type_context: String,
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
    tokio::fs::write(
        dir.join("PistonTypes.java"),
        include_str!("../ghidra/PistonTypes.java"),
    )
    .await?;
    Ok(tokio::fs::canonicalize(dir).await?)
}
async fn terminate(child: &mut tokio::process::Child, pid: Option<u32>) {
    #[cfg(unix)]
    if let Some(pid) = pid {
        let _ = tokio::process::Command::new("kill")
            .args(["-TERM", "--", &format!("-{pid}")])
            .status()
            .await;
        if tokio::time::timeout(Duration::from_secs(5), child.wait())
            .await
            .is_ok()
        {
            return;
        }
        let _ = tokio::process::Command::new("kill")
            .args(["-KILL", "--", &format!("-{pid}")])
            .status()
            .await;
        let _ = child.wait().await;
        return;
    }
    let _ = child.kill().await;
    let _ = child.wait().await;
}
pub(crate) async fn headless(
    config: &Config,
    binary: &str,
    args: &[String],
    cancel: Option<CancellationToken>,
) -> Result<()> {
    if config.ghidra_gui
        && args.iter().any(|arg| arg == "-process")
        && crate::desktop::status(config, binary).await != "connected"
    {
        crate::desktop::open(config, binary).await?;
    }
    if crate::desktop::dispatch(config, binary, args, cancel.clone()).await? {
        return Ok(());
    }
    let home = config
        .ghidra_home
        .as_ref()
        .context("Set GHIDRA_HOME or ghidra_home in pistondecompiler.toml")?;
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
    let timeout = tokio::time::sleep(Duration::from_secs(config.ghidra_timeout_secs));
    tokio::pin!(timeout);
    let cancelled = async {
        match cancel {
            Some(cancel) => cancel.cancelled().await,
            None => std::future::pending().await,
        }
    };
    tokio::pin!(cancelled);
    let status = tokio::select! {
        status = child.wait() => status?,
        () = &mut cancelled => {
            terminate(&mut child, pid).await;
            anyhow::bail!("Ghidra operation cancelled; see {}", project.join("headless.log").display());
        }
        () = &mut timeout => {
            terminate(&mut child, pid).await;
            anyhow::bail!("Ghidra exceeded its time limit; see {}", project.join("headless.log").display());
        }
    };
    ensure!(
        status.success(),
        "Ghidra failed; see {}",
        project.join("headless.log").display()
    );
    Ok(())
}
pub async fn extract(db: &Db, config: &Config, binary: &str) -> Result<()> {
    extract_inner(db, config, binary, None).await
}
pub async fn extract_cancellable(
    db: &Db,
    config: &Config,
    binary: &str,
    cancel: CancellationToken,
) -> Result<()> {
    extract_inner(db, config, binary, Some(cancel)).await
}
async fn extract_inner(
    db: &Db,
    config: &Config,
    binary: &str,
    cancel: Option<CancellationToken>,
) -> Result<()> {
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
    sqlx::query("INSERT INTO extraction_progress(binary_id,phase) VALUES (?,'Ghidra startup and analysis') ON CONFLICT(binary_id) DO UPDATE SET phase=excluded.phase,completed=0,total=0,started_at=unixepoch(),phase_started_at=unixepoch(),updated_at=unixepoch(),detail='' ").bind(binary).execute(&db.pool).await?;
    let progress_path = PathBuf::from(format!("{}.progress.json", output.display()));
    if progress_path.exists() {
        tokio::fs::remove_file(&progress_path).await?;
    }
    let result = async {
        let project=config.data_dir.join("binaries").join(binary).join("ghidra/piston.gpr");
        let mut args=if project.exists() {
            vec!["-process".into(),"program.bin".into()]
        } else {
            vec!["-import".into(),row.get("path")]
        };
        args.extend(["-postScript".into(),"PistonExport.java".into(),output.to_string_lossy().into_owned()]);
        let mut extraction_config=config.clone();
        extraction_config.ghidra_gui=false;
        let operation = headless(&extraction_config, binary, &args, cancel);
        tokio::pin!(operation);
        let mut ticker = tokio::time::interval(Duration::from_secs(1));
        loop {
            tokio::select! {
                result = &mut operation => { result?; break; }
                _ = ticker.tick() => {
                    if let Err(error) = extraction_tick(db,config,binary,&progress_path).await {
                        tracing::warn!(%error,"Cannot update extraction progress");
                    }
                }
            }
        }
        sqlx::query("UPDATE extraction_progress SET phase='Importing function index',completed=0,total=0,phase_started_at=unixepoch(),updated_at=unixepoch() WHERE binary_id=?").bind(binary).execute(&db.pool).await?;
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
    if result.is_ok() {
        sqlx::query("UPDATE extraction_progress SET completed=(SELECT COUNT(*) FROM functions WHERE binary_id=?),total=(SELECT COUNT(*) FROM functions WHERE binary_id=?) WHERE binary_id=?")
            .bind(binary).bind(binary).bind(binary).execute(&db.pool).await?;
    }
    sqlx::query(
        "UPDATE extraction_progress SET phase=?,updated_at=unixepoch(),detail=? WHERE binary_id=?",
    )
    .bind(if result.is_ok() {
        "Extraction complete"
    } else {
        "Extraction failed"
    })
    .bind(
        result
            .as_ref()
            .err()
            .map(|e| format!("{e:#}"))
            .unwrap_or_default(),
    )
    .bind(binary)
    .execute(&db.pool)
    .await?;
    if result.is_ok()
        && config.ghidra_gui
        && let Err(error) = crate::desktop::open(config, binary).await
    {
        db.event(
            binary,
            "error",
            &format!("Extraction completed, but the Ghidra desktop could not open: {error:#}"),
        )
        .await?;
    }
    result
}

async fn extraction_tick(db: &Db, config: &Config, binary: &str, progress: &Path) -> Result<()> {
    use tokio::io::{AsyncReadExt, AsyncSeekExt};
    if let Ok(content) = tokio::fs::read_to_string(progress).await {
        let value: serde_json::Value = serde_json::from_str(&content)?;
        sqlx::query("UPDATE extraction_progress SET phase_started_at=CASE WHEN phase!='Decompiling functions' THEN unixepoch() ELSE phase_started_at END,phase='Decompiling functions',completed=?,total=?,detail=?,updated_at=unixepoch() WHERE binary_id=?")
            .bind(value["completed"].as_i64().unwrap_or(0)).bind(value["total"].as_i64().unwrap_or(0))
            .bind(value["function"].as_str().unwrap_or("")).bind(binary).execute(&db.pool).await?;
    } else {
        let path = config
            .data_dir
            .join("binaries")
            .join(binary)
            .join("ghidra/headless.log");
        if let Ok(mut file) = tokio::fs::File::open(path).await {
            let length = file.metadata().await?.len();
            file.seek(std::io::SeekFrom::Start(length.saturating_sub(4096)))
                .await?;
            let mut bytes = Vec::new();
            file.take(4096).read_to_end(&mut bytes).await?;
            let text = String::from_utf8_lossy(&bytes);
            let detail = text
                .lines()
                .rev()
                .find(|line| !line.trim().is_empty())
                .unwrap_or("");
            sqlx::query(
                "UPDATE extraction_progress SET detail=?,updated_at=unixepoch() WHERE binary_id=?",
            )
            .bind(detail)
            .bind(binary)
            .execute(&db.pool)
            .await?;
        }
    }
    Ok(())
}
pub async fn import_export(db: &Db, binary: &str, path: &Path) -> Result<()> {
    let mut lines = BufReader::new(tokio::fs::File::open(path).await?).lines();
    let mut tx = db.pool.begin().await?;
    let existing: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM functions WHERE binary_id=?")
        .bind(binary)
        .fetch_one(&mut *tx)
        .await?;
    ensure!(existing == 0, "binary already has indexed functions");
    let metadata_path = path.with_extension("metadata.json");
    let metadata = tokio::fs::read_to_string(metadata_path)
        .await
        .unwrap_or_else(|_| {
            r#"{"source":"imported JSONL","ghidra_version":"unknown","exporter_version":"unknown"}"#
                .into()
        });
    let _: serde_json::Value = serde_json::from_str(&metadata)?;
    let mut addresses = HashMap::new();
    let mut pending_edges = Vec::new();
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
        } else if f.pseudocode.is_empty() && f.disassembly.is_empty() {
            "code unavailable"
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
        sqlx::query("UPDATE functions SET comment=? WHERE id=?")
            .bind(&f.comment)
            .bind(&id)
            .execute(&mut *tx)
            .await?;
        sqlx::query("UPDATE functions SET type_context=? WHERE id=?")
            .bind(&f.type_context)
            .bind(&id)
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
    let (ids, edges, ranks, modules) = tokio::task::spawn_blocking(move || {
        let ranks = graph::dependency_ranks(&ids, &edges);
        let modules = graph::modules(&ids, &edges);
        (ids, edges, ranks, modules)
    })
    .await?;
    for id in &ids {
        sqlx::query("UPDATE functions SET module=? WHERE id=?")
            .bind(&modules[id])
            .bind(id)
            .execute(&mut *tx)
            .await?;
        sqlx::query("INSERT INTO jobs(id,binary_id,function_id,stage,priority) SELECT ?,?,id,'map',? FROM functions WHERE id=? AND skip_reason=''")
            .bind(uuid::Uuid::new_v4().to_string()).bind(binary).bind(-(ranks[id] as i64)).bind(id).execute(&mut *tx).await?;
    }
    crate::graph::rebuild(&mut tx, binary).await?;
    crate::knowledge::snapshot(&mut tx, binary, &metadata).await?;
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
pub async fn execute_apply(
    db: &Db,
    config: &Config,
    operation_id: &str,
    cancel: Option<CancellationToken>,
) -> Result<crate::proto::ApplyOperation> {
    let mut tx = db.pool.begin().await?;
    let changed=sqlx::query("UPDATE apply_operations SET status='applying',error='' WHERE id=? AND status IN ('preview','uncertain') AND NOT EXISTS(SELECT 1 FROM apply_operations other WHERE other.binary_id=apply_operations.binary_id AND other.id<>apply_operations.id AND other.status IN ('applying','uncertain')) AND NOT EXISTS(SELECT 1 FROM type_operations t WHERE t.binary_id=apply_operations.binary_id AND t.status IN ('applying','uncertain'))").bind(operation_id).execute(&mut *tx).await?.rows_affected();
    ensure!(
        changed == 1,
        "Change set is already applied or another unresolved writer owns this binary"
    );
    let invalid:i64=sqlx::query_scalar("SELECT COUNT(*) FROM apply_items i JOIN results r ON r.id=i.result_id WHERE i.operation_id=? AND (r.revision<>i.revision OR r.stale=1)").bind(operation_id).fetch_one(&mut *tx).await?;
    ensure!(
        invalid == 0,
        "Reviewed results changed or became stale. Create a new preview."
    );
    tx.commit().await?;
    let operation = crate::knowledge::apply_operation(db, operation_id).await?;
    let result=async {
        let folder=tokio::fs::canonicalize(config.data_dir.join("binaries").join(&operation.binary_id)).await?;
        let path=folder.join(format!("apply-{operation_id}.json"));
        let report=folder.join(format!("apply-{operation_id}-report.json"));
        tokio::fs::write(&path,serde_json::to_vec(&operation.items)?).await?;
        if report.exists(){tokio::fs::remove_file(&report).await?;}
        headless(config,&operation.binary_id,&["-process".into(),"program.bin".into(),"-noanalysis".into(),"-postScript".into(),"PistonApply.java".into(),path.to_string_lossy().into_owned(),report.to_string_lossy().into_owned()],cancel).await?;
        let outcomes:Vec<crate::proto::ApplyItem>=serde_json::from_slice(&tokio::fs::read(report).await?)?;
        ensure!(outcomes.len()==operation.items.len(),"Ghidra returned an incomplete report");
        let mut seen=HashSet::new();
        let mut tx=db.pool.begin().await?;
        for item in &outcomes {
            let expected=operation.items.iter().find(|i|i.result_id==item.result_id).context("Unknown result in Ghidra report")?;
            ensure!(seen.insert(&item.result_id)&&item.address==expected.address&&item.name==expected.name&&item.summary==expected.summary&&["applied","conflict"].contains(&item.status.as_str()),"Invalid Ghidra outcome");
            sqlx::query("UPDATE apply_items SET status=?,error=? WHERE operation_id=? AND result_id=?").bind(&item.status).bind(&item.error).bind(operation_id).bind(&item.result_id).execute(&mut *tx).await?;
            if item.status=="applied" {sqlx::query("UPDATE functions SET name=?,comment=? WHERE id=(SELECT function_id FROM results WHERE id=?)").bind(&item.name).bind(&item.summary).bind(&item.result_id).execute(&mut *tx).await?;}
        }
        let status=if outcomes.iter().any(|i|i.status=="conflict"){"conflict"}else{"applied"};
        sqlx::query("UPDATE apply_operations SET status=? WHERE id=?").bind(status).bind(operation_id).execute(&mut *tx).await?;
        tx.commit().await?;anyhow::Ok(())
    }.await;
    if let Err(error) = result {
        sqlx::query("UPDATE apply_operations SET status='uncertain',error=? WHERE id=?")
            .bind(format!("{error:#}"))
            .bind(operation_id)
            .execute(&db.pool)
            .await?;
        return Err(error);
    }
    db.event(
        &operation.binary_id,
        "info",
        &format!("Ghidra change set {operation_id} finished. Inspect item outcomes."),
    )
    .await?;
    crate::knowledge::apply_operation(db, operation_id).await
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    #[tokio::test]
    async fn cancellation_terminates_the_headless_process_group() {
        let directory = tempfile::tempdir().unwrap();
        let home = directory.path().join("ghidra");
        let support = home.join("support");
        std::fs::create_dir_all(&support).unwrap();
        let executable = support.join("analyzeHeadless");
        std::fs::write(
            &executable,
            "#!/bin/sh\nsleep 300 &\nchild=$!\necho \"$child\" > \"$1/child.pid\"\nwait \"$child\"\n",
        )
        .unwrap();
        std::fs::set_permissions(&executable, std::fs::Permissions::from_mode(0o755)).unwrap();
        let config = Config {
            data_dir: directory.path().join("data"),
            ghidra_home: Some(home),
            ghidra_timeout_secs: 60,
            ..Default::default()
        };
        let pid_path = config.data_dir.join("binaries/binary/ghidra/child.pid");
        let cancel = CancellationToken::new();
        let task_cancel = cancel.clone();
        let task =
            tokio::spawn(async move { headless(&config, "binary", &[], Some(task_cancel)).await });
        for _ in 0..100 {
            if pid_path.is_file() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        let pid = std::fs::read_to_string(&pid_path).unwrap();
        cancel.cancel();
        let error = task.await.unwrap().unwrap_err().to_string();
        assert!(error.contains("cancelled"));
        let process = PathBuf::from(format!("/proc/{}", pid.trim()));
        for _ in 0..100 {
            if !process.exists() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        assert!(
            !process.exists(),
            "headless child process survived cancellation"
        );
    }
}

/// Refresh an existing program without deleting results, reviews, or accounting.
pub async fn refresh(db: &Db, config: &Config, binary: &str) -> Result<()> {
    let folder = tokio::fs::canonicalize(config.data_dir.join("binaries").join(binary)).await?;
    let output = folder.join(format!("refresh-{}.jsonl", crate::knowledge::id()));
    headless(
        config,
        binary,
        &[
            "-process".into(),
            "program.bin".into(),
            "-noanalysis".into(),
            "-postScript".into(),
            "PistonExport.java".into(),
            output.to_string_lossy().into_owned(),
        ],
        None,
    )
    .await?;
    refresh_export(db, binary, &output).await
}
pub async fn refresh_export(db: &Db, binary: &str, path: &Path) -> Result<()> {
    let mut lines = BufReader::new(tokio::fs::File::open(path).await?).lines();
    let mut tx = db.pool.begin().await?;
    let mut seen = HashSet::new();
    while let Some(line) = lines.next_line().await? {
        if line.trim().is_empty() {
            continue;
        }
        let f: ExportFunction = serde_json::from_str(&line)?;
        ensure!(
            seen.insert(f.address.clone()),
            "Duplicate function in refreshed extraction"
        );
        let id = format!("{binary}:{}", f.address);
        let old: (String, String, Option<String>) = sqlx::query_as(
            "SELECT pseudocode,type_context,current_result_id FROM functions WHERE id=?",
        )
        .bind(&id)
        .fetch_one(&mut *tx)
        .await?;
        if (old.0 != f.pseudocode || old.1 != f.type_context)
            && let Some(result) = old.2
        {
            sqlx::query("UPDATE results SET stale=1 WHERE id=?")
                .bind(&result)
                .execute(&mut *tx)
                .await?;
            crate::knowledge::invalidate(&mut tx, &result).await?;
        }
        sqlx::query("UPDATE functions SET type_context=? WHERE id=?")
            .bind(&f.type_context)
            .bind(&id)
            .execute(&mut *tx)
            .await?;
        let changed=sqlx::query("UPDATE functions SET name=?,comment=?,pseudocode=?,disassembly=?,pcode=?,fingerprint=? WHERE id=? AND binary_id=?")
            .bind(&f.name).bind(&f.comment).bind(&f.pseudocode).bind(&f.disassembly).bind(&f.pcode).bind(hex::encode(Sha256::digest(f.pseudocode.as_bytes()))).bind(&id).bind(binary).execute(&mut *tx).await?.rows_affected();
        ensure!(
            changed == 1,
            "Refreshed function not present in original extraction"
        );
        sqlx::query("UPDATE function_search SET name=?,pseudocode=? WHERE function_id=?")
            .bind(&f.name)
            .bind(&f.pseudocode)
            .bind(&id)
            .execute(&mut *tx)
            .await?;
        for address in f.callees {
            sqlx::query("INSERT OR IGNORE INTO edges(caller,callee) SELECT ?,id FROM functions WHERE binary_id=? AND address=?").bind(&id).bind(binary).bind(address).execute(&mut *tx).await?;
        }
    }
    let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM functions WHERE binary_id=?")
        .bind(binary)
        .fetch_one(&mut *tx)
        .await?;
    ensure!(
        seen.len() as i64 == count && count > 0,
        "Refreshed extraction is incomplete"
    );

    let metadata = tokio::fs::read_to_string(path.with_extension("metadata.json")).await?;
    crate::knowledge::snapshot(&mut tx, binary, &metadata).await?;
    graph::rebuild(&mut tx, binary).await?;
    tx.commit().await?;
    Ok(())
}
