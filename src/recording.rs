//! Durable manual capture sessions. Child commands are files, never shell strings.
use crate::{config::Config, db::Db, proto, runtime};
use anyhow::{Context, Result, ensure};
use serde_json::{Value, json};
use sqlx::Row;
use std::{path::PathBuf, process::Stdio, time::Duration};
use tokio_util::sync::CancellationToken;

pub fn directory(config: &Config, id: &str) -> PathBuf {
    config.data_dir.join("recordings").join(id)
}
async fn atomic(path: &std::path::Path, value: &Value) -> Result<()> {
    let temp = path.with_extension("tmp");
    tokio::fs::write(&temp, serde_json::to_vec(value)?).await?;
    tokio::fs::rename(temp, path).await?;
    Ok(())
}
pub async fn get(db: &Db, config: &Config, id: &str) -> Result<proto::Recording> {
    let r = sqlx::query("SELECT * FROM recordings WHERE id=?")
        .bind(id)
        .fetch_one(&db.pool)
        .await?;
    let progress = tokio::fs::read_to_string(directory(config, id).join("progress.json"))
        .await
        .unwrap_or_else(|_| "{}".into());
    let coverage: Option<(i64,i64)> = sqlx::query_as("SELECT COUNT(DISTINCT o.function_id),COUNT(DISTINCT CASE WHEN NOT EXISTS(SELECT 1 FROM runtime_observations p JOIN runtime_sessions s ON s.id=p.session_id WHERE s.binary_id=current.binary_id AND s.rowid<current.rowid AND p.function_id=o.function_id) THEN o.function_id END) FROM runtime_sessions current LEFT JOIN runtime_observations o ON o.session_id=current.id WHERE current.id=? GROUP BY current.id").bind(id).fetch_optional(&db.pool).await?;
    Ok(proto::Recording {
        id: id.into(),
        binary_id: r.get("binary_id"),
        scenario: r.get("scenario"),
        mode: r.get("mode"),
        status: r.get("status"),
        error: r.get("error"),
        created_at: r.get("created_at"),
        finished_at: r.get::<Option<i64>, _>("finished_at").unwrap_or(0),
        progress_json: progress,
        coverage_json: coverage
            .map(|(observed, new)| {
                json!({"observed_functions":observed,"new_functions":new}).to_string()
            })
            .unwrap_or_else(|| "{}".into()),
        analysis_run_id: r
            .get::<Option<String>, _>("analysis_run_id")
            .unwrap_or_default(),
        ghidra_status: r.get("ghidra_status"),
    })
}
pub async fn list(db: &Db, config: &Config, binary: &str) -> Result<proto::RecordingList> {
    db.binary(binary).await?;
    let ids: Vec<String> = sqlx::query_scalar(
        "SELECT id FROM recordings WHERE binary_id=? ORDER BY created_at DESC,rowid DESC LIMIT 100",
    )
    .bind(binary)
    .fetch_all(&db.pool)
    .await?;
    let mut recordings = Vec::new();
    for id in ids {
        recordings.push(get(db, config, &id).await?);
    }
    Ok(proto::RecordingList { recordings })
}
pub async fn start(db: &Db, config: &Config, r: &proto::StartRecordingRequest) -> Result<String> {
    ensure!(
        !r.scenario.trim().is_empty() && r.scenario.len() <= 256,
        "Enter a scenario of up to 256 bytes"
    );
    ensure!(
        ["explore", "investigate"].contains(&r.mode.as_str()),
        "Choose explore or investigate"
    );
    ensure!(
        (1..=3600).contains(&r.seconds),
        "Choose a duration between 1 and 3600 seconds"
    );
    ensure!(
        r.argument_count <= 8 && r.snapshot_bytes <= 4096,
        "Capture at most 8 argument slots and 4096 bytes per snapshot"
    );
    ensure!(
        !r.trace_memory || r.mode == "investigate",
        "Memory tracing requires investigate mode"
    );
    ensure!(
        r.mode != "investigate" || !r.function_ids.is_empty(),
        "Select functions for an investigation"
    );
    ensure!(
        r.function_ids.len() <= 200,
        "Investigate at most 200 functions"
    );
    ensure!(
        r.arguments.len() <= 128 && r.arguments.iter().all(|a| a.len() <= 4096),
        "Launch arguments exceed limits"
    );
    let b = db.binary(&r.binary_id).await?;
    ensure!(b.status != "extracting", "Wait for extraction to finish");
    let executable = tokio::fs::canonicalize(&r.executable)
        .await
        .context("Select the original executable on this computer")?;
    let mut plan = runtime::capture_plan(db, &r.binary_id).await?;
    let allocators: Vec<_> = config
        .runtime_allocators
        .iter()
        .filter(|a| a.binary_sha256 == b.sha256)
        .collect();
    ensure!(
        allocators.iter().all(|a| a.size_argument < 8),
        "Custom allocator argument slots must be below 8"
    );
    plan["allocator_hooks"] = serde_json::to_value(allocators)?;
    plan["function_entries"] = json!(
        plan["functions"]
            .as_array()
            .unwrap()
            .iter()
            .filter_map(|f| f["rva"].as_u64())
            .collect::<Vec<_>>()
    );
    let selected: std::collections::HashSet<String> = r.function_ids.iter().cloned().collect();
    let base = plan["image_base"]
        .as_u64()
        .context("Missing Ghidra image base")?;
    let functions = plan["functions"].as_array_mut().unwrap();
    if !selected.is_empty() {
        let rows: Vec<(String, String)> =
            sqlx::query_as("SELECT id,address FROM functions WHERE binary_id=?")
                .bind(&r.binary_id)
                .fetch_all(&db.pool)
                .await?;
        let addresses: std::collections::HashSet<u64> = rows
            .into_iter()
            .filter(|(id, _)| selected.contains(id))
            .filter_map(|(_, address)| {
                u64::from_str_radix(address.trim_start_matches("0x"), 16).ok()
            })
            .collect();
        functions.retain(|f| addresses.contains(&(base + f["rva"].as_u64().unwrap())));
    }
    ensure!(
        !functions.is_empty() && functions.len() <= 10000,
        "Select between 1 and 10000 functions"
    );
    ensure!(
        selected.is_empty() || functions.len() == selected.len(),
        "Selected functions do not belong to this binary or are not eligible"
    );
    for f in functions {
        f["arguments"] = json!(if r.mode == "investigate" {
            r.argument_count
        } else {
            0
        });
        f["snapshot_bytes"] = json!(if r.mode == "investigate" {
            r.snapshot_bytes
        } else {
            0
        });
    }
    let id = uuid::Uuid::new_v4().to_string();
    let runtime_dir = config.data_dir.join("runtime");
    tokio::fs::create_dir_all(&runtime_dir).await?;
    tokio::fs::write(
        runtime_dir.join("capture.py"),
        include_str!("../scripts/runtime/capture.py"),
    )
    .await?;
    plan["marker_script"] = json!(tokio::fs::canonicalize(runtime_dir.join("capture.py")).await?);
    plan["session_id"] = json!(id);
    plan["trace_calls"] = json!(r.mode == "investigate");
    plan["trace_blocks"] = json!(r.mode == "investigate");
    plan["trace_memory"] = json!(r.trace_memory);
    plan["trace_objects"] = json!(r.mode == "investigate");
    plan["argv"] = json!(r.arguments);
    plan["cwd"] = json!(r.working_directory);
    let root = directory(config, &id);
    tokio::fs::create_dir_all(root.join("commands")).await?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        tokio::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700)).await?;
    }
    atomic(&root.join("plan.json"), &plan).await?;
    tokio::fs::write(
        root.join("capture.py"),
        include_str!("../scripts/runtime/capture.py"),
    )
    .await?;
    tokio::fs::write(
        root.join("collector.js"),
        include_str!("../scripts/runtime/collector.js"),
    )
    .await?;
    let options = json!({"executable":executable,"pid":r.pid,"seconds":r.seconds});
    let mut tx = db.pool.begin().await?;
    // Acquiring the write lock before checking workers closes the scheduler race.
    sqlx::query("UPDATE binaries SET paused=1 WHERE id=?")
        .bind(&r.binary_id)
        .execute(&mut *tx)
        .await?;
    let active:i64=sqlx::query_scalar("SELECT COUNT(*) FROM jobs WHERE binary_id=? AND status IN ('running','batched','uncertain')").bind(&r.binary_id).fetch_one(&mut *tx).await?;
    ensure!(
        active == 0,
        "Pause analysis and wait for active jobs before recording"
    );
    sqlx::query("INSERT INTO recordings(id,binary_id,scenario,mode,status,options_json) VALUES(?,?,?,?,'starting',?)").bind(&id).bind(&r.binary_id).bind(r.scenario.trim()).bind(&r.mode).bind(options.to_string()).execute(&mut *tx).await.context("Another recording is active. Stop it first")?;
    atomic(
        &config.data_dir.join("recordings/active.json"),
        &json!({"id":id}),
    )
    .await?;
    tx.commit().await?;
    Ok(id)
}
pub async fn command(db: &Db, config: &Config, id: &str, action: &str, label: &str) -> Result<()> {
    let record = get(db, config, id).await?;
    ensure!(
        ["starting", "recording", "stopping"].contains(&record.status.as_str()),
        "Recording is not active"
    );
    ensure!(
        ["stop", "marker"].contains(&action),
        "Unknown recorder command"
    );
    ensure!(label.len() <= 256, "Marker is too long");
    atomic(
        &directory(config, id)
            .join("commands")
            .join(format!("{}.json", uuid::Uuid::new_v4())),
        &json!({"action":action,"label":if label.is_empty(){"Marker"}else{label}}),
    )
    .await?;
    if action == "stop" {
        sqlx::query("UPDATE recordings SET status='stopping' WHERE id=? AND status IN ('starting','recording')").bind(id).execute(&db.pool).await?;
    }
    Ok(())
}
pub async fn run(db: &Db, config: &Config, id: &str, cancel: CancellationToken) -> Result<()> {
    let record = get(db, config, id).await?;
    let options: String = sqlx::query_scalar("SELECT options_json FROM recordings WHERE id=?")
        .bind(id)
        .fetch_one(&db.pool)
        .await?;
    let options: Value = serde_json::from_str(&options)?;
    let root = tokio::fs::canonicalize(directory(config, id)).await?;
    let log = std::fs::File::create(root.join("capture.log"))?;
    let mut cmd = tokio::process::Command::new(&config.runtime_python);
    cmd.arg(root.join("capture.py"))
        .arg(
            options["executable"]
                .as_str()
                .context("Missing executable")?,
        )
        .arg(root.join("plan.json"))
        .arg(root.join("trace.json"))
        .args([
            "--scenario",
            &record.scenario,
            "--seconds",
            &options["seconds"].to_string(),
            "--directory",
        ])
        .arg(&root)
        .arg("--managed")
        .stdin(Stdio::piped())
        .stdout(Stdio::from(log.try_clone()?))
        .stderr(Stdio::from(log))
        .kill_on_drop(true);
    if let Some(pid) = options["pid"].as_u64().filter(|p| *p > 0) {
        cmd.args(["--pid", &pid.to_string()]);
    }
    let mut child = cmd
        .spawn()
        .context("Cannot start recorder. Configure runtime_python with Frida installed")?;
    let mut parent_pipe = child.stdin.take();
    let mut shutdown = false;
    let deadline = tokio::time::sleep(Duration::from_secs(
        options["seconds"].as_u64().unwrap_or(3600) + 60,
    ));
    tokio::pin!(deadline);
    let status = loop {
        tokio::select! {
            result=child.wait()=>break result?,
            ()=&mut deadline=>{child.kill().await?;anyhow::bail!("Recorder timed out. Recover the saved journal before analysis");},
            ()=cancel.cancelled(), if !shutdown=>{shutdown=true;parent_pipe.take();},
            ()=tokio::time::sleep(Duration::from_millis(500))=>{
                let progress=tokio::fs::read(root.join("progress.json")).await.ok().and_then(|b|serde_json::from_slice::<Value>(&b).ok());
                if progress.as_ref().is_some_and(|v|v["state"]=="recording") {sqlx::query("UPDATE recordings SET status='recording' WHERE id=? AND status='starting'").bind(id).execute(&db.pool).await?;}
            }
        }
    };
    if !status.success() {
        let log = tokio::fs::read_to_string(root.join("capture.log"))
            .await
            .unwrap_or_default();
        anyhow::bail!(
            "Capture failed: {}",
            log.chars()
                .rev()
                .take(2500)
                .collect::<String>()
                .chars()
                .rev()
                .collect::<String>()
        );
    }
    import_saved(db, config, id).await
}
pub async fn fail(db: &Db, id: &str, error: &anyhow::Error) -> Result<()> {
    sqlx::query("UPDATE recordings SET status='failed',error=?,finished_at=unixepoch() WHERE id=?")
        .bind(format!("{error:#}"))
        .bind(id)
        .execute(&db.pool)
        .await?;
    Ok(())
}
pub async fn import_saved(db: &Db, config: &Config, id: &str) -> Result<()> {
    let r = get(db, config, id).await?;
    sqlx::query("UPDATE recordings SET status='importing',error='' WHERE id=?")
        .bind(id)
        .execute(&db.pool)
        .await?;
    runtime::import(db, &r.binary_id, &directory(config, id).join("trace.json")).await?;
    sqlx::query("UPDATE recordings SET status='ready',finished_at=unixepoch() WHERE id=?")
        .bind(id)
        .execute(&db.pool)
        .await?;
    db.event(
        &r.binary_id,
        "info",
        &format!(
            "Recording '{}' imported. Runtime evidence is ready for analysis.",
            r.scenario
        ),
    )
    .await?;
    Ok(())
}
pub async fn recover(db: &Db, config: &Config, id: &str) -> Result<()> {
    let r = get(db, config, id).await?;
    ensure!(
        ["failed", "interrupted"].contains(&r.status.as_str()),
        "Only interrupted or failed recordings need recovery"
    );
    let root = tokio::fs::canonicalize(directory(config, id)).await?;
    #[cfg(target_os = "linux")]
    if let Ok(bytes) = tokio::fs::read(root.join("progress.json")).await
        && let Ok(progress) = serde_json::from_slice::<Value>(&bytes)
        && let Some(pid) = progress["recorder_pid"].as_u64()
        && let Ok(command) = tokio::fs::read(format!("/proc/{pid}/cmdline")).await
    {
        ensure!(
            !String::from_utf8_lossy(&command)
                .contains(&root.join("capture.py").display().to_string()),
            "The previous recorder is still exiting. Retry recovery after it stops"
        );
    }
    // A completed immutable trace may already have been imported before shutdown.
    if !root.join("trace.json").exists() {
        let result = tokio::process::Command::new(&config.runtime_python)
            .arg(root.join("capture.py"))
            .arg("--recover")
            .arg(&root)
            .output()
            .await?;
        ensure!(
            result.status.success(),
            "Cannot recover journal: {}",
            String::from_utf8_lossy(&result.stderr)
        );
    }
    import_saved(db, config, id).await
}
pub async fn analyze(db: &Db, ai: &crate::ai::Ai, id: &str) -> Result<()> {
    ensure!(
        ai.config.configured(),
        "Configure the model and key before analysis"
    );
    let (binary, status): (String, String) =
        sqlx::query_as("SELECT binary_id,status FROM recordings WHERE id=?")
            .bind(id)
            .fetch_one(&db.pool)
            .await?;
    ensure!(status == "ready", "Import this recording before analysis");
    let active:i64=sqlx::query_scalar("SELECT COUNT(*) FROM recordings WHERE status IN ('starting','recording','stopping','importing')").fetch_one(&db.pool).await?;
    ensure!(active == 0, "Stop the active recording first");
    let existing: Option<String> =
        sqlx::query_scalar("SELECT analysis_run_id FROM recordings WHERE id=?")
            .bind(id)
            .fetch_one(&db.pool)
            .await?;
    if let Some(run) = existing {
        sqlx::query("UPDATE binaries SET active_run_id=? WHERE id=?")
            .bind(run)
            .bind(&binary)
            .execute(&db.pool)
            .await?;
        return crate::pipeline::control(db, ai, &binary, "resume").await;
    }
    let functions:Vec<String>=sqlx::query_scalar("SELECT DISTINCT o.function_id FROM runtime_observations o JOIN functions f ON f.id=o.function_id WHERE session_id=? AND f.skip_reason='' ORDER BY o.function_id").bind(id).fetch_all(&db.pool).await?;
    ensure!(
        !functions.is_empty(),
        "This recording has no mapped functions to analyze"
    );
    let run = crate::knowledge::reanalyze_scope(
        db,
        &ai.config,
        &proto::ReanalysisRequest {
            binary_id: binary.clone(),
            function_ids: functions,
            stale_only: false,
            investigation_id: String::new(),
            stage: "map".into(),
        },
    )
    .await?;
    sqlx::query("UPDATE recordings SET analysis_run_id=? WHERE id=?")
        .bind(&run.id)
        .bind(id)
        .execute(&db.pool)
        .await?;
    crate::pipeline::control(db, ai, &binary, "resume").await
}
pub async fn publish(db: &Db, config: &Config, id: &str) -> Result<()> {
    let r = get(db, config, id).await?;
    ensure!(
        r.status == "ready",
        "Import the recording before publishing Ghidra evidence"
    );
    sqlx::query("UPDATE recordings SET ghidra_status='saving' WHERE id=?")
        .bind(id)
        .execute(&db.pool)
        .await?;
    let result: Result<()> = async {
        let functions: Vec<(String, i64)> = sqlx::query_as("SELECT f.address,COUNT(*) FROM runtime_observations o JOIN functions f ON f.id=o.function_id WHERE session_id=? GROUP BY f.id ORDER BY f.address")
            .bind(id).fetch_all(&db.pool).await?;
        let root = tokio::fs::canonicalize(directory(config, id)).await?;
        let trace: crate::runtime::Trace=serde_json::from_slice(&tokio::fs::read(root.join("trace.json")).await?)?;
        trace.validate()?;
        let calls: Vec<_>=trace.events.iter().filter_map(|event|match event.observation {
            crate::runtime::Observation::Call{site_rva,target_rva} | crate::runtime::Observation::VirtualDispatch{site_rva,target_rva,..} => Some(json!({"site":format!("{:x}",trace.image_base+site_rva),"target":format!("{:x}",trace.image_base+target_rva)})),
            _=>None,
        }).collect();
        let manifest = json!({"session":id,"scenario":r.scenario,"trace":root.join("trace.json"),"calls":calls,
            "functions":functions.into_iter().map(|(address,events)|json!({"address":address,"events":events})).collect::<Vec<_>>()});
        atomic(&root.join("ghidra.json"), &manifest).await?;
        let scripts = crate::ghidra::install_scripts(config).await?;
        let mut arguments = vec!["-process".into(), "program.bin".into(), "-noanalysis".into(),
            "-scriptPath".into(), scripts.display().to_string(), "-postScript".into(),
            "PistonRuntime.java".into(), root.join("ghidra.json").display().to_string()];
        for suffix in ["applied", "verified"] {
            let acknowledgement = root.join(format!("ghidra.json.{suffix}"));
            if acknowledgement.exists() { tokio::fs::remove_file(&acknowledgement).await?; }
            if suffix == "verified" { arguments.push("verify".into()); }
            crate::ghidra::headless(config, &r.binary_id, &arguments, None).await?;
            ensure!(tokio::fs::read_to_string(acknowledgement).await? == id,
                "Ghidra did not acknowledge runtime evidence");
        }
        crate::ghidra::refresh(db,config,&r.binary_id).await?;
        Ok(())
    }.await;
    let status = match &result {
        Ok(()) => "saved".into(),
        Err(e) => format!("Retry needed: {e:#}"),
    };
    sqlx::query("UPDATE recordings SET ghidra_status=? WHERE id=?")
        .bind(status)
        .bind(id)
        .execute(&db.pool)
        .await?;
    result
}
