//! Native Ghidra desktop ownership. Operations use its live Program, never a second writer.
use crate::{config::Config, ghidra};
use anyhow::{Context, Result, bail, ensure};
use serde::Deserialize;
use std::{
    path::{Path, PathBuf},
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tokio_util::sync::CancellationToken;

#[derive(Deserialize)]
struct Session {
    session: String,
    updated_at: u64,
    pid: u64,
    ready: bool,
}
fn directory(config: &Config, binary: &str) -> PathBuf {
    config
        .data_dir
        .join("binaries")
        .join(binary)
        .join("desktop")
}
fn process_alive(pid: u64) -> bool {
    #[cfg(target_os = "linux")]
    {
        Path::new("/proc").join(pid.to_string()).exists()
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = pid;
        true
    }
}
async fn session(config: &Config, binary: &str) -> Result<Option<Session>> {
    let path = directory(config, binary).join("session.json");
    if !path.exists() {
        return Ok(None);
    }
    let state: Session = serde_json::from_slice(&tokio::fs::read(path).await?)?;
    if !process_alive(state.pid) {
        tokio::fs::remove_file(directory(config, binary).join("session.json")).await?;
        return Ok(None);
    }
    let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
    ensure!(
        state.ready && now.saturating_sub(state.updated_at) < 10,
        "Ghidra desktop disconnected. Close its project and reopen Ghidra before retrying; no headless fallback is allowed while desktop ownership is uncertain."
    );
    Ok(Some(state))
}

pub async fn dispatch(
    config: &Config,
    binary: &str,
    args: &[String],
    cancel: Option<CancellationToken>,
) -> Result<bool> {
    let Some(state) = session(config, binary).await? else {
        ensure!(
            status(config, binary).await != "starting",
            "Ghidra desktop is starting; finish its native prompts before running an operation"
        );
        return Ok(false);
    };
    let script = args
        .iter()
        .position(|s| s == "-postScript")
        .context("Desktop operations require a Piston script")?;
    ensure!(
        !args.iter().any(|s| s == "-import"),
        "Close Ghidra before reimporting the project"
    );
    let name = args
        .get(script + 1)
        .context("Missing desktop script name")?;
    ensure!(
        [
            "PistonExport.java",
            "PistonTypes.java",
            "PistonApply.java",
            "PistonRuntime.java"
        ]
        .contains(&name.as_str()),
        "Unsupported desktop script"
    );
    request(config, binary, &state, name, &args[script + 2..], cancel).await?;
    Ok(true)
}

async fn request(
    config: &Config,
    binary: &str,
    state: &Session,
    script: &str,
    args: &[String],
    cancel: Option<CancellationToken>,
) -> Result<()> {
    let root = directory(config, binary);
    let id = uuid::Uuid::new_v4().to_string();
    let input = root.join(format!("{id}.request.json"));
    let output = root.join(format!("{id}.response.json"));
    let temp = root.join(format!("{id}.tmp"));
    tokio::fs::write(
        &temp,
        serde_json::to_vec(
            &serde_json::json!({"session":state.session,"script":script,"args":args}),
        )?,
    )
    .await?;
    tokio::fs::rename(temp, &input).await?;
    let wait = async {
        loop {
            if output.exists() {
                let report: serde_json::Value =
                    serde_json::from_slice(&tokio::fs::read(&output).await?)?;
                tokio::fs::remove_file(&output).await?;
                ensure!(
                    report["ok"] == true,
                    "Ghidra desktop operation failed: {}",
                    report["error"]
                );
                return Ok(());
            }
            let current = session(config, binary)
                .await?
                .context("Ghidra desktop closed during the operation; reconcile before retrying")?;
            ensure!(
                current.session == state.session,
                "Ghidra desktop session changed during the operation"
            );
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    };
    let cancelled = async {
        match cancel {
            Some(c) => c.cancelled().await,
            None => std::future::pending().await,
        }
    };
    tokio::select! {
        result=wait=>result,
        _=tokio::time::sleep(Duration::from_secs(config.ghidra_timeout_secs))=>{
            tokio::fs::write(format!("{}.cancel",input.display()),b"").await?;
            bail!("Ghidra desktop operation timed out. Cancellation requested; reconcile the operation before retrying.")
        }
        _=cancelled=>{
            tokio::fs::write(format!("{}.cancel",input.display()),b"").await?;
            bail!("Ghidra desktop operation cancelled; reconcile its outcome before retrying.")
        }
    }
}

fn jars(directory: &Path, paths: &mut Vec<PathBuf>) -> Result<()> {
    for entry in std::fs::read_dir(directory)? {
        let entry = entry?;
        let path = entry.path();
        if entry.file_type()?.is_dir() {
            jars(&path, paths)?;
        } else if path.extension().is_some_and(|s| s == "jar") {
            paths.push(path);
        }
    }
    Ok(())
}

pub async fn open(config: &Config, binary: &str) -> Result<()> {
    if let Some(state) = session(config, binary).await? {
        return request(config, binary, &state, "focus", &[], None).await;
    }
    let home = tokio::fs::canonicalize(
        config
            .ghidra_home
            .as_ref()
            .context("Configure GHIDRA_HOME first")?,
    )
    .await?;
    let folder = tokio::fs::canonicalize(config.data_dir.join("binaries").join(binary)).await?;
    let project = folder.join("ghidra/piston.gpr");
    ensure!(
        project.exists(),
        "Extract this binary before opening Ghidra"
    );
    let root = directory(config, binary);
    tokio::fs::create_dir_all(&root).await?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        tokio::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700)).await?;
    }
    let root = tokio::fs::canonicalize(root).await?;
    // Serialize desktop launches across CLI/API callers without taking Ghidra's project lock.
    let lock = std::fs::OpenOptions::new()
        .create(true)
        .truncate(false)
        .read(true)
        .write(true)
        .open(root.join("launch.lock"))?;
    fs2::FileExt::try_lock_exclusive(&lock).context("Ghidra desktop is already starting")?;
    let launch_path = root.join("launch.json");
    if let Ok(bytes) = tokio::fs::read(&launch_path).await {
        let launch: serde_json::Value = serde_json::from_slice(&bytes)?;
        if launch["pid"].as_u64().is_some_and(process_alive) {
            bail!(
                "Ghidra is already starting. Complete any prompts in its native window, then try again."
            );
        }
    }
    let scripts = ghidra::install_scripts(config).await?;
    tokio::fs::write(
        root.join("PistonDesktop.java"),
        include_str!("../ghidra/PistonDesktop.java"),
    )
    .await?;
    tokio::fs::write(
        root.join("PistonLaunch.java"),
        include_str!("../ghidra/PistonLaunch.java"),
    )
    .await?;
    let classes = root.join("classes");
    tokio::fs::create_dir_all(&classes).await?;
    let mut libraries = Vec::new();
    jars(&home.join("Ghidra"), &mut libraries)?;
    let classpath = std::env::join_paths(&libraries)?;
    let javac = std::env::var_os("JAVA_HOME")
        .map(|p| PathBuf::from(p).join("bin/javac"))
        .unwrap_or("javac".into());
    let compiled = tokio::process::Command::new(javac)
        .arg("-cp")
        .arg(classpath)
        .arg("-d")
        .arg(&classes)
        .args([
            root.join("PistonLaunch.java"),
            root.join("PistonDesktop.java"),
            scripts.join("PistonExport.java"),
            scripts.join("PistonApply.java"),
            scripts.join("PistonTypes.java"),
            scripts.join("PistonRuntime.java"),
        ])
        .output()
        .await
        .context("A JDK is required to launch the Ghidra desktop connection")?;
    ensure!(
        compiled.status.success(),
        "Cannot compile Ghidra desktop connection: {}",
        String::from_utf8_lossy(&compiled.stderr)
    );
    let launcher = root.join("launcher");
    tokio::fs::create_dir_all(&launcher).await?;
    tokio::fs::copy(
        classes.join("PistonLaunch.class"),
        launcher.join("PistonLaunch.class"),
    )
    .await?;
    let log = std::fs::File::create(root.join("desktop.log"))?;
    let java = std::env::var_os("JAVA_HOME")
        .map(|p| PathBuf::from(p).join("bin/java"))
        .unwrap_or("java".into());
    let mut process = tokio::process::Command::new(java);
    process
        .arg("-Djava.system.class.loader=ghidra.GhidraClassLoader")
        .arg("-cp")
        .arg(std::env::join_paths([
            home.join("Ghidra/Framework/Utility/lib/Utility.jar"),
            launcher,
        ])?)
        .arg("PistonLaunch")
        .arg(classes)
        .arg(project)
        .arg(&root)
        .arg(uuid::Uuid::new_v4().to_string())
        .stdin(std::process::Stdio::null())
        .stdout(log.try_clone()?)
        .stderr(log);
    let mut child = process.spawn().context("Cannot open Ghidra desktop")?;
    tokio::fs::write(
        launch_path,
        serde_json::to_vec(&serde_json::json!({"pid":child.id()}))?,
    )
    .await?;
    for _ in 0..240 {
        if session(config, binary).await?.is_some() {
            // Reap the process if this backend remains alive; the desktop otherwise owns its lifetime.
            tokio::spawn(async move {
                let _ = child.wait().await;
            });
            return Ok(());
        }
        if let Some(status) = child.try_wait()? {
            bail!(
                "Ghidra desktop exited ({status}); see {}",
                root.join("desktop.log").display()
            );
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
    tokio::spawn(async move {
        let _ = child.wait().await;
    });
    bail!(
        "Ghidra is still starting or needs attention in its native window. See {}",
        root.join("desktop.log").display()
    )
}

pub async fn status(config: &Config, binary: &str) -> String {
    match session(config, binary).await {
        Ok(Some(_)) => "connected".into(),
        Ok(None) => {
            let path = directory(config, binary).join("launch.json");
            if let Ok(bytes) = tokio::fs::read(path).await
                && let Ok(launch) = serde_json::from_slice::<serde_json::Value>(&bytes)
                && launch["pid"].as_u64().is_some_and(process_alive)
            {
                return "starting".into();
            }
            "closed".into()
        }
        Err(_) => "disconnected".into(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    async fn fixture() -> (tempfile::TempDir, Config) {
        let dir = tempfile::tempdir().unwrap();
        let config = Config {
            data_dir: dir.path().to_owned(),
            ghidra_timeout_secs: 1,
            ..Default::default()
        };
        let root = directory(&config, "b");
        tokio::fs::create_dir_all(&root).await.unwrap();
        tokio::fs::write(root.join("session.json"),serde_json::to_vec(&serde_json::json!({"session":"test","pid":std::process::id(),"ready":true,"updated_at":SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs()})).unwrap()).await.unwrap();
        (dir, config)
    }
    #[tokio::test]
    async fn desktop_dispatch_awaits_acknowledgement() {
        let (_dir, config) = fixture().await;
        let root = directory(&config, "b");
        let responder = tokio::spawn(async move {
            loop {
                let mut entries = tokio::fs::read_dir(&root).await.unwrap();
                while let Some(entry) = entries.next_entry().await.unwrap() {
                    if entry.path().to_string_lossy().ends_with(".request.json") {
                        let request: serde_json::Value =
                            serde_json::from_slice(&tokio::fs::read(entry.path()).await.unwrap())
                                .unwrap();
                        assert_eq!(request["session"], "test");
                        assert_eq!(request["args"].as_array().unwrap().len(), 1);
                        let response = entry
                            .path()
                            .to_string_lossy()
                            .replace(".request.json", ".response.json");
                        tokio::fs::write(response, b"{\"ok\":true}").await.unwrap();
                        return;
                    }
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        });
        assert!(
            dispatch(
                &config,
                "b",
                &[
                    "-postScript".into(),
                    "PistonExport.java".into(),
                    "export.jsonl".into()
                ],
                None
            )
            .await
            .unwrap()
        );
        responder.await.unwrap();
    }
    #[tokio::test]
    async fn desktop_rejects_imports_and_uncertain_ownership() {
        let (_dir, config) = fixture().await;
        assert!(
            dispatch(
                &config,
                "b",
                &[
                    "-import".into(),
                    "-postScript".into(),
                    "PistonExport.java".into()
                ],
                None
            )
            .await
            .is_err()
        );
        let state = directory(&config, "b").join("session.json");
        let mut value: serde_json::Value =
            serde_json::from_slice(&tokio::fs::read(&state).await.unwrap()).unwrap();
        value["updated_at"] = serde_json::json!(0);
        tokio::fs::write(state, serde_json::to_vec(&value).unwrap())
            .await
            .unwrap();
        assert!(dispatch(&config, "b", &[], None).await.is_err());
    }
    #[tokio::test]
    async fn timeout_requests_cancellation_without_headless_fallback() {
        let (_dir, config) = fixture().await;
        assert!(
            dispatch(
                &config,
                "b",
                &[
                    "-postScript".into(),
                    "PistonExport.java".into(),
                    "out".into()
                ],
                None
            )
            .await
            .is_err()
        );
        let files = std::fs::read_dir(directory(&config, "b")).unwrap();
        assert!(files.into_iter().any(|entry| {
            entry
                .unwrap()
                .path()
                .extension()
                .is_some_and(|s| s == "cancel")
        }));
    }
}
