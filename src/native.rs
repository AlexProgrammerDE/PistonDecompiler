//! Private build-pinned instruction fixtures. Comparator commands stay on the local CLI.
use crate::{config::Config, db::Db};
use anyhow::{Context, Result, ensure};
use serde_json::Value;
use std::{path::Path, process::Stdio, time::Duration};
use tokio_util::sync::CancellationToken;

pub async fn run(
    db: &Db,
    config: &Config,
    binary: &str,
    fixture: &Path,
    cancel: CancellationToken,
) -> Result<Value> {
    let binary = db.binary(binary).await?;
    let path: String = sqlx::query_scalar("SELECT path FROM binaries WHERE id=?")
        .bind(&binary.id)
        .fetch_one(&db.pool)
        .await?;
    ensure!(
        tokio::fs::metadata(fixture).await?.len() <= 8 * 1024 * 1024,
        "Native fixture exceeds 8 MiB"
    );
    let fixture_value: Value = serde_json::from_slice(&tokio::fs::read(fixture).await?)?;
    ensure!(
        fixture_value["sha256"] == binary.sha256,
        "Native fixture belongs to another binary build"
    );
    let scripts = config.data_dir.join("native-tools/piston_native");
    tokio::fs::create_dir_all(&scripts).await?;
    for (name, source) in [
        (
            "__init__.py",
            include_str!("../scripts/native/piston_native/__init__.py"),
        ),
        (
            "__main__.py",
            include_str!("../scripts/native/piston_native/__main__.py"),
        ),
    ] {
        tokio::fs::write(scripts.join(name), source).await?;
    }
    let folder = config.data_dir.join("binaries").join(&binary.id);
    let id = uuid::Uuid::new_v4();
    let input = folder.join(format!("native-{id}.json"));
    let output = folder.join(format!("native-{id}-report.json"));
    tokio::fs::write(&input, serde_json::to_vec(&fixture_value)?).await?;
    let log = std::fs::File::create(folder.join(format!("native-{id}.log")))?;
    let mut child = tokio::process::Command::new(&config.runtime_python)
        .env(
            "PYTHONPATH",
            tokio::fs::canonicalize(config.data_dir.join("native-tools")).await?,
        )
        .args(["-m", "piston_native"])
        .arg(tokio::fs::canonicalize(input).await?)
        .arg("--binary")
        .arg(path)
        .arg("--output")
        .arg(&output)
        .stdin(Stdio::null())
        .stdout(log.try_clone()?)
        .stderr(log)
        .kill_on_drop(true)
        .spawn()
        .context("Cannot start native fixture runner")?;
    let status = tokio::select! {
        result = child.wait() => result?,
        _ = cancel.cancelled() => { child.kill().await?; child.wait().await?; anyhow::bail!("Native fixture cancelled"); }
        _ = tokio::time::sleep(Duration::from_secs(120)) => { child.kill().await?; child.wait().await?; anyhow::bail!("Native fixture exceeded 120 seconds"); }
    };
    ensure!(
        status.success(),
        "Native fixture failed; inspect native-{id}.log in the binary directory"
    );
    ensure!(
        tokio::fs::metadata(&output).await?.len() <= 16 * 1024 * 1024,
        "Native fixture report exceeds 16 MiB"
    );
    Ok(serde_json::from_slice(&tokio::fs::read(output).await?)?)
}

pub async fn private_fixture(
    config: &Config,
    binary: &str,
    relative: &str,
) -> Result<std::path::PathBuf> {
    ensure!(
        !Path::new(relative).is_absolute(),
        "Use a fixture path relative to native-fixtures"
    );
    let root = tokio::fs::canonicalize(
        config
            .data_dir
            .join("binaries")
            .join(binary)
            .join("native-fixtures"),
    )
    .await?;
    let path = tokio::fs::canonicalize(root.join(relative)).await?;
    ensure!(
        path.starts_with(&root),
        "Fixture path leaves the private fixture directory"
    );
    Ok(path)
}
