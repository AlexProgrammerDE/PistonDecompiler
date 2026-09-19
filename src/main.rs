use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use fs2::FileExt;
use piston_decompiler::{
    ai::Ai,
    batch,
    config::Config,
    db::Db,
    ghidra, pipeline,
    server::{self, Service},
};
use std::{path::PathBuf, sync::Arc};
use tokio_util::sync::CancellationToken;

#[derive(Parser)]
#[command(
    name = "piston",
    version,
    about = "Persistent Ghidra and AI binary analysis"
)]
struct Cli {
    #[arg(long, default_value = "piston.toml", global = true)]
    config: PathBuf,
    #[command(subcommand)]
    command: Command,
}
#[derive(Subcommand)]
enum Command {
    /// Serve the gRPC-Web API, web app and durable AI workers.
    Serve,
    /// Import a binary. Ghidra never executes the input program.
    Import {
        path: PathBuf,
        #[arg(long)]
        extract: bool,
    },
    /// Run Ghidra headless extraction and build indexes.
    Extract { binary: String },
    /// Import a previously exported PistonExport JSONL file.
    ImportExport { binary: String, path: PathBuf },
    /// Run queued AI work until complete, paused or interrupted.
    Run { binary: String },
    /// Inspect binary status and accounting as JSON.
    Status { binary: Option<String> },
    /// Pause, resume, or retry failed/uncertain jobs.
    Control {
        binary: String,
        #[arg(value_parser=["pause","resume","retry"])]
        action: String,
    },
    /// Accept or reject the latest proposal for a function.
    Review {
        function: String,
        #[arg(long)]
        accept: bool,
    },
    /// Apply accepted proposals through the single Ghidra writer.
    Apply { binary: String },
    /// Manage true asynchronous provider batches.
    Batch {
        #[command(subcommand)]
        command: BatchCommand,
    },
}
#[derive(Subcommand)]
enum BatchCommand {
    Submit { binary: String },
    Collect { id: String },
    Attach { id: String, remote: String },
    List,
}
#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "piston_decompiler=info".into()),
        )
        .with_writer(std::io::stderr)
        .init();
    let cli = Cli::parse();
    let config = Arc::new(Config::load(&cli.config)?);
    tokio::fs::create_dir_all(&config.data_dir).await?;
    let lock = std::fs::OpenOptions::new()
        .create(true)
        .truncate(false)
        .read(true)
        .write(true)
        .open(config.data_dir.join("piston.lock"))?;
    lock.try_lock_exclusive()
        .context("data directory is in use; use the web API while the server is running")?;
    let db = Db::open(&config.data_dir.join("piston.db")).await?;
    db.recover().await?;
    let ai = Arc::new(Ai::new(config.ai.clone())?);
    match cli.command {
        Command::Serve => {
            server::serve(Service {
                db,
                ai,
                config,
                ghidra_gate: Arc::new(tokio::sync::Semaphore::new(1)),
                shutdown: CancellationToken::new(),
            })
            .await?
        }
        Command::Import { path, extract } => {
            let b = db.import(&path, &config).await?;
            println!("{}", serde_json::to_string_pretty(&b)?);
            if extract {
                ghidra::extract(&db, &config, &b.id).await?;
            }
        }
        Command::Extract { binary } => ghidra::extract(&db, &config, &binary).await?,
        Command::ImportExport { binary, path } => {
            db.binary(&binary).await?;
            ghidra::import_export(&db, &binary, &path).await?;
        }
        Command::Status { binary } => match binary {
            Some(id) => println!(
                "{}",
                serde_json::to_string_pretty(&db.overview(&id).await?)?
            ),
            None => println!("{}", serde_json::to_string_pretty(&db.binaries().await?)?),
        },
        Command::Control { binary, action } => {
            pipeline::control(&db, &ai, &binary, &action).await?
        }
        Command::Review { function, accept } => pipeline::review(&db, &function, accept).await?,
        Command::Apply { binary } => {
            println!(
                "Applied {} proposals",
                ghidra::apply(&db, &config, &binary).await?
            );
        }
        Command::Run { binary } => {
            pipeline::control(&db, &ai, &binary, "resume").await?;
            // CLI run is scoped to this binary. Other projects remain paused.
            sqlx::query("UPDATE binaries SET paused=1 WHERE id<>?")
                .bind(&binary)
                .execute(&db.pool)
                .await?;
            let cancel = CancellationToken::new();
            let worker = tokio::spawn(pipeline::work(db.clone(), ai, cancel.clone()));
            loop {
                tokio::select! { _ = tokio::signal::ctrl_c() => break, () = tokio::time::sleep(std::time::Duration::from_secs(1)) => {} }
                let o = db.overview(&binary).await?;
                if o.paused || o.queued + o.running == 0 {
                    break;
                }
            }
            cancel.cancel();
            worker.await?;
            println!(
                "{}",
                serde_json::to_string_pretty(&db.overview(&binary).await?)?
            );
        }
        Command::Batch { command } => match command {
            BatchCommand::Submit { binary } => {
                println!("{}", batch::submit(&db, &ai, &config, &binary).await?)
            }
            BatchCommand::Collect { id } => println!("{}", batch::collect(&db, &ai, &id).await?),
            BatchCommand::Attach { id, remote } => batch::attach(&db, &id, &remote).await?,
            BatchCommand::List => {
                use sqlx::Row;
                for row in
                    sqlx::query("SELECT id,remote_id,status FROM batches ORDER BY created_at DESC")
                        .fetch_all(&db.pool)
                        .await?
                {
                    println!(
                        "{}\t{}\t{}",
                        row.get::<String, _>("id"),
                        row.get::<String, _>("remote_id"),
                        row.get::<String, _>("status")
                    );
                }
            }
        },
    }
    Ok(())
}
