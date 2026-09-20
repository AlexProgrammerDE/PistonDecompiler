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
    name = "pistondecompiler",
    version,
    about = "Persistent Ghidra and AI binary analysis"
)]
struct Cli {
    #[arg(long, default_value = "pistondecompiler.toml", global = true)]
    config: PathBuf,
    #[command(subcommand)]
    command: Command,
}
#[derive(Subcommand)]
enum Command {
    /// Serve the gRPC-Web API, web app and durable AI workers.
    Serve,
    /// Open the native Ghidra desktop for an extracted binary.
    OpenGhidra {
        binary: String,
    },
    /// Run callee-first recovery with bounded type and decompilation iterations.
    Recover {
        binary: String,
        #[arg(long, default_value_t = 3)]
        iterations: u32,
        #[arg(long)]
        apply_types: bool,
    },
    /// Preview and merge structured type proposals against the current Ghidra program.
    PreviewTypes {
        #[arg(required = true)]
        results: Vec<String>,
    },
    /// Apply an exact type preview and refresh Ghidra evidence.
    ApplyTypes {
        operation: String,
    },
    /// Refresh decompilation from the existing Ghidra program.
    Refresh {
        binary: String,
    },
    /// Import normalized runtime observations while the binary is paused.
    ImportTrace {
        binary: String,
        path: PathBuf,
    },
    /// Report observed coverage and unresolved regions.
    RecoveryStatus {
        binary: String,
    },
    CapturePlan {
        binary: String,
    },
    Coverage {
        binary: String,
    },
    /// Import a binary. Ghidra never executes the input program.
    Import {
        path: PathBuf,
        #[arg(long)]
        extract: bool,
    },
    /// Run Ghidra headless extraction and build indexes.
    Extract {
        binary: String,
    },
    /// Import a previously exported PistonExport JSONL file.
    ImportExport {
        binary: String,
        path: PathBuf,
    },
    /// Run queued AI work until complete, paused or interrupted.
    Run {
        binary: String,
    },
    /// Inspect binary status and accounting as JSON.
    Status {
        binary: Option<String>,
    },
    /// Inspect a function, its evidence, and durable decision assessments.
    Inspect {
        function: String,
    },
    /// Pause, resume, or retry failed/uncertain jobs.
    Control {
        binary: String,
        #[arg(value_parser=["pause","resume","retry","all"])]
        action: String,
    },
    /// Review an exact result revision.
    Review {
        result: String,
        #[arg(long)]
        revision: u32,
        #[arg(long)]
        accept: bool,
    },
    /// Apply accepted proposals through the single Ghidra writer.
    Preview {
        binary: String,
    },
    Apply {
        operation: String,
    },
    /// Manage true asynchronous provider batches.
    Batch {
        #[command(subcommand)]
        command: BatchCommand,
    },
}
#[derive(Subcommand)]
enum BatchCommand {
    Submit {
        binary: String,
    },
    Collect {
        id: String,
    },
    Attach {
        id: String,
        remote: String,
    },
    /// Return an abandoned batch to the queue. Inspect the provider first for uncertain submissions.
    Abandon {
        id: String,
        #[arg(long)]
        confirmed_not_submitted: bool,
    },
    List,
}
fn main() -> Result<()> {
    let cli = Cli::parse();
    let env_path = cli.config.with_file_name(".env");
    if let Err(error) = dotenvy::from_path(&env_path) {
        anyhow::ensure!(
            error.not_found(),
            "Cannot load {}. Check file permissions and dotenv syntax.",
            env_path.display()
        );
    }
    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?
        .block_on(run(cli))
}

async fn run(cli: Cli) -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "piston_decompiler=info".into()),
        )
        .with_writer(std::io::stderr)
        .init();
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
        Command::OpenGhidra { binary } => {
            piston_decompiler::desktop::open(&config, &binary).await?
        }
        Command::PreviewTypes { results } => println!(
            "{}",
            serde_json::to_string_pretty(
                &piston_decompiler::types::preview_many(&db, &config, &results).await?
            )?
        ),
        Command::ApplyTypes { operation } => {
            piston_decompiler::types::apply(&db, &config, &operation).await?
        }
        Command::Refresh { binary } => ghidra::refresh(&db, &config, &binary).await?,
        Command::ImportTrace { binary, path } => println!(
            "{}",
            piston_decompiler::runtime::import(&db, &binary, &path).await?
        ),
        Command::RecoveryStatus { binary } => {
            use sqlx::Row;
            let rows =
                sqlx::query("SELECT * FROM recovery_iterations WHERE binary_id=? ORDER BY rowid")
                    .bind(&binary)
                    .fetch_all(&db.pool)
                    .await?;
            let records:Vec<_>=rows.iter().map(|r|serde_json::json!({"id":r.get::<String,_>("id"),"component":r.get::<String,_>("component_id"),"iteration":r.get::<i64,_>("iteration"),"run_id":r.get::<String,_>("run_id"),"status":r.get::<String,_>("status"),"error":r.get::<String,_>("error")})).collect();
            println!("{}", serde_json::to_string_pretty(&records)?);
        }
        Command::CapturePlan { binary } => println!(
            "{}",
            serde_json::to_string_pretty(
                &piston_decompiler::runtime::capture_plan(&db, &binary).await?
            )?
        ),
        Command::Coverage { binary } => println!(
            "{}",
            serde_json::to_string_pretty(
                &piston_decompiler::runtime::coverage(&db, &binary).await?
            )?
        ),
        Command::Recover {
            binary,
            iterations,
            apply_types,
        } => {
            let recovery = piston_decompiler::recovery::run(
                &db,
                &config,
                &ai,
                &binary,
                iterations,
                apply_types,
            );
            tokio::pin!(recovery);
            let mut ticker = tokio::time::interval(std::time::Duration::from_secs(5));
            loop {
                tokio::select! {
                    result = &mut recovery => { result?; break; }
                    _ = ticker.tick() => {
                        match piston_decompiler::progress::reports(&db, &binary).await {
                            Ok(reports) => tracing::info!(progress=%serde_json::to_string(&reports)?, "Recovery progress"),
                            Err(error) => tracing::warn!(%error, "Cannot read recovery progress"),
                        }
                    }
                }
            }
        }
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
        Command::Inspect { function } => println!(
            "{}",
            serde_json::to_string_pretty(&db.function(&function).await?)?
        ),
        Command::Control { binary, action } => {
            pipeline::control(&db, &ai, &binary, &action).await?
        }
        Command::Review {
            result,
            revision,
            accept,
        } => {
            pipeline::review(
                &db,
                &piston_decompiler::proto::ReviewRequest {
                    result_id: result,
                    expected_revision: revision,
                    field: "both".into(),
                    decision: if accept { "accepted" } else { "rejected" }.into(),
                    reason: String::new(),
                },
            )
            .await?
        }
        Command::Preview { binary } => println!(
            "{}",
            serde_json::to_string_pretty(
                &piston_decompiler::knowledge::preview_apply(&db, &binary).await?
            )?
        ),
        Command::Apply { operation } => println!(
            "{}",
            serde_json::to_string_pretty(
                &ghidra::execute_apply(&db, &config, &operation, None).await?
            )?
        ),
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
                if o.paused {
                    break;
                }
                match pipeline::run_state(&db, &binary).await? {
                    pipeline::RunState::Work | pipeline::RunState::Waiting => {}
                    pipeline::RunState::BatchBlocked => {
                        eprintln!(
                            "Local analysis is waiting for an asynchronous provider batch. Run `pistondecompiler batch list`, then collect the completed batch."
                        );
                        break;
                    }
                    pipeline::RunState::DependencyBlocked => {
                        eprintln!(
                            "Analysis is blocked by uncertain callee requests. Inspect their accounting before retrying."
                        );
                        break;
                    }
                    pipeline::RunState::Complete => break,
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
            BatchCommand::Abandon {
                id,
                confirmed_not_submitted,
            } => batch::abandon(&db, &id, confirmed_not_submitted).await?,
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
