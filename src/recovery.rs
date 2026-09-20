//! CLI entry point for the same automatic recovery used by the server.
use crate::{ai::Ai, automatic, config::Config, db::Db, pipeline};
use anyhow::{Result, ensure};

pub async fn run(
    db: &Db,
    config: &Config,
    ai: &Ai,
    binary: &str,
    max_iterations: u32,
) -> Result<()> {
    ensure!(
        (1..=5).contains(&max_iterations),
        "Recovery requires 1 to 5 iterations"
    );
    ensure!(ai.config.configured(), "Configure the model and key first");
    pipeline::control(db, ai, binary, "resume").await?;
    loop {
        ensure!(!db.overview(binary).await?.paused, "Recovery is paused");
        let mut jobs = Vec::new();
        for _ in 0..ai.config.concurrency {
            if let Some(job) = pipeline::claim(db, ai, Some(binary), false).await? {
                jobs.push(job);
            } else {
                break;
            }
        }
        if jobs.is_empty() {
            match pipeline::run_state(db, binary).await? {
                pipeline::RunState::Complete => {
                    if automatic::advance(db, config, binary, max_iterations).await? {
                        return Ok(());
                    }
                }
                pipeline::RunState::BatchBlocked | pipeline::RunState::DependencyBlocked => {
                    anyhow::bail!(
                        "Provider requests are still unresolved; recovery will resume when they finish"
                    )
                }
                _ => {}
            }
            tokio::time::sleep(std::time::Duration::from_secs(1)).await;
            continue;
        }
        let outcomes = futures::future::join_all(jobs.iter().map(|job| async move {
            if crate::decisions::is_decision_stage(&job.stage) {
                match crate::decisions::analyze(ai, db, job).await {
                    Ok(c) => crate::decisions::finish(db, job, c).await,
                    Err(e) => pipeline::fail(db, ai, job, &format!("{e:#}")).await,
                }
            } else {
                match ai.analyze_job(db, job).await {
                    Ok(c) => pipeline::finish(db, ai, job, c).await,
                    Err(e) => pipeline::fail(db, ai, job, &format!("{e:#}")).await,
                }
            }
        }))
        .await;
        for outcome in outcomes {
            outcome?;
        }
    }
}
