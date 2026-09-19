use crate::{
    ai::Ai,
    config::Config,
    db::Db,
    ghidra, pipeline,
    proto::{
        self,
        piston_service_server::{PistonService, PistonServiceServer},
    },
};
use anyhow::{Result, ensure};
use sqlx::Row;
use std::{path::PathBuf, sync::Arc};
use tokio::sync::Semaphore;
use tokio_util::sync::CancellationToken;
use tonic::{Request, Response, Status};
use tower::Layer;

#[derive(Clone)]
pub struct Service {
    pub db: Db,
    pub ai: Arc<Ai>,
    pub config: Arc<Config>,
    pub ghidra_gate: Arc<Semaphore>,
    pub shutdown: CancellationToken,
}
fn status(error: anyhow::Error) -> Status {
    if let Some(sqlx::Error::RowNotFound) = error.downcast_ref::<sqlx::Error>() {
        return Status::not_found("record not found");
    }
    tracing::warn!(%error,"RPC failed");
    Status::failed_precondition(format!("{error:#}"))
}
#[tonic::async_trait]
impl PistonService for Service {
    async fn list_binaries(
        &self,
        _: Request<proto::Empty>,
    ) -> Result<Response<proto::BinaryList>, Status> {
        Ok(Response::new(proto::BinaryList {
            binaries: self.db.binaries().await.map_err(status)?,
        }))
    }
    async fn import_binary(
        &self,
        request: Request<proto::ImportRequest>,
    ) -> Result<Response<proto::Binary>, Status> {
        let r = request.into_inner();
        if !r.path.is_empty() && !r.content.is_empty() {
            return Err(Status::invalid_argument(
                "provide a server path or uploaded content, not both",
            ));
        }
        if r.content.is_empty() {
            let binary = self
                .db
                .import(&PathBuf::from(r.path), &self.config)
                .await
                .map_err(status)?;
            return Ok(Response::new(binary));
        }
        let uploads = self.config.data_dir.join("uploads");
        tokio::fs::create_dir_all(&uploads)
            .await
            .map_err(|e| status(e.into()))?;
        let path = uploads.join(uuid::Uuid::new_v4().to_string());
        tokio::fs::write(&path, r.content)
            .await
            .map_err(|e| status(e.into()))?;
        let result = self.db.import(&path, &self.config).await;
        let _ = tokio::fs::remove_file(path).await;
        let mut binary = result.map_err(status)?;
        if !r.name.trim().is_empty() && binary.name.len() == 36 {
            binary.name = PathBuf::from(r.name)
                .file_name()
                .unwrap_or_default()
                .to_string_lossy()
                .chars()
                .take(255)
                .collect();
            sqlx::query("UPDATE binaries SET name=? WHERE id=?")
                .bind(&binary.name)
                .bind(&binary.id)
                .execute(&self.db.pool)
                .await
                .map_err(|e| status(e.into()))?;
        }
        Ok(Response::new(binary))
    }
    async fn get_overview(
        &self,
        r: Request<proto::BinaryRequest>,
    ) -> Result<Response<proto::Overview>, Status> {
        Ok(Response::new(
            self.db
                .overview(&r.into_inner().binary_id)
                .await
                .map_err(status)?,
        ))
    }
    async fn list_functions(
        &self,
        r: Request<proto::FunctionQuery>,
    ) -> Result<Response<proto::FunctionList>, Status> {
        Ok(Response::new(
            self.db.functions(&r.into_inner()).await.map_err(status)?,
        ))
    }
    async fn get_function(
        &self,
        r: Request<proto::FunctionRequest>,
    ) -> Result<Response<proto::FunctionDetail>, Status> {
        Ok(Response::new(
            self.db.function(&r.into_inner().id).await.map_err(status)?,
        ))
    }
    async fn list_jobs(
        &self,
        r: Request<proto::BinaryRequest>,
    ) -> Result<Response<proto::JobList>, Status> {
        let rows = sqlx::query("SELECT j.*,f.name FROM jobs j JOIN functions f ON f.id=j.function_id WHERE j.binary_id=? ORDER BY j.updated_at DESC,j.id LIMIT 500").bind(r.into_inner().binary_id).fetch_all(&self.db.pool).await.map_err(|e|status(e.into()))?;
        Ok(Response::new(proto::JobList {
            jobs: rows
                .iter()
                .map(|r| proto::Job {
                    id: r.get("id"),
                    function_id: r.get("function_id"),
                    name: r.get("name"),
                    stage: r.get("stage"),
                    status: r.get("status"),
                    attempts: r.get::<i64, _>("attempts") as u32,
                    error: r.get("error"),
                    updated_at: r.get("updated_at"),
                    reserved_usd: r.get("reserved_usd"),
                })
                .collect(),
        }))
    }
    async fn list_events(
        &self,
        r: Request<proto::BinaryRequest>,
    ) -> Result<Response<proto::EventList>, Status> {
        let rows = sqlx::query("SELECT * FROM events WHERE binary_id=? ORDER BY id DESC LIMIT 200")
            .bind(r.into_inner().binary_id)
            .fetch_all(&self.db.pool)
            .await
            .map_err(|e| status(e.into()))?;
        Ok(Response::new(proto::EventList {
            events: rows
                .iter()
                .map(|r| proto::Event {
                    id: r.get("id"),
                    created_at: r.get("created_at"),
                    level: r.get("level"),
                    message: r.get("message"),
                })
                .collect(),
        }))
    }
    async fn control_pipeline(
        &self,
        r: Request<proto::ControlRequest>,
    ) -> Result<Response<proto::Empty>, Status> {
        let r = r.into_inner();
        if r.action == "extract" || r.action == "apply" {
            self.db.binary(&r.binary_id).await.map_err(status)?;
            if self.config.ghidra_home.is_none() {
                return Err(Status::failed_precondition("Configure GHIDRA_HOME first"));
            }
            let permit = self.ghidra_gate.clone().try_acquire_owned().map_err(|_| {
                Status::resource_exhausted("Ghidra is processing another operation")
            })?;
            let service = self.clone();
            tokio::spawn(async move {
                let _permit = permit;
                let result = if r.action == "extract" {
                    ghidra::extract_cancellable(
                        &service.db,
                        &service.config,
                        &r.binary_id,
                        service.shutdown.clone(),
                    )
                    .await
                } else {
                    ghidra::apply_cancellable(
                        &service.db,
                        &service.config,
                        &r.binary_id,
                        service.shutdown.clone(),
                    )
                    .await
                    .map(|_| ())
                };
                if let Err(error) = result {
                    let _ = service
                        .db
                        .event(
                            &r.binary_id,
                            "error",
                            &format!("Ghidra operation failed: {error:#}"),
                        )
                        .await;
                }
            });
        } else {
            pipeline::control(&self.db, &self.ai, &r.binary_id, &r.action)
                .await
                .map_err(status)?;
        }
        Ok(Response::new(proto::Empty {}))
    }
    async fn review_proposal(
        &self,
        r: Request<proto::ReviewRequest>,
    ) -> Result<Response<proto::Empty>, Status> {
        let r = r.into_inner();
        pipeline::review(&self.db, &r.function_id, r.accept)
            .await
            .map_err(status)?;
        Ok(Response::new(proto::Empty {}))
    }
    async fn get_settings(
        &self,
        _: Request<proto::Empty>,
    ) -> Result<Response<proto::Settings>, Status> {
        let ai = &self.config.ai;
        Ok(Response::new(proto::Settings {
            ai_configured: ai.configured(),
            ghidra_configured: self
                .config
                .ghidra_home
                .as_ref()
                .is_some_and(|p| p.join("support/analyzeHeadless").is_file()),
            model: ai.model.clone(),
            escalation_model: ai.escalation_model.clone(),
            concurrency: ai.concurrency as u32,
            budget_usd: ai.budget_usd,
            max_input_bytes: ai.max_input_bytes as u32,
            provider_url: ai.base_url.clone(),
            batch_enabled: ai.batch_enabled,
        }))
    }
}
pub fn router(service: Service, addr: std::net::SocketAddr) -> Result<axum::Router> {
    ensure!(
        addr.ip().is_loopback(),
        "Piston currently supports loopback access only. Use an authenticated SSH tunnel for remote access."
    );
    let rpc = PistonServiceServer::new(service.clone())
        .max_decoding_message_size(128 * 1024 * 1024)
        .max_encoding_message_size(8 * 1024 * 1024);
    let grpc = tonic_web::GrpcWebLayer::new().layer(rpc);
    let policy = crate::web_security::BrowserPolicy::new(addr, &service.config.browser_origins)?;
    let router = tonic::service::Routes::new(grpc)
        .into_axum_router()
        .route(
            "/healthz",
            axum::routing::get(|| async { axum::http::StatusCode::NO_CONTENT }),
        )
        .fallback_service(
            tower_http::services::ServeDir::new(&service.config.web_dir).not_found_service(
                tower_http::services::ServeFile::new(service.config.web_dir.join("index.html")),
            ),
        )
        .layer(axum::middleware::from_fn_with_state(
            policy,
            crate::web_security::guard,
        ));
    Ok(router)
}
pub async fn serve(service: Service) -> Result<()> {
    let addr: std::net::SocketAddr = service.config.listen.parse()?;
    let router = router(service.clone(), addr)?;
    let listener = tokio::net::TcpListener::bind(addr).await?;
    tracing::info!(%addr,"Piston gRPC-Web and frontend ready");
    let cancel = service.shutdown.clone();
    let worker = if service.config.ai.configured() {
        Some(tokio::spawn(pipeline::work(
            service.db.clone(),
            service.ai.clone(),
            cancel.clone(),
        )))
    } else {
        None
    };
    axum::serve(listener, router)
        .with_graceful_shutdown(async move {
            let _ = tokio::signal::ctrl_c().await;
            cancel.cancel();
        })
        .await?;
    if let Some(worker) = worker {
        worker.await?;
    }
    // Wait for the single Ghidra writer before releasing the data-directory lock.
    let _permit = service.ghidra_gate.acquire().await?;
    Ok(())
}
