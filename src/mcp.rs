//! MCP shares the web server's Ghidra gate and existing desktop dispatch.
use crate::{research, server::Service, types::TypePlan};
use rmcp::{
    ErrorData, RoleServer, ServerHandler,
    handler::server::wrapper::Parameters,
    model::{CallToolResult, ContentBlock, Implementation, ServerCapabilities, ServerConfig},
    service::RequestContext,
    tool, tool_handler, tool_router,
    transport::streamable_http_server::{
        StreamableHttpServerConfig, StreamableHttpService, session::local::LocalSessionManager,
    },
};
use serde::Deserialize;
use serde_json::Value;
use std::sync::Arc;

#[derive(Clone)]
pub struct ResearchServer {
    service: Service,
}
#[derive(Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct QueryRequest {
    pub binary_id: String,
    /// One to 32 bounded queries against the same open program.
    pub queries: Vec<research::Query>,
}
#[derive(Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AnnotationRequest {
    pub binary_id: String,
    pub annotations: Vec<research::Annotation>,
}
#[derive(Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct TypeRequest {
    pub binary_id: String,
    pub plan: TypePlan,
}
#[derive(Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct OperationRequest {
    pub operation_id: String,
}
#[derive(Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct NativeRequest {
    pub binary_id: String,
    /// Path inside this binary's private native-fixtures directory.
    pub fixture: String,
}

fn result(value: anyhow::Result<Value>) -> Result<CallToolResult, ErrorData> {
    match value {
        Ok(value) => Ok(CallToolResult::structured(value)),
        Err(error) => Ok(CallToolResult::error(vec![ContentBlock::text(format!(
            "{error:#}"
        ))])),
    }
}
impl ResearchServer {
    pub fn new(service: Service) -> Self {
        Self { service }
    }
    fn permit(&self) -> Result<tokio::sync::OwnedSemaphorePermit, ErrorData> {
        self.service
            .ghidra_gate
            .clone()
            .try_acquire_owned()
            .map_err(|_| {
                ErrorData::invalid_params(
                    "Ghidra or recording is busy; wait for its current operation",
                    None,
                )
            })
    }
    async fn perform<F, Fut>(
        &self,
        cancel: tokio_util::sync::CancellationToken,
        operation: F,
    ) -> Result<CallToolResult, ErrorData>
    where
        F: FnOnce(Service, tokio_util::sync::CancellationToken) -> Fut + Send + 'static,
        Fut: std::future::Future<Output = anyhow::Result<Value>> + Send + 'static,
    {
        let permit = self.permit()?;
        let service = self.service.clone();
        // A dropped MCP request still signals cancellation; its task retains the writer gate.
        let _cancel_on_drop = cancel.clone().drop_guard();
        let task = tokio::spawn(async move {
            let _permit = permit;
            let shutdown = service.shutdown.clone();
            let future = operation(service, cancel.clone());
            tokio::pin!(future);
            tokio::select! {
                result = &mut future => result,
                _ = shutdown.cancelled() => { cancel.cancel(); future.await }
            }
        });
        result(
            task.await
                .map_err(anyhow::Error::from)
                .and_then(|value| value),
        )
    }
}

#[tool_router]
impl ResearchServer {
    #[tool(
        description = "Execute a private SHA-256 pinned PE x64 instruction fixture using Unicorn. Fixture paths are relative to the binary's native-fixtures directory. Returns register/byte observations and explicit boundaries. Does not run the game or a comparator command.",
        annotations(read_only_hint = true)
    )]
    async fn run_native_fixture(
        &self,
        Parameters(request): Parameters<NativeRequest>,
        ctx: RequestContext<RoleServer>,
    ) -> Result<CallToolResult, ErrorData> {
        self.perform(ctx.ct, move |service, cancel| async move {
            service.db.binary(&request.binary_id).await?;
            let path = crate::native::private_fixture(
                &service.config,
                &request.binary_id,
                &request.fixture,
            )
            .await?;
            crate::native::run(
                &service.db,
                &service.config,
                &request.binary_id,
                &path,
                cancel,
            )
            .await
        })
        .await
    }
    #[tool(
        description = "List imported binaries and their build hashes. Read only.",
        annotations(read_only_hint = true)
    )]
    async fn list_binaries(&self) -> Result<CallToolResult, ErrorData> {
        result(async { Ok(serde_json::to_value(self.service.db.binaries().await?)?) }.await)
    }

    #[tool(
        description = "Inspect functions, decompile one function, search names, find callers/xrefs, read memory or inspect pointer tables. Batch up to 32 queries. Uses live Ghidra when connected; never starts a second project writer. Pointer table results do not prove class identity.",
        annotations(read_only_hint = true)
    )]
    async fn query_program(
        &self,
        Parameters(request): Parameters<QueryRequest>,
        ctx: RequestContext<RoleServer>,
    ) -> Result<CallToolResult, ErrorData> {
        self.perform(ctx.ct, move |service, cancel| async move {
            research::query(
                &service.db,
                &service.config,
                &request.binary_id,
                request.queries,
                cancel,
            )
            .await
        })
        .await
    }

    #[tool(
        description = "Preview verified names/comments against inspected values. Requires paused binary analysis. Returns a durable operation ID; apply_research_operation saves it. Does not modify the program.",
        annotations(read_only_hint = false, destructive_hint = false)
    )]
    async fn preview_annotations(
        &self,
        Parameters(request): Parameters<AnnotationRequest>,
        ctx: RequestContext<RoleServer>,
    ) -> Result<CallToolResult, ErrorData> {
        self.perform(ctx.ct, move |service, cancel| async move {
            research::preview_annotations(
                &service.db,
                &service.config,
                &request.binary_id,
                request.annotations,
                cancel,
            )
            .await
        })
        .await
    }

    #[tool(
        description = "Validate a structured type/signature plan in an isolated program. Requires paused analysis. Returns a durable operation ID and conflicts/metrics. Does not modify the live program.",
        annotations(read_only_hint = false, destructive_hint = false)
    )]
    async fn preview_research_types(
        &self,
        Parameters(request): Parameters<TypeRequest>,
        ctx: RequestContext<RoleServer>,
    ) -> Result<CallToolResult, ErrorData> {
        self.perform(ctx.ct, move |service, cancel| async move {
            research::preview_types(
                &service.db,
                &service.config,
                &request.binary_id,
                request.plan,
                cancel,
            )
            .await
        })
        .await
    }

    #[tool(
        description = "Apply and save an exact annotation/type preview. Refuses changed values. On timeout/cancellation the outcome is uncertain: inspect and retry the same operation ID to reconcile. Saves existing unsaved desktop edits too.",
        annotations(
            read_only_hint = false,
            destructive_hint = true,
            idempotent_hint = true
        )
    )]
    async fn apply_research_operation(
        &self,
        Parameters(request): Parameters<OperationRequest>,
        ctx: RequestContext<RoleServer>,
    ) -> Result<CallToolResult, ErrorData> {
        self.perform(ctx.ct, move |service, cancel| async move {
            research::apply(&service.db, &service.config, &request.operation_id, cancel).await
        })
        .await
    }

    #[tool(
        description = "Read the durable preview, outcome and error for a research operation. Read only.",
        annotations(read_only_hint = true)
    )]
    async fn get_research_operation(
        &self,
        Parameters(request): Parameters<OperationRequest>,
    ) -> Result<CallToolResult, ErrorData> {
        result(research::operation(&self.service.db, &request.operation_id).await)
    }
}

#[tool_handler]
impl ServerHandler for ResearchServer {
    fn get_info(&self) -> ServerConfig {
        ServerConfig::new(ServerCapabilities::builder().enable_tools().build())
            .with_server_info(Implementation::from_build_env())
            .with_instructions("Research the imported binary using bounded live Ghidra queries. Inspect before previewing annotations. Save only verified interpretations. Decompiler output and pointer tables are evidence, not proof of native runtime behavior. Native execution fixtures test selected instructions with explicit boundaries.")
    }
}

pub fn http(
    service: Service,
    address: std::net::SocketAddr,
) -> StreamableHttpService<ResearchServer, LocalSessionManager> {
    let mut config = StreamableHttpServerConfig::default();
    config.cancellation_token = service.shutdown.clone();
    config.allowed_hosts = vec![address.to_string(), format!("localhost:{}", address.port())];
    config.allowed_origins = vec![
        format!("http://{address}"),
        format!("http://localhost:{}", address.port()),
    ];
    StreamableHttpService::new(
        move || Ok(ResearchServer::new(service.clone())),
        Arc::new(LocalSessionManager::default()),
        config,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio_util::sync::CancellationToken;

    #[tokio::test]
    async fn dropped_request_cancels_work_but_retains_gate_until_reconciled() {
        let dir = tempfile::tempdir().unwrap();
        let db = crate::db::Db::open(&dir.path().join("test.db"))
            .await
            .unwrap();
        let config = Arc::new(crate::config::Config::default());
        let gate = Arc::new(tokio::sync::Semaphore::new(1));
        let service = Service {
            db,
            ai: Arc::new(crate::ai::Ai::new(config.ai.clone()).unwrap()),
            config,
            ghidra_gate: gate.clone(),
            shutdown: CancellationToken::new(),
        };
        let server = ResearchServer::new(service);
        let started = Arc::new(tokio::sync::Notify::new());
        let cancelled = Arc::new(tokio::sync::Notify::new());
        let reconciled = Arc::new(tokio::sync::Notify::new());
        let start = started.clone();
        let cancel = cancelled.clone();
        let done = reconciled.clone();
        let task = tokio::spawn(async move {
            server
                .perform(CancellationToken::new(), move |_, token| async move {
                    start.notify_one();
                    token.cancelled().await;
                    cancel.notify_one();
                    done.notified().await;
                    Ok(serde_json::json!({"status":"uncertain"}))
                })
                .await
        });
        started.notified().await;
        task.abort();
        cancelled.notified().await;
        assert!(gate.try_acquire().is_err());
        reconciled.notify_one();
        let _permit = tokio::time::timeout(std::time::Duration::from_secs(2), gate.acquire())
            .await
            .unwrap()
            .unwrap();
    }
}
