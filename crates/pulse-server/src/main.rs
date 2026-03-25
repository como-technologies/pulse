use std::sync::Arc;

use axum::http::HeaderValue;
use axum::{
    Router,
    routing::{get, post},
};
use tokio::net::TcpListener;
use tower_http::{
    request_id::{MakeRequestId, PropagateRequestIdLayer, RequestId, SetRequestIdLayer},
    trace::TraceLayer,
};
use tracing_subscriber::EnvFilter;

use pulse_identity::{
    Authenticator, InMemorySessionStore, QuestionBatch, SamplingEngine, SessionStore, TokenIssuer,
};
use pulse_protocol::messages::ResponseType;
use pulse_protocol::{QuestionText, TenantId, UnixTimestamp};
use pulse_signal::{
    InMemoryLedger, InMemoryStore, ResponseCollector, ResponseStore, SpentTokenLedger,
};

use pulse_server::cmk::CmkProvider;
use pulse_server::config::Config;
use pulse_server::dek_store::InMemoryDekStore;
use pulse_server::dev_auth::DevAuthenticator;
use pulse_server::dev_cmk::DevCmkProvider;
use pulse_server::dev_sampling::DevSamplingEngine;
use pulse_server::dev_tenant_keys::InMemoryTenantKeyStore;
use pulse_server::encrypting_store::EncryptingResponseStore;
use pulse_server::sqlite_ledger::SqliteLedger;
use pulse_server::sqlite_store::SqliteStore;
use pulse_server::tenant_provisioner::TenantProvisioner;
use pulse_server::{IdentityState, SignalState, identity_routes, signal_routes};

#[derive(Clone)]
struct MakeRequestUuid;

impl MakeRequestId for MakeRequestUuid {
    fn make_request_id<B>(&mut self, _request: &axum::http::Request<B>) -> Option<RequestId> {
        let id = uuid::Uuid::new_v4().to_string();
        Some(RequestId::new(HeaderValue::from_str(&id).unwrap()))
    }
}

fn trace_layer(
    zone: &'static str,
) -> TraceLayer<
    tower_http::classify::SharedClassifier<tower_http::classify::ServerErrorsAsFailures>,
    impl Fn(&axum::http::Request<axum::body::Body>) -> tracing::Span + Clone,
> {
    TraceLayer::new_for_http().make_span_with(
        move |request: &axum::http::Request<axum::body::Body>| {
            let request_id = request
                .headers()
                .get("x-request-id")
                .and_then(|v: &HeaderValue| v.to_str().ok())
                .unwrap_or("unknown");
            tracing::info_span!(
                "request",
                zone = zone,
                method = %request.method(),
                path = %request.uri().path(),
                request_id = %request_id,
            )
        },
    )
}

fn create_cmk_provider(config: &Config) -> anyhow::Result<Arc<dyn CmkProvider>> {
    match config.cmk_provider.as_str() {
        "dev" => Ok(Arc::new(DevCmkProvider::new())),
        other => anyhow::bail!("unsupported PULSE_CMK_PROVIDER: {other:?}; expected 'dev'"),
    }
}

fn create_authenticator(config: &Config) -> anyhow::Result<Arc<dyn Authenticator>> {
    match config.auth_provider.as_str() {
        "dev" => {
            tracing::info!("Using dev authenticator (accepts any non-empty credential)");
            Ok(Arc::new(DevAuthenticator))
        }
        other => anyhow::bail!("unsupported PULSE_AUTH_PROVIDER: {other:?}; expected 'dev'"),
    }
}

fn create_storage(
    config: &Config,
) -> anyhow::Result<(Arc<dyn SpentTokenLedger>, Arc<dyn ResponseStore>)> {
    match config.db_url.as_str() {
        "memory" => {
            tracing::info!("Using in-memory storage (no persistence)");
            Ok((
                Arc::new(InMemoryLedger::new()),
                Arc::new(InMemoryStore::new()),
            ))
        }
        url if url.starts_with("sqlite:") => {
            let path = std::path::Path::new(&url["sqlite:".len()..]);
            tracing::info!(path = %path.display(), "Using SQLite storage");
            Ok((
                Arc::new(SqliteLedger::open(path)?),
                Arc::new(SqliteStore::open(path)?),
            ))
        }
        other => anyhow::bail!(
            "unsupported PULSE_DB_URL: {other:?}; expected 'memory' or 'sqlite:<path>'"
        ),
    }
}

fn create_sampling_engine(config: &Config) -> anyhow::Result<Arc<dyn SamplingEngine>> {
    match config.sampling_provider.as_str() {
        "dev" => {
            let batch_id = pulse_protocol::QuestionBatchId::new();
            let batch = QuestionBatch {
                id: batch_id,
                question_text: QuestionText::from("How are you feeling about work today?"),
                response_type: ResponseType::Scale5,
                expiry: UnixTimestamp(u64::MAX),
            };
            tracing::info!(
                question_batch_id = %batch_id,
                "Using dev sampling engine (accepts any employee)"
            );
            Ok(Arc::new(DevSamplingEngine::new(
                batch,
                config.max_tokens_per_batch,
            )))
        }
        other => {
            anyhow::bail!("unsupported PULSE_SAMPLING_PROVIDER: {other:?}; expected 'dev'")
        }
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| EnvFilter::new("pulse=info,tower_http=info")),
        )
        .with_target(true)
        .init();

    let config = Config::from_env();
    tracing::info!(
        identity_addr = %config.identity_addr,
        signal_addr = %config.signal_addr,
        db_url = %config.db_url,
        key_version = config.key_version,
        auth_provider = %config.auth_provider,
        sampling_provider = %config.sampling_provider,
        cmk_provider = %config.cmk_provider,
        tenant_id = %config.tenant_id,
        k_threshold = config.k_threshold,
        max_tokens_per_batch = config.max_tokens_per_batch,
        "Configuration loaded"
    );

    // Parse default tenant ID from config
    let default_tenant_id = TenantId::from_uuid(
        uuid::Uuid::parse_str(&config.tenant_id).expect("PULSE_TENANT_ID must be a valid UUID"),
    );

    let cmk = create_cmk_provider(&config)?;

    // Create DEK store and tenant key store
    let dek_store = Arc::new(InMemoryDekStore::new());
    let tenant_key_store = Arc::new(InMemoryTenantKeyStore::new());

    // Create tenant provisioner and auto-provision the default tenant
    let provisioner =
        TenantProvisioner::new(cmk.clone(), dek_store.clone(), tenant_key_store.clone());
    provisioner.provision(default_tenant_id)?;
    tracing::info!(tenant_id = %default_tenant_id, "auto-provisioned default tenant");

    let authenticator = create_authenticator(&config)?;

    // Session store (in-memory — sessions don't need to survive restart)
    let session_store: Arc<dyn SessionStore> = Arc::new(InMemorySessionStore::new());

    let (ledger, base_store) = create_storage(&config)?;

    // Wrap the base store with envelope encryption
    let store: Arc<dyn ResponseStore> = Arc::new(EncryptingResponseStore::new(
        base_store,
        dek_store.clone(),
        cmk.clone(),
    ));

    let sampling_engine = create_sampling_engine(&config)?;

    // Identity zone state — authentication, sessions, token issuance, sampling
    let identity_state = Arc::new(IdentityState {
        issuer: TokenIssuer::with_sampling(tenant_key_store.clone(), sampling_engine.clone()),
        authenticator,
        session_store,
        sampling_engine,
        tenant_id: default_tenant_id,
    });

    // Analytics engine — decrypts response payloads and aggregates by segment
    let analytics = pulse_server::analytics::AnalyticsEngine::new(
        store.clone(),
        dek_store.clone(),
        cmk.clone(),
        config.k_threshold,
    );

    // Signal zone state — anonymous response collection and analytics
    let signal_state = Arc::new(SignalState {
        collector: ResponseCollector::new(tenant_key_store, ledger, store.clone()),
        store,
        analytics: Some(analytics),
    });

    // Identity zone router — authenticated endpoints
    let identity_router = Router::new()
        .route("/auth", post(identity_routes::auth))
        .route("/question", get(identity_routes::get_questions))
        .route("/token/sign", post(identity_routes::sign_token))
        .with_state(identity_state)
        .layer(PropagateRequestIdLayer::x_request_id())
        .layer(trace_layer("identity"))
        .layer(SetRequestIdLayer::x_request_id(MakeRequestUuid));

    // Signal zone router — anonymous endpoints (NO auth)
    let signal_router = Router::new()
        .route("/response", post(signal_routes::submit_response))
        .route("/debug/responses", get(signal_routes::debug_responses))
        .route(
            "/analytics/batch/{batch_id}",
            get(pulse_server::analytics_routes::aggregate_batch),
        )
        .with_state(signal_state)
        .layer(PropagateRequestIdLayer::x_request_id())
        .layer(trace_layer("signal"))
        .layer(SetRequestIdLayer::x_request_id(MakeRequestUuid));

    tracing::info!("Identity zone listening on {}", config.identity_addr);
    tracing::info!("Signal zone listening on {}", config.signal_addr);

    let identity_listener = TcpListener::bind(&config.identity_addr).await?;
    let signal_listener = TcpListener::bind(&config.signal_addr).await?;

    tokio::try_join!(
        axum::serve(identity_listener, identity_router).into_future(),
        axum::serve(signal_listener, signal_router).into_future(),
    )?;

    Ok(())
}
