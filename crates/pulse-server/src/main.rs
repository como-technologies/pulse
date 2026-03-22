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
use pulse_protocol::{KeyVersion, QuestionText, UnixTimestamp};
use pulse_signal::{
    InMemoryLedger, InMemoryStore, ResponseCollector, ResponseStore, SpentTokenLedger,
};

use pulse_server::config::Config;
use pulse_server::dev_auth::DevAuthenticator;
use pulse_server::dev_sampling::DevSamplingEngine;
use pulse_server::key_store::load_or_generate_keypair;
use pulse_server::sqlite_ledger::SqliteLedger;
use pulse_server::sqlite_store::SqliteStore;
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
        key_path = %config.key_path.display(),
        key_version = config.key_version,
        auth_provider = %config.auth_provider,
        sampling_provider = %config.sampling_provider,
        k_threshold = config.k_threshold,
        max_tokens_per_batch = config.max_tokens_per_batch,
        "Configuration loaded"
    );

    // Load or generate blind-signature keypair
    let kp = load_or_generate_keypair(&config.key_path)?;
    let pk = kp.pk.clone();

    // Select authentication provider
    let authenticator: Arc<dyn Authenticator> = match config.auth_provider.as_str() {
        "dev" => {
            tracing::info!("Using dev authenticator (accepts any non-empty credential)");
            Arc::new(DevAuthenticator)
        }
        other => {
            anyhow::bail!("unsupported PULSE_AUTH_PROVIDER: {other:?}; expected 'dev'");
        }
    };

    // Session store (in-memory — sessions don't need to survive restart)
    let session_store: Arc<dyn SessionStore> = Arc::new(InMemorySessionStore::new());

    // Select storage backend based on db_url
    let (ledger, store): (Arc<dyn SpentTokenLedger>, Arc<dyn ResponseStore>) =
        match config.db_url.as_str() {
            "memory" => {
                tracing::info!("Using in-memory storage (no persistence)");
                let ledger = Arc::new(InMemoryLedger::new());
                let store = Arc::new(InMemoryStore::new());
                (ledger, store)
            }
            url if url.starts_with("sqlite:") => {
                let path = std::path::Path::new(&url["sqlite:".len()..]);
                tracing::info!(path = %path.display(), "Using SQLite storage");
                let ledger = Arc::new(SqliteLedger::open(path)?);
                let store = Arc::new(SqliteStore::open(path)?);
                (ledger, store)
            }
            other => {
                anyhow::bail!(
                    "unsupported PULSE_DB_URL: {other:?}; expected 'memory' or 'sqlite:<path>'"
                );
            }
        };

    // Select sampling engine provider
    let sampling_engine: Arc<dyn SamplingEngine> = match config.sampling_provider.as_str() {
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
            Arc::new(DevSamplingEngine::new(batch, config.max_tokens_per_batch))
        }
        other => {
            anyhow::bail!("unsupported PULSE_SAMPLING_PROVIDER: {other:?}; expected 'dev'");
        }
    };

    // Identity zone state — authentication, sessions, token issuance, sampling
    let identity_state = Arc::new(IdentityState {
        issuer: TokenIssuer::with_sampling(
            kp.sk,
            KeyVersion(config.key_version),
            sampling_engine.clone(),
        ),
        authenticator,
        session_store,
        sampling_engine,
    });

    // Signal zone state — anonymous response collection
    let signal_state = Arc::new(SignalState {
        collector: ResponseCollector::new(pk, ledger, store.clone()),
        store,
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
