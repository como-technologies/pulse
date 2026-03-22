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

use pulse_crypto::blind_sig;
use pulse_identity::TokenIssuer;
use pulse_protocol::{KeyVersion, QuestionBatchId};
use pulse_signal::{InMemoryLedger, InMemoryStore, ResponseCollector};

use pulse_server::{AppState, identity_routes, signal_routes};

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

    // Generate RSA keypair for blind signatures
    tracing::info!("Generating RSA-2048 blind signature keypair...");
    let kp = blind_sig::generate_keypair()?;
    let pk = kp.pk.clone();
    tracing::info!("Keypair generated.");

    // Shared infrastructure (in-memory for Slice 0)
    let ledger = Arc::new(InMemoryLedger::new());
    let store = Arc::new(InMemoryStore::new());
    let question_batch_id = QuestionBatchId::new();

    let state = Arc::new(AppState {
        issuer: TokenIssuer::new(kp.sk, KeyVersion(1)),
        collector: ResponseCollector::new(pk, ledger, store.clone()),
        store,
        question_batch_id,
    });

    // Identity zone router (port 8001) — authenticated endpoints
    let identity_router = Router::new()
        .route("/auth", post(identity_routes::auth))
        .route("/question", get(identity_routes::get_question))
        .route("/token/sign", post(identity_routes::sign_token))
        .with_state(state.clone())
        .layer(PropagateRequestIdLayer::x_request_id())
        .layer(trace_layer("identity"))
        .layer(SetRequestIdLayer::x_request_id(MakeRequestUuid));

    // Signal zone router (port 8002) — anonymous endpoints (NO auth)
    let signal_router = Router::new()
        .route("/response", post(signal_routes::submit_response))
        .route("/debug/responses", get(signal_routes::debug_responses))
        .with_state(state.clone())
        .layer(PropagateRequestIdLayer::x_request_id())
        .layer(trace_layer("signal"))
        .layer(SetRequestIdLayer::x_request_id(MakeRequestUuid));

    tracing::info!("Identity zone listening on port 8001");
    tracing::info!("Signal zone listening on port 8002");
    tracing::info!("Question batch ID: {question_batch_id}");

    let identity_listener = TcpListener::bind("127.0.0.1:8001").await?;
    let signal_listener = TcpListener::bind("127.0.0.1:8002").await?;

    tokio::try_join!(
        axum::serve(identity_listener, identity_router).into_future(),
        axum::serve(signal_listener, signal_router).into_future(),
    )?;

    Ok(())
}
