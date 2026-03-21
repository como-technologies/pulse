use std::sync::Arc;

use axum::{
    Router,
    routing::{get, post},
};
use tokio::net::TcpListener;
use uuid::Uuid;

use pulse_core::identity::TokenIssuer;
use pulse_core::signal::{InMemoryLedger, InMemoryStore, ResponseCollector};
use pulse_crypto::blind_sig;

mod identity_routes;
mod signal_routes;

/// Shared application state across both zones.
///
/// In a production system, the Identity zone and Signal zone would NOT share
/// state directly. The only shared artifact is the Token Issuer's public key.
/// For Slice 0, we keep them in one process for simplicity.
pub struct AppState {
    pub issuer: TokenIssuer,
    pub collector: ResponseCollector,
    pub store: Arc<InMemoryStore>,
    pub question_batch_id: Uuid,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt::init();

    // Generate RSA keypair for blind signatures
    tracing::info!("Generating RSA-2048 blind signature keypair...");
    let kp = blind_sig::generate_keypair()?;
    let pk = kp.pk.clone();
    tracing::info!("Keypair generated.");

    // Shared infrastructure (in-memory for Slice 0)
    let ledger = Arc::new(InMemoryLedger::new());
    let store = Arc::new(InMemoryStore::new());
    let question_batch_id = Uuid::new_v4();

    let state = Arc::new(AppState {
        issuer: TokenIssuer::new(kp.sk, 1),
        collector: ResponseCollector::new(pk, ledger, store.clone()),
        store,
        question_batch_id,
    });

    // Identity zone router (port 8001) — authenticated endpoints
    let identity_router = Router::new()
        .route("/auth", post(identity_routes::auth))
        .route("/question", get(identity_routes::get_question))
        .route("/token/sign", post(identity_routes::sign_token))
        .with_state(state.clone());

    // Signal zone router (port 8002) — anonymous endpoints (NO auth)
    let signal_router = Router::new()
        .route("/response", post(signal_routes::submit_response))
        .route("/debug/responses", get(signal_routes::debug_responses))
        .with_state(state.clone());

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
