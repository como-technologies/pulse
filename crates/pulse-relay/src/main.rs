use std::sync::Arc;
use std::time::Duration;

use axum::{Router, routing::post};
use tokio::net::TcpListener;
use tower_http::trace::TraceLayer;
use tracing_subscriber::EnvFilter;

use pulse_relay::batcher::{self, Batcher};
use pulse_relay::config::Config;
use pulse_relay::{RelayState, routes};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| EnvFilter::new("pulse_relay=info,tower_http=info")),
        )
        .with_target(true)
        .init();

    let config = Config::from_env();
    tracing::info!(
        listen_addr = %config.listen_addr,
        signal_url = %config.signal_url,
        batch_size = config.batch_size,
        batch_window_secs = config.batch_window_secs,
        min_delay_ms = config.min_delay_ms,
        max_delay_ms = config.max_delay_ms,
        request_timeout_secs = config.request_timeout_secs,
        "Configuration loaded"
    );

    let config = Arc::new(config);

    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(config.request_timeout_secs))
        .build()?;

    let batcher = Arc::new(Batcher::new(config.batch_size));

    let relay_state = Arc::new(RelayState {
        batcher: batcher.clone(),
        config: config.clone(),
        client: client.clone(),
    });

    // Shutdown signal: watch channel lets both the flush loop and the server
    // observe a single ctrl-c event.
    let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(());

    // Spawn the background flush loop with a shutdown receiver
    let flush_handle = tokio::spawn(batcher::flush_loop(
        batcher,
        config.clone(),
        client,
        shutdown_rx,
    ));

    // Trace layer — only method and path in span. No source IP, no request ID.
    let trace_layer = TraceLayer::new_for_http().make_span_with(
        |request: &axum::http::Request<axum::body::Body>| {
            tracing::info_span!(
                "relay",
                method = %request.method(),
                path = %request.uri().path(),
            )
        },
    );

    let router = Router::new()
        .route("/response", post(routes::relay_response))
        .with_state(relay_state)
        .layer(trace_layer);

    tracing::info!("Relay listening on {}", config.listen_addr);

    let listener = TcpListener::bind(&config.listen_addr).await?;
    axum::serve(listener, router)
        .with_graceful_shutdown(async move {
            tokio::signal::ctrl_c()
                .await
                .expect("failed to listen for ctrl-c");
            tracing::info!("ctrl-c received, initiating graceful shutdown");
            // Signal the flush loop to perform its final flush
            let _ = shutdown_tx.send(());
        })
        .await?;

    // Wait for the flush loop to finish its final flush
    let _ = flush_handle.await;
    tracing::info!("relay shut down cleanly");

    Ok(())
}
