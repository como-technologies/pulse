use std::sync::Arc;
use std::time::Duration;

use axum::body::Bytes;
use axum::extract::State;
use axum::http::StatusCode;
use axum::response::IntoResponse;

use crate::RelayState;
use crate::batcher::ForwardResult;

/// Accept an anonymous response submission and queue it for batched forwarding.
///
/// The body is treated as opaque bytes — never deserialized, never logged.
/// No client headers are read or forwarded.
pub async fn relay_response(
    State(state): State<Arc<RelayState>>,
    body: Bytes,
) -> impl IntoResponse {
    let receiver = state.batcher.enqueue(body);

    match tokio::time::timeout(
        Duration::from_secs(state.config.request_timeout_secs),
        receiver,
    )
    .await
    {
        Ok(Ok(ForwardResult::Response { status, body })) => (status, body).into_response(),
        Ok(Ok(ForwardResult::Error(msg))) => {
            tracing::warn!(error = %msg, "upstream forwarding failed");
            StatusCode::BAD_GATEWAY.into_response()
        }
        Ok(Err(_)) => {
            // oneshot channel dropped — internal error
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
        Err(_) => {
            tracing::warn!("client timed out waiting for batch flush");
            StatusCode::GATEWAY_TIMEOUT.into_response()
        }
    }
}
