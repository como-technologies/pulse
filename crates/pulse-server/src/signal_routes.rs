use std::sync::Arc;

use axum::{Json, extract::State, http::StatusCode, response::IntoResponse};
use serde::Serialize;

use pulse_signal::ResponseStore;
use pulse_protocol::messages::ResponseSubmit;

use crate::AppState;

/// Accept an anonymous response submission — NO authentication required.
pub async fn submit_response(
    State(state): State<Arc<AppState>>,
    Json(submit): Json<ResponseSubmit>,
) -> impl IntoResponse {
    match state.collector.accept(&submit) {
        Ok(()) => (
            StatusCode::OK,
            Json(serde_json::json!({"status": "accepted"})),
        )
            .into_response(),
        Err(e) => (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error": e.to_string()})),
        )
            .into_response(),
    }
}

/// Debug endpoint — list stored encrypted responses (dev only).
#[derive(Serialize)]
struct DebugResponse {
    count: usize,
    responses: Vec<DebugResponseEntry>,
}

#[derive(Serialize)]
struct DebugResponseEntry {
    question_batch_id: String,
    encrypted_blob_len: usize,
    received_at: u64,
}

pub async fn debug_responses(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    let stored = state.store.list();
    Json(DebugResponse {
        count: stored.len(),
        responses: stored
            .iter()
            .map(|r| DebugResponseEntry {
                question_batch_id: r.question_batch_id.to_string(),
                encrypted_blob_len: r.encrypted_blob.len(),
                received_at: r.received_at,
            })
            .collect(),
    })
}
