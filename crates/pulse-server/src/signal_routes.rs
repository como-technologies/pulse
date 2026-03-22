use std::sync::Arc;

use axum::{Json, extract::State, http::StatusCode, response::IntoResponse};
use serde::Serialize;

use pulse_protocol::messages::{RejectReason, ResponseSubmit};
use pulse_protocol::{QuestionBatchId, UnixTimestamp};
use pulse_signal::CollectorError;

use crate::AppState;
use crate::error::ApiError;

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
        Err(e) => map_collector_error(e).into_response(),
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
    question_batch_id: QuestionBatchId,
    encrypted_blob_len: usize,
    received_at: UnixTimestamp,
}

pub async fn debug_responses(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    let stored = state.store.list();
    Json(DebugResponse {
        count: stored.len(),
        responses: stored
            .iter()
            .map(|r| DebugResponseEntry {
                question_batch_id: r.question_batch_id,
                encrypted_blob_len: r.encrypted_blob.0.len(),
                received_at: r.received_at,
            })
            .collect(),
    })
}

fn map_collector_error(e: CollectorError) -> ApiError {
    match e {
        CollectorError::Rejected(reason) => {
            let (code, message) = match reason {
                RejectReason::InvalidSignature => (
                    "RESPONSE_INVALID_SIGNATURE",
                    "blind signature verification failed",
                ),
                RejectReason::TokenExpired => ("RESPONSE_TOKEN_EXPIRED", "token has expired"),
                RejectReason::TokenAlreadySpent => (
                    "RESPONSE_TOKEN_ALREADY_SPENT",
                    "token has already been used",
                ),
                RejectReason::BatchMismatch => (
                    "RESPONSE_BATCH_MISMATCH",
                    "question batch ID does not match token",
                ),
                RejectReason::TenantMismatch => {
                    ("RESPONSE_TENANT_MISMATCH", "tenant ID does not match token")
                }
                RejectReason::Malformed => ("RESPONSE_MALFORMED", "token payload is malformed"),
            };
            ApiError::ResponseRejected {
                code,
                message: message.to_string(),
            }
        }
    }
}
