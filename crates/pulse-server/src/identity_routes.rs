use std::fmt;
use std::sync::Arc;

use axum::{Json, extract::State, http::StatusCode, response::IntoResponse};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use pulse_identity::{EmployeeId, IssuerError};
use pulse_protocol::messages::{QuestionDelivery, ResponseType, TokenDeniedReason, TokenRequest};
use pulse_protocol::{BlindedToken, QuestionBatchId, QuestionText, UnixTimestamp};

use crate::AppState;
use crate::error::ApiError;

// ── Auth stub ──

#[derive(Deserialize)]
pub struct ApiKey(pub String);

impl fmt::Debug for ApiKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("ApiKey").field(&"[REDACTED]").finish()
    }
}

#[derive(Deserialize)]
pub struct AuthRequest {
    pub api_key: ApiKey,
}

#[derive(Serialize)]
pub struct AuthResponse {
    pub employee_id: String,
    pub session_token: String,
}

/// Stub auth — accepts any non-empty API key, returns a fake session.
pub async fn auth(Json(req): Json<AuthRequest>) -> impl IntoResponse {
    if req.api_key.0.is_empty() {
        return ApiError::Unauthorized("missing api_key".to_string()).into_response();
    }
    // In Slice 0, the API key IS the employee ID for simplicity
    let resp = AuthResponse {
        employee_id: req.api_key.0.clone(),
        session_token: Uuid::new_v4().to_string(),
    };
    (StatusCode::OK, Json(resp)).into_response()
}

// ── Question delivery ──

/// Return the single hardcoded question (Slice 0).
pub async fn get_question(State(state): State<Arc<AppState>>) -> Json<QuestionDelivery> {
    Json(QuestionDelivery {
        question_batch_id: state.question_batch_id,
        question_text: QuestionText::from("How are you feeling about work today?"),
        response_type: ResponseType::Scale5,
        expiry: UnixTimestamp(u64::MAX),
    })
}

// ── Token signing ──

#[derive(Deserialize)]
pub struct SignRequest {
    pub employee_id: String,
    pub blinded_token: BlindedToken,
    pub question_batch_id: QuestionBatchId,
}

/// Sign a blinded token for an authenticated employee.
pub async fn sign_token(
    State(state): State<Arc<AppState>>,
    Json(req): Json<SignRequest>,
) -> impl IntoResponse {
    let token_request = TokenRequest {
        blinded_token: req.blinded_token,
        question_batch_id: req.question_batch_id,
    };

    let employee_id = EmployeeId(req.employee_id);
    match state.issuer.sign_token(&employee_id, &token_request) {
        Ok(resp) => (
            StatusCode::OK,
            Json(serde_json::json!({
                "blind_signature": resp.blind_signature,
                "key_version": resp.key_version,
            })),
        )
            .into_response(),
        Err(e) => map_issuer_error(e).into_response(),
    }
}

fn map_issuer_error(e: IssuerError) -> ApiError {
    match e {
        IssuerError::Denied(reason) => {
            let (code, message) = match reason {
                TokenDeniedReason::FrequencyCap => (
                    "TOKEN_DENIED_FREQUENCY_CAP",
                    "frequency cap exceeded for this batch",
                ),
                TokenDeniedReason::NotAuthorized => (
                    "TOKEN_DENIED_NOT_AUTHORIZED",
                    "employee not authorized for this batch",
                ),
                TokenDeniedReason::BatchExpired => {
                    ("TOKEN_DENIED_BATCH_EXPIRED", "question batch has expired")
                }
            };
            ApiError::TokenDenied {
                code,
                message: message.to_string(),
            }
        }
        IssuerError::SigningFailed(inner) => ApiError::SigningFailed(inner.to_string()),
    }
}
