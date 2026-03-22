use std::sync::Arc;

use axum::{Json, extract::State, http::StatusCode, response::IntoResponse};
use serde::{Deserialize, Serialize};

use pulse_identity::{AuthError, IssuerError};
use pulse_protocol::messages::{QuestionDelivery, ResponseType, TokenDeniedReason, TokenRequest};
use pulse_protocol::{BlindedToken, QuestionBatchId, QuestionText, UnixTimestamp};

use crate::IdentityState;
use crate::auth_extractor::AuthenticatedEmployee;
use crate::error::ApiError;

// ── Auth ──

#[derive(Deserialize)]
pub struct AuthRequest {
    pub api_key: String,
}

#[derive(Serialize)]
pub struct AuthResponse {
    pub employee_id: String,
    pub session_token: String,
}

/// Authenticate a credential via the pluggable [`Authenticator`] and create a session.
pub async fn auth(
    State(state): State<Arc<IdentityState>>,
    Json(req): Json<AuthRequest>,
) -> impl IntoResponse {
    match state.authenticator.authenticate(&req.api_key).await {
        Ok(employee_id) => {
            let session_token = state.session_store.create(employee_id.clone());
            let resp = AuthResponse {
                employee_id: employee_id.0,
                session_token: session_token.0,
            };
            (StatusCode::OK, Json(resp)).into_response()
        }
        Err(e) => map_auth_error(e).into_response(),
    }
}

// ── Question delivery ──

/// Return the single hardcoded question (Slice 0). Requires a valid session.
pub async fn get_question(
    _employee: AuthenticatedEmployee,
    State(state): State<Arc<IdentityState>>,
) -> Json<QuestionDelivery> {
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
    pub blinded_token: BlindedToken,
    pub question_batch_id: QuestionBatchId,
}

/// Sign a blinded token. Employee identity comes from the session, not the request body.
pub async fn sign_token(
    employee: AuthenticatedEmployee,
    State(state): State<Arc<IdentityState>>,
    Json(req): Json<SignRequest>,
) -> impl IntoResponse {
    let token_request = TokenRequest {
        blinded_token: req.blinded_token,
        question_batch_id: req.question_batch_id,
    };

    match state.issuer.sign_token(&employee.0, &token_request) {
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

fn map_auth_error(e: AuthError) -> ApiError {
    match e {
        AuthError::InvalidCredentials => ApiError::Unauthorized("invalid credentials".to_string()),
        AuthError::ProviderError(msg) => {
            tracing::error!(error = %msg, "auth provider error");
            ApiError::Unauthorized("authentication failed".to_string())
        }
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
