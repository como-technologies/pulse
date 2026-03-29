use std::sync::Arc;

use axum::{Json, extract::State, http::StatusCode, response::IntoResponse};
use serde::{Deserialize, Serialize};

use pulse_identity::{AuthError, IssuerError};
use pulse_protocol::messages::{QuestionDelivery, TokenDeniedReason, TokenRequest};

use crate::IdentityState;
use crate::auth_extractor::AuthenticatedEmployee;
use crate::binary::Binary;
use crate::error::ApiError;

// ── Config (client bootstrap) ──

#[derive(Serialize)]
pub struct ConfigResponse {
    pub tenant_id: String,
    pub key_version: u32,
    pub public_key_pem: String,
}

/// Return server configuration needed by clients: tenant ID, key version, and public key.
pub async fn get_config(State(state): State<Arc<IdentityState>>) -> Json<ConfigResponse> {
    let pem = state
        .public_key
        .to_pem()
        .expect("public key PEM encoding cannot fail");
    Json(ConfigResponse {
        tenant_id: state.tenant_id.0.to_string(),
        key_version: state.key_version.0,
        public_key_pem: pem,
    })
}

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

/// Authenticate a credential via the pluggable [`Authenticator`](pulse_identity::Authenticator) and create a session.
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

/// Return the employee's assigned questions with coarsened segment vectors.
pub async fn get_questions(
    employee: AuthenticatedEmployee,
    State(state): State<Arc<IdentityState>>,
) -> Binary<Vec<QuestionDelivery>> {
    let assignments = state.sampling_engine.assignments_for(&employee.0);
    Binary(
        assignments
            .into_iter()
            .map(|d| QuestionDelivery {
                question_batch_id: d.question_batch_id,
                question_text: d.question_text,
                response_type: d.response_type,
                expiry: d.expiry,
                segment_vector: d.coarsened_segments,
            })
            .collect(),
    )
}

// ── Token signing ──

/// Sign a blinded token. Employee identity comes from the session, not the request body.
pub async fn sign_token(
    employee: AuthenticatedEmployee,
    State(state): State<Arc<IdentityState>>,
    Binary(token_request): Binary<TokenRequest>,
) -> impl IntoResponse {
    match state
        .issuer
        .sign_token(&state.tenant_id, &employee.0, &token_request)
    {
        Ok(resp) => Binary(resp).into_response(),
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
        IssuerError::TenantNotFound(id) => {
            ApiError::Unauthorized(format!("tenant not found: {id}"))
        }
    }
}
