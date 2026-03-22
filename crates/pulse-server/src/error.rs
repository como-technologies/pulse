use axum::{Json, http::StatusCode, response::IntoResponse};
use serde::Serialize;

/// Structured error response returned to API consumers.
///
/// Every error response has the same flat shape:
/// ```json
/// { "code": "RESPONSE_TOKEN_ALREADY_SPENT", "message": "token has already been used" }
/// ```
///
/// `code` is a stable, machine-readable SCREAMING_SNAKE_CASE identifier.
/// `message` is human-readable and may change between versions.
#[derive(Debug, Serialize)]
pub struct ErrorResponse {
    pub code: &'static str,
    pub message: String,
}

/// Server-layer error type. Each variant maps to a specific HTTP status code
/// and error code. Constructed from domain errors via explicit mapping functions
/// in the route modules (not blanket `From` impls).
#[derive(Debug)]
pub enum ApiError {
    /// Token request denied for a policy reason (403).
    TokenDenied { code: &'static str, message: String },
    /// Blind signing failed due to internal crypto error (500).
    SigningFailed(String),
    /// Authentication failure (401).
    Unauthorized(String),
    /// Response rejected for a validation reason (422).
    ResponseRejected { code: &'static str, message: String },
    /// Malformed request body (400).
    BadRequest(String),
}

impl IntoResponse for ApiError {
    fn into_response(self) -> axum::response::Response {
        let (status, code, message) = match self {
            ApiError::TokenDenied { code, message } => (StatusCode::FORBIDDEN, code, message),
            ApiError::SigningFailed(msg) => {
                tracing::error!(error = %msg, "blind signing failed");
                (StatusCode::INTERNAL_SERVER_ERROR, "SIGNING_FAILED", msg)
            }
            ApiError::Unauthorized(msg) => (StatusCode::UNAUTHORIZED, "UNAUTHORIZED", msg),
            ApiError::ResponseRejected { code, message } => {
                (StatusCode::UNPROCESSABLE_ENTITY, code, message)
            }
            ApiError::BadRequest(msg) => (StatusCode::BAD_REQUEST, "BAD_REQUEST", msg),
        };

        if status.is_client_error() {
            tracing::warn!(status = status.as_u16(), error_code = code, "client error");
        }

        (status, Json(ErrorResponse { code, message })).into_response()
    }
}
