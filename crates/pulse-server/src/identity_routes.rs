use std::sync::Arc;

use axum::{
    Json,
    extract::State,
    http::StatusCode,
    response::IntoResponse,
};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use pulse_protocol::messages::{QuestionDelivery, ResponseType, TokenRequest};

use crate::AppState;

// ── Auth stub ──

#[derive(Deserialize)]
pub struct AuthRequest {
    pub api_key: String,
}

#[derive(Serialize)]
pub struct AuthResponse {
    pub employee_id: String,
    pub session_token: String,
}

/// Stub auth — accepts any non-empty API key, returns a fake session.
pub async fn auth(Json(req): Json<AuthRequest>) -> impl IntoResponse {
    if req.api_key.is_empty() {
        return (StatusCode::UNAUTHORIZED, Json(serde_json::json!({"error": "missing api_key"}))).into_response();
    }
    // In Slice 0, the API key IS the employee ID for simplicity
    let resp = AuthResponse {
        employee_id: req.api_key.clone(),
        session_token: Uuid::new_v4().to_string(),
    };
    (StatusCode::OK, Json(resp)).into_response()
}

// ── Question delivery ──

/// Return the single hardcoded question (Slice 0).
pub async fn get_question(State(state): State<Arc<AppState>>) -> Json<QuestionDelivery> {
    Json(QuestionDelivery {
        question_batch_id: state.question_batch_id,
        question_text: "How are you feeling about work today?".to_string(),
        response_type: ResponseType::Scale5,
        expiry: u64::MAX,
    })
}

// ── Token signing ──

#[derive(Deserialize)]
pub struct SignRequest {
    pub employee_id: String,
    pub blinded_token: Vec<u8>,
    pub question_batch_id: Uuid,
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

    match state.issuer.sign_token(&req.employee_id, &token_request) {
        Ok(resp) => (
            StatusCode::OK,
            Json(serde_json::json!({
                "blind_signature": resp.blind_signature,
                "key_version": resp.key_version,
            })),
        )
            .into_response(),
        Err(e) => (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error": e.to_string()})),
        )
            .into_response(),
    }
}
