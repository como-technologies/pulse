//! End-to-end HTTP test exercising the full anonymous response flow
//! across both Identity (port 8001) and Signal (port 8002) zones.

use std::sync::Arc;

use axum::{
    Router,
    routing::{get, post},
};
use serde_json::Value;
use tokio::net::TcpListener;
use uuid::Uuid;

use pulse_crypto::{aead, blind_sig};
use pulse_identity::TokenIssuer;
use pulse_protocol::token::{AttestationClass, TokenPayload};
use pulse_protocol::{KeyVersion, Nonce, QuestionBatchId, TenantId, UnixTimestamp};
use pulse_signal::{InMemoryLedger, InMemoryStore, ResponseCollector};

// Replicate AppState here since it's in main.rs (binary crate)
struct TestAppState {
    issuer: TokenIssuer,
    collector: ResponseCollector,
    store: Arc<InMemoryStore>,
    question_batch_id: QuestionBatchId,
}

// Route handler wrappers that reference TestAppState
mod handlers {
    use axum::{Json, extract::State, http::StatusCode, response::IntoResponse};
    use pulse_identity::EmployeeId;
    use pulse_protocol::messages::{QuestionDelivery, ResponseSubmit, ResponseType, TokenRequest};
    use pulse_protocol::{BlindedToken, QuestionBatchId, QuestionText, UnixTimestamp};
    use pulse_signal::ResponseStore;
    use serde::Deserialize;
    use std::sync::Arc;

    use super::TestAppState;

    #[derive(Deserialize)]
    pub struct SignRequest {
        pub employee_id: String,
        pub blinded_token: BlindedToken,
        pub question_batch_id: QuestionBatchId,
    }

    pub async fn get_question(State(state): State<Arc<TestAppState>>) -> Json<QuestionDelivery> {
        Json(QuestionDelivery {
            question_batch_id: state.question_batch_id,
            question_text: QuestionText::from("How are you feeling about work today?"),
            response_type: ResponseType::Scale5,
            expiry: UnixTimestamp(u64::MAX),
        })
    }

    pub async fn sign_token(
        State(state): State<Arc<TestAppState>>,
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
            Err(e) => (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({"error": e.to_string()})),
            )
                .into_response(),
        }
    }

    pub async fn submit_response(
        State(state): State<Arc<TestAppState>>,
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

    pub async fn debug_responses(State(state): State<Arc<TestAppState>>) -> impl IntoResponse {
        let stored = state.store.list();
        Json(serde_json::json!({
            "count": stored.len(),
        }))
    }
}

async fn start_test_servers() -> (String, String, Arc<TestAppState>) {
    let kp = blind_sig::generate_keypair().unwrap();
    let pk = kp.pk.clone();
    let ledger = Arc::new(InMemoryLedger::new());
    let store = Arc::new(InMemoryStore::new());
    let question_batch_id = QuestionBatchId::from_uuid(Uuid::new_v4());

    let state = Arc::new(TestAppState {
        issuer: TokenIssuer::new(kp.sk, KeyVersion(1)),
        collector: ResponseCollector::new(pk, ledger, store.clone()),
        store,
        question_batch_id,
    });

    let identity_router = Router::new()
        .route("/question", get(handlers::get_question))
        .route("/token/sign", post(handlers::sign_token))
        .with_state(state.clone());

    let signal_router = Router::new()
        .route("/response", post(handlers::submit_response))
        .route("/debug/responses", get(handlers::debug_responses))
        .with_state(state.clone());

    // Bind to port 0 for random available ports
    let identity_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let signal_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();

    let identity_addr = identity_listener.local_addr().unwrap();
    let signal_addr = signal_listener.local_addr().unwrap();

    tokio::spawn(axum::serve(identity_listener, identity_router).into_future());
    tokio::spawn(axum::serve(signal_listener, signal_router).into_future());

    (
        format!("http://{identity_addr}"),
        format!("http://{signal_addr}"),
        state,
    )
}

#[tokio::test]
async fn full_http_flow() {
    let (identity_url, signal_url, state) = start_test_servers().await;
    let client = reqwest::Client::new();
    let batch_id = state.question_batch_id;
    let tenant_id = TenantId::from_uuid(Uuid::new_v4());
    let encryption_key = aead::generate_key();

    // 1. Get question from Identity zone
    let question: Value = client
        .get(format!("{identity_url}/question"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(question["question_batch_id"], batch_id.0.to_string());

    // 2. Create and blind a token
    let token = TokenPayload {
        nonce: Nonce::random(),
        question_batch_id: batch_id,
        tenant_id,
        expiry: UnixTimestamp(u64::MAX),
        segment_vector: vec!["engineering".into()],
        attestation_class: AttestationClass::Personal,
        key_version: KeyVersion(1),
    };
    let token_bytes = token.to_bytes();

    let pk = &state.collector.public_key();
    let blinding_result = blind_sig::blind(pk, &token_bytes.0).unwrap();

    // 3. Request blind signature from Identity zone
    let sign_resp: Value = client
        .post(format!("{identity_url}/token/sign"))
        .json(&serde_json::json!({
            "employee_id": "employee-42",
            "blinded_token": blinding_result.blind_message.0,
            "question_batch_id": batch_id.0,
        }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();

    let blind_sig_bytes: Vec<u8> = sign_resp["blind_signature"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_u64().unwrap() as u8)
        .collect();

    // 4. Unblind the signature
    let blind_sig_val = pulse_crypto::BlindSignature(blind_sig_bytes);
    let sig = blind_sig::finalize(pk, &blind_sig_val, &blinding_result, &token_bytes.0).unwrap();

    // 5. Encrypt response
    let encrypted_response = aead::encrypt(&encryption_key, b"5").unwrap();

    // 6. Submit to Signal zone (different URL, NO auth)
    let submit_resp = client
        .post(format!("{signal_url}/response"))
        .json(&serde_json::json!({
            "token": token_bytes.0,
            "signature": sig.0,
            "msg_randomizer": blinding_result.msg_randomizer.map(|r| r.0),
            "key_version": 1,
            "question_batch_id": batch_id.0,
            "tenant_id": tenant_id.0,
            "response_blob": encrypted_response,
        }))
        .send()
        .await
        .unwrap();

    assert_eq!(submit_resp.status(), 200);
    let body: Value = submit_resp.json().await.unwrap();
    assert_eq!(body["status"], "accepted");

    // 7. Verify response is stored
    let debug: Value = client
        .get(format!("{signal_url}/debug/responses"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(debug["count"], 1);

    // 8. Duplicate submission should fail
    let dup_resp = client
        .post(format!("{signal_url}/response"))
        .json(&serde_json::json!({
            "token": token_bytes.0,
            "signature": sig.0,
            "msg_randomizer": blinding_result.msg_randomizer.map(|r| r.0),
            "key_version": 1,
            "question_batch_id": batch_id.0,
            "tenant_id": tenant_id.0,
            "response_blob": encrypted_response,
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(dup_resp.status(), 400);
}
