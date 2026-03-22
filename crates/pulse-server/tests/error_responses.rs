//! Tests verifying structured error responses with correct HTTP status codes
//! and machine-readable error codes.

use std::sync::Arc;

use axum::{
    Router,
    routing::{get, post},
};
use serde_json::Value;
use tokio::net::TcpListener;

use pulse_crypto::{aead, blind_sig};
use pulse_identity::{InMemorySessionStore, QuestionBatch, SamplingEngine, TokenIssuer};
use pulse_protocol::messages::ResponseType;
use pulse_protocol::token::{AttestationClass, TokenPayload};
use pulse_protocol::{KeyVersion, Nonce, QuestionBatchId, QuestionText, TenantId, UnixTimestamp};
use pulse_signal::{InMemoryLedger, InMemoryStore, ResponseCollector};

use pulse_server::dev_auth::DevAuthenticator;
use pulse_server::dev_sampling::DevSamplingEngine;
use pulse_server::{IdentityState, SignalState, identity_routes, signal_routes};

async fn start_test_servers() -> (String, String, Arc<IdentityState>, QuestionBatchId) {
    let kp = blind_sig::generate_keypair().unwrap();
    let pk = kp.pk.clone();
    let ledger = Arc::new(InMemoryLedger::new());
    let store: Arc<dyn pulse_signal::ResponseStore> = Arc::new(InMemoryStore::new());

    let batch_id = QuestionBatchId::new();
    let batch = QuestionBatch {
        id: batch_id,
        question_text: QuestionText::from("test question"),
        response_type: ResponseType::Scale5,
        expiry: UnixTimestamp(u64::MAX),
    };
    let sampling_engine: Arc<dyn SamplingEngine> = Arc::new(DevSamplingEngine::new(batch, 1));

    let identity_state = Arc::new(IdentityState {
        issuer: TokenIssuer::with_sampling(kp.sk, KeyVersion(1), sampling_engine.clone()),
        authenticator: Arc::new(DevAuthenticator),
        session_store: Arc::new(InMemorySessionStore::new()),
        sampling_engine,
    });

    let signal_state = Arc::new(SignalState {
        collector: ResponseCollector::new(pk, ledger, store.clone()),
        store,
    });

    let identity_router = Router::new()
        .route("/auth", post(identity_routes::auth))
        .route("/question", get(identity_routes::get_questions))
        .route("/token/sign", post(identity_routes::sign_token))
        .with_state(identity_state.clone());

    let signal_router = Router::new()
        .route("/response", post(signal_routes::submit_response))
        .route("/debug/responses", get(signal_routes::debug_responses))
        .with_state(signal_state);

    let identity_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let signal_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();

    let identity_addr = identity_listener.local_addr().unwrap();
    let signal_addr = signal_listener.local_addr().unwrap();

    tokio::spawn(axum::serve(identity_listener, identity_router).into_future());
    tokio::spawn(axum::serve(signal_listener, signal_router).into_future());

    (
        format!("http://{identity_addr}"),
        format!("http://{signal_addr}"),
        identity_state,
        batch_id,
    )
}

/// Authenticate and complete a token signing flow, returning data needed for submission.
async fn sign_token_flow(
    identity_url: &str,
    state: &IdentityState,
    batch_id: QuestionBatchId,
    tenant_id: TenantId,
) -> (
    pulse_protocol::TokenBytes,
    pulse_crypto::Signature,
    Option<[u8; 32]>,
) {
    let client = reqwest::Client::new();

    // Authenticate first
    let auth_resp: Value = client
        .post(format!("{identity_url}/auth"))
        .json(&serde_json::json!({"api_key": "employee-42"}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let session_token = auth_resp["session_token"].as_str().unwrap().to_string();

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

    let pk = state.issuer.public_key();
    let blinding_result = blind_sig::blind(&pk, &token_bytes.0).unwrap();

    let sign_resp: Value = client
        .post(format!("{identity_url}/token/sign"))
        .header("Authorization", format!("Bearer {session_token}"))
        .json(&serde_json::json!({
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

    let blind_sig_val = pulse_crypto::BlindSignature(blind_sig_bytes);
    let sig = blind_sig::finalize(&pk, &blind_sig_val, &blinding_result, &token_bytes.0).unwrap();

    let msg_randomizer = blinding_result.msg_randomizer.map(|r| r.0);

    (token_bytes, sig, msg_randomizer)
}

#[tokio::test]
async fn duplicate_submission_returns_422_with_error_code() {
    let (identity_url, signal_url, state, batch_id) = start_test_servers().await;
    let client = reqwest::Client::new();
    let tenant_id = TenantId::new();
    let encryption_key = aead::generate_key();

    let (token_bytes, sig, msg_randomizer) =
        sign_token_flow(&identity_url, &state, batch_id, tenant_id).await;

    let payload = serde_json::json!({
        "token": token_bytes.0,
        "signature": sig.0,
        "msg_randomizer": msg_randomizer,
        "key_version": 1,
        "question_batch_id": batch_id.0,
        "tenant_id": tenant_id.0,
        "response_blob": aead::encrypt(&encryption_key, b"4").unwrap(),
    });

    // First submission succeeds
    let resp = client
        .post(format!("{signal_url}/response"))
        .json(&payload)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);

    // Duplicate returns 422 with structured error
    let dup = client
        .post(format!("{signal_url}/response"))
        .json(&payload)
        .send()
        .await
        .unwrap();
    assert_eq!(dup.status(), 422);
    let body: Value = dup.json().await.unwrap();
    assert_eq!(body["code"], "RESPONSE_TOKEN_ALREADY_SPENT");
    assert!(!body["message"].as_str().unwrap().is_empty());
}

#[tokio::test]
async fn forged_signature_returns_422() {
    let (_identity_url, signal_url, _state, batch_id) = start_test_servers().await;
    let client = reqwest::Client::new();
    let tenant_id = TenantId::new();

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

    let resp = client
        .post(format!("{signal_url}/response"))
        .json(&serde_json::json!({
            "token": token_bytes.0,
            "signature": vec![0xDEu8; 256],
            "msg_randomizer": null,
            "key_version": 1,
            "question_batch_id": batch_id.0,
            "tenant_id": tenant_id.0,
            "response_blob": vec![0x00u8],
        }))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 422);
    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["code"], "RESPONSE_INVALID_SIGNATURE");
}

#[tokio::test]
async fn batch_mismatch_returns_422() {
    let (identity_url, signal_url, state, batch_id) = start_test_servers().await;
    let client = reqwest::Client::new();
    let tenant_id = TenantId::new();
    let wrong_batch_id = QuestionBatchId::new();

    let (token_bytes, sig, msg_randomizer) =
        sign_token_flow(&identity_url, &state, batch_id, tenant_id).await;

    let resp = client
        .post(format!("{signal_url}/response"))
        .json(&serde_json::json!({
            "token": token_bytes.0,
            "signature": sig.0,
            "msg_randomizer": msg_randomizer,
            "key_version": 1,
            "question_batch_id": wrong_batch_id.0,
            "tenant_id": tenant_id.0,
            "response_blob": vec![0x00u8],
        }))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 422);
    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["code"], "RESPONSE_BATCH_MISMATCH");
}

#[tokio::test]
async fn empty_api_key_returns_401() {
    let (identity_url, _signal_url, _state, _batch_id) = start_test_servers().await;
    let client = reqwest::Client::new();

    let resp = client
        .post(format!("{identity_url}/auth"))
        .json(&serde_json::json!({"api_key": ""}))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 401);
    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["code"], "UNAUTHORIZED");
    assert!(!body["message"].as_str().unwrap().is_empty());
}

#[tokio::test]
async fn missing_auth_header_returns_401() {
    let (identity_url, _signal_url, _state, _batch_id) = start_test_servers().await;
    let client = reqwest::Client::new();

    // GET /question without Authorization header
    let resp = client
        .get(format!("{identity_url}/question"))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 401);
    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["code"], "UNAUTHORIZED");
}

#[tokio::test]
async fn invalid_session_token_returns_401() {
    let (identity_url, _signal_url, _state, _batch_id) = start_test_servers().await;
    let client = reqwest::Client::new();

    // POST /token/sign with a fake session token
    let resp = client
        .post(format!("{identity_url}/token/sign"))
        .header("Authorization", "Bearer fake-token-value")
        .json(&serde_json::json!({
            "blinded_token": vec![0u8; 256],
            "question_batch_id": QuestionBatchId::new().0,
        }))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 401);
    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["code"], "UNAUTHORIZED");
}

#[tokio::test]
async fn error_response_has_consistent_structure() {
    let (_identity_url, signal_url, _state, batch_id) = start_test_servers().await;
    let client = reqwest::Client::new();
    let tenant_id = TenantId::new();

    // Submit with forged signature to trigger an error
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

    let resp = client
        .post(format!("{signal_url}/response"))
        .json(&serde_json::json!({
            "token": token_bytes.0,
            "signature": vec![0xDEu8; 256],
            "msg_randomizer": null,
            "key_version": 1,
            "question_batch_id": batch_id.0,
            "tenant_id": tenant_id.0,
            "response_blob": vec![0x00u8],
        }))
        .send()
        .await
        .unwrap();

    let body: Value = resp.json().await.unwrap();

    // Every error response must have exactly "code" and "message" at the top level
    assert!(
        body["code"].is_string(),
        "error response must have 'code' string field"
    );
    assert!(
        body["message"].is_string(),
        "error response must have 'message' string field"
    );
    assert_eq!(
        body.as_object().unwrap().len(),
        2,
        "error response must have exactly 2 fields"
    );
}
