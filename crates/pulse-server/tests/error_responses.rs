//! Tests verifying structured error responses with correct HTTP status codes
//! and machine-readable error codes.

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

use pulse_server::{AppState, identity_routes, signal_routes};

async fn start_test_servers() -> (String, String, Arc<AppState>) {
    let kp = blind_sig::generate_keypair().unwrap();
    let pk = kp.pk.clone();
    let ledger = Arc::new(InMemoryLedger::new());
    let store = Arc::new(InMemoryStore::new());
    let question_batch_id = QuestionBatchId::from_uuid(Uuid::new_v4());

    let state = Arc::new(AppState {
        issuer: TokenIssuer::new(kp.sk, KeyVersion(1)),
        collector: ResponseCollector::new(pk, ledger, store.clone()),
        store,
        question_batch_id,
    });

    let identity_router = Router::new()
        .route("/auth", post(identity_routes::auth))
        .route("/question", get(identity_routes::get_question))
        .route("/token/sign", post(identity_routes::sign_token))
        .with_state(state.clone());

    let signal_router = Router::new()
        .route("/response", post(signal_routes::submit_response))
        .route("/debug/responses", get(signal_routes::debug_responses))
        .with_state(state.clone());

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

/// Helper: complete a valid token signing flow, returning the data needed for submission.
async fn sign_token_flow(
    identity_url: &str,
    state: &AppState,
    batch_id: QuestionBatchId,
    tenant_id: TenantId,
) -> (
    pulse_protocol::TokenBytes,
    pulse_crypto::Signature,
    Option<[u8; 32]>,
) {
    let client = reqwest::Client::new();

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

    let pk = state.collector.public_key();
    let blinding_result = blind_sig::blind(pk, &token_bytes.0).unwrap();

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

    let blind_sig_val = pulse_crypto::BlindSignature(blind_sig_bytes);
    let sig = blind_sig::finalize(pk, &blind_sig_val, &blinding_result, &token_bytes.0).unwrap();

    let msg_randomizer = blinding_result.msg_randomizer.map(|r| r.0);

    (token_bytes, sig, msg_randomizer)
}

#[tokio::test]
async fn duplicate_submission_returns_422_with_error_code() {
    let (identity_url, signal_url, state) = start_test_servers().await;
    let client = reqwest::Client::new();
    let batch_id = state.question_batch_id;
    let tenant_id = TenantId::from_uuid(Uuid::new_v4());
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
    let (_identity_url, signal_url, state) = start_test_servers().await;
    let client = reqwest::Client::new();
    let batch_id = state.question_batch_id;
    let tenant_id = TenantId::from_uuid(Uuid::new_v4());

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
    let (identity_url, signal_url, state) = start_test_servers().await;
    let client = reqwest::Client::new();
    let batch_id = state.question_batch_id;
    let tenant_id = TenantId::from_uuid(Uuid::new_v4());
    let wrong_batch_id = QuestionBatchId::from_uuid(Uuid::new_v4());

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
    let (identity_url, _signal_url, _state) = start_test_servers().await;
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
async fn error_response_has_consistent_structure() {
    let (_identity_url, signal_url, state) = start_test_servers().await;
    let client = reqwest::Client::new();
    let batch_id = state.question_batch_id;
    let tenant_id = TenantId::from_uuid(Uuid::new_v4());

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
