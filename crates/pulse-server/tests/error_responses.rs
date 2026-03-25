//! Tests verifying structured error responses with correct HTTP status codes
//! and machine-readable error codes.

mod common;

use pulse_crypto::{aead, blind_sig};
use pulse_protocol::messages::{ResponseSubmit, TokenRequest, TokenResponse};
use pulse_protocol::token::{AttestationClass, TokenPayload};
use pulse_protocol::{
    BlindedToken, EncryptedBlob, KeyVersion, Nonce, QuestionBatchId, SignatureBytes, TenantId,
    UnixTimestamp,
};
use serde_json::Value;

/// Authenticate and complete a token signing flow, returning data needed for submission.
async fn sign_token_flow(
    identity_url: &str,
    pk: &pulse_crypto::BrssPublicKey,
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

    let blinding_result = blind_sig::blind(pk, &token_bytes.0).unwrap();

    let token_request = TokenRequest {
        blinded_token: BlindedToken(blinding_result.blind_message.0.clone()),
        question_batch_id: batch_id,
    };
    let sign_resp_bytes = client
        .post(format!("{identity_url}/token/sign"))
        .header("Authorization", format!("Bearer {session_token}"))
        .body(postcard::to_allocvec(&token_request).unwrap())
        .send()
        .await
        .unwrap()
        .bytes()
        .await
        .unwrap();
    let token_response: TokenResponse = postcard::from_bytes(&sign_resp_bytes).unwrap();

    let blind_sig_val = pulse_crypto::BlindSignature(token_response.blind_signature.0.clone());
    let sig = blind_sig::finalize(pk, &blind_sig_val, &blinding_result, &token_bytes.0).unwrap();

    let msg_randomizer = blinding_result.msg_randomizer.map(|r| r.0);

    (token_bytes, sig, msg_randomizer)
}

#[tokio::test]
async fn duplicate_submission_returns_422_with_error_code() {
    let servers = common::start_test_servers(false).await;
    let client = reqwest::Client::new();
    let encryption_key = aead::generate_key();

    let (token_bytes, sig, msg_randomizer) = sign_token_flow(
        &servers.identity_url,
        &servers.pk,
        servers.batch_id,
        servers.tenant_id,
    )
    .await;

    let submit = ResponseSubmit {
        token: token_bytes,
        signature: SignatureBytes(sig.0.clone()),
        msg_randomizer,
        key_version: KeyVersion(1),
        question_batch_id: servers.batch_id,
        tenant_id: servers.tenant_id,
        response_blob: EncryptedBlob(aead::encrypt(&encryption_key, b"4").unwrap()),
    };
    let submit_bytes = postcard::to_allocvec(&submit).unwrap();

    // First submission succeeds
    let resp = client
        .post(format!("{}/response", servers.signal_url))
        .body(submit_bytes.clone())
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);

    // Duplicate returns 422 with structured error
    let dup = client
        .post(format!("{}/response", servers.signal_url))
        .body(submit_bytes)
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
    let servers = common::start_test_servers(false).await;
    let client = reqwest::Client::new();

    let token = TokenPayload {
        nonce: Nonce::random(),
        question_batch_id: servers.batch_id,
        tenant_id: servers.tenant_id,
        expiry: UnixTimestamp(u64::MAX),
        segment_vector: vec!["engineering".into()],
        attestation_class: AttestationClass::Personal,
        key_version: KeyVersion(1),
    };
    let token_bytes = token.to_bytes();

    let submit = ResponseSubmit {
        token: token_bytes,
        signature: SignatureBytes(vec![0xDE; 256]),
        msg_randomizer: None,
        key_version: KeyVersion(1),
        question_batch_id: servers.batch_id,
        tenant_id: servers.tenant_id,
        response_blob: EncryptedBlob(vec![0x00]),
    };
    let resp = client
        .post(format!("{}/response", servers.signal_url))
        .body(postcard::to_allocvec(&submit).unwrap())
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 422);
    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["code"], "RESPONSE_INVALID_SIGNATURE");
}

#[tokio::test]
async fn batch_mismatch_returns_422() {
    let servers = common::start_test_servers(false).await;
    let client = reqwest::Client::new();
    let wrong_batch_id = QuestionBatchId::new();

    let (token_bytes, sig, msg_randomizer) = sign_token_flow(
        &servers.identity_url,
        &servers.pk,
        servers.batch_id,
        servers.tenant_id,
    )
    .await;

    let submit = ResponseSubmit {
        token: token_bytes,
        signature: SignatureBytes(sig.0.clone()),
        msg_randomizer,
        key_version: KeyVersion(1),
        question_batch_id: wrong_batch_id,
        tenant_id: servers.tenant_id,
        response_blob: EncryptedBlob(vec![0x00]),
    };
    let resp = client
        .post(format!("{}/response", servers.signal_url))
        .body(postcard::to_allocvec(&submit).unwrap())
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 422);
    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["code"], "RESPONSE_BATCH_MISMATCH");
}

#[tokio::test]
async fn empty_api_key_returns_401() {
    let servers = common::start_test_servers(false).await;
    let client = reqwest::Client::new();

    let resp = client
        .post(format!("{}/auth", servers.identity_url))
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
    let servers = common::start_test_servers(false).await;
    let client = reqwest::Client::new();

    // GET /question without Authorization header
    let resp = client
        .get(format!("{}/question", servers.identity_url))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 401);
    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["code"], "UNAUTHORIZED");
}

#[tokio::test]
async fn invalid_session_token_returns_401() {
    let servers = common::start_test_servers(false).await;
    let client = reqwest::Client::new();

    // POST /token/sign with a fake session token
    let fake_request = TokenRequest {
        blinded_token: BlindedToken(vec![0u8; 256]),
        question_batch_id: QuestionBatchId::new(),
    };
    let resp = client
        .post(format!("{}/token/sign", servers.identity_url))
        .header("Authorization", "Bearer fake-token-value")
        .body(postcard::to_allocvec(&fake_request).unwrap())
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 401);
    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["code"], "UNAUTHORIZED");
}

#[tokio::test]
async fn error_response_has_consistent_structure() {
    let servers = common::start_test_servers(false).await;
    let client = reqwest::Client::new();

    // Submit with forged signature to trigger an error
    let token = TokenPayload {
        nonce: Nonce::random(),
        question_batch_id: servers.batch_id,
        tenant_id: servers.tenant_id,
        expiry: UnixTimestamp(u64::MAX),
        segment_vector: vec!["engineering".into()],
        attestation_class: AttestationClass::Personal,
        key_version: KeyVersion(1),
    };
    let token_bytes = token.to_bytes();

    let submit = ResponseSubmit {
        token: token_bytes,
        signature: SignatureBytes(vec![0xDE; 256]),
        msg_randomizer: None,
        key_version: KeyVersion(1),
        question_batch_id: servers.batch_id,
        tenant_id: servers.tenant_id,
        response_blob: EncryptedBlob(vec![0x00]),
    };
    let resp = client
        .post(format!("{}/response", servers.signal_url))
        .body(postcard::to_allocvec(&submit).unwrap())
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
