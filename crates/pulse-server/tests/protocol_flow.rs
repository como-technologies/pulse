//! Full 14-step blind signature protocol flow — in-memory integration test.
//!
//! This test exercises the complete anonymous response lifecycle:
//! 1. Identity zone: Token Issuer signs a blinded token for an authenticated employee
//! 2. Client: unblinds the signature
//! 3. Signal zone: Response Collector verifies and accepts the anonymous response
//!
//! Key assertions:
//! - The Identity zone never sees the unblinded token or response content
//! - The Signal zone never sees the employee identity
//! - Duplicate submissions are rejected
//! - Forged signatures are rejected
//! - Wrong batch IDs are rejected

use std::sync::Arc;

use pulse_identity::TokenIssuer;
use pulse_signal::{InMemoryLedger, InMemoryStore, ResponseCollector, ResponseStore};
use pulse_crypto::aead;
use pulse_crypto::blind_sig;
use pulse_protocol::messages::{ResponseSubmit, TokenRequest};
use pulse_protocol::token::{AttestationClass, TokenPayload};
use uuid::Uuid;

fn setup() -> (
    TokenIssuer,
    ResponseCollector,
    Arc<InMemoryStore>,
    pulse_crypto::BrssPublicKey,
) {
    let kp = blind_sig::generate_keypair().unwrap();
    let pk = kp.pk.clone();
    let issuer = TokenIssuer::new(kp.sk, 1);
    let ledger = Arc::new(InMemoryLedger::new());
    let store = Arc::new(InMemoryStore::new());
    let collector = ResponseCollector::new(kp.pk, ledger, store.clone());
    (issuer, collector, store, pk)
}

fn make_token(batch_id: Uuid, tenant_id: Uuid) -> TokenPayload {
    TokenPayload {
        nonce: rand::random(),
        question_batch_id: batch_id,
        tenant_id,
        expiry: u64::MAX, // won't expire during tests
        segment_vector: vec!["engineering".into()],
        attestation_class: AttestationClass::Personal,
        key_version: 1,
    }
}

#[test]
fn full_protocol_flow() {
    let (issuer, collector, store, pk) = setup();
    let batch_id = Uuid::new_v4();
    let tenant_id = Uuid::new_v4();
    let encryption_key = aead::generate_key();

    // ── Step 1-2: Client creates token payload ──
    let token = make_token(batch_id, tenant_id);
    let token_bytes = token.to_bytes();

    // ── Step 3-4: Client blinds the token ──
    let blinding_result = blind_sig::blind(&pk, &token_bytes).unwrap();

    // ── Step 5-7: Token Issuer signs the blinded token (Identity zone) ──
    // The issuer knows "employee-42" requested a token, but never sees the token value.
    let token_request = TokenRequest {
        blinded_token: blinding_result.blind_message.0.clone(),
        question_batch_id: batch_id,
    };
    let token_response = issuer.sign_token("employee-42", &token_request).unwrap();

    // ── Step 8-9: Client unblinds the signature ──
    let blind_sig = pulse_crypto::BlindSignature(token_response.blind_signature);
    let sig = blind_sig::finalize(&pk, &blind_sig, &blinding_result, &token_bytes).unwrap();

    // ── Step 10: Client encrypts the response ──
    let response_data = b"4"; // 4 on a 5-point scale
    let encrypted_response = aead::encrypt(&encryption_key, response_data).unwrap();

    // ── Step 11-14: Client submits via anonymous channel (Signal zone) ──
    let submit = ResponseSubmit {
        token: token_bytes.clone(),
        signature: sig.0.clone(),
        msg_randomizer: blinding_result.msg_randomizer.map(|r| r.0),
        key_version: 1,
        question_batch_id: batch_id,
        tenant_id,
        response_blob: encrypted_response.clone(),
    };
    collector.accept(&submit).unwrap();

    // ── Assertions ──

    // Response is stored
    assert_eq!(store.count(), 1);
    let stored = store.list();
    let stored_response = &stored[0];

    // Stored response is the encrypted blob (no plaintext)
    assert_eq!(stored_response.encrypted_blob, encrypted_response);

    // Stored response can be decrypted with the key
    let decrypted = aead::decrypt(&encryption_key, &stored_response.encrypted_blob).unwrap();
    assert_eq!(decrypted, b"4");

    // Identity zone log has employee identity
    let issuance_log = issuer.issuance_log();
    assert_eq!(issuance_log.len(), 1);
    assert_eq!(issuance_log[0].employee_id, "employee-42");

    // BUT: the issuance log has NO unblinded token value — only batch ID
    // (The token issuer never saw the actual token, only the blinded version)

    // Signal zone store has NO employee identity
    // (ResponseSubmit and StoredResponse contain no employee_id field — enforced by types)
}

#[test]
fn duplicate_submission_rejected() {
    let (issuer, collector, _, pk) = setup();
    let batch_id = Uuid::new_v4();
    let tenant_id = Uuid::new_v4();
    let encryption_key = aead::generate_key();

    let token = make_token(batch_id, tenant_id);
    let token_bytes = token.to_bytes();
    let blinding_result = blind_sig::blind(&pk, &token_bytes).unwrap();

    let token_request = TokenRequest {
        blinded_token: blinding_result.blind_message.0.clone(),
        question_batch_id: batch_id,
    };
    let token_response = issuer.sign_token("employee-42", &token_request).unwrap();
    let blind_sig_val = pulse_crypto::BlindSignature(token_response.blind_signature);
    let sig = blind_sig::finalize(&pk, &blind_sig_val, &blinding_result, &token_bytes).unwrap();

    let submit = ResponseSubmit {
        token: token_bytes,
        signature: sig.0.clone(),
        msg_randomizer: blinding_result.msg_randomizer.map(|r| r.0),
        key_version: 1,
        question_batch_id: batch_id,
        tenant_id,
        response_blob: aead::encrypt(&encryption_key, b"3").unwrap(),
    };

    // First submission succeeds
    collector.accept(&submit).unwrap();
    // Second submission of the same token is rejected
    let result = collector.accept(&submit);
    assert!(result.is_err());
}

#[test]
fn forged_signature_rejected() {
    let (_, collector, _, _) = setup();
    let batch_id = Uuid::new_v4();
    let tenant_id = Uuid::new_v4();

    let token = make_token(batch_id, tenant_id);
    let token_bytes = token.to_bytes();

    let submit = ResponseSubmit {
        token: token_bytes,
        signature: vec![0xDE; 256], // fake signature
        msg_randomizer: None,
        key_version: 1,
        question_batch_id: batch_id,
        tenant_id,
        response_blob: vec![0x00],
    };

    let result = collector.accept(&submit);
    assert!(result.is_err());
}

#[test]
fn wrong_batch_id_rejected() {
    let (issuer, collector, _, pk) = setup();
    let batch_id = Uuid::new_v4();
    let wrong_batch_id = Uuid::new_v4();
    let tenant_id = Uuid::new_v4();

    let token = make_token(batch_id, tenant_id);
    let token_bytes = token.to_bytes();
    let blinding_result = blind_sig::blind(&pk, &token_bytes).unwrap();

    let token_request = TokenRequest {
        blinded_token: blinding_result.blind_message.0.clone(),
        question_batch_id: batch_id,
    };
    let token_response = issuer.sign_token("employee-42", &token_request).unwrap();
    let blind_sig_val = pulse_crypto::BlindSignature(token_response.blind_signature);
    let sig = blind_sig::finalize(&pk, &blind_sig_val, &blinding_result, &token_bytes).unwrap();

    // Submit with a different batch_id than what's in the token
    let submit = ResponseSubmit {
        token: token_bytes,
        signature: sig.0.clone(),
        msg_randomizer: blinding_result.msg_randomizer.map(|r| r.0),
        key_version: 1,
        question_batch_id: wrong_batch_id, // mismatch!
        tenant_id,
        response_blob: vec![0x00],
    };

    let result = collector.accept(&submit);
    assert!(result.is_err());
}

#[test]
fn wrong_tenant_id_rejected() {
    let (issuer, collector, _, pk) = setup();
    let batch_id = Uuid::new_v4();
    let tenant_id = Uuid::new_v4();
    let wrong_tenant_id = Uuid::new_v4();

    let token = make_token(batch_id, tenant_id);
    let token_bytes = token.to_bytes();
    let blinding_result = blind_sig::blind(&pk, &token_bytes).unwrap();

    let token_request = TokenRequest {
        blinded_token: blinding_result.blind_message.0.clone(),
        question_batch_id: batch_id,
    };
    let token_response = issuer.sign_token("employee-42", &token_request).unwrap();
    let blind_sig_val = pulse_crypto::BlindSignature(token_response.blind_signature);
    let sig = blind_sig::finalize(&pk, &blind_sig_val, &blinding_result, &token_bytes).unwrap();

    let submit = ResponseSubmit {
        token: token_bytes,
        signature: sig.0.clone(),
        msg_randomizer: blinding_result.msg_randomizer.map(|r| r.0),
        key_version: 1,
        question_batch_id: batch_id,
        tenant_id: wrong_tenant_id, // mismatch!
        response_blob: vec![0x00],
    };

    let result = collector.accept(&submit);
    assert!(result.is_err());
}
