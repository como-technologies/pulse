//! Multi-tenancy integration tests exercising per-tenant keypair isolation,
//! envelope encryption round-trips, and crypto-shredding.

use std::sync::Arc;

use pulse_crypto::{aead, blind_sig};
use pulse_protocol::messages::{RejectReason, ResponseSubmit};
use pulse_protocol::token::{AttestationClass, TokenPayload};
use pulse_protocol::{
    EncryptedBlob, KeyVersion, Nonce, QuestionBatchId, SignatureBytes, TenantId, UnixTimestamp,
};
use pulse_signal::{
    InMemoryLedger, InMemoryStore, ResponseCollector, ResponseStore, StoredResponse,
};

use pulse_server::cmk::CmkProvider;
use pulse_server::dek_store::{DekDomain, DekStore, InMemoryDekStore};
use pulse_server::dev_cmk::DevCmkProvider;
use pulse_server::dev_tenant_keys::InMemoryTenantKeyStore;
use pulse_server::encrypting_store::EncryptingResponseStore;

// ---------------------------------------------------------------------------
// Test 1: Cross-tenant token rejected
// ---------------------------------------------------------------------------

#[test]
fn cross_tenant_token_rejected() {
    // Create two tenants, each with their own keypair.
    let kp_a = blind_sig::generate_keypair().unwrap();
    let kp_b = blind_sig::generate_keypair().unwrap();

    let tenant_a = TenantId::new();
    let tenant_b = TenantId::new();

    let key_store = Arc::new(InMemoryTenantKeyStore::new());
    key_store.register_tenant(tenant_a, kp_a.sk.clone(), kp_a.pk.clone(), KeyVersion(1));
    key_store.register_tenant(tenant_b, kp_b.sk.clone(), kp_b.pk.clone(), KeyVersion(1));

    let ledger = Arc::new(InMemoryLedger::new());
    let store = Arc::new(InMemoryStore::new());
    let collector = ResponseCollector::new(key_store, ledger, store);

    let batch_id = QuestionBatchId::new();

    // Sign a token with Tenant A's key. The token payload contains tenant_id=A.
    let token = TokenPayload {
        nonce: Nonce::random(),
        question_batch_id: batch_id,
        tenant_id: tenant_a,
        expiry: UnixTimestamp(u64::MAX),
        segment_vector: vec!["engineering".into()],
        attestation_class: AttestationClass::Personal,
        key_version: KeyVersion(1),
    };
    let token_bytes = token.to_bytes();

    let blinding_result = blind_sig::blind(&kp_a.pk, &token_bytes.0).unwrap();
    let blind_sig_val = blind_sig::blind_sign(&kp_a.sk, &blinding_result.blind_message).unwrap();
    let sig =
        blind_sig::finalize(&kp_a.pk, &blind_sig_val, &blinding_result, &token_bytes.0).unwrap();

    // Submit with Tenant A's tenant_id — should succeed.
    let submit_a = ResponseSubmit {
        token: token_bytes.clone(),
        signature: SignatureBytes(sig.0.clone()),
        msg_randomizer: blinding_result.msg_randomizer.map(|r| r.0),
        key_version: KeyVersion(1),
        question_batch_id: batch_id,
        tenant_id: tenant_a,
        response_blob: EncryptedBlob(vec![0x42]),
    };
    collector.accept(&submit_a).unwrap();

    // Now try submitting the same token but claiming tenant_id=B.
    // The token's inner tenant_id is A, so the collector should reject with TenantMismatch.
    // We need a fresh token (since the first one was spent) with tenant_id=A inside
    // but submitted under tenant_b's outer envelope.
    let token2 = TokenPayload {
        nonce: Nonce::random(),
        question_batch_id: batch_id,
        tenant_id: tenant_a, // Inner payload says tenant A
        expiry: UnixTimestamp(u64::MAX),
        segment_vector: vec!["engineering".into()],
        attestation_class: AttestationClass::Personal,
        key_version: KeyVersion(1),
    };
    let token2_bytes = token2.to_bytes();

    let blinding2 = blind_sig::blind(&kp_a.pk, &token2_bytes.0).unwrap();
    let blind_sig2 = blind_sig::blind_sign(&kp_a.sk, &blinding2.blind_message).unwrap();
    let sig2 = blind_sig::finalize(&kp_a.pk, &blind_sig2, &blinding2, &token2_bytes.0).unwrap();

    let submit_cross = ResponseSubmit {
        token: token2_bytes,
        signature: SignatureBytes(sig2.0.clone()),
        msg_randomizer: blinding2.msg_randomizer.map(|r| r.0),
        key_version: KeyVersion(1),
        question_batch_id: batch_id,
        tenant_id: tenant_b, // Outer envelope says tenant B — mismatch!
        response_blob: EncryptedBlob(vec![0x42]),
    };
    let err = collector
        .accept(&submit_cross)
        .expect_err("cross-tenant submission must be rejected");

    // The collector checks token.tenant_id != submit.tenant_id → TenantMismatch
    match err {
        pulse_signal::CollectorError::Rejected(reason) => {
            assert!(
                matches!(reason, RejectReason::TenantMismatch),
                "expected TenantMismatch, got {reason:?}"
            );
        }
    }
}

/// A separate test proving per-tenant keypair isolation at the crypto level:
/// a token signed by Tenant A's key cannot verify with Tenant B's public key.
#[test]
fn signature_verification_fails_with_wrong_tenant_key() {
    let kp_a = blind_sig::generate_keypair().unwrap();
    let kp_b = blind_sig::generate_keypair().unwrap();

    let msg = b"test token payload";
    let blinding_result = blind_sig::blind(&kp_a.pk, msg).unwrap();
    let blind_sig_val = blind_sig::blind_sign(&kp_a.sk, &blinding_result.blind_message).unwrap();
    let sig = blind_sig::finalize(&kp_a.pk, &blind_sig_val, &blinding_result, msg).unwrap();

    // Verify with Tenant A's key — should succeed
    blind_sig::verify(&kp_a.pk, &sig, blinding_result.msg_randomizer, msg).unwrap();

    // Verify with Tenant B's key — should fail (InvalidSignature)
    let result = blind_sig::verify(&kp_b.pk, &sig, blinding_result.msg_randomizer, msg);
    assert!(
        result.is_err(),
        "signature signed by Tenant A must not verify with Tenant B's key"
    );
}

// ---------------------------------------------------------------------------
// Test 2: Envelope encryption round-trip
// ---------------------------------------------------------------------------

#[test]
fn envelope_encryption_round_trip() {
    let cmk = Arc::new(DevCmkProvider::new());
    let dek_store = Arc::new(InMemoryDekStore::new());
    let inner = Arc::new(InMemoryStore::new());
    let tenant_id = TenantId::new();

    // Provision a DEK-responses for this tenant
    let dek = aead::generate_key();
    let wrapped = cmk.wrap_dek(&tenant_id, &dek).unwrap();
    dek_store.store_wrapped_dek(&tenant_id, DekDomain::Responses, wrapped);

    let encrypting_store =
        EncryptingResponseStore::new(inner.clone(), dek_store.clone(), cmk.clone());

    let original_blob = vec![1, 2, 3, 4, 5, 6, 7, 8];

    // Store a response through the encrypting store
    encrypting_store.store(StoredResponse {
        encrypted_blob: EncryptedBlob(original_blob.clone()),
        question_batch_id: QuestionBatchId::new(),
        tenant_id,
        received_at: UnixTimestamp::now(),
    });

    // The inner store should hold a different (envelope-encrypted) blob
    let inner_responses = inner.list();
    assert_eq!(inner_responses.len(), 1);
    assert_ne!(
        inner_responses[0].encrypted_blob.0, original_blob,
        "inner store must hold the envelope-encrypted blob, not the original"
    );

    // Reading through the encrypting store should return the original (decrypted) blob
    let responses = encrypting_store.list();
    assert_eq!(responses.len(), 1);
    assert_eq!(
        responses[0].encrypted_blob.0, original_blob,
        "encrypting store must transparently decrypt on list()"
    );
}

// ---------------------------------------------------------------------------
// Test 3: Crypto-shredding
// ---------------------------------------------------------------------------

#[test]
fn crypto_shredding() {
    let cmk = Arc::new(DevCmkProvider::new());
    let dek_store = Arc::new(InMemoryDekStore::new());
    let inner = Arc::new(InMemoryStore::new());
    let tenant_id = TenantId::new();

    // Provision a DEK-responses for this tenant
    let dek = aead::generate_key();
    let wrapped = cmk.wrap_dek(&tenant_id, &dek).unwrap();
    dek_store.store_wrapped_dek(&tenant_id, DekDomain::Responses, wrapped);

    let encrypting_store =
        EncryptingResponseStore::new(inner.clone(), dek_store.clone(), cmk.clone());

    let original_blob = vec![10, 20, 30, 40, 50];

    // Store a response
    encrypting_store.store(StoredResponse {
        encrypted_blob: EncryptedBlob(original_blob.clone()),
        question_batch_id: QuestionBatchId::new(),
        tenant_id,
        received_at: UnixTimestamp::now(),
    });

    // Verify it's readable before shredding
    let pre_shred = encrypting_store.list();
    assert_eq!(pre_shred.len(), 1);
    assert_eq!(pre_shred[0].encrypted_blob.0, original_blob);

    // --- Crypto-shred: delete the tenant's DEKs ---
    dek_store.delete_tenant(&tenant_id);

    // List responses — the blob is NOT decryptable (returned as-is, still encrypted)
    let post_shred = encrypting_store.list();
    assert_eq!(post_shred.len(), 1);
    assert_ne!(
        post_shred[0].encrypted_blob.0, original_blob,
        "after crypto-shredding, the blob must remain encrypted (not the original)"
    );

    // The blob should match what the inner store holds (still envelope-encrypted)
    let inner_responses = inner.list();
    assert_eq!(
        post_shred[0].encrypted_blob.0, inner_responses[0].encrypted_blob.0,
        "after shredding, the encrypting store should return the raw inner blob unchanged"
    );
}
