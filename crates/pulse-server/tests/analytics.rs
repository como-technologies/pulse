//! Analytics Engine integration tests — verifies decryption, aggregation,
//! k-anonymity suppression, epoch rotation, and crypto-shredding.

use std::sync::Arc;

use pulse_crypto::{aead, pseudonym};
use pulse_protocol::epoch::EpochConfig;
use pulse_protocol::messages::{ResponseData, ResponsePayload, ResponseType};
use pulse_protocol::{
    EncryptedBlob, EpochId, Pseudonym, QuestionBatchId, SegmentLabel, TenantId, UnixTimestamp,
};
use pulse_signal::{InMemoryStore, ResponseStore, StoredResponse};

use pulse_server::analytics::AnalyticsEngine;
use pulse_server::cmk::CmkProvider;
use pulse_server::dek_store::{DekDomain, DekStore, InMemoryDekStore};
use pulse_server::dev_cmk::DevCmkProvider;

struct TestSetup {
    engine: AnalyticsEngine,
    store: Arc<InMemoryStore>,
    dek_store: Arc<InMemoryDekStore>,
    tenant_id: TenantId,
    analytics_dek: [u8; 32],
}

fn setup(k_threshold: usize) -> TestSetup {
    let cmk = Arc::new(DevCmkProvider::new());
    let dek_store = Arc::new(InMemoryDekStore::new());
    let store = Arc::new(InMemoryStore::new());
    let tenant_id = TenantId::new();

    let analytics_dek = aead::generate_key();
    let wrapped = cmk.wrap_dek(&tenant_id, &analytics_dek).unwrap();
    dek_store.store_wrapped_dek(&tenant_id, DekDomain::Analytics, wrapped);

    let engine = AnalyticsEngine::new(store.clone(), dek_store.clone(), cmk, k_threshold);

    TestSetup {
        engine,
        store,
        dek_store,
        tenant_id,
        analytics_dek,
    }
}

fn encrypt_payload(dek: &[u8; 32], payload: &ResponsePayload) -> Vec<u8> {
    let bytes = postcard::to_allocvec(payload).unwrap();
    aead::encrypt(dek, &bytes).unwrap()
}

fn store_response(
    store: &dyn ResponseStore,
    dek: &[u8; 32],
    payload: &ResponsePayload,
    batch_id: QuestionBatchId,
    tenant_id: TenantId,
) {
    store.store(StoredResponse {
        encrypted_blob: EncryptedBlob(encrypt_payload(dek, payload)),
        question_batch_id: batch_id,
        tenant_id,
        received_at: UnixTimestamp::now(),
    });
}

fn make_payload(pseudonym: [u8; 32], score: u8, segments: &[&str]) -> ResponsePayload {
    ResponsePayload {
        pseudonym: Pseudonym(pseudonym),
        epoch_id: EpochId("epoch-0".into()),
        response_type: ResponseType::Scale5,
        response_data: ResponseData::Scale5(score),
        segment_vector: segments.iter().map(|s| SegmentLabel::from(*s)).collect(),
    }
}

#[test]
fn multiple_pseudonyms_aggregate_correctly() {
    let t = setup(2);
    let batch_id = QuestionBatchId::new();

    // 3 responses from 3 different pseudonyms in the same segment
    for i in 0..3 {
        let mut pseudo = [0u8; 32];
        pseudo[0] = i;
        store_response(
            t.store.as_ref(),
            &t.analytics_dek,
            &make_payload(pseudo, i + 3, &["engineering"]),
            batch_id,
            t.tenant_id,
        );
    }

    let result = t.engine.aggregate_batch(&batch_id, &t.tenant_id).unwrap();
    assert_eq!(result.total_responses, 3);
    assert_eq!(result.total_decrypted, 3);
    assert_eq!(result.segments.len(), 1);

    let seg = &result.segments[0];
    assert_eq!(seg.segment_label.0, "engineering");
    assert_eq!(seg.response_count, 3);
    assert_eq!(seg.unique_pseudonyms, 3);
    assert!(!seg.suppressed);
    // average of 3, 4, 5 = 4.0
    assert_eq!(seg.average_score, Some(4.0));
}

#[test]
fn k_anonymity_suppresses_small_groups() {
    let t = setup(3); // k=3
    let batch_id = QuestionBatchId::new();

    // 2 pseudonyms in engineering (< k=3, should be suppressed)
    store_response(
        t.store.as_ref(),
        &t.analytics_dek,
        &make_payload([1u8; 32], 5, &["engineering"]),
        batch_id,
        t.tenant_id,
    );
    store_response(
        t.store.as_ref(),
        &t.analytics_dek,
        &make_payload([2u8; 32], 3, &["engineering"]),
        batch_id,
        t.tenant_id,
    );

    // 3 pseudonyms in marketing (== k=3, not suppressed)
    for i in 0..3 {
        let mut pseudo = [10u8; 32];
        pseudo[0] = i;
        store_response(
            t.store.as_ref(),
            &t.analytics_dek,
            &make_payload(pseudo, 4, &["marketing"]),
            batch_id,
            t.tenant_id,
        );
    }

    let result = t.engine.aggregate_batch(&batch_id, &t.tenant_id).unwrap();
    assert_eq!(result.total_decrypted, 5);

    let eng = result
        .segments
        .iter()
        .find(|s| s.segment_label.0 == "engineering")
        .unwrap();
    assert!(eng.suppressed);
    assert_eq!(eng.average_score, None); // suppressed

    let mkt = result
        .segments
        .iter()
        .find(|s| s.segment_label.0 == "marketing")
        .unwrap();
    assert!(!mkt.suppressed);
    assert_eq!(mkt.average_score, Some(4.0));
}

#[test]
fn crypto_shredded_tenant_returns_error() {
    let t = setup(1);
    let batch_id = QuestionBatchId::new();

    store_response(
        t.store.as_ref(),
        &t.analytics_dek,
        &make_payload([1u8; 32], 4, &["engineering"]),
        batch_id,
        t.tenant_id,
    );

    // Simulate crypto-shredding
    t.dek_store.delete_tenant(&t.tenant_id);

    let result = t.engine.aggregate_batch(&batch_id, &t.tenant_id);
    assert!(result.is_err());
}

#[test]
fn epoch_rotation_produces_different_pseudonyms() {
    let secret = pseudonym::generate_employee_secret();
    let tenant_id = TenantId::new();

    let config = EpochConfig {
        duration_secs: 3600,
    };

    let epoch_0 = config.epoch_at(&UnixTimestamp(0));
    let epoch_1 = config.epoch_at(&UnixTimestamp(3600));

    let p0 = pseudonym::derive_pseudonym(&secret, tenant_id.0.as_bytes(), epoch_0.0.as_bytes());
    let p1 = pseudonym::derive_pseudonym(&secret, tenant_id.0.as_bytes(), epoch_1.0.as_bytes());

    assert_ne!(
        p0, p1,
        "same employee should get different pseudonyms in different epochs"
    );
}

#[test]
fn same_epoch_same_pseudonym() {
    let secret = pseudonym::generate_employee_secret();
    let tenant_id = TenantId::new();
    let epoch = EpochId("epoch-42".into());

    let p1 = pseudonym::derive_pseudonym(&secret, tenant_id.0.as_bytes(), epoch.0.as_bytes());
    let p2 = pseudonym::derive_pseudonym(&secret, tenant_id.0.as_bytes(), epoch.0.as_bytes());

    assert_eq!(
        p1, p2,
        "same employee + same epoch must produce same pseudonym"
    );
}

#[test]
fn responses_from_multiple_batches_isolated() {
    let t = setup(1);
    let batch_a = QuestionBatchId::new();
    let batch_b = QuestionBatchId::new();

    store_response(
        t.store.as_ref(),
        &t.analytics_dek,
        &make_payload([1u8; 32], 5, &["engineering"]),
        batch_a,
        t.tenant_id,
    );
    store_response(
        t.store.as_ref(),
        &t.analytics_dek,
        &make_payload([2u8; 32], 2, &["engineering"]),
        batch_b,
        t.tenant_id,
    );

    let result_a = t.engine.aggregate_batch(&batch_a, &t.tenant_id).unwrap();
    assert_eq!(result_a.total_responses, 1);
    assert_eq!(result_a.segments[0].average_score, Some(5.0));

    let result_b = t.engine.aggregate_batch(&batch_b, &t.tenant_id).unwrap();
    assert_eq!(result_b.total_responses, 1);
    assert_eq!(result_b.segments[0].average_score, Some(2.0));
}

#[test]
fn response_with_multiple_segments_counted_in_each() {
    let t = setup(1);
    let batch_id = QuestionBatchId::new();

    // One response belonging to two segments
    store_response(
        t.store.as_ref(),
        &t.analytics_dek,
        &make_payload([1u8; 32], 4, &["engineering", "backend"]),
        batch_id,
        t.tenant_id,
    );

    let result = t.engine.aggregate_batch(&batch_id, &t.tenant_id).unwrap();
    assert_eq!(result.total_responses, 1);
    assert_eq!(result.segments.len(), 2);

    for seg in &result.segments {
        assert_eq!(seg.response_count, 1);
        assert_eq!(seg.average_score, Some(4.0));
    }
}
