use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use pulse_protocol::messages::{ResponseData, ResponsePayload};
use pulse_protocol::{QuestionBatchId, SegmentLabel, TenantId};
use pulse_signal::ResponseStore;

use crate::cmk::CmkProvider;
use crate::dek_store::{DekDomain, DekStore};

/// Error type for analytics operations.
#[derive(Debug, thiserror::Error)]
pub enum AnalyticsError {
    #[error("tenant analytics DEK not found (crypto-shredded?)")]
    DekNotFound,
    #[error("DEK unwrap failed: {0}")]
    DekUnwrapFailed(String),
}

/// Aggregated results for a question batch.
#[derive(Debug, Clone, serde::Serialize)]
pub struct BatchAggregation {
    pub question_batch_id: QuestionBatchId,
    pub tenant_id: TenantId,
    pub total_responses: usize,
    pub total_decrypted: usize,
    pub total_failed: usize,
    pub segments: Vec<SegmentAggregation>,
}

/// Aggregated results for a single segment within a batch.
#[derive(Debug, Clone, serde::Serialize)]
pub struct SegmentAggregation {
    pub segment_label: SegmentLabel,
    pub response_count: usize,
    pub unique_pseudonyms: usize,
    pub average_score: Option<f64>,
    /// True if this segment has fewer than k unique pseudonyms and results are suppressed.
    pub suppressed: bool,
}

/// Analytics Engine — decrypts response blobs and aggregates by segment and pseudonym.
///
/// Lives in the composition root (Signal zone). Has access to tenant DEKs via
/// CMK unwrap but never has access to employee identity.
pub struct AnalyticsEngine {
    store: Arc<dyn ResponseStore>,
    dek_store: Arc<dyn DekStore>,
    cmk: Arc<dyn CmkProvider>,
    k_threshold: usize,
}

impl AnalyticsEngine {
    #[must_use]
    pub fn new(
        store: Arc<dyn ResponseStore>,
        dek_store: Arc<dyn DekStore>,
        cmk: Arc<dyn CmkProvider>,
        k_threshold: usize,
    ) -> Self {
        Self {
            store,
            dek_store,
            cmk,
            k_threshold,
        }
    }

    /// Unwrap the analytics DEK for a tenant.
    fn unwrap_analytics_dek(&self, tenant_id: &TenantId) -> Result<[u8; 32], AnalyticsError> {
        let wrapped = self
            .dek_store
            .get_wrapped_dek(tenant_id, &DekDomain::Analytics)
            .ok_or(AnalyticsError::DekNotFound)?;
        self.cmk
            .unwrap_dek(tenant_id, &wrapped)
            .map_err(|e| AnalyticsError::DekUnwrapFailed(e.to_string()))
    }

    /// Decrypt a single response blob into a ResponsePayload.
    fn decrypt_response(analytics_dek: &[u8; 32], blob: &[u8]) -> Result<ResponsePayload, String> {
        let plaintext =
            pulse_crypto::aead::decrypt(analytics_dek, blob).map_err(|e| e.to_string())?;
        postcard::from_bytes(&plaintext).map_err(|e| e.to_string())
    }

    /// Aggregate responses for a question batch.
    #[tracing::instrument(
        name = "AnalyticsEngine::aggregate_batch",
        skip(self),
        fields(%batch_id, %tenant_id)
    )]
    pub fn aggregate_batch(
        &self,
        batch_id: &QuestionBatchId,
        tenant_id: &TenantId,
    ) -> Result<BatchAggregation, AnalyticsError> {
        let analytics_dek = self.unwrap_analytics_dek(tenant_id)?;

        // list_by_batch returns blobs with the at-rest layer already stripped
        // (EncryptingResponseStore handles that). We strip the client analytics layer.
        let responses = self.store.list_by_batch(batch_id, tenant_id);

        let mut payloads: Vec<ResponsePayload> = Vec::new();
        let mut failed = 0usize;

        for response in &responses {
            match Self::decrypt_response(&analytics_dek, &response.encrypted_blob.0) {
                Ok(payload) => payloads.push(payload),
                Err(e) => {
                    tracing::warn!(error = %e, "failed to decrypt response blob");
                    failed += 1;
                }
            }
        }

        let segments = self.aggregate_by_segment(&payloads);

        tracing::info!(
            total = responses.len(),
            decrypted = payloads.len(),
            failed,
            segments = segments.len(),
            "batch aggregation complete"
        );

        Ok(BatchAggregation {
            question_batch_id: *batch_id,
            tenant_id: *tenant_id,
            total_responses: responses.len(),
            total_decrypted: payloads.len(),
            total_failed: failed,
            segments,
        })
    }

    /// Group decrypted responses by segment and compute aggregates.
    fn aggregate_by_segment(&self, payloads: &[ResponsePayload]) -> Vec<SegmentAggregation> {
        let mut by_segment: HashMap<&SegmentLabel, Vec<&ResponsePayload>> = HashMap::new();

        for payload in payloads {
            for seg in &payload.segment_vector {
                by_segment.entry(seg).or_default().push(payload);
            }
        }

        let mut segments: Vec<SegmentAggregation> = by_segment
            .into_iter()
            .map(|(label, entries)| {
                let unique_pseudonyms: HashSet<&pulse_protocol::Pseudonym> =
                    entries.iter().map(|p| &p.pseudonym).collect();
                let unique_count = unique_pseudonyms.len();
                let suppressed = unique_count < self.k_threshold;

                let average_score = if suppressed {
                    None
                } else {
                    compute_average_score(&entries)
                };

                SegmentAggregation {
                    segment_label: label.clone(),
                    response_count: entries.len(),
                    unique_pseudonyms: unique_count,
                    average_score,
                    suppressed,
                }
            })
            .collect();

        // Sort by segment label for deterministic output
        segments.sort_by(|a, b| a.segment_label.0.cmp(&b.segment_label.0));
        segments
    }
}

/// Compute average score for Scale5 responses. Returns None if no Scale5 data.
fn compute_average_score(entries: &[&ResponsePayload]) -> Option<f64> {
    let scores: Vec<f64> = entries
        .iter()
        .filter_map(|p| match &p.response_data {
            ResponseData::Scale5(v) => Some(*v as f64),
            _ => None,
        })
        .collect();
    if scores.is_empty() {
        return None;
    }
    Some(scores.iter().sum::<f64>() / scores.len() as f64)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dek_store::InMemoryDekStore;
    use crate::dev_cmk::DevCmkProvider;
    use pulse_protocol::messages::ResponseType;
    use pulse_protocol::{EncryptedBlob, EpochId, Pseudonym, UnixTimestamp};
    use pulse_signal::{InMemoryStore, StoredResponse};

    fn setup() -> (
        AnalyticsEngine,
        Arc<InMemoryStore>,
        Arc<InMemoryDekStore>,
        Arc<DevCmkProvider>,
        TenantId,
        [u8; 32], // analytics DEK
    ) {
        let cmk = Arc::new(DevCmkProvider::new());
        let dek_store = Arc::new(InMemoryDekStore::new());
        let inner = Arc::new(InMemoryStore::new());
        let tenant_id = TenantId::new();

        // Provision analytics DEK
        let analytics_dek = pulse_crypto::aead::generate_key();
        let wrapped = cmk.wrap_dek(&tenant_id, &analytics_dek).unwrap();
        dek_store.store_wrapped_dek(&tenant_id, DekDomain::Analytics, wrapped);

        let engine = AnalyticsEngine::new(inner.clone(), dek_store.clone(), cmk.clone(), 2);
        (engine, inner, dek_store, cmk, tenant_id, analytics_dek)
    }

    fn make_payload(pseudonym: [u8; 32], score: u8, segment: &str) -> ResponsePayload {
        ResponsePayload {
            pseudonym: Pseudonym(pseudonym),
            epoch_id: EpochId("epoch-0".into()),
            response_type: ResponseType::Scale5,
            response_data: ResponseData::Scale5(score),
            segment_vector: vec![SegmentLabel::from(segment)],
        }
    }

    fn encrypt_and_store(
        store: &InMemoryStore,
        dek: &[u8; 32],
        payload: &ResponsePayload,
        batch_id: QuestionBatchId,
        tenant_id: TenantId,
    ) {
        let bytes = postcard::to_allocvec(payload).unwrap();
        let encrypted = pulse_crypto::aead::encrypt(dek, &bytes).unwrap();
        store.store(StoredResponse {
            encrypted_blob: EncryptedBlob(encrypted),
            question_batch_id: batch_id,
            tenant_id,
            received_at: UnixTimestamp::now(),
        });
    }

    #[test]
    fn aggregate_single_response() {
        let (engine, store, _, _, tenant_id, dek) = setup();
        let batch_id = QuestionBatchId::new();
        let payload = make_payload([1u8; 32], 4, "engineering");

        encrypt_and_store(&store, &dek, &payload, batch_id, tenant_id);

        let result = engine.aggregate_batch(&batch_id, &tenant_id).unwrap();
        assert_eq!(result.total_responses, 1);
        assert_eq!(result.total_decrypted, 1);
        assert_eq!(result.total_failed, 0);
        assert_eq!(result.segments.len(), 1);
        // k=2 but only 1 pseudonym → suppressed
        assert!(result.segments[0].suppressed);
        assert_eq!(result.segments[0].average_score, None);
    }

    #[test]
    fn aggregate_multiple_pseudonyms_not_suppressed() {
        let (engine, store, _, _, tenant_id, dek) = setup();
        let batch_id = QuestionBatchId::new();

        // Two different pseudonyms → meets k=2 threshold
        encrypt_and_store(
            &store,
            &dek,
            &make_payload([1u8; 32], 4, "engineering"),
            batch_id,
            tenant_id,
        );
        encrypt_and_store(
            &store,
            &dek,
            &make_payload([2u8; 32], 2, "engineering"),
            batch_id,
            tenant_id,
        );

        let result = engine.aggregate_batch(&batch_id, &tenant_id).unwrap();
        assert_eq!(result.total_decrypted, 2);
        assert_eq!(result.segments.len(), 1);
        assert!(!result.segments[0].suppressed);
        assert_eq!(result.segments[0].unique_pseudonyms, 2);
        assert_eq!(result.segments[0].average_score, Some(3.0)); // (4+2)/2
    }

    #[test]
    fn aggregate_multiple_segments() {
        let (engine, store, _, _, tenant_id, dek) = setup();
        let batch_id = QuestionBatchId::new();

        encrypt_and_store(
            &store,
            &dek,
            &make_payload([1u8; 32], 5, "engineering"),
            batch_id,
            tenant_id,
        );
        encrypt_and_store(
            &store,
            &dek,
            &make_payload([2u8; 32], 3, "engineering"),
            batch_id,
            tenant_id,
        );
        encrypt_and_store(
            &store,
            &dek,
            &make_payload([3u8; 32], 1, "marketing"),
            batch_id,
            tenant_id,
        );

        let result = engine.aggregate_batch(&batch_id, &tenant_id).unwrap();
        assert_eq!(result.total_decrypted, 3);
        assert_eq!(result.segments.len(), 2);

        let eng = result
            .segments
            .iter()
            .find(|s| s.segment_label.0 == "engineering")
            .unwrap();
        assert!(!eng.suppressed);
        assert_eq!(eng.unique_pseudonyms, 2);
        assert_eq!(eng.average_score, Some(4.0)); // (5+3)/2

        let mkt = result
            .segments
            .iter()
            .find(|s| s.segment_label.0 == "marketing")
            .unwrap();
        assert!(mkt.suppressed); // only 1 pseudonym, k=2
    }

    #[test]
    fn dek_not_found_returns_error() {
        let cmk = Arc::new(DevCmkProvider::new());
        let dek_store = Arc::new(InMemoryDekStore::new());
        let store = Arc::new(InMemoryStore::new());
        let tenant_id = TenantId::new();
        // No DEK provisioned

        let engine = AnalyticsEngine::new(store, dek_store, cmk, 2);
        let result = engine.aggregate_batch(&QuestionBatchId::new(), &tenant_id);
        assert!(result.is_err());
    }

    #[test]
    fn empty_batch_returns_zero_counts() {
        let (engine, _, _, _, tenant_id, _) = setup();
        let batch_id = QuestionBatchId::new();

        let result = engine.aggregate_batch(&batch_id, &tenant_id).unwrap();
        assert_eq!(result.total_responses, 0);
        assert_eq!(result.total_decrypted, 0);
        assert!(result.segments.is_empty());
    }

    #[test]
    fn corrupted_blob_counted_as_failed() {
        let (engine, store, _, _, tenant_id, _) = setup();
        let batch_id = QuestionBatchId::new();

        // Store a blob that is NOT encrypted with the analytics DEK
        store.store(StoredResponse {
            encrypted_blob: EncryptedBlob(vec![0xDE, 0xAD, 0xBE, 0xEF]),
            question_batch_id: batch_id,
            tenant_id,
            received_at: UnixTimestamp::now(),
        });

        let result = engine.aggregate_batch(&batch_id, &tenant_id).unwrap();
        assert_eq!(result.total_responses, 1);
        assert_eq!(result.total_decrypted, 0);
        assert_eq!(result.total_failed, 1);
    }
}
