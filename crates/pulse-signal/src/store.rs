use std::sync::Mutex;

use pulse_protocol::{EncryptedBlob, QuestionBatchId, TenantId, UnixTimestamp};

// ANCHOR: stored_response
/// A stored anonymous response — encrypted blob with metadata.
#[derive(Debug, Clone)]
pub struct StoredResponse {
    /// The encrypted response blob (opaque ciphertext).
    pub encrypted_blob: EncryptedBlob,
    /// Question batch this response belongs to.
    pub question_batch_id: QuestionBatchId,
    /// Tenant this response belongs to.
    pub tenant_id: TenantId,
    /// Unix timestamp when the response was received.
    pub received_at: UnixTimestamp,
}
// ANCHOR_END: stored_response

// ANCHOR: response_store
/// Trait for persisting anonymous responses.
pub trait ResponseStore: Send + Sync {
    fn store(&self, response: StoredResponse);
    fn count(&self) -> usize;
    fn list(&self) -> Vec<StoredResponse>;
    /// List responses for a specific question batch and tenant.
    fn list_by_batch(
        &self,
        question_batch_id: &QuestionBatchId,
        tenant_id: &TenantId,
    ) -> Vec<StoredResponse> {
        self.list()
            .into_iter()
            .filter(|r| r.question_batch_id == *question_batch_id && r.tenant_id == *tenant_id)
            .collect()
    }
}
// ANCHOR_END: response_store

/// In-memory response store for development and testing.
pub struct InMemoryStore {
    responses: Mutex<Vec<StoredResponse>>,
}

impl InMemoryStore {
    pub fn new() -> Self {
        Self {
            responses: Mutex::new(Vec::new()),
        }
    }
}

impl Default for InMemoryStore {
    fn default() -> Self {
        Self::new()
    }
}

impl ResponseStore for InMemoryStore {
    fn store(&self, response: StoredResponse) {
        self.responses
            .lock()
            .expect("store lock poisoned")
            .push(response);
    }

    fn count(&self) -> usize {
        self.responses.lock().expect("store lock poisoned").len()
    }

    fn list(&self) -> Vec<StoredResponse> {
        self.responses.lock().expect("store lock poisoned").clone()
    }
}
