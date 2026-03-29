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
/// Append-only storage for encrypted anonymous responses.
///
/// The Signal zone never decrypts response content — implementations must
/// treat [`StoredResponse::encrypted_blob`] as opaque bytes.
///
/// # Implementor requirements
///
/// - [`store`](Self::store) appends only — never updates or deletes existing
///   responses.
/// - [`list`](Self::list) returns responses in insertion order.
/// - Database errors are catastrophic — use `.expect("...")` to crash the
///   process (same convention as `SpentTokenLedger`).
pub trait ResponseStore: Send + Sync {
    /// Append an encrypted response to the store. Never updates or deletes.
    fn store(&self, response: StoredResponse);
    /// Return the total number of stored responses.
    fn count(&self) -> usize;
    /// Return all stored responses in insertion order.
    fn list(&self) -> Vec<StoredResponse>;
    /// List responses for a specific question batch and tenant.
    ///
    /// The default implementation filters [`list()`](Self::list). Custom
    /// backends should override this for efficiency (e.g., a WHERE clause).
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
