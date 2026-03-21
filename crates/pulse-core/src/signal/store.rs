use std::sync::Mutex;

/// A stored anonymous response — encrypted blob with metadata.
#[derive(Debug, Clone)]
pub struct StoredResponse {
    /// The encrypted response blob (opaque ciphertext).
    pub encrypted_blob: Vec<u8>,
    /// Question batch this response belongs to.
    pub question_batch_id: uuid::Uuid,
    /// Unix timestamp when the response was received.
    pub received_at: u64,
}

/// Trait for persisting anonymous responses.
pub trait ResponseStore: Send + Sync {
    fn store(&self, response: StoredResponse);
    fn count(&self) -> usize;
    fn list(&self) -> Vec<StoredResponse>;
}

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
        self.responses
            .lock()
            .expect("store lock poisoned")
            .clone()
    }
}
