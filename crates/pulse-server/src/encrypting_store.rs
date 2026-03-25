use std::sync::Arc;

use pulse_signal::{ResponseStore, StoredResponse};

use crate::cmk::CmkProvider;
use crate::dek_store::{DekDomain, DekStore};

/// Decorator that adds envelope encryption to any [`ResponseStore`].
///
/// On `store()`: looks up the tenant's wrapped DEK-responses, unwraps it via the
/// CMK provider, and encrypts the response blob under the DEK before delegating
/// to the inner store.
///
/// On `list()`: retrieves responses from the inner store, attempts to decrypt
/// each blob using the tenant's DEK. If the DEK is unavailable (crypto-shredded),
/// the response is returned with the blob still encrypted (graceful degradation).
///
/// This provides defense-in-depth: responses are encrypted first by the client
/// (AES-256-GCM with the client's key), then again by the server (under the
/// tenant's DEK wrapped by the CMK). Deleting the CMK or the wrapped DEK
/// renders stored responses unrecoverable.
pub struct EncryptingResponseStore {
    inner: Arc<dyn ResponseStore>,
    dek_store: Arc<dyn DekStore>,
    cmk: Arc<dyn CmkProvider>,
}

impl EncryptingResponseStore {
    #[must_use]
    pub fn new(
        inner: Arc<dyn ResponseStore>,
        dek_store: Arc<dyn DekStore>,
        cmk: Arc<dyn CmkProvider>,
    ) -> Self {
        Self {
            inner,
            dek_store,
            cmk,
        }
    }

    /// Unwrap the response DEK for a tenant. Returns the 32-byte plaintext DEK.
    fn unwrap_response_dek(&self, tenant_id: &pulse_protocol::TenantId) -> Option<[u8; 32]> {
        let wrapped = self
            .dek_store
            .get_wrapped_dek(tenant_id, &DekDomain::Responses)?;
        match self.cmk.unwrap_dek(tenant_id, &wrapped) {
            Ok(dek) => Some(dek),
            Err(e) => {
                tracing::warn!(
                    tenant_id = %tenant_id,
                    error = %e,
                    "failed to unwrap response DEK (tenant may be crypto-shredded)"
                );
                None
            }
        }
    }

    /// Attempt to decrypt each response blob in place using the tenant's DEK.
    /// If the DEK is unavailable, the blob stays encrypted (graceful degradation).
    fn decrypt_responses(&self, responses: &mut [StoredResponse]) {
        for response in responses {
            if let Some(dek) = self.unwrap_response_dek(&response.tenant_id) {
                match pulse_crypto::aead::decrypt(&dek, &response.encrypted_blob.0) {
                    Ok(decrypted) => {
                        response.encrypted_blob = pulse_protocol::EncryptedBlob(decrypted);
                    }
                    Err(e) => {
                        tracing::warn!(
                            tenant_id = %response.tenant_id,
                            error = %e,
                            "failed to decrypt response blob (returning as-is)"
                        );
                    }
                }
            }
        }
    }
}

impl ResponseStore for EncryptingResponseStore {
    fn store(&self, mut response: StoredResponse) {
        // Writing to a crypto-shredded tenant is a bug — panic on DEK lookup failure.
        let wrapped = self
            .dek_store
            .get_wrapped_dek(&response.tenant_id, &DekDomain::Responses)
            .expect("DEK not found for tenant on store — tenant may not be provisioned");
        let dek = self
            .cmk
            .unwrap_dek(&response.tenant_id, &wrapped)
            .expect("failed to unwrap DEK on store — CMK may be unavailable");

        let encrypted = pulse_crypto::aead::encrypt(&dek, &response.encrypted_blob.0)
            .expect("envelope encryption failed");
        response.encrypted_blob = pulse_protocol::EncryptedBlob(encrypted);

        self.inner.store(response);
    }

    fn count(&self) -> usize {
        self.inner.count()
    }

    fn list_by_batch(
        &self,
        question_batch_id: &pulse_protocol::QuestionBatchId,
        tenant_id: &pulse_protocol::TenantId,
    ) -> Vec<StoredResponse> {
        let mut responses = self.inner.list_by_batch(question_batch_id, tenant_id);
        self.decrypt_responses(&mut responses);
        responses
    }

    fn list(&self) -> Vec<StoredResponse> {
        let mut responses = self.inner.list();
        self.decrypt_responses(&mut responses);
        responses
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dek_store::InMemoryDekStore;
    use crate::dev_cmk::DevCmkProvider;
    use pulse_protocol::{EncryptedBlob, QuestionBatchId, TenantId, UnixTimestamp};
    use pulse_signal::InMemoryStore;

    fn setup() -> (
        EncryptingResponseStore,
        Arc<InMemoryStore>,
        Arc<InMemoryDekStore>,
        Arc<DevCmkProvider>,
        TenantId,
    ) {
        let cmk = Arc::new(DevCmkProvider::new());
        let dek_store = Arc::new(InMemoryDekStore::new());
        let inner = Arc::new(InMemoryStore::new());
        let tenant_id = TenantId::new();

        // Provision a DEK for the tenant
        let dek = pulse_crypto::aead::generate_key();
        let wrapped = cmk.wrap_dek(&tenant_id, &dek).unwrap();
        dek_store.store_wrapped_dek(&tenant_id, crate::dek_store::DekDomain::Responses, wrapped);

        let store = EncryptingResponseStore::new(inner.clone(), dek_store.clone(), cmk.clone());
        (store, inner, dek_store, cmk, tenant_id)
    }

    #[test]
    fn store_encrypts_blob() {
        let (store, inner, _dek_store, _cmk, tenant_id) = setup();
        let original_blob = vec![1, 2, 3, 4, 5];

        store.store(StoredResponse {
            encrypted_blob: EncryptedBlob(original_blob.clone()),
            question_batch_id: QuestionBatchId::new(),
            tenant_id,
            received_at: UnixTimestamp::now(),
        });

        // The inner store should have a different (envelope-encrypted) blob
        let inner_responses = inner.list();
        assert_eq!(inner_responses.len(), 1);
        assert_ne!(inner_responses[0].encrypted_blob.0, original_blob);
    }

    #[test]
    fn list_decrypts_blob() {
        let (store, _inner, _dek_store, _cmk, tenant_id) = setup();
        let original_blob = vec![1, 2, 3, 4, 5];

        store.store(StoredResponse {
            encrypted_blob: EncryptedBlob(original_blob.clone()),
            question_batch_id: QuestionBatchId::new(),
            tenant_id,
            received_at: UnixTimestamp::now(),
        });

        // Reading through the encrypting store should return the original blob
        let responses = store.list();
        assert_eq!(responses.len(), 1);
        assert_eq!(responses[0].encrypted_blob.0, original_blob);
    }

    #[test]
    fn count_delegates_to_inner() {
        let (store, _inner, _dek_store, _cmk, tenant_id) = setup();

        store.store(StoredResponse {
            encrypted_blob: EncryptedBlob(vec![42]),
            question_batch_id: QuestionBatchId::new(),
            tenant_id,
            received_at: UnixTimestamp::now(),
        });

        assert_eq!(store.count(), 1);
    }

    #[test]
    fn crypto_shredded_tenant_returns_encrypted_blob() {
        let (store, _inner, dek_store, _cmk, tenant_id) = setup();
        let original_blob = vec![1, 2, 3, 4, 5];

        store.store(StoredResponse {
            encrypted_blob: EncryptedBlob(original_blob.clone()),
            question_batch_id: QuestionBatchId::new(),
            tenant_id,
            received_at: UnixTimestamp::now(),
        });

        // Simulate crypto-shredding by deleting the tenant's DEKs
        dek_store.delete_tenant(&tenant_id);

        // Reading should return the blob still encrypted (graceful degradation)
        let responses = store.list();
        assert_eq!(responses.len(), 1);
        // The blob should NOT be the original (it's still envelope-encrypted)
        assert_ne!(responses[0].encrypted_blob.0, original_blob);
    }

    #[test]
    #[should_panic(expected = "DEK not found")]
    fn store_to_shredded_tenant_panics() {
        let (store, _inner, dek_store, _cmk, tenant_id) = setup();

        // Delete the tenant's DEKs first
        dek_store.delete_tenant(&tenant_id);

        // Attempting to store should panic — writing to a shredded tenant is a bug
        store.store(StoredResponse {
            encrypted_blob: EncryptedBlob(vec![42]),
            question_batch_id: QuestionBatchId::new(),
            tenant_id,
            received_at: UnixTimestamp::now(),
        });
    }
}
