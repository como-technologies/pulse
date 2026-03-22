use std::collections::HashMap;
use std::sync::Mutex;

use pulse_protocol::TenantId;

/// Domain that a DEK protects. Each domain has its own independent DEK per tenant,
/// enabling fine-grained crypto-shredding (e.g., delete response DEKs but keep
/// blind-sig DEKs during a key rotation).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DekDomain {
    /// DEK for encrypting/decrypting stored response blobs.
    Responses,
    /// DEK for encrypting/decrypting blind-signature key material at rest.
    BlindSig,
}

/// Stores wrapped (encrypted) DEKs, keyed by (tenant, domain).
///
/// The DEKs are stored in their wrapped form — only the [`CmkProvider`](crate::cmk::CmkProvider)
/// can unwrap them. Deleting a tenant's wrapped DEKs is one half of crypto-shredding;
/// deleting the CMK is the other.
pub trait DekStore: Send + Sync {
    /// Store a wrapped DEK for a tenant + domain. Overwrites any existing entry.
    fn store_wrapped_dek(&self, tenant_id: &TenantId, domain: DekDomain, wrapped: Vec<u8>);

    /// Retrieve a wrapped DEK for a tenant + domain. Returns `None` if not found
    /// (e.g., tenant was crypto-shredded).
    fn get_wrapped_dek(&self, tenant_id: &TenantId, domain: &DekDomain) -> Option<Vec<u8>>;

    /// Delete all wrapped DEKs for a tenant (crypto-shredding).
    fn delete_tenant(&self, tenant_id: &TenantId);
}

/// In-memory DEK store for development and testing.
pub struct InMemoryDekStore {
    deks: Mutex<HashMap<(TenantId, DekDomain), Vec<u8>>>,
}

impl InMemoryDekStore {
    pub fn new() -> Self {
        Self {
            deks: Mutex::new(HashMap::new()),
        }
    }
}

impl Default for InMemoryDekStore {
    fn default() -> Self {
        Self::new()
    }
}

impl DekStore for InMemoryDekStore {
    fn store_wrapped_dek(&self, tenant_id: &TenantId, domain: DekDomain, wrapped: Vec<u8>) {
        self.deks
            .lock()
            .expect("dek store lock poisoned")
            .insert((*tenant_id, domain), wrapped);
    }

    fn get_wrapped_dek(&self, tenant_id: &TenantId, domain: &DekDomain) -> Option<Vec<u8>> {
        self.deks
            .lock()
            .expect("dek store lock poisoned")
            .get(&(*tenant_id, *domain))
            .cloned()
    }

    fn delete_tenant(&self, tenant_id: &TenantId) {
        let mut guard = self.deks.lock().expect("dek store lock poisoned");
        guard.retain(|(tid, _), _| tid != tenant_id);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn store_and_retrieve() {
        let store = InMemoryDekStore::new();
        let tenant_id = TenantId::new();
        let wrapped = vec![1, 2, 3, 4];

        store.store_wrapped_dek(&tenant_id, DekDomain::Responses, wrapped.clone());
        assert_eq!(
            store.get_wrapped_dek(&tenant_id, &DekDomain::Responses),
            Some(wrapped)
        );
    }

    #[test]
    fn separate_domains() {
        let store = InMemoryDekStore::new();
        let tenant_id = TenantId::new();

        store.store_wrapped_dek(&tenant_id, DekDomain::Responses, vec![1]);
        store.store_wrapped_dek(&tenant_id, DekDomain::BlindSig, vec![2]);

        assert_eq!(
            store.get_wrapped_dek(&tenant_id, &DekDomain::Responses),
            Some(vec![1])
        );
        assert_eq!(
            store.get_wrapped_dek(&tenant_id, &DekDomain::BlindSig),
            Some(vec![2])
        );
    }

    #[test]
    fn delete_tenant_removes_all_domains() {
        let store = InMemoryDekStore::new();
        let tenant_id = TenantId::new();

        store.store_wrapped_dek(&tenant_id, DekDomain::Responses, vec![1]);
        store.store_wrapped_dek(&tenant_id, DekDomain::BlindSig, vec![2]);

        store.delete_tenant(&tenant_id);

        assert_eq!(
            store.get_wrapped_dek(&tenant_id, &DekDomain::Responses),
            None
        );
        assert_eq!(
            store.get_wrapped_dek(&tenant_id, &DekDomain::BlindSig),
            None
        );
    }

    #[test]
    fn missing_tenant_returns_none() {
        let store = InMemoryDekStore::new();
        let tenant_id = TenantId::new();
        assert_eq!(
            store.get_wrapped_dek(&tenant_id, &DekDomain::Responses),
            None
        );
    }
}
