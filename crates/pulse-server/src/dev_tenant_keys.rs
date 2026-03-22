use std::collections::HashMap;
use std::sync::Mutex;

use pulse_crypto::blind_sig::{BrssPublicKey, BrssSecretKey};
use pulse_identity::{TenantKeyError as IdentityKeyError, TenantSigningKeyStore};
use pulse_protocol::{KeyVersion, TenantId};
use pulse_signal::{TenantKeyError as SignalKeyError, TenantVerificationKeyStore};

/// A single tenant's key entry: version, signing key, verification key.
type TenantKeyEntry = (KeyVersion, BrssSecretKey, BrssPublicKey);

/// In-memory tenant key store for development and testing.
///
/// Implements both [`TenantSigningKeyStore`] (Identity zone) and
/// [`TenantVerificationKeyStore`] (Signal zone), allowing a single instance
/// (wrapped in `Arc`) to be shared across both zones in the composition root.
pub struct InMemoryTenantKeyStore {
    keys: Mutex<HashMap<TenantId, Vec<TenantKeyEntry>>>,
}

impl Default for InMemoryTenantKeyStore {
    fn default() -> Self {
        Self::new()
    }
}

impl InMemoryTenantKeyStore {
    pub fn new() -> Self {
        Self {
            keys: Mutex::new(HashMap::new()),
        }
    }

    /// Register a keypair for a tenant at a specific key version.
    pub fn register_tenant(
        &self,
        tenant_id: TenantId,
        sk: BrssSecretKey,
        pk: BrssPublicKey,
        key_version: KeyVersion,
    ) {
        self.keys
            .lock()
            .expect("tenant key store lock poisoned")
            .entry(tenant_id)
            .or_default()
            .push((key_version, sk, pk));
    }
}

impl TenantSigningKeyStore for InMemoryTenantKeyStore {
    fn signing_key(
        &self,
        tenant_id: &TenantId,
    ) -> Result<(BrssSecretKey, KeyVersion), IdentityKeyError> {
        let guard = self.keys.lock().expect("tenant key store lock poisoned");
        let entries = guard
            .get(tenant_id)
            .ok_or(IdentityKeyError::TenantNotFound(*tenant_id))?;
        // Return the latest key version (last registered)
        let (kv, sk, _pk) = entries
            .last()
            .ok_or_else(|| IdentityKeyError::KeyUnavailable("no keys registered".into()))?;
        Ok((sk.clone(), *kv))
    }
}

impl TenantVerificationKeyStore for InMemoryTenantKeyStore {
    fn verification_key(
        &self,
        tenant_id: &TenantId,
        key_version: &KeyVersion,
    ) -> Result<BrssPublicKey, SignalKeyError> {
        let guard = self.keys.lock().expect("tenant key store lock poisoned");
        let entries = guard
            .get(tenant_id)
            .ok_or(SignalKeyError::TenantNotFound(*tenant_id))?;
        for (kv, _sk, pk) in entries {
            if kv == key_version {
                return Ok(pk.clone());
            }
        }
        Err(SignalKeyError::KeyVersionNotFound)
    }
}
