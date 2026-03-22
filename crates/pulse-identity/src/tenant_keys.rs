use pulse_crypto::blind_sig::BrssSecretKey;
use pulse_protocol::{KeyVersion, TenantId};

#[derive(Debug, thiserror::Error)]
pub enum TenantKeyError {
    #[error("tenant not found: {0}")]
    TenantNotFound(TenantId),
    #[error("key unavailable: {0}")]
    KeyUnavailable(String),
}

/// Provides the blind-signature signing key for a tenant.
///
/// Implementations live in the composition root (`pulse-server`), not here —
/// this crate only defines the interface.
pub trait TenantSigningKeyStore: Send + Sync {
    /// Return the current signing key and its version for the given tenant.
    fn signing_key(
        &self,
        tenant_id: &TenantId,
    ) -> Result<(BrssSecretKey, KeyVersion), TenantKeyError>;
}
