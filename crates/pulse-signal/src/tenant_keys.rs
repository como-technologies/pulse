use pulse_crypto::BrssPublicKey;
use pulse_protocol::{KeyVersion, TenantId};

#[derive(Debug, thiserror::Error)]
pub enum TenantKeyError {
    #[error("tenant not found: {0}")]
    TenantNotFound(TenantId),
    #[error("key version not found")]
    KeyVersionNotFound,
}

/// Provides the blind-signature verification key for a tenant.
///
/// Implementations live in the composition root (`pulse-server`), not here —
/// this crate only defines the interface.
pub trait TenantVerificationKeyStore: Send + Sync {
    /// Return the public verification key for a specific tenant and key version.
    fn verification_key(
        &self,
        tenant_id: &TenantId,
        key_version: &KeyVersion,
    ) -> Result<BrssPublicKey, TenantKeyError>;
}
