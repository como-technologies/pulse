use pulse_protocol::TenantId;

#[derive(Debug, thiserror::Error)]
pub enum CmkError {
    #[error("wrap failed: {0}")]
    WrapFailed(String),
    #[error("unwrap failed: {0}")]
    UnwrapFailed(String),
}

// ANCHOR: cmk_provider_trait
/// Customer-Managed Key provider — wraps/unwraps DEKs.
///
/// The CMK itself is held by the tenant, never stored by Pulse.
/// In production, this would integrate with a cloud KMS (e.g., AWS KMS,
/// GCP Cloud KMS). The dev implementation uses a single local wrapping key.
///
/// The trait is synchronous. For async KMS clients, use
/// `tokio::task::block_in_place` (matching the storage provider pattern).
pub trait CmkProvider: Send + Sync {
    /// Wrap (encrypt) a plaintext 32-byte DEK under the tenant's CMK.
    ///
    /// Returns opaque wrapped bytes whose format is provider-specific
    /// (e.g., AWS KMS returns a `CiphertextBlob`).
    fn wrap_dek(&self, tenant_id: &TenantId, plaintext_dek: &[u8; 32])
    -> Result<Vec<u8>, CmkError>;

    /// Unwrap (decrypt) a previously wrapped DEK, returning the original
    /// 32-byte plaintext key.
    ///
    /// Must return [`CmkError::UnwrapFailed`] if the CMK has been deleted
    /// or revoked — this is the crypto-shredding trigger.
    fn unwrap_dek(&self, tenant_id: &TenantId, wrapped_dek: &[u8]) -> Result<[u8; 32], CmkError>;
}
// ANCHOR_END: cmk_provider_trait
