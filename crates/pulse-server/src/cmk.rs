use pulse_protocol::TenantId;

#[derive(Debug, thiserror::Error)]
pub enum CmkError {
    #[error("wrap failed: {0}")]
    WrapFailed(String),
    #[error("unwrap failed: {0}")]
    UnwrapFailed(String),
}

/// Customer-Managed Key provider — wraps/unwraps DEKs.
///
/// The CMK itself is held by the tenant, never stored by Pulse.
/// In production, this would integrate with a cloud KMS (e.g., AWS KMS,
/// GCP Cloud KMS). The dev implementation uses a single local wrapping key.
pub trait CmkProvider: Send + Sync {
    /// Wrap (encrypt) a 32-byte DEK under the tenant's CMK.
    fn wrap_dek(&self, tenant_id: &TenantId, plaintext_dek: &[u8; 32])
    -> Result<Vec<u8>, CmkError>;

    /// Unwrap (decrypt) a wrapped DEK using the tenant's CMK.
    fn unwrap_dek(&self, tenant_id: &TenantId, wrapped_dek: &[u8]) -> Result<[u8; 32], CmkError>;
}
