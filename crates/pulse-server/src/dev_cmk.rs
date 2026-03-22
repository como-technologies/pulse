use pulse_protocol::TenantId;

use crate::cmk::{CmkError, CmkProvider};

/// Dev-only CMK provider that uses a single fixed AES-256 key for all tenants.
///
/// Selected via `PULSE_CMK_PROVIDER=dev`. Not for production use.
/// In production, each tenant would have their own CMK in a cloud KMS.
pub struct DevCmkProvider {
    wrapping_key: [u8; 32],
}

impl DevCmkProvider {
    pub fn new() -> Self {
        let wrapping_key = pulse_crypto::aead::generate_key();
        tracing::info!("Using dev CMK provider (single fixed wrapping key — NOT for production)");
        Self { wrapping_key }
    }
}

impl Default for DevCmkProvider {
    fn default() -> Self {
        Self::new()
    }
}

impl CmkProvider for DevCmkProvider {
    fn wrap_dek(
        &self,
        _tenant_id: &TenantId,
        plaintext_dek: &[u8; 32],
    ) -> Result<Vec<u8>, CmkError> {
        pulse_crypto::aead::wrap_key(&self.wrapping_key, plaintext_dek)
            .map_err(|e| CmkError::WrapFailed(e.to_string()))
    }

    fn unwrap_dek(&self, _tenant_id: &TenantId, wrapped_dek: &[u8]) -> Result<[u8; 32], CmkError> {
        pulse_crypto::aead::unwrap_key(&self.wrapping_key, wrapped_dek)
            .map_err(|e| CmkError::UnwrapFailed(e.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wrap_unwrap_round_trip() {
        let provider = DevCmkProvider::new();
        let tenant_id = TenantId::new();
        let dek = pulse_crypto::aead::generate_key();

        let wrapped = provider.wrap_dek(&tenant_id, &dek).unwrap();
        let unwrapped = provider.unwrap_dek(&tenant_id, &wrapped).unwrap();
        assert_eq!(unwrapped, dek);
    }

    #[test]
    fn different_tenants_same_wrapping_key() {
        let provider = DevCmkProvider::new();
        let tenant_a = TenantId::new();
        let tenant_b = TenantId::new();
        let dek = pulse_crypto::aead::generate_key();

        // Dev provider uses the same key for all tenants
        let wrapped_a = provider.wrap_dek(&tenant_a, &dek).unwrap();
        let unwrapped_b = provider.unwrap_dek(&tenant_b, &wrapped_a).unwrap();
        assert_eq!(unwrapped_b, dek);
    }
}
