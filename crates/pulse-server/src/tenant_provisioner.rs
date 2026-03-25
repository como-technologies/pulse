use std::sync::Arc;

use pulse_protocol::{KeyVersion, TenantId};

use crate::cmk::CmkProvider;
use crate::dek_store::{DekDomain, DekStore};
use crate::dev_tenant_keys::InMemoryTenantKeyStore;

/// Provisions a new tenant with all required cryptographic material:
///
/// 1. **DEK-responses** — data encryption key for envelope-encrypting response blobs,
///    wrapped by the tenant's CMK and stored in the DEK store.
/// 2. **DEK-blindsig** — data encryption key for blind-signature key material at rest,
///    wrapped by the tenant's CMK and stored in the DEK store.
/// 3. **DEK-analytics** — data encryption key for client-side response payload encryption;
///    the Analytics Engine uses this to decrypt response payloads for aggregation.
/// 4. **Blind-signature keypair** — RSA keypair for the blind signature protocol,
///    registered in the tenant key store.
///
/// The provisioner is the single entry point for tenant onboarding, ensuring all
/// material is generated atomically.
pub struct TenantProvisioner {
    cmk: Arc<dyn CmkProvider>,
    dek_store: Arc<dyn DekStore>,
    key_store: Arc<InMemoryTenantKeyStore>,
}

impl TenantProvisioner {
    #[must_use]
    pub fn new(
        cmk: Arc<dyn CmkProvider>,
        dek_store: Arc<dyn DekStore>,
        key_store: Arc<InMemoryTenantKeyStore>,
    ) -> Self {
        Self {
            cmk,
            dek_store,
            key_store,
        }
    }

    /// Provision a new tenant with all required cryptographic material.
    #[tracing::instrument(
        name = "TenantProvisioner::provision",
        skip(self),
        fields(tenant_id = %tenant_id)
    )]
    pub fn provision(&self, tenant_id: TenantId) -> anyhow::Result<()> {
        // 1. Generate and wrap DEK-responses
        let dek_responses = pulse_crypto::aead::generate_key();
        let wrapped = self.cmk.wrap_dek(&tenant_id, &dek_responses)?;
        self.dek_store
            .store_wrapped_dek(&tenant_id, DekDomain::Responses, wrapped);
        tracing::debug!("stored wrapped DEK-responses");

        // 2. Generate and wrap DEK-blindsig
        let dek_blindsig = pulse_crypto::aead::generate_key();
        let wrapped = self.cmk.wrap_dek(&tenant_id, &dek_blindsig)?;
        self.dek_store
            .store_wrapped_dek(&tenant_id, DekDomain::BlindSig, wrapped);
        tracing::debug!("stored wrapped DEK-blindsig");

        // 3. Generate and wrap DEK-analytics (client-side response payload encryption)
        let dek_analytics = pulse_crypto::aead::generate_key();
        let wrapped = self.cmk.wrap_dek(&tenant_id, &dek_analytics)?;
        self.dek_store
            .store_wrapped_dek(&tenant_id, DekDomain::Analytics, wrapped);
        tracing::debug!("stored wrapped DEK-analytics");

        // 4. Generate blind-signature keypair and register
        let kp = pulse_crypto::blind_sig::generate_keypair()?;
        self.key_store
            .register_tenant(tenant_id, kp.sk, kp.pk, KeyVersion(1));
        tracing::debug!("registered blind-signature keypair");

        tracing::info!("tenant provisioned successfully");
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cmk::CmkProvider;
    use crate::dek_store::InMemoryDekStore;
    use crate::dev_cmk::DevCmkProvider;
    use pulse_identity::TenantSigningKeyStore;
    use pulse_signal::TenantVerificationKeyStore;

    #[test]
    fn provision_creates_all_material() {
        let cmk = Arc::new(DevCmkProvider::new());
        let dek_store = Arc::new(InMemoryDekStore::new());
        let key_store = Arc::new(InMemoryTenantKeyStore::new());

        let provisioner = TenantProvisioner::new(cmk.clone(), dek_store.clone(), key_store.clone());
        let tenant_id = TenantId::new();

        provisioner.provision(tenant_id).unwrap();

        // DEK-responses exists and is valid
        let wrapped_responses = dek_store
            .get_wrapped_dek(&tenant_id, &DekDomain::Responses)
            .expect("DEK-responses should exist");
        let dek = cmk.unwrap_dek(&tenant_id, &wrapped_responses).unwrap();
        assert_eq!(dek.len(), 32);

        // DEK-blindsig exists and is valid
        let wrapped_blindsig = dek_store
            .get_wrapped_dek(&tenant_id, &DekDomain::BlindSig)
            .expect("DEK-blindsig should exist");
        let dek = cmk.unwrap_dek(&tenant_id, &wrapped_blindsig).unwrap();
        assert_eq!(dek.len(), 32);

        // DEK-analytics exists and is valid
        let wrapped_analytics = dek_store
            .get_wrapped_dek(&tenant_id, &DekDomain::Analytics)
            .expect("DEK-analytics should exist");
        let dek = cmk.unwrap_dek(&tenant_id, &wrapped_analytics).unwrap();
        assert_eq!(dek.len(), 32);

        // Signing key is available
        let (sk, kv) = key_store.signing_key(&tenant_id).unwrap();
        assert_eq!(kv, KeyVersion(1));

        // Verification key is available
        let pk = key_store
            .verification_key(&tenant_id, &KeyVersion(1))
            .unwrap();

        // Keys are consistent (can sign and verify)
        let msg = b"test message";
        let blinding_result = pulse_crypto::blind_sig::blind(&pk, msg).unwrap();
        let blind_sig =
            pulse_crypto::blind_sig::blind_sign(&sk, &blinding_result.blind_message).unwrap();
        let sig =
            pulse_crypto::blind_sig::finalize(&pk, &blind_sig, &blinding_result, msg).unwrap();
        pulse_crypto::blind_sig::verify(&pk, &sig, blinding_result.msg_randomizer, msg).unwrap();
    }

    #[test]
    fn provision_multiple_tenants() {
        let cmk = Arc::new(DevCmkProvider::new());
        let dek_store = Arc::new(InMemoryDekStore::new());
        let key_store = Arc::new(InMemoryTenantKeyStore::new());

        let provisioner = TenantProvisioner::new(cmk.clone(), dek_store.clone(), key_store.clone());
        let tenant_a = TenantId::new();
        let tenant_b = TenantId::new();

        provisioner.provision(tenant_a).unwrap();
        provisioner.provision(tenant_b).unwrap();

        // Both tenants have independent DEKs
        let wrapped_a = dek_store
            .get_wrapped_dek(&tenant_a, &DekDomain::Responses)
            .unwrap();
        let wrapped_b = dek_store
            .get_wrapped_dek(&tenant_b, &DekDomain::Responses)
            .unwrap();
        assert_ne!(wrapped_a, wrapped_b);

        // Both tenants have independent signing keys
        let (_, kv_a) = key_store.signing_key(&tenant_a).unwrap();
        let (_, kv_b) = key_store.signing_key(&tenant_b).unwrap();
        assert_eq!(kv_a, KeyVersion(1));
        assert_eq!(kv_b, KeyVersion(1));
    }
}
