use pulse_crypto::{aead, pseudonym};
use pulse_protocol::epoch::EpochConfig;
use pulse_protocol::messages::{ResponseData, ResponsePayload, ResponseType};
use pulse_protocol::{EncryptedBlob, EpochId, Pseudonym, SegmentLabel, TenantId};

use crate::error::ClientError;

/// Derive an anonymous pseudonym for this employee/tenant/epoch combination.
pub fn derive_pseudonym(
    employee_secret: &[u8; 32],
    tenant_id: &TenantId,
    epoch_id: &EpochId,
) -> Pseudonym {
    let bytes = pseudonym::derive_pseudonym(
        employee_secret,
        tenant_id.0.as_bytes(),
        epoch_id.0.as_bytes(),
    );
    Pseudonym(bytes)
}

/// Build and encrypt a `ResponsePayload` into an `EncryptedBlob`.
pub fn encrypt_response(
    analytics_dek: &[u8; 32],
    pseudonym: Pseudonym,
    epoch_id: EpochId,
    response_type: ResponseType,
    response_data: ResponseData,
    segment_vector: Vec<SegmentLabel>,
) -> Result<EncryptedBlob, ClientError> {
    let payload = ResponsePayload {
        pseudonym,
        epoch_id,
        response_type,
        response_data,
        segment_vector,
    };
    let payload_bytes =
        postcard::to_allocvec(&payload).map_err(|e| ClientError::Serialization(e.to_string()))?;
    let encrypted = aead::encrypt(analytics_dek, &payload_bytes)?;
    Ok(EncryptedBlob(encrypted))
}

/// Generate a new random employee secret for pseudonym derivation.
///
/// This secret must be stored on the client device and never transmitted.
pub fn generate_employee_secret() -> [u8; 32] {
    pseudonym::generate_employee_secret()
}

/// Compute the current epoch ID from the default epoch configuration.
pub fn current_epoch() -> EpochId {
    EpochConfig::default().current_epoch()
}

#[cfg(test)]
mod tests {
    use super::*;
    use pulse_protocol::messages::ResponseType;

    #[test]
    fn pseudonym_derivation_matches_crypto() {
        let secret = [42u8; 32];
        let tenant_id = TenantId::new();
        let epoch_id = EpochId("epoch-7".to_string());

        let p = derive_pseudonym(&secret, &tenant_id, &epoch_id);
        let direct =
            pseudonym::derive_pseudonym(&secret, tenant_id.0.as_bytes(), epoch_id.0.as_bytes());
        assert_eq!(p.0, direct);
    }

    #[test]
    fn encrypt_response_round_trip() {
        let dek = aead::generate_key();
        let pseudonym = Pseudonym([1u8; 32]);
        let epoch_id = EpochId("epoch-7".to_string());

        let blob = encrypt_response(
            &dek,
            pseudonym,
            epoch_id.clone(),
            ResponseType::Scale5,
            ResponseData::Scale5(4),
            vec![SegmentLabel::from("engineering")],
        )
        .unwrap();

        // Decrypt and verify round-trip
        let decrypted = aead::decrypt(&dek, &blob.0).unwrap();
        let payload: ResponsePayload = postcard::from_bytes(&decrypted).unwrap();
        assert_eq!(payload.pseudonym, pseudonym);
        assert_eq!(payload.epoch_id, epoch_id);
    }

    #[test]
    fn current_epoch_returns_valid_id() {
        let epoch = current_epoch();
        assert!(epoch.0.starts_with("epoch-"));
    }

    #[test]
    fn generated_secrets_are_unique() {
        let s1 = generate_employee_secret();
        let s2 = generate_employee_secret();
        assert_ne!(s1, s2);
    }
}
