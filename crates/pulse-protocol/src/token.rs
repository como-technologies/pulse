use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Device attestation class — determines the identity confidence of the device.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AttestationClass {
    /// Personal authenticated device (phone, laptop) — high confidence
    Personal,
    /// Shared device scoped to a group (team tablet) — medium confidence
    Group,
    /// Shared device scoped to a location (breakroom button) — low confidence
    Location,
    /// Hybrid: shared display + phone handoff — high confidence
    Hybrid,
}

/// Token payload that gets blind-signed by the Token Issuer.
///
/// This is the message `T` from the anonymity protocol spec (Section 2.4).
/// The client blinds this payload, the Token Issuer signs it blind,
/// and the Response Collector verifies the signature.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TokenPayload {
    /// Random unique value preventing token collision.
    pub nonce: [u8; 32],
    /// Scopes the token to a specific question batch.
    pub question_batch_id: Uuid,
    /// Prevents cross-tenant token reuse.
    pub tenant_id: Uuid,
    /// Unix timestamp bounding the validity window.
    pub expiry: u64,
    /// Coarsened org segment identifiers (embedded at issuance time for k-anonymity).
    pub segment_vector: Vec<String>,
    /// Device class that obtained this token.
    pub attestation_class: AttestationClass,
    /// Which signing key version was used.
    pub key_version: u32,
}

impl TokenPayload {
    /// Serialize the token to bytes for blind signing.
    pub fn to_bytes(&self) -> Vec<u8> {
        serde_json::to_vec(self).expect("token serialization cannot fail")
    }

    /// Deserialize a token from bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, serde_json::Error> {
        serde_json::from_slice(bytes)
    }

    /// Check whether the token has expired relative to the given timestamp.
    pub fn is_expired(&self, now_unix: u64) -> bool {
        now_unix >= self.expiry
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_token() -> TokenPayload {
        TokenPayload {
            nonce: rand_nonce(),
            question_batch_id: Uuid::new_v4(),
            tenant_id: Uuid::new_v4(),
            expiry: 1_700_000_000,
            segment_vector: vec!["engineering".into(), "backend".into()],
            attestation_class: AttestationClass::Personal,
            key_version: 1,
        }
    }

    fn rand_nonce() -> [u8; 32] {
        let mut nonce = [0u8; 32];
        use std::time::{SystemTime, UNIX_EPOCH};
        let seed = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        // Simple pseudo-random for tests; real code uses rand::random()
        for (i, byte) in nonce.iter_mut().enumerate() {
            *byte = ((seed >> (i % 16)) & 0xFF) as u8;
        }
        nonce
    }

    #[test]
    fn serialize_deserialize_round_trip() {
        let token = sample_token();
        let bytes = token.to_bytes();
        let recovered = TokenPayload::from_bytes(&bytes).unwrap();
        assert_eq!(token, recovered);
    }

    #[test]
    fn expiry_check() {
        let token = TokenPayload {
            expiry: 1_000,
            ..sample_token()
        };
        assert!(!token.is_expired(999));
        assert!(token.is_expired(1_000));
        assert!(token.is_expired(1_001));
    }
}
