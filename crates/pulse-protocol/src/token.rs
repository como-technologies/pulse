use serde::{Deserialize, Serialize};

use crate::{
    KeyVersion, Nonce, QuestionBatchId, SegmentLabel, TenantId, TokenBytes, UnixTimestamp,
};

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

// ANCHOR: token_payload
/// Token payload that gets blind-signed by the Token Issuer.
///
/// This is the message `T` from the anonymity protocol spec (Section 2.4).
/// The client blinds this payload, the Token Issuer signs it blind,
/// and the Response Collector verifies the signature.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TokenPayload {
    /// Random unique value preventing token collision.
    pub nonce: Nonce,
    /// Scopes the token to a specific question batch.
    pub question_batch_id: QuestionBatchId,
    /// Prevents cross-tenant token reuse.
    pub tenant_id: TenantId,
    /// Unix timestamp bounding the validity window.
    pub expiry: UnixTimestamp,
    /// Coarsened org segment identifiers (embedded at issuance time for k-anonymity).
    pub segment_vector: Vec<SegmentLabel>,
    /// Device class that obtained this token.
    pub attestation_class: AttestationClass,
    /// Which signing key version was used.
    pub key_version: KeyVersion,
}
// ANCHOR_END: token_payload

impl TokenPayload {
    /// Serialize the token to bytes for blind signing.
    pub fn to_bytes(&self) -> TokenBytes {
        TokenBytes(postcard::to_allocvec(self).expect("token serialization cannot fail"))
    }

    /// Deserialize a token from bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, postcard::Error> {
        postcard::from_bytes(bytes)
    }

    /// Check whether the token has expired relative to the given timestamp.
    pub fn is_expired(&self, now: UnixTimestamp) -> bool {
        now.0 >= self.expiry.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_token() -> TokenPayload {
        TokenPayload {
            nonce: Nonce::random(),
            question_batch_id: QuestionBatchId::new(),
            tenant_id: TenantId::new(),
            expiry: UnixTimestamp(1_700_000_000),
            segment_vector: vec!["engineering".into(), "backend".into()],
            attestation_class: AttestationClass::Personal,
            key_version: KeyVersion(1),
        }
    }

    #[test]
    fn serialize_deserialize_round_trip() {
        let token = sample_token();
        let bytes = token.to_bytes();
        let recovered = TokenPayload::from_bytes(&bytes.0).unwrap();
        assert_eq!(token, recovered);
    }

    #[test]
    fn expiry_check() {
        let token = TokenPayload {
            expiry: UnixTimestamp(1_000),
            ..sample_token()
        };
        assert!(!token.is_expired(UnixTimestamp(999)));
        assert!(token.is_expired(UnixTimestamp(1_000)));
        assert!(token.is_expired(UnixTimestamp(1_001)));
    }
}
