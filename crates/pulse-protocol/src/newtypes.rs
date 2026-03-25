use std::fmt;

use serde::{Deserialize, Serialize};
use uuid::Uuid;

// ANCHOR: sensitive_trait
/// Marker trait for types whose Debug and Display are intentionally redacted
/// to prevent accidental logging of sensitive data (PII, cryptographic material,
/// linkable identifiers). Access the inner value via `.0` for database/wire operations.
pub trait Sensitive {}
// ANCHOR_END: sensitive_trait

/// Identifies a question batch.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct QuestionBatchId(pub Uuid);

impl QuestionBatchId {
    pub fn new() -> Self {
        Self(Uuid::new_v4())
    }

    pub fn from_uuid(id: Uuid) -> Self {
        Self(id)
    }
}

impl Default for QuestionBatchId {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Display for QuestionBatchId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

/// Identifies a tenant.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct TenantId(pub Uuid);

impl TenantId {
    pub fn new() -> Self {
        Self(Uuid::new_v4())
    }

    pub fn from_uuid(id: Uuid) -> Self {
        Self(id)
    }
}

impl Default for TenantId {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Display for TenantId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

/// Signing key version number.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct KeyVersion(pub u32);

impl fmt::Display for KeyVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

/// Unix epoch timestamp (seconds).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct UnixTimestamp(pub u64);

impl fmt::Display for UnixTimestamp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

impl UnixTimestamp {
    pub fn now() -> Self {
        let secs = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        Self(secs)
    }
}

/// 32-byte random nonce for token uniqueness.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Nonce(pub [u8; 32]);

impl Nonce {
    pub fn random() -> Self {
        Self(rand::random())
    }
}

impl AsRef<[u8]> for Nonce {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

/// Blinded token payload (opaque to the Token Issuer).
///
/// Debug and Display are redacted — this is cryptographic material that could
/// link identity to signal if logged.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct BlindedToken(pub Vec<u8>);

impl Sensitive for BlindedToken {}

impl fmt::Debug for BlindedToken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("BlindedToken").field(&"[REDACTED]").finish()
    }
}

impl fmt::Display for BlindedToken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "[REDACTED:BlindedToken]")
    }
}

impl AsRef<[u8]> for BlindedToken {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

/// Blind signature over a blinded token.
///
/// Debug and Display are redacted — cryptographic material.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct BlindSig(pub Vec<u8>);

impl Sensitive for BlindSig {}

impl fmt::Debug for BlindSig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("BlindSig").field(&"[REDACTED]").finish()
    }
}

impl fmt::Display for BlindSig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "[REDACTED:BlindSig]")
    }
}

impl AsRef<[u8]> for BlindSig {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

/// Serialized TokenPayload bytes.
///
/// Debug and Display are redacted — contains the full token value.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct TokenBytes(pub Vec<u8>);

impl Sensitive for TokenBytes {}

impl fmt::Debug for TokenBytes {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("TokenBytes").field(&"[REDACTED]").finish()
    }
}

impl fmt::Display for TokenBytes {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "[REDACTED:TokenBytes]")
    }
}

impl AsRef<[u8]> for TokenBytes {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

/// Unblinded signature bytes (verifiable by the Response Collector).
///
/// Debug and Display are redacted — cryptographic material.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct SignatureBytes(pub Vec<u8>);

impl Sensitive for SignatureBytes {}

impl fmt::Debug for SignatureBytes {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("SignatureBytes")
            .field(&"[REDACTED]")
            .finish()
    }
}

impl fmt::Display for SignatureBytes {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "[REDACTED:SignatureBytes]")
    }
}

impl AsRef<[u8]> for SignatureBytes {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

/// Encrypted response blob (AES-256-GCM ciphertext).
///
/// Debug and Display are redacted — contains encrypted response data.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct EncryptedBlob(pub Vec<u8>);

impl Sensitive for EncryptedBlob {}

impl fmt::Debug for EncryptedBlob {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("EncryptedBlob").field(&"[REDACTED]").finish()
    }
}

impl fmt::Display for EncryptedBlob {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "[REDACTED:EncryptedBlob]")
    }
}

impl AsRef<[u8]> for EncryptedBlob {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

/// Stable anonymous pseudonym for longitudinal sentiment tracking.
///
/// Derived client-side as `HMAC-SHA256(employee_secret, tenant_id || epoch_id)`.
/// Contains identity-linkable material — Debug and Display are redacted.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Pseudonym(pub [u8; 32]);

impl Sensitive for Pseudonym {}

impl fmt::Debug for Pseudonym {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("Pseudonym").field(&"[REDACTED]").finish()
    }
}

impl fmt::Display for Pseudonym {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "[REDACTED:Pseudonym]")
    }
}

/// Time-based epoch identifier bounding the pseudonym correlation window.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct EpochId(pub String);

impl fmt::Display for EpochId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

impl From<&str> for EpochId {
    fn from(s: &str) -> Self {
        Self(s.to_string())
    }
}

impl From<String> for EpochId {
    fn from(s: String) -> Self {
        Self(s)
    }
}

/// Coarsened organization segment label (e.g., "engineering", "backend").
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct SegmentLabel(pub String);

impl From<&str> for SegmentLabel {
    fn from(s: &str) -> Self {
        Self(s.to_string())
    }
}

impl From<String> for SegmentLabel {
    fn from(s: String) -> Self {
        Self(s)
    }
}

/// Question text delivered to the client.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct QuestionText(pub String);

impl From<&str> for QuestionText {
    fn from(s: &str) -> Self {
        Self(s.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Verify that sensitive types never leak their inner value through Debug or Display.
    /// This is a security invariant — if these tests fail, PII could leak into logs.
    #[test]
    fn sensitive_types_redact_debug() {
        let blinded = BlindedToken(vec![1, 2, 3]);
        let blind_sig = BlindSig(vec![4, 5, 6]);
        let token = TokenBytes(vec![7, 8, 9]);
        let sig = SignatureBytes(vec![10, 11, 12]);
        let blob = EncryptedBlob(vec![13, 14, 15]);
        let pseudonym = Pseudonym([42u8; 32]);

        for (debug_output, type_name) in [
            (format!("{blinded:?}"), "BlindedToken"),
            (format!("{blind_sig:?}"), "BlindSig"),
            (format!("{token:?}"), "TokenBytes"),
            (format!("{sig:?}"), "SignatureBytes"),
            (format!("{blob:?}"), "EncryptedBlob"),
            (format!("{pseudonym:?}"), "Pseudonym"),
        ] {
            assert!(
                debug_output.contains("[REDACTED]"),
                "{type_name} Debug must contain [REDACTED], got: {debug_output}"
            );
            assert!(
                !debug_output.contains("1,")
                    && !debug_output.contains("4,")
                    && !debug_output.contains("7,")
                    && !debug_output.contains("10,")
                    && !debug_output.contains("13,")
                    && !debug_output.contains("42,"),
                "{type_name} Debug must not contain inner bytes, got: {debug_output}"
            );
        }
    }

    #[test]
    fn sensitive_types_redact_display() {
        let blinded = BlindedToken(vec![1, 2, 3]);
        let blind_sig = BlindSig(vec![4, 5, 6]);
        let token = TokenBytes(vec![7, 8, 9]);
        let sig = SignatureBytes(vec![10, 11, 12]);
        let blob = EncryptedBlob(vec![13, 14, 15]);
        let pseudonym = Pseudonym([42u8; 32]);

        for (display_output, type_name) in [
            (format!("{blinded}"), "BlindedToken"),
            (format!("{blind_sig}"), "BlindSig"),
            (format!("{token}"), "TokenBytes"),
            (format!("{sig}"), "SignatureBytes"),
            (format!("{blob}"), "EncryptedBlob"),
            (format!("{pseudonym}"), "Pseudonym"),
        ] {
            assert!(
                display_output.contains("[REDACTED"),
                "{type_name} Display must contain [REDACTED, got: {display_output}"
            );
        }
    }

    #[test]
    fn sensitive_types_still_serialize_to_real_values() {
        let token = TokenBytes(vec![1, 2, 3]);
        let json = serde_json::to_string(&token).unwrap();
        assert!(
            json.contains("[1,2,3]"),
            "serde must serialize real inner value, got: {json}"
        );
    }

    #[test]
    fn safe_types_show_real_values_in_debug() {
        let batch = QuestionBatchId::new();
        let epoch = EpochId("epoch-42".to_string());

        for (debug_output, type_name) in [
            (format!("{batch:?}"), "QuestionBatchId"),
            (format!("{epoch:?}"), "EpochId"),
        ] {
            assert!(
                !debug_output.contains("REDACTED"),
                "{type_name} must not be redacted, got: {debug_output}"
            );
        }
    }
}
