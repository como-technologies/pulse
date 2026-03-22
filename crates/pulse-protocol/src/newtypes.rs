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

/// Unix epoch timestamp (seconds).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct UnixTimestamp(pub u64);

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
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Nonce(pub [u8; 32]);

impl Nonce {
    pub fn random() -> Self {
        Self(rand::random())
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

        for (debug_output, type_name) in [
            (format!("{blinded:?}"), "BlindedToken"),
            (format!("{blind_sig:?}"), "BlindSig"),
            (format!("{token:?}"), "TokenBytes"),
            (format!("{sig:?}"), "SignatureBytes"),
            (format!("{blob:?}"), "EncryptedBlob"),
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
                    && !debug_output.contains("13,"),
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

        for (display_output, type_name) in [
            (format!("{blinded}"), "BlindedToken"),
            (format!("{blind_sig}"), "BlindSig"),
            (format!("{token}"), "TokenBytes"),
            (format!("{sig}"), "SignatureBytes"),
            (format!("{blob}"), "EncryptedBlob"),
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
        let debug = format!("{batch:?}");
        assert!(
            !debug.contains("REDACTED"),
            "safe types must not be redacted"
        );
    }
}
