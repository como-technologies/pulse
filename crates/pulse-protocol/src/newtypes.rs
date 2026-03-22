use std::fmt;

use serde::{Deserialize, Serialize};
use uuid::Uuid;

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
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct BlindedToken(pub Vec<u8>);

/// Blind signature over a blinded token.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct BlindSig(pub Vec<u8>);

/// Serialized TokenPayload bytes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct TokenBytes(pub Vec<u8>);

/// Unblinded signature bytes (verifiable by the Response Collector).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct SignatureBytes(pub Vec<u8>);

/// Encrypted response blob (AES-256-GCM ciphertext).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct EncryptedBlob(pub Vec<u8>);

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
