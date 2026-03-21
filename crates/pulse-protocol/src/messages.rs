use serde::{Deserialize, Serialize};
use uuid::Uuid;

// ── Phase 1: Identity-Aware Channel (Client ↔ Identity Zone) ──

/// Client requests a blind signature on a token.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenRequest {
    /// The blinded token payload (opaque to the Token Issuer).
    pub blinded_token: Vec<u8>,
    /// Which question batch this token is for.
    pub question_batch_id: Uuid,
}

/// Token Issuer returns a blind signature.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenResponse {
    /// The blind signature over the blinded token.
    pub blind_signature: Vec<u8>,
    /// Which signing key version was used.
    pub key_version: u32,
}

/// Token Issuer denies the request.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenDenied {
    pub reason: TokenDeniedReason,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum TokenDeniedReason {
    FrequencyCap,
    NotAuthorized,
    BatchExpired,
}

/// Server delivers a question to the client.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QuestionDelivery {
    pub question_batch_id: Uuid,
    pub question_text: String,
    pub response_type: ResponseType,
    /// Unix timestamp when this batch expires.
    pub expiry: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ResponseType {
    Scale5,
    Binary,
    Emoji,
    FreeText,
}

// ── Phase 2: Anonymous Channel (Client → Relay → Signal Zone) ──

/// Client submits an anonymous response with a verified token.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResponseSubmit {
    /// The unblinded token payload (serialized TokenPayload).
    pub token: Vec<u8>,
    /// The unblinded signature.
    pub signature: Vec<u8>,
    /// Message randomizer from the blinding process (needed for verification).
    pub msg_randomizer: Option<[u8; 32]>,
    /// Which signing key version to verify against.
    pub key_version: u32,
    /// The question batch this response is for.
    pub question_batch_id: Uuid,
    /// Tenant identifier.
    pub tenant_id: Uuid,
    /// Encrypted response content (opaque blob — protocol doesn't interpret it).
    pub response_blob: Vec<u8>,
}

/// Response accepted by the Response Collector.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResponseAck;

/// Response rejected by the Response Collector.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResponseReject {
    pub reason: RejectReason,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum RejectReason {
    InvalidSignature,
    TokenExpired,
    TokenAlreadySpent,
    BatchMismatch,
    TenantMismatch,
    Malformed,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn token_request_round_trip() {
        let req = TokenRequest {
            blinded_token: vec![1, 2, 3, 4],
            question_batch_id: Uuid::new_v4(),
        };
        let json = serde_json::to_string(&req).unwrap();
        let recovered: TokenRequest = serde_json::from_str(&json).unwrap();
        assert_eq!(req.blinded_token, recovered.blinded_token);
        assert_eq!(req.question_batch_id, recovered.question_batch_id);
    }

    #[test]
    fn response_submit_round_trip() {
        let submit = ResponseSubmit {
            token: vec![10; 64],
            signature: vec![20; 256],
            msg_randomizer: Some([42u8; 32]),
            key_version: 1,
            question_batch_id: Uuid::new_v4(),
            tenant_id: Uuid::new_v4(),
            response_blob: vec![0xDE, 0xAD],
        };
        let json = serde_json::to_string(&submit).unwrap();
        let recovered: ResponseSubmit = serde_json::from_str(&json).unwrap();
        assert_eq!(submit.token, recovered.token);
        assert_eq!(submit.signature, recovered.signature);
        assert_eq!(submit.msg_randomizer, recovered.msg_randomizer);
        assert_eq!(submit.response_blob, recovered.response_blob);
    }

    #[test]
    fn reject_reasons_serialize() {
        let reject = ResponseReject {
            reason: RejectReason::TokenAlreadySpent,
        };
        let json = serde_json::to_string(&reject).unwrap();
        assert!(json.contains("TokenAlreadySpent"));
    }
}
