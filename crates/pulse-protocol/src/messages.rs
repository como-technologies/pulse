use serde::{Deserialize, Serialize};

use crate::{
    BlindSig, BlindedToken, EncryptedBlob, EpochId, KeyVersion, Pseudonym, QuestionBatchId,
    QuestionText, SegmentLabel, SignatureBytes, TenantId, TokenBytes, UnixTimestamp,
};

// ── Phase 1: Identity-Aware Channel (Client ↔ Identity Zone) ──

/// Client requests a blind signature on a token.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenRequest {
    /// The blinded token payload (opaque to the Token Issuer).
    pub blinded_token: BlindedToken,
    /// Which question batch this token is for.
    pub question_batch_id: QuestionBatchId,
}

/// Token Issuer returns a blind signature.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenResponse {
    /// The blind signature over the blinded token.
    pub blind_signature: BlindSig,
    /// Which signing key version was used.
    pub key_version: KeyVersion,
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
    pub question_batch_id: QuestionBatchId,
    pub question_text: QuestionText,
    pub response_type: ResponseType,
    /// Unix timestamp when this batch expires.
    pub expiry: UnixTimestamp,
    /// Coarsened org segment identifiers for k-anonymity.
    /// The client embeds these in `TokenPayload::segment_vector` before blinding.
    pub segment_vector: Vec<SegmentLabel>,
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
    pub token: TokenBytes,
    /// The unblinded signature.
    pub signature: SignatureBytes,
    /// Message randomizer from the blinding process (needed for verification).
    pub msg_randomizer: Option<[u8; 32]>,
    /// Which signing key version to verify against.
    pub key_version: KeyVersion,
    /// The question batch this response is for.
    pub question_batch_id: QuestionBatchId,
    /// Tenant identifier.
    pub tenant_id: TenantId,
    /// Encrypted response content (opaque blob — protocol doesn't interpret it).
    pub response_blob: EncryptedBlob,
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

// ── Response Payload (cleartext inner structure of encrypted blob) ──

/// Typed response data matching the question's response type.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ResponseData {
    Scale5(u8),
    Binary(bool),
    Emoji(String),
    FreeText(String),
}

/// Cleartext response payload that lives inside the encrypted response blob.
///
/// The client constructs this, encrypts it with the analytics DEK, and submits
/// the ciphertext as `response_blob` in [`ResponseSubmit`]. The Analytics Engine
/// decrypts the blob and parses this structure for aggregation.
///
/// The Response Collector never sees this — it treats the blob as opaque bytes.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResponsePayload {
    /// Stable anonymous pseudonym for longitudinal tracking.
    pub pseudonym: Pseudonym,
    /// Which epoch this pseudonym is scoped to.
    pub epoch_id: EpochId,
    /// The response type (must match the question's expected type).
    pub response_type: ResponseType,
    /// The actual response data.
    pub response_data: ResponseData,
    /// Coarsened segment labels (echoed from QuestionDelivery for analytics).
    pub segment_vector: Vec<SegmentLabel>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn token_request_round_trip() {
        let req = TokenRequest {
            blinded_token: BlindedToken(vec![1, 2, 3, 4]),
            question_batch_id: QuestionBatchId::new(),
        };
        let bytes = postcard::to_allocvec(&req).unwrap();
        let recovered: TokenRequest = postcard::from_bytes(&bytes).unwrap();
        assert_eq!(req.blinded_token, recovered.blinded_token);
        assert_eq!(req.question_batch_id, recovered.question_batch_id);
    }

    #[test]
    fn response_submit_round_trip() {
        let submit = ResponseSubmit {
            token: TokenBytes(vec![10; 64]),
            signature: SignatureBytes(vec![20; 256]),
            msg_randomizer: Some([42u8; 32]),
            key_version: KeyVersion(1),
            question_batch_id: QuestionBatchId::new(),
            tenant_id: TenantId::new(),
            response_blob: EncryptedBlob(vec![0xDE, 0xAD]),
        };
        let bytes = postcard::to_allocvec(&submit).unwrap();
        let recovered: ResponseSubmit = postcard::from_bytes(&bytes).unwrap();
        assert_eq!(submit.token, recovered.token);
        assert_eq!(submit.signature, recovered.signature);
        assert_eq!(submit.msg_randomizer, recovered.msg_randomizer);
        assert_eq!(submit.response_blob, recovered.response_blob);
    }

    #[test]
    fn response_payload_round_trip() {
        let payload = ResponsePayload {
            pseudonym: Pseudonym([42u8; 32]),
            epoch_id: EpochId("epoch-7".to_string()),
            response_type: ResponseType::Scale5,
            response_data: ResponseData::Scale5(4),
            segment_vector: vec![SegmentLabel::from("engineering")],
        };
        let bytes = postcard::to_allocvec(&payload).unwrap();
        let recovered: ResponsePayload = postcard::from_bytes(&bytes).unwrap();
        assert_eq!(recovered.pseudonym, payload.pseudonym);
        assert_eq!(recovered.epoch_id, payload.epoch_id);
        assert_eq!(recovered.segment_vector, payload.segment_vector);
    }

    #[test]
    fn reject_reason_round_trip() {
        let reject = ResponseReject {
            reason: RejectReason::TokenAlreadySpent,
        };
        let bytes = postcard::to_allocvec(&reject).unwrap();
        let recovered: ResponseReject = postcard::from_bytes(&bytes).unwrap();
        assert!(matches!(recovered.reason, RejectReason::TokenAlreadySpent));
    }
}
