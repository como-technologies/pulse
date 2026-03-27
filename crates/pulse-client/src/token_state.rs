use pulse_crypto::blind_sig::{self, BrssPublicKey};
use pulse_crypto::{BlindSignature, BlindingResult};
use pulse_protocol::messages::{QuestionDelivery, TokenRequest, TokenResponse};
use pulse_protocol::token::{AttestationClass, TokenPayload};
use pulse_protocol::{
    BlindedToken, EncryptedBlob, KeyVersion, Nonce, SignatureBytes, TenantId, TokenBytes,
};

use crate::ResponseSubmit;
use crate::error::ClientError;

/// A token that has been constructed and blinded — ready to send to the Token Issuer.
pub struct BlindedTokenState {
    token_payload: TokenPayload,
    token_bytes: TokenBytes,
    blinding_result: BlindingResult,
}

impl BlindedTokenState {
    /// Construct a new token from question delivery data and blind it.
    pub fn new(
        question: &QuestionDelivery,
        tenant_id: TenantId,
        attestation_class: AttestationClass,
        key_version: KeyVersion,
        public_key: &BrssPublicKey,
    ) -> Result<Self, ClientError> {
        let token_payload = TokenPayload {
            nonce: Nonce::random(),
            question_batch_id: question.question_batch_id,
            tenant_id,
            expiry: question.expiry,
            segment_vector: question.segment_vector.clone(),
            attestation_class,
            key_version,
        };
        let token_bytes = token_payload.to_bytes();
        let blinding_result = blind_sig::blind(public_key, &token_bytes.0)?;

        Ok(Self {
            token_payload,
            token_bytes,
            blinding_result,
        })
    }

    /// Build the `TokenRequest` to send to the server.
    pub fn token_request(&self) -> TokenRequest {
        TokenRequest {
            blinded_token: BlindedToken(self.blinding_result.blind_message.0.clone()),
            question_batch_id: self.token_payload.question_batch_id,
        }
    }

    /// Apply the server's blind signature response, advancing to `SignedTokenState`.
    pub fn apply_signature(self, response: TokenResponse) -> SignedTokenState {
        SignedTokenState {
            token_payload: self.token_payload,
            token_bytes: self.token_bytes,
            blinding_result: self.blinding_result,
            blind_signature: BlindSignature(response.blind_signature.0.clone()),
            key_version: response.key_version,
        }
    }
}

/// A token with a blind signature from the server — needs unblinding.
pub struct SignedTokenState {
    token_payload: TokenPayload,
    token_bytes: TokenBytes,
    blinding_result: BlindingResult,
    blind_signature: BlindSignature,
    key_version: KeyVersion,
}

impl SignedTokenState {
    /// Unblind the signature and verify it, producing a `ReadyToken`.
    pub fn finalize(self, public_key: &BrssPublicKey) -> Result<ReadyToken, ClientError> {
        let signature = blind_sig::finalize(
            public_key,
            &self.blind_signature,
            &self.blinding_result,
            &self.token_bytes.0,
        )?;

        Ok(ReadyToken {
            token_payload: self.token_payload,
            token_bytes: self.token_bytes,
            signature_bytes: SignatureBytes(signature.0.clone()),
            msg_randomizer: self.blinding_result.msg_randomizer.map(|r| r.0),
            key_version: self.key_version,
        })
    }
}

/// A token ready for anonymous submission — unblinded and verified.
pub struct ReadyToken {
    token_payload: TokenPayload,
    token_bytes: TokenBytes,
    signature_bytes: SignatureBytes,
    msg_randomizer: Option<[u8; 32]>,
    key_version: KeyVersion,
}

impl ReadyToken {
    /// Build the `ResponseSubmit` message for anonymous submission.
    pub fn build_submission(&self, response_blob: EncryptedBlob) -> ResponseSubmit {
        ResponseSubmit {
            token: self.token_bytes.clone(),
            signature: self.signature_bytes.clone(),
            msg_randomizer: self.msg_randomizer,
            key_version: self.key_version,
            question_batch_id: self.token_payload.question_batch_id,
            tenant_id: self.token_payload.tenant_id,
            response_blob,
        }
    }

    /// Access the token payload (e.g., for segment_vector when building the response).
    pub fn token_payload(&self) -> &TokenPayload {
        &self.token_payload
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pulse_crypto::blind_sig;
    use pulse_protocol::messages::ResponseType;
    use pulse_protocol::{QuestionBatchId, QuestionText, SegmentLabel, UnixTimestamp};

    fn test_question() -> QuestionDelivery {
        QuestionDelivery {
            question_batch_id: QuestionBatchId::new(),
            question_text: QuestionText::from("How are you?"),
            response_type: ResponseType::Scale5,
            expiry: UnixTimestamp(u64::MAX),
            segment_vector: vec![SegmentLabel::from("engineering")],
        }
    }

    #[test]
    fn full_token_lifecycle() {
        let kp = blind_sig::generate_keypair().unwrap();
        let tenant_id = TenantId::new();
        let question = test_question();

        // Blind
        let blinded = BlindedTokenState::new(
            &question,
            tenant_id,
            AttestationClass::Personal,
            KeyVersion(1),
            &kp.pk,
        )
        .unwrap();

        // Simulate server signing
        let token_request = blinded.token_request();
        let blind_msg = pulse_crypto::BlindMessage(token_request.blinded_token.0.clone());
        let blind_sig = blind_sig::blind_sign(&kp.sk, &blind_msg).unwrap();

        let token_response = TokenResponse {
            blind_signature: pulse_protocol::BlindSig(blind_sig.0.clone()),
            key_version: KeyVersion(1),
        };

        // Apply signature
        let signed = blinded.apply_signature(token_response);

        // Finalize (unblind)
        let ready = signed.finalize(&kp.pk).unwrap();

        // Build submission
        let blob = EncryptedBlob(vec![0xDE, 0xAD]);
        let submit = ready.build_submission(blob.clone());

        assert_eq!(submit.question_batch_id, question.question_batch_id);
        assert_eq!(submit.tenant_id, tenant_id);
        assert_eq!(submit.key_version, KeyVersion(1));
        assert_eq!(submit.response_blob, blob);
    }

    #[test]
    fn wrong_key_fails_finalize() {
        let kp1 = blind_sig::generate_keypair().unwrap();
        let kp2 = blind_sig::generate_keypair().unwrap();
        let tenant_id = TenantId::new();
        let question = test_question();

        let blinded = BlindedTokenState::new(
            &question,
            tenant_id,
            AttestationClass::Personal,
            KeyVersion(1),
            &kp1.pk,
        )
        .unwrap();

        let token_request = blinded.token_request();
        let blind_msg = pulse_crypto::BlindMessage(token_request.blinded_token.0.clone());
        let blind_sig_val = blind_sig::blind_sign(&kp1.sk, &blind_msg).unwrap();

        let token_response = TokenResponse {
            blind_signature: pulse_protocol::BlindSig(blind_sig_val.0.clone()),
            key_version: KeyVersion(1),
        };

        let signed = blinded.apply_signature(token_response);

        // Finalize with wrong key should fail
        let result = signed.finalize(&kp2.pk);
        assert!(result.is_err());
    }
}
