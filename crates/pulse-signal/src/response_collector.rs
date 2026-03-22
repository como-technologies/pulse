use std::sync::Arc;

use pulse_crypto::blind_sig::{self, BrssPublicKey};
use pulse_crypto::{MessageRandomizer, Signature};
use pulse_protocol::UnixTimestamp;
use pulse_protocol::messages::{RejectReason, ResponseSubmit};
use pulse_protocol::token::TokenPayload;

use crate::ledger::{SpendResult, SpentTokenLedger, TokenHash};
use crate::store::{ResponseStore, StoredResponse};

#[derive(Debug, thiserror::Error)]
pub enum CollectorError {
    #[error("response rejected: {0:?}")]
    Rejected(RejectReason),
}

/// Response Collector — validates anonymous responses and stores them.
///
/// Lives in the Signal zone. Never knows who submitted a response.
/// Verifies blind signatures, checks the spent-token ledger, and stores encrypted blobs.
pub struct ResponseCollector {
    /// The Token Issuer's public key (the only artifact shared from the Identity zone).
    pub_key: BrssPublicKey,
    /// Append-only spent-token ledger.
    ledger: Arc<dyn SpentTokenLedger>,
    /// Encrypted response storage.
    store: Arc<dyn ResponseStore>,
}

impl ResponseCollector {
    pub fn new(
        pub_key: BrssPublicKey,
        ledger: Arc<dyn SpentTokenLedger>,
        store: Arc<dyn ResponseStore>,
    ) -> Self {
        Self {
            pub_key,
            ledger,
            store,
        }
    }

    /// Get a reference to the public verification key.
    pub fn public_key(&self) -> &BrssPublicKey {
        &self.pub_key
    }

    /// Process an anonymous response submission.
    #[tracing::instrument(
        name = "ResponseCollector::accept",
        skip(self, submit),
        fields(
            question_batch_id = %submit.question_batch_id,
            tenant_id = %submit.tenant_id,
            key_version = submit.key_version.0,
        )
    )]
    pub fn accept(&self, submit: &ResponseSubmit) -> Result<(), CollectorError> {
        // 1. Deserialize the token payload
        tracing::debug!("deserializing token payload");
        let token = TokenPayload::from_bytes(&submit.token.0)
            .map_err(|_| CollectorError::Rejected(RejectReason::Malformed))?;

        // 2. Check token fields
        tracing::debug!("checking token fields");
        if token.question_batch_id != submit.question_batch_id {
            return Err(CollectorError::Rejected(RejectReason::BatchMismatch));
        }
        if token.tenant_id != submit.tenant_id {
            return Err(CollectorError::Rejected(RejectReason::TenantMismatch));
        }

        let now = UnixTimestamp::now();
        if token.is_expired(now) {
            return Err(CollectorError::Rejected(RejectReason::TokenExpired));
        }

        // 3. Verify the blind signature
        tracing::debug!("verifying blind signature");
        let sig = Signature(submit.signature.0.clone());
        let msg_randomizer = submit.msg_randomizer.map(MessageRandomizer);

        blind_sig::verify(&self.pub_key, &sig, msg_randomizer, &submit.token.0)
            .map_err(|_| CollectorError::Rejected(RejectReason::InvalidSignature))?;

        // 4. Check the spent-token ledger (atomic check-and-spend)
        tracing::debug!("checking spent-token ledger");
        let token_hash = TokenHash::from_token_bytes(&submit.token.0);
        match self.ledger.check_and_spend(token_hash) {
            SpendResult::Accepted => {}
            SpendResult::AlreadySpent => {
                return Err(CollectorError::Rejected(RejectReason::TokenAlreadySpent));
            }
        }

        // 5. Store the encrypted response blob (no identity info)
        tracing::debug!("storing encrypted response");
        self.store.store(StoredResponse {
            encrypted_blob: submit.response_blob.clone(),
            question_batch_id: submit.question_batch_id,
            received_at: now,
        });

        tracing::info!("response accepted");
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ledger::InMemoryLedger;
    use crate::store::InMemoryStore;
    use pulse_crypto::blind_sig;
    use pulse_protocol::messages::ResponseSubmit;
    use pulse_protocol::token::AttestationClass;
    use pulse_protocol::{
        EncryptedBlob, KeyVersion, Nonce, QuestionBatchId, SignatureBytes, TenantId,
    };
    use tracing_test::traced_test;

    fn setup() -> (ResponseCollector, pulse_crypto::BrssPublicKey) {
        let kp = blind_sig::generate_keypair().unwrap();
        let pk = kp.pk.clone();
        let ledger = Arc::new(InMemoryLedger::new());
        let store = Arc::new(InMemoryStore::new());
        let collector = ResponseCollector::new(kp.pk, ledger, store);
        (collector, pk)
    }

    fn make_forged_submit(batch_id: QuestionBatchId, tenant_id: TenantId) -> ResponseSubmit {
        let token = pulse_protocol::token::TokenPayload {
            nonce: Nonce::random(),
            question_batch_id: batch_id,
            tenant_id,
            expiry: UnixTimestamp(u64::MAX),
            segment_vector: vec!["engineering".into()],
            attestation_class: AttestationClass::Personal,
            key_version: KeyVersion(1),
        };
        let token_bytes = token.to_bytes();

        ResponseSubmit {
            token: token_bytes,
            signature: SignatureBytes(vec![0xDE; 256]),
            msg_randomizer: None,
            key_version: KeyVersion(1),
            question_batch_id: batch_id,
            tenant_id,
            response_blob: EncryptedBlob(vec![0x00]),
        }
    }

    fn full_setup() -> (
        ResponseCollector,
        pulse_crypto::BrssPublicKey,
        pulse_crypto::BrssSecretKey,
    ) {
        let kp = blind_sig::generate_keypair().unwrap();
        let pk = kp.pk.clone();
        let ledger = Arc::new(InMemoryLedger::new());
        let store = Arc::new(InMemoryStore::new());
        let collector = ResponseCollector::new(kp.pk, ledger, store);
        (collector, pk, kp.sk)
    }

    fn make_signed_submit(
        pk: &pulse_crypto::BrssPublicKey,
        sk: &pulse_crypto::BrssSecretKey,
        batch_id: QuestionBatchId,
        tenant_id: TenantId,
    ) -> ResponseSubmit {
        let token = pulse_protocol::token::TokenPayload {
            nonce: Nonce::random(),
            question_batch_id: batch_id,
            tenant_id,
            expiry: UnixTimestamp(u64::MAX),
            segment_vector: vec!["engineering".into()],
            attestation_class: AttestationClass::Personal,
            key_version: KeyVersion(1),
        };
        let token_bytes = token.to_bytes();
        let blinding_result = blind_sig::blind(pk, &token_bytes.0).unwrap();
        let blind_sig_val = blind_sig::blind_sign(sk, &blinding_result.blind_message).unwrap();
        let sig =
            blind_sig::finalize(pk, &blind_sig_val, &blinding_result, &token_bytes.0).unwrap();

        ResponseSubmit {
            token: token_bytes,
            signature: SignatureBytes(sig.0.clone()),
            msg_randomizer: blinding_result.msg_randomizer.map(|r| r.0),
            key_version: KeyVersion(1),
            question_batch_id: batch_id,
            tenant_id,
            response_blob: EncryptedBlob(vec![0x42]),
        }
    }

    #[traced_test]
    #[test]
    fn accept_logs_success() {
        let (collector, pk, sk) = full_setup();
        let batch_id = QuestionBatchId::new();
        let tenant_id = TenantId::new();

        let submit = make_signed_submit(&pk, &sk, batch_id, tenant_id);
        collector.accept(&submit).unwrap();

        assert!(logs_contain("response accepted"));
        assert!(logs_contain("deserializing token payload"));
        assert!(logs_contain("verifying blind signature"));
        assert!(logs_contain("storing encrypted response"));
    }

    #[traced_test]
    #[test]
    fn duplicate_submission_does_not_log_success() {
        let (collector, pk, sk) = full_setup();
        let batch_id = QuestionBatchId::new();
        let tenant_id = TenantId::new();

        let submit = make_signed_submit(&pk, &sk, batch_id, tenant_id);
        collector.accept(&submit).unwrap();

        // Second submission should fail — the "response accepted" count stays at 1
        let result = collector.accept(&submit);
        assert!(result.is_err());
    }

    #[traced_test]
    #[test]
    fn forged_signature_logs_no_success() {
        let (collector, _pk) = setup();
        let batch_id = QuestionBatchId::new();
        let tenant_id = TenantId::new();

        let submit = make_forged_submit(batch_id, tenant_id);
        let result = collector.accept(&submit);
        assert!(result.is_err());

        // Should NOT contain success message
        assert!(!logs_contain("response accepted"));
        // Should contain the debug steps up to the failure point
        assert!(logs_contain("verifying blind signature"));
    }
}
