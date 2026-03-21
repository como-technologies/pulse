use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use pulse_crypto::blind_sig::{self, BrssPublicKey};
use pulse_crypto::{MessageRandomizer, Signature};
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
    pub fn accept(&self, submit: &ResponseSubmit) -> Result<(), CollectorError> {
        // 1. Deserialize the token payload
        let token = TokenPayload::from_bytes(&submit.token)
            .map_err(|_| CollectorError::Rejected(RejectReason::Malformed))?;

        // 2. Check token fields
        if token.question_batch_id != submit.question_batch_id {
            return Err(CollectorError::Rejected(RejectReason::BatchMismatch));
        }
        if token.tenant_id != submit.tenant_id {
            return Err(CollectorError::Rejected(RejectReason::TenantMismatch));
        }

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        if token.is_expired(now) {
            return Err(CollectorError::Rejected(RejectReason::TokenExpired));
        }

        // 3. Verify the blind signature
        let sig = Signature(submit.signature.clone());
        let msg_randomizer = submit.msg_randomizer.map(MessageRandomizer);

        blind_sig::verify(&self.pub_key, &sig, msg_randomizer, &submit.token)
            .map_err(|_| CollectorError::Rejected(RejectReason::InvalidSignature))?;

        // 4. Check the spent-token ledger (atomic check-and-spend)
        let token_hash = TokenHash::from_token_bytes(&submit.token);
        match self.ledger.check_and_spend(token_hash) {
            SpendResult::Accepted => {}
            SpendResult::AlreadySpent => {
                return Err(CollectorError::Rejected(RejectReason::TokenAlreadySpent));
            }
        }

        // 5. Store the encrypted response blob (no identity info)
        self.store.store(StoredResponse {
            encrypted_blob: submit.response_blob.clone(),
            question_batch_id: submit.question_batch_id,
            received_at: now,
        });

        Ok(())
    }
}
