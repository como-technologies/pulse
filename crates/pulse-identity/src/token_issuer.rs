use std::sync::{Arc, Mutex};

use std::fmt;

use serde::{Deserialize, Serialize};

use pulse_crypto::BlindMessage;
use pulse_crypto::blind_sig::{self, BrssSecretKey};
use pulse_protocol::messages::{TokenDeniedReason, TokenRequest, TokenResponse};
use pulse_protocol::{BlindSig, KeyVersion, QuestionBatchId, UnixTimestamp};

use crate::sampling::{SamplingEngine, SamplingError};

/// Identity-zone employee identifier.
///
/// Debug and Display are intentionally redacted to prevent accidental logging
/// of PII. Access the inner value via `.0` for database/wire operations.
#[derive(Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct EmployeeId(pub String);

impl fmt::Debug for EmployeeId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("EmployeeId").field(&"[REDACTED]").finish()
    }
}

impl fmt::Display for EmployeeId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "[REDACTED:EmployeeId]")
    }
}

/// Record of a token issuance — stored in the Identity zone.
/// Contains employee identity (this is the Identity zone — it knows WHO).
/// Never contains the unblinded token value.
#[derive(Debug, Clone)]
pub struct IssuanceRecord {
    pub employee_id: EmployeeId,
    pub question_batch_id: QuestionBatchId,
    pub issued_at: UnixTimestamp,
}

#[derive(Debug, thiserror::Error)]
pub enum IssuerError {
    #[error("token denied: {0:?}")]
    Denied(TokenDeniedReason),
    #[error("blind signing failed: {0}")]
    SigningFailed(#[from] pulse_crypto::blind_sig::BlindSigError),
}

/// Token Issuer — signs blinded tokens for authorized employees.
///
/// Lives in the Identity zone. Knows WHO requested a token but never sees
/// the actual token value (only the blinded version).
pub struct TokenIssuer {
    /// The signing secret key.
    secret_key: BrssSecretKey,
    /// Current key version.
    key_version: KeyVersion,
    /// Issuance log (identity-aware — records which employee got a token).
    issuance_log: Mutex<Vec<IssuanceRecord>>,
    /// Optional sampling engine for authorization and frequency cap enforcement.
    sampling_engine: Option<Arc<dyn SamplingEngine>>,
}

impl TokenIssuer {
    /// Create a TokenIssuer without a sampling engine (accepts all requests).
    /// Used in tests and examples that don't need sampling.
    pub fn new(secret_key: BrssSecretKey, key_version: KeyVersion) -> Self {
        Self {
            secret_key,
            key_version,
            issuance_log: Mutex::new(Vec::new()),
            sampling_engine: None,
        }
    }

    /// Create a TokenIssuer with a sampling engine for authorization enforcement.
    pub fn with_sampling(
        secret_key: BrssSecretKey,
        key_version: KeyVersion,
        engine: Arc<dyn SamplingEngine>,
    ) -> Self {
        Self {
            secret_key,
            key_version,
            issuance_log: Mutex::new(Vec::new()),
            sampling_engine: Some(engine),
        }
    }

    /// Derive the public verification key from the signing key.
    pub fn public_key(&self) -> pulse_crypto::BrssPublicKey {
        self.secret_key
            .public_key()
            .expect("public key derivation from valid secret key should never fail")
    }

    /// Process a token signing request from an authenticated employee.
    ///
    /// The `employee_id` comes from the authenticated session (Identity zone).
    /// The `request.blinded_token` is opaque — the Token Issuer cannot see
    /// the actual token value.
    #[tracing::instrument(
        name = "TokenIssuer::sign_token",
        skip(self),
        fields(question_batch_id = %request.question_batch_id, key_version = self.key_version.0)
    )]
    pub fn sign_token(
        &self,
        employee_id: &EmployeeId,
        request: &TokenRequest,
    ) -> Result<TokenResponse, IssuerError> {
        // Check authorization via sampling engine (if configured)
        if let Some(engine) = &self.sampling_engine {
            engine
                .authorize_and_record_issuance(employee_id, &request.question_batch_id)
                .map_err(|e| match e {
                    SamplingError::NotAssigned => {
                        IssuerError::Denied(TokenDeniedReason::NotAuthorized)
                    }
                    SamplingError::FrequencyCapExceeded => {
                        IssuerError::Denied(TokenDeniedReason::FrequencyCap)
                    }
                    SamplingError::BatchExpired => {
                        IssuerError::Denied(TokenDeniedReason::BatchExpired)
                    }
                })?;
        }

        // Sign the blinded token (we never see the actual value)
        let blind_msg = BlindMessage(request.blinded_token.0.clone());
        let blind_sig = blind_sig::blind_sign(&self.secret_key, &blind_msg).map_err(|e| {
            tracing::error!(error = %e, "blind signing crypto failure");
            IssuerError::SigningFailed(e)
        })?;

        // Record the issuance (identity-aware log)
        let now = UnixTimestamp::now();

        self.issuance_log
            .lock()
            .expect("issuance log lock poisoned")
            .push(IssuanceRecord {
                employee_id: employee_id.clone(),
                question_batch_id: request.question_batch_id,
                issued_at: now,
            });

        tracing::info!("token issued");

        Ok(TokenResponse {
            blind_signature: BlindSig(blind_sig.0),
            key_version: self.key_version,
        })
    }

    /// Get a copy of the issuance log (for auditing/testing).
    pub fn issuance_log(&self) -> Vec<IssuanceRecord> {
        self.issuance_log
            .lock()
            .expect("issuance log lock poisoned")
            .clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn employee_id_redacts_debug_and_display() {
        let id = EmployeeId("alice@example.com".into());

        let debug = format!("{id:?}");
        assert!(
            debug.contains("[REDACTED]"),
            "Debug must redact, got: {debug}"
        );
        assert!(
            !debug.contains("alice"),
            "Debug must not contain real value, got: {debug}"
        );

        let display = format!("{id}");
        assert!(
            display.contains("[REDACTED"),
            "Display must redact, got: {display}"
        );
        assert!(
            !display.contains("alice"),
            "Display must not contain real value, got: {display}"
        );
    }

    #[test]
    fn employee_id_inner_value_accessible_via_field() {
        let id = EmployeeId("alice@example.com".into());
        assert_eq!(id.0, "alice@example.com");
    }

    #[test]
    fn employee_id_equality_works_despite_redacted_debug() {
        let a = EmployeeId("alice".into());
        let b = EmployeeId("alice".into());
        let c = EmployeeId("bob".into());
        assert_eq!(a, b);
        assert_ne!(a, c);
    }

    // ── TokenIssuer + SamplingEngine denial tests ──

    use crate::sampling::{FrequencyPolicy, InMemorySamplingEngine, QuestionBatch};
    use pulse_protocol::messages::{ResponseType, TokenDeniedReason};
    use pulse_protocol::{BlindedToken, QuestionBatchId, QuestionText, UnixTimestamp};

    fn issuer_with_sampling() -> (TokenIssuer, QuestionBatchId) {
        let kp = pulse_crypto::blind_sig::generate_keypair().unwrap();
        let batch_id = QuestionBatchId::new();

        let mut engine = InMemorySamplingEngine::new(
            1,
            FrequencyPolicy {
                max_tokens_per_employee_per_batch: 1,
            },
        );
        engine.add_segment("company".into(), None);
        engine.add_employee(EmployeeId("alice".into()), vec!["company".into()]);
        engine.add_batch(QuestionBatch {
            id: batch_id,
            question_text: QuestionText::from("test"),
            response_type: ResponseType::Scale5,
            expiry: UnixTimestamp(u64::MAX),
        });
        engine.assign(&EmployeeId("alice".into()), &batch_id);

        let issuer = TokenIssuer::with_sampling(kp.sk, KeyVersion(1), Arc::new(engine));
        (issuer, batch_id)
    }

    fn make_token_request(batch_id: QuestionBatchId) -> TokenRequest {
        // Use a minimal blinded token (will fail crypto but we're testing authorization)
        TokenRequest {
            blinded_token: BlindedToken(vec![0u8; 256]),
            question_batch_id: batch_id,
        }
    }

    #[test]
    fn sign_token_denied_not_assigned() {
        let (issuer, batch_id) = issuer_with_sampling();
        let bob = EmployeeId("bob".into()); // not in roster/assignments

        let err = issuer
            .sign_token(&bob, &make_token_request(batch_id))
            .unwrap_err();
        assert!(
            matches!(err, IssuerError::Denied(TokenDeniedReason::NotAuthorized)),
            "expected NotAuthorized, got {err:?}"
        );
    }

    #[test]
    fn sign_token_denied_frequency_cap() {
        let (issuer, batch_id) = issuer_with_sampling();
        let alice = EmployeeId("alice".into());
        let req = make_token_request(batch_id);

        // First request — authorization passes, then crypto may fail (fake blinded token)
        // but the issuance is recorded
        let result = issuer.sign_token(&alice, &req);
        // It may succeed or fail at signing — either way, the issuance was recorded
        if result.is_err() {
            // Signing failed but issuance was recorded — second attempt hits frequency cap
        }

        let err = issuer.sign_token(&alice, &req).unwrap_err();
        assert!(
            matches!(err, IssuerError::Denied(TokenDeniedReason::FrequencyCap)),
            "expected FrequencyCap, got {err:?}"
        );
    }

    #[test]
    fn sign_token_denied_expired_batch() {
        let kp = pulse_crypto::blind_sig::generate_keypair().unwrap();
        let batch_id = QuestionBatchId::new();

        let mut engine = InMemorySamplingEngine::new(
            1,
            FrequencyPolicy {
                max_tokens_per_employee_per_batch: 1,
            },
        );
        engine.add_segment("company".into(), None);
        engine.add_employee(EmployeeId("alice".into()), vec!["company".into()]);
        engine.add_batch(QuestionBatch {
            id: batch_id,
            question_text: QuestionText::from("test"),
            response_type: ResponseType::Scale5,
            expiry: UnixTimestamp(0), // already expired
        });
        engine.assign(&EmployeeId("alice".into()), &batch_id);

        let issuer = TokenIssuer::with_sampling(kp.sk, KeyVersion(1), Arc::new(engine));
        let alice = EmployeeId("alice".into());

        let err = issuer
            .sign_token(&alice, &make_token_request(batch_id))
            .unwrap_err();
        assert!(
            matches!(err, IssuerError::Denied(TokenDeniedReason::BatchExpired)),
            "expected BatchExpired, got {err:?}"
        );
    }
}
