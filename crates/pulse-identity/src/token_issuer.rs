use std::sync::Mutex;

use std::fmt;

use serde::{Deserialize, Serialize};

use pulse_crypto::BlindMessage;
use pulse_crypto::blind_sig::{self, BrssSecretKey};
use pulse_protocol::messages::{TokenDeniedReason, TokenRequest, TokenResponse};
use pulse_protocol::{BlindSig, KeyVersion, QuestionBatchId, UnixTimestamp};

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
}

impl TokenIssuer {
    pub fn new(secret_key: BrssSecretKey, key_version: KeyVersion) -> Self {
        Self {
            secret_key,
            key_version,
            issuance_log: Mutex::new(Vec::new()),
        }
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
        // In a full implementation, this would check:
        // - Is the employee authorized for this question batch?
        // - Has the employee already been issued a token for this batch?
        // - Has the employee exceeded their frequency cap?
        // For Slice 0, we accept all requests.

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
}
