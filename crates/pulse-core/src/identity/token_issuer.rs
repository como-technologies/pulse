use std::sync::Mutex;

use pulse_crypto::blind_sig::{self, BrssSecretKey};
use pulse_crypto::BlindMessage;
use pulse_protocol::messages::{TokenDeniedReason, TokenRequest, TokenResponse};

/// Record of a token issuance — stored in the Identity zone.
/// Contains employee identity (this is the Identity zone — it knows WHO).
/// Never contains the unblinded token value.
#[derive(Debug, Clone)]
pub struct IssuanceRecord {
    pub employee_id: String,
    pub question_batch_id: uuid::Uuid,
    pub issued_at: u64,
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
    key_version: u32,
    /// Issuance log (identity-aware — records which employee got a token).
    issuance_log: Mutex<Vec<IssuanceRecord>>,
}

impl TokenIssuer {
    pub fn new(secret_key: BrssSecretKey, key_version: u32) -> Self {
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
    pub fn sign_token(
        &self,
        employee_id: &str,
        request: &TokenRequest,
    ) -> Result<TokenResponse, IssuerError> {
        // In a full implementation, this would check:
        // - Is the employee authorized for this question batch?
        // - Has the employee already been issued a token for this batch?
        // - Has the employee exceeded their frequency cap?
        // For Slice 0, we accept all requests.

        // Sign the blinded token (we never see the actual value)
        let blind_msg = BlindMessage(request.blinded_token.clone());
        let blind_sig = blind_sig::blind_sign(&self.secret_key, &blind_msg)?;

        // Record the issuance (identity-aware log)
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        self.issuance_log
            .lock()
            .expect("issuance log lock poisoned")
            .push(IssuanceRecord {
                employee_id: employee_id.to_string(),
                question_batch_id: request.question_batch_id,
                issued_at: now,
            });

        Ok(TokenResponse {
            blind_signature: blind_sig.0,
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
