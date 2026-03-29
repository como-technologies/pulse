//! Sync protocol engine — message building, response parsing, and crypto operations.
//!
//! No I/O, no async. All transport-facing inputs are `&TransportResponse`,
//! all outputs are domain types. This is the future `no_std` extraction point.

use pulse_crypto::blind_sig::BrssPublicKey;
use pulse_protocol::messages::{QuestionDelivery, TokenResponse};
use pulse_protocol::token::AttestationClass;
use pulse_protocol::{EncryptedBlob, KeyVersion, TenantId};

use crate::error::ClientError;
use crate::flow::{ServerConfig, SessionContext};
use crate::token_state::{BlindedTokenState, ReadyToken, SignedTokenState};
use crate::transport::TransportResponse;

/// Sync protocol engine holding server config.
///
/// Created after connecting to the server (via `PulseClient::connect()`)
/// or with pre-loaded config (via `ConnectedClient::with_config()`).
/// Handles all non-I/O protocol work: message construction, response parsing,
/// and cryptographic operations.
pub struct ProtocolEngine {
    pk: BrssPublicKey,
    tenant_id: TenantId,
    key_version: KeyVersion,
}

impl ProtocolEngine {
    pub fn new(pk: BrssPublicKey, tenant_id: TenantId, key_version: KeyVersion) -> Self {
        Self {
            pk,
            tenant_id,
            key_version,
        }
    }

    pub fn tenant_id(&self) -> TenantId {
        self.tenant_id
    }

    pub fn key_version(&self) -> KeyVersion {
        self.key_version
    }

    pub fn public_key(&self) -> &BrssPublicKey {
        &self.pk
    }

    // ── Config discovery ──

    /// Parse a `/config` response into `ServerConfig`.
    /// Associated function — no `&self` because the engine doesn't exist yet.
    pub fn parse_config(resp: &TransportResponse) -> Result<ServerConfig, ClientError> {
        check_error(resp)?;

        let json: serde_json::Value = serde_json::from_slice(&resp.body)
            .map_err(|e| ClientError::Serialization(e.to_string()))?;

        let tenant_str = json["tenant_id"]
            .as_str()
            .ok_or_else(|| ClientError::Serialization("missing tenant_id".into()))?;
        let tenant_id = TenantId::from_uuid(
            uuid::Uuid::parse_str(tenant_str)
                .map_err(|e| ClientError::Serialization(format!("invalid tenant_id: {e}")))?,
        );

        let kv = json["key_version"]
            .as_u64()
            .ok_or_else(|| ClientError::Serialization("missing key_version".into()))?
            as u32;
        let key_version = KeyVersion(kv);

        let pem = json["public_key_pem"]
            .as_str()
            .ok_or_else(|| ClientError::Serialization("missing public_key_pem".into()))?;
        let public_key = BrssPublicKey::from_pem(pem)
            .map_err(|e| ClientError::Serialization(format!("invalid public key PEM: {e}")))?;

        Ok(ServerConfig {
            tenant_id,
            key_version,
            public_key,
        })
    }

    // ── Authentication ──

    /// Build the JSON body for `POST /auth`.
    pub fn build_auth_request(credential: &str) -> Result<Vec<u8>, ClientError> {
        let body = serde_json::json!({"api_key": credential});
        serde_json::to_vec(&body).map_err(|e| ClientError::Serialization(e.to_string()))
    }

    /// Parse an auth response into `SessionContext`.
    pub fn parse_auth_response(resp: &TransportResponse) -> Result<SessionContext, ClientError> {
        if resp.status == 401 {
            return Err(ClientError::AuthFailed(
                String::from_utf8_lossy(&resp.body).into_owned(),
            ));
        }
        check_error(resp)?;

        let json: serde_json::Value = serde_json::from_slice(&resp.body)
            .map_err(|e| ClientError::Serialization(e.to_string()))?;

        let session_token = json["session_token"]
            .as_str()
            .ok_or_else(|| ClientError::Serialization("missing session_token".into()))?
            .to_string();

        Ok(SessionContext { session_token })
    }

    // ── Questions ──

    /// Parse a questions response (postcard-encoded `Vec<QuestionDelivery>`).
    pub fn parse_questions(resp: &TransportResponse) -> Result<Vec<QuestionDelivery>, ClientError> {
        check_error(resp)?;

        postcard::from_bytes(&resp.body).map_err(|e| ClientError::Serialization(e.to_string()))
    }

    // ── Token blinding (pure crypto) ──

    /// Blind a token for the given question. Pure crypto, no I/O.
    pub fn blind_token(
        &self,
        question: &QuestionDelivery,
        attestation_class: AttestationClass,
    ) -> Result<BlindedTokenState, ClientError> {
        BlindedTokenState::new(
            question,
            self.tenant_id,
            attestation_class,
            self.key_version,
            &self.pk,
        )
    }

    // ── Token signing request/response ──

    /// Build the postcard-encoded body for `POST /token/sign`.
    pub fn build_sign_request(blinded: &BlindedTokenState) -> Result<Vec<u8>, ClientError> {
        let token_request = blinded.token_request();
        postcard::to_allocvec(&token_request).map_err(|e| ClientError::Serialization(e.to_string()))
    }

    /// Parse a token signing response, advancing the typestate.
    pub fn parse_sign_response(
        blinded: BlindedTokenState,
        resp: &TransportResponse,
    ) -> Result<SignedTokenState, ClientError> {
        if (resp.status == 403 || resp.status == 422)
            && let Ok(json) = serde_json::from_slice::<serde_json::Value>(&resp.body)
        {
            return Err(ClientError::TokenDenied {
                code: json["code"].as_str().unwrap_or("UNKNOWN").to_string(),
                reason: json["message"].as_str().unwrap_or("unknown").to_string(),
            });
        }
        check_error(resp)?;

        let token_response: TokenResponse = postcard::from_bytes(&resp.body)
            .map_err(|e| ClientError::Serialization(e.to_string()))?;

        Ok(blinded.apply_signature(token_response))
    }

    // ── Token finalization (pure crypto) ──

    /// Unblind the signature and verify it. Pure crypto, no I/O.
    pub fn finalize_token(&self, signed: SignedTokenState) -> Result<ReadyToken, ClientError> {
        signed.finalize(&self.pk)
    }

    // ── Response submission ──

    /// Build the postcard-encoded body for `POST /response`.
    pub fn build_submit_request(
        token: &ReadyToken,
        blob: EncryptedBlob,
    ) -> Result<Vec<u8>, ClientError> {
        let submit = token.build_submission(blob);
        postcard::to_allocvec(&submit).map_err(|e| ClientError::Serialization(e.to_string()))
    }

    /// Parse a response submission result.
    pub fn parse_submit_response(resp: &TransportResponse) -> Result<(), ClientError> {
        if resp.status == 422
            && let Ok(json) = serde_json::from_slice::<serde_json::Value>(&resp.body)
        {
            return Err(ClientError::ResponseRejected {
                code: json["code"].as_str().unwrap_or("UNKNOWN").to_string(),
                reason: json["message"].as_str().unwrap_or("unknown").to_string(),
            });
        }
        check_error(resp)?;
        Ok(())
    }
}

fn check_error(resp: &TransportResponse) -> Result<(), ClientError> {
    if resp.status >= 400 {
        return Err(ClientError::ServerError {
            status: resp.status,
            body: String::from_utf8_lossy(&resp.body).into_owned(),
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_auth_response_success() {
        let resp = TransportResponse {
            status: 200,
            body: br#"{"employee_id":"emp-1","session_token":"tok-abc"}"#.to_vec(),
        };
        let session = ProtocolEngine::parse_auth_response(&resp).unwrap();
        assert_eq!(session.session_token, "tok-abc");
    }

    #[test]
    fn parse_auth_response_401() {
        let resp = TransportResponse {
            status: 401,
            body: b"bad credentials".to_vec(),
        };
        let err = ProtocolEngine::parse_auth_response(&resp).unwrap_err();
        assert!(matches!(err, ClientError::AuthFailed(_)));
    }

    #[test]
    fn parse_submit_response_success() {
        let resp = TransportResponse {
            status: 200,
            body: vec![],
        };
        ProtocolEngine::parse_submit_response(&resp).unwrap();
    }

    #[test]
    fn parse_submit_response_token_spent() {
        let resp = TransportResponse {
            status: 422,
            body: br#"{"code":"RESPONSE_TOKEN_ALREADY_SPENT","message":"duplicate"}"#.to_vec(),
        };
        let err = ProtocolEngine::parse_submit_response(&resp).unwrap_err();
        match err {
            ClientError::ResponseRejected { code, .. } => {
                assert_eq!(code, "RESPONSE_TOKEN_ALREADY_SPENT");
            }
            other => panic!("expected ResponseRejected, got: {other}"),
        }
    }

    #[test]
    fn build_auth_request_roundtrip() {
        let body = ProtocolEngine::build_auth_request("my-key").unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["api_key"], "my-key");
    }
}
