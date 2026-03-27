use pulse_crypto::blind_sig::BrssPublicKey;
use pulse_protocol::messages::{QuestionDelivery, TokenResponse};
use pulse_protocol::token::AttestationClass;
use pulse_protocol::{EncryptedBlob, KeyVersion, TenantId};

use crate::error::ClientError;
use crate::token_state::{BlindedTokenState, ReadyToken, SignedTokenState};
use crate::transport::{HttpTransport, TransportResponse};

/// Session context returned after authentication.
pub struct SessionContext {
    pub session_token: String,
}

/// Server configuration returned by [`PulseClient::connect`].
pub struct ServerConfig {
    pub tenant_id: TenantId,
    pub key_version: KeyVersion,
    pub public_key: BrssPublicKey,
}

/// High-level Pulse protocol client.
///
/// Orchestrates the two-phase anonymous response flow:
/// - Phase 1 (authenticated): connect → auth → questions → blind → sign → unblind
/// - Phase 2 (anonymous): encrypt → submit via signal zone
///
/// Call [`connect`](Self::connect) first to fetch server config (public key, tenant ID),
/// then [`authenticate`](Self::authenticate) to get a session.
pub struct PulseClient<T: HttpTransport> {
    transport: T,
    identity_url: String,
    signal_url: String,
    public_key: Option<BrssPublicKey>,
    tenant_id: Option<TenantId>,
    key_version: Option<KeyVersion>,
}

impl<T: HttpTransport> PulseClient<T> {
    /// Create a new client. Call [`connect`](Self::connect) to fetch server config before
    /// starting the protocol flow.
    pub fn new(transport: T, identity_url: String, signal_url: String) -> Self {
        Self {
            transport,
            identity_url,
            signal_url,
            public_key: None,
            tenant_id: None,
            key_version: None,
        }
    }

    /// Create a client with pre-configured server config (for tests).
    pub fn with_config(
        transport: T,
        identity_url: String,
        signal_url: String,
        public_key: BrssPublicKey,
        tenant_id: TenantId,
        key_version: KeyVersion,
    ) -> Self {
        Self {
            transport,
            identity_url,
            signal_url,
            public_key: Some(public_key),
            tenant_id: Some(tenant_id),
            key_version: Some(key_version),
        }
    }

    pub fn tenant_id(&self) -> Option<TenantId> {
        self.tenant_id
    }

    pub fn key_version(&self) -> Option<KeyVersion> {
        self.key_version
    }

    pub fn public_key(&self) -> Option<&BrssPublicKey> {
        self.public_key.as_ref()
    }

    /// Fetch server configuration: tenant ID, key version, and public key.
    ///
    /// Must be called before [`blind_token`](Self::blind_token) or any operation
    /// that requires the public key.
    #[tracing::instrument(skip(self))]
    pub async fn connect(&mut self) -> Result<ServerConfig, ClientError> {
        let resp = self
            .transport
            .get_binary(&format!("{}/config", self.identity_url), None)
            .await?;

        check_error(&resp)?;

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

        self.tenant_id = Some(tenant_id);
        self.key_version = Some(key_version);
        self.public_key = Some(public_key.clone());

        Ok(ServerConfig {
            tenant_id,
            key_version,
            public_key,
        })
    }

    /// Phase 1, Step 1: Authenticate and get a session token.
    #[tracing::instrument(skip(self, api_key))]
    pub async fn authenticate(&self, api_key: &str) -> Result<SessionContext, ClientError> {
        let body = serde_json::json!({"api_key": api_key});
        let body_bytes =
            serde_json::to_vec(&body).map_err(|e| ClientError::Serialization(e.to_string()))?;

        let resp = self
            .transport
            .post_json(&format!("{}/auth", self.identity_url), &body_bytes)
            .await?;

        if resp.status == 401 {
            return Err(ClientError::AuthFailed(
                String::from_utf8_lossy(&resp.body).into_owned(),
            ));
        }

        check_error(&resp)?;

        let json: serde_json::Value = serde_json::from_slice(&resp.body)
            .map_err(|e| ClientError::Serialization(e.to_string()))?;

        let session_token = json["session_token"]
            .as_str()
            .ok_or_else(|| ClientError::Serialization("missing session_token".into()))?
            .to_string();

        Ok(SessionContext { session_token })
    }

    /// Phase 1, Step 2: Fetch assigned questions.
    #[tracing::instrument(skip(self, session))]
    pub async fn fetch_questions(
        &self,
        session: &SessionContext,
    ) -> Result<Vec<QuestionDelivery>, ClientError> {
        let resp = self
            .transport
            .get_binary(
                &format!("{}/question", self.identity_url),
                Some(&session.session_token),
            )
            .await?;

        check_error(&resp)?;

        let questions: Vec<QuestionDelivery> = postcard::from_bytes(&resp.body)
            .map_err(|e| ClientError::Serialization(e.to_string()))?;

        Ok(questions)
    }

    /// Phase 1, Step 3: Create a blinded token for a question.
    ///
    /// Requires [`connect`](Self::connect) to have been called first.
    pub fn blind_token(
        &self,
        question: &QuestionDelivery,
        attestation_class: AttestationClass,
    ) -> Result<BlindedTokenState, ClientError> {
        let public_key = self
            .public_key
            .as_ref()
            .ok_or_else(|| ClientError::Transport("not connected — call connect() first".into()))?;
        let tenant_id = self
            .tenant_id
            .ok_or_else(|| ClientError::Transport("not connected — call connect() first".into()))?;
        let key_version = self
            .key_version
            .ok_or_else(|| ClientError::Transport("not connected — call connect() first".into()))?;

        BlindedTokenState::new(
            question,
            tenant_id,
            attestation_class,
            key_version,
            public_key,
        )
    }

    /// Phase 1, Step 4: Request blind signature from the server.
    #[tracing::instrument(skip(self, session, blinded))]
    pub async fn request_signature(
        &self,
        session: &SessionContext,
        blinded: BlindedTokenState,
    ) -> Result<SignedTokenState, ClientError> {
        let token_request = blinded.token_request();
        let body = postcard::to_allocvec(&token_request)
            .map_err(|e| ClientError::Serialization(e.to_string()))?;

        let resp = self
            .transport
            .post_binary(
                &format!("{}/token/sign", self.identity_url),
                &body,
                Some(&session.session_token),
            )
            .await?;

        if resp.status == 403 || resp.status == 422 {
            // Server denied the token request — parse the JSON error
            if let Ok(json) = serde_json::from_slice::<serde_json::Value>(&resp.body) {
                return Err(ClientError::TokenDenied {
                    code: json["code"].as_str().unwrap_or("UNKNOWN").to_string(),
                    reason: json["message"].as_str().unwrap_or("unknown").to_string(),
                });
            }
        }

        check_error(&resp)?;

        let token_response: TokenResponse = postcard::from_bytes(&resp.body)
            .map_err(|e| ClientError::Serialization(e.to_string()))?;

        Ok(blinded.apply_signature(token_response))
    }

    /// Phase 1, Step 5: Unblind the signature (local, no network).
    ///
    /// Requires [`connect`](Self::connect) to have been called first.
    pub fn finalize_token(&self, signed: SignedTokenState) -> Result<ReadyToken, ClientError> {
        let public_key = self
            .public_key
            .as_ref()
            .ok_or_else(|| ClientError::Transport("not connected — call connect() first".into()))?;
        signed.finalize(public_key)
    }

    /// Phase 2: Submit anonymous response to the signal zone (NO auth).
    #[tracing::instrument(skip(self, token, response_blob))]
    pub async fn submit_response(
        &self,
        token: &ReadyToken,
        response_blob: EncryptedBlob,
    ) -> Result<(), ClientError> {
        let submit = token.build_submission(response_blob);
        let body = postcard::to_allocvec(&submit)
            .map_err(|e| ClientError::Serialization(e.to_string()))?;

        let resp = self
            .transport
            .post_binary(
                &format!("{}/response", self.signal_url),
                &body,
                None, // NO auth — anonymous submission
            )
            .await?;

        if resp.status == 422
            && let Ok(json) = serde_json::from_slice::<serde_json::Value>(&resp.body)
        {
            return Err(ClientError::ResponseRejected {
                code: json["code"].as_str().unwrap_or("UNKNOWN").to_string(),
                reason: json["message"].as_str().unwrap_or("unknown").to_string(),
            });
        }

        check_error(&resp)?;
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
