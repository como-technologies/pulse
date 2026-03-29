use pulse_crypto::blind_sig::BrssPublicKey;
use pulse_protocol::messages::QuestionDelivery;
use pulse_protocol::token::AttestationClass;
use pulse_protocol::{EncryptedBlob, KeyVersion, TenantId};

use crate::engine::ProtocolEngine;
use crate::error::ClientError;
use crate::token_state::{BlindedTokenState, ReadyToken, SignedTokenState};
use crate::transport::HttpTransport;

/// Session context returned after authentication.
#[derive(Debug)]
pub struct SessionContext {
    pub session_token: String,
}

/// Server configuration returned by [`PulseClient::connect`].
pub struct ServerConfig {
    pub tenant_id: TenantId,
    pub key_version: KeyVersion,
    pub public_key: BrssPublicKey,
}

/// Disconnected client — can discover server config or authenticate.
///
/// Call [`connect`](Self::connect) to fetch server config and transition
/// to [`ConnectedClient`], or use [`ConnectedClient::with_config`] to
/// skip discovery when config is already known.
pub struct PulseClient<T: HttpTransport> {
    transport: T,
    identity_url: String,
    signal_url: String,
}

impl<T: HttpTransport> PulseClient<T> {
    /// Create a disconnected client. Call [`connect`](Self::connect) to
    /// fetch server config before starting the protocol flow.
    pub fn new(transport: T, identity_url: String, signal_url: String) -> Self {
        Self {
            transport,
            identity_url,
            signal_url,
        }
    }

    /// Fetch server config and transition to [`ConnectedClient`].
    ///
    /// Consumes `self` — the disconnected client no longer exists after this call.
    #[tracing::instrument(skip(self))]
    pub async fn connect(self) -> Result<(ConnectedClient<T>, ServerConfig), ClientError> {
        let resp = self
            .transport
            .get_binary(&format!("{}/config", self.identity_url), None)
            .await?;

        let config = ProtocolEngine::parse_config(&resp)?;
        let engine = ProtocolEngine::new(
            config.public_key.clone(),
            config.tenant_id,
            config.key_version,
        );

        let connected = ConnectedClient {
            transport: self.transport,
            identity_url: self.identity_url,
            signal_url: self.signal_url,
            engine,
        };

        Ok((connected, config))
    }

    /// Authenticate before connecting (credential doesn't need server config).
    #[tracing::instrument(skip(self, credential))]
    pub async fn authenticate(&self, credential: &str) -> Result<SessionContext, ClientError> {
        let body = ProtocolEngine::build_auth_request(credential)?;
        let resp = self
            .transport
            .post_json(&format!("{}/auth", self.identity_url), &body)
            .await?;
        ProtocolEngine::parse_auth_response(&resp)
    }
}

/// Connected client — has server config, can run the full protocol flow.
///
/// Created by [`PulseClient::connect`] or [`ConnectedClient::with_config`].
/// All crypto operations (`blind_token`, `finalize_token`) are available
/// because the public key is guaranteed to exist — no runtime `Option` checks.
pub struct ConnectedClient<T: HttpTransport> {
    transport: T,
    identity_url: String,
    signal_url: String,
    engine: ProtocolEngine,
}

impl<T: HttpTransport> ConnectedClient<T> {
    /// Create a connected client with pre-loaded config.
    ///
    /// Use this in tests or when config is cached from a prior [`PulseClient::connect`].
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
            engine: ProtocolEngine::new(public_key, tenant_id, key_version),
        }
    }

    /// Access the protocol engine for direct sync operations.
    pub fn engine(&self) -> &ProtocolEngine {
        &self.engine
    }

    // ── Phase 1 (authenticated) ──

    /// Phase 1, Step 1: Authenticate and get a session token.
    #[tracing::instrument(skip(self, credential))]
    pub async fn authenticate(&self, credential: &str) -> Result<SessionContext, ClientError> {
        let body = ProtocolEngine::build_auth_request(credential)?;
        let resp = self
            .transport
            .post_json(&format!("{}/auth", self.identity_url), &body)
            .await?;
        ProtocolEngine::parse_auth_response(&resp)
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
        ProtocolEngine::parse_questions(&resp)
    }

    /// Phase 1, Step 3: Create a blinded token for a question.
    pub fn blind_token(
        &self,
        question: &QuestionDelivery,
        attestation_class: AttestationClass,
    ) -> Result<BlindedTokenState, ClientError> {
        self.engine.blind_token(question, attestation_class)
    }

    /// Phase 1, Step 4: Request blind signature from the server.
    #[tracing::instrument(skip(self, session, blinded))]
    pub async fn request_signature(
        &self,
        session: &SessionContext,
        blinded: BlindedTokenState,
    ) -> Result<SignedTokenState, ClientError> {
        let body = ProtocolEngine::build_sign_request(&blinded)?;
        let resp = self
            .transport
            .post_binary(
                &format!("{}/token/sign", self.identity_url),
                &body,
                Some(&session.session_token),
            )
            .await?;
        ProtocolEngine::parse_sign_response(blinded, &resp)
    }

    /// Phase 1, Step 5: Unblind the signature (local, no network).
    pub fn finalize_token(&self, signed: SignedTokenState) -> Result<ReadyToken, ClientError> {
        self.engine.finalize_token(signed)
    }

    // ── Phase 2 (anonymous) ──

    /// Phase 2: Submit anonymous response to the signal zone (NO auth).
    #[tracing::instrument(skip(self, token, response_blob))]
    pub async fn submit_response(
        &self,
        token: &ReadyToken,
        response_blob: EncryptedBlob,
    ) -> Result<(), ClientError> {
        let body = ProtocolEngine::build_submit_request(token, response_blob)?;
        let resp = self
            .transport
            .post_binary(
                &format!("{}/response", self.signal_url),
                &body,
                None, // NO auth — anonymous submission
            )
            .await?;
        ProtocolEngine::parse_submit_response(&resp)
    }
}
