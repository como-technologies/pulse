use pulse_crypto::aead::AeadError;
use pulse_crypto::blind_sig::BlindSigError;

#[derive(Debug, thiserror::Error)]
pub enum ClientError {
    #[error("transport error: {0}")]
    Transport(String),

    #[error("authentication failed: {0}")]
    AuthFailed(String),

    #[error("token denied ({code}): {reason}")]
    TokenDenied { reason: String, code: String },

    #[error("response rejected ({code}): {reason}")]
    ResponseRejected { reason: String, code: String },

    #[error("blinding failed: {0}")]
    Blinding(#[from] BlindSigError),

    #[error("encryption failed: {0}")]
    Encryption(#[from] AeadError),

    #[error("serialization failed: {0}")]
    Serialization(String),

    #[error("server returned HTTP {status}: {body}")]
    ServerError { status: u16, body: String },
}
