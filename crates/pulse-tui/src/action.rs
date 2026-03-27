use pulse_client::{ClientError, ReadyToken, SessionContext};
use pulse_crypto::BrssPublicKey;
use pulse_protocol::messages::QuestionDelivery;
use pulse_protocol::{KeyVersion, TenantId};

/// All events that can change application state.
pub enum Action {
    // Navigation
    Quit,
    Back,
    NextField,
    PrevField,

    // Input
    CharInput(char),
    Backspace,
    Submit,

    // Question selection
    SelectUp,
    SelectDown,

    // Response input (Scale5)
    ScaleUp,
    ScaleDown,

    // Async results from protocol operations
    Connected {
        session: SessionContext,
        questions: Vec<QuestionDelivery>,
        tenant_id: TenantId,
        key_version: KeyVersion,
        public_key: BrssPublicKey,
    },
    TokenReady(Box<ReadyToken>),
    ResponseSubmitted,
    ProtocolError(ClientError),

    // Log
    Log(String),
}
