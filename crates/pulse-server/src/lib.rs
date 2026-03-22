use std::sync::Arc;

use pulse_identity::TokenIssuer;
use pulse_protocol::QuestionBatchId;
use pulse_signal::{InMemoryStore, ResponseCollector};

pub mod error;
pub mod identity_routes;
pub mod signal_routes;

/// Shared application state across both zones.
///
/// In a production system, the Identity zone and Signal zone would NOT share
/// state directly. The only shared artifact is the Token Issuer's public key.
/// For Slice 0, we keep them in one process for simplicity.
pub struct AppState {
    pub issuer: TokenIssuer,
    pub collector: ResponseCollector,
    pub store: Arc<InMemoryStore>,
    pub question_batch_id: QuestionBatchId,
}
