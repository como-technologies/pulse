use std::sync::Arc;

use pulse_identity::TokenIssuer;
use pulse_protocol::QuestionBatchId;
use pulse_signal::{InMemoryStore, ResponseCollector};

pub mod error;
pub mod identity_routes;
pub mod signal_routes;

/// Shared application state across both zones.
///
/// In production, Identity and Signal zones deploy independently with separate
/// state. We co-locate them here because the Cargo dependency graph already
/// enforces the real safety boundary — no route handler can accidentally cross
/// zones since the types won't resolve. This struct is purely an ergonomic
/// convenience that avoids duplicating routers, middleware, and test harness
/// setup while features are still being built out.
///
/// Split into `IdentityState` / `SignalState` in separate binaries when:
/// - Zones need independent deployment (separate containers/ports)
/// - Zone-specific middleware makes the single-app shape awkward
///
/// Identity zone: [`TokenIssuer`]
/// Signal zone: [`ResponseCollector`], [`InMemoryStore`]
pub struct AppState {
    pub issuer: TokenIssuer,
    pub collector: ResponseCollector,
    pub store: Arc<InMemoryStore>,
    pub question_batch_id: QuestionBatchId,
}
