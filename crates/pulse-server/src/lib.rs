use std::sync::Arc;

use pulse_identity::{Authenticator, SessionStore, TokenIssuer};
use pulse_protocol::QuestionBatchId;
use pulse_signal::{ResponseCollector, ResponseStore};

pub mod auth_extractor;
pub mod config;
pub mod dev_auth;
pub mod error;
pub mod identity_routes;
pub mod key_store;
pub mod signal_routes;
pub mod sqlite_ledger;
pub mod sqlite_store;

/// Identity zone state. Holds authentication, session management, and token issuance.
///
/// This type is deliberately separate from [`SignalState`] so that identity-zone
/// components (authenticator, session store) are invisible to signal-zone code.
/// The auth extractor [`auth_extractor::AuthenticatedEmployee`] compiles only
/// against this type — it is a compile error to use it in a signal-zone handler.
///
/// See [`SignalState`] for the signal-zone counterpart.
pub struct IdentityState {
    pub issuer: TokenIssuer,
    pub authenticator: Arc<dyn Authenticator>,
    pub session_store: Arc<dyn SessionStore>,
    pub question_batch_id: QuestionBatchId,
}

/// Signal zone state. Holds response collection and storage.
///
/// This type carries no authentication components. Signal-zone handlers accept
/// anonymous submissions — adding auth here would be a design violation.
/// The Cargo dependency graph prevents `pulse-signal` from importing
/// `pulse-identity`, and this type split prevents accidental auth leakage
/// at the composition-root level.
///
/// See [`IdentityState`] for the identity-zone counterpart.
pub struct SignalState {
    pub collector: ResponseCollector,
    pub store: Arc<dyn ResponseStore>,
    pub question_batch_id: QuestionBatchId,
}
