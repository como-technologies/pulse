use std::sync::Arc;

use pulse_identity::{Authenticator, SamplingEngine, SessionStore, TokenIssuer};
use pulse_protocol::TenantId;
use pulse_signal::{ResponseCollector, ResponseStore};

pub mod auth_extractor;
pub mod cmk;
pub mod config;
pub mod dek_store;
pub mod dev_auth;
pub mod dev_cmk;
pub mod dev_sampling;
pub mod dev_tenant_keys;
pub mod encrypting_store;
pub mod error;
pub mod identity_routes;
pub mod key_store;
pub mod signal_routes;
pub mod sqlite_ledger;
pub mod sqlite_store;
pub mod tenant_provisioner;

/// Identity zone state. Holds authentication, session management, token issuance,
/// and the sampling engine.
///
/// This type is deliberately separate from [`SignalState`] so that identity-zone
/// components (authenticator, session store, sampling engine) are invisible to
/// signal-zone code. The auth extractor [`auth_extractor::AuthenticatedEmployee`]
/// compiles only against this type — it is a compile error to use it in a
/// signal-zone handler.
///
/// See [`SignalState`] for the signal-zone counterpart.
pub struct IdentityState {
    pub issuer: TokenIssuer,
    pub authenticator: Arc<dyn Authenticator>,
    pub session_store: Arc<dyn SessionStore>,
    pub sampling_engine: Arc<dyn SamplingEngine>,
    /// Default tenant for this identity zone instance (dev simplification).
    pub tenant_id: TenantId,
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
}
