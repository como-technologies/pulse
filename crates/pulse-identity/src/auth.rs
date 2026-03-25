use crate::EmployeeId;

/// Errors returned by [`Authenticator`] implementations.
#[derive(Debug, thiserror::Error)]
pub enum AuthError {
    #[error("invalid credentials")]
    InvalidCredentials,
    #[error("provider error: {0}")]
    ProviderError(String),
}

/// Pluggable authentication backend for the Identity zone.
///
/// Implementations verify a credential (API key, OIDC token, etc.) and return
/// the authenticated [`EmployeeId`]. The trait is async to support providers
/// that require network calls (e.g., OIDC token validation).
///
/// Implementations live in the composition root (`pulse-server`), not here —
/// this crate only defines the interface.
// ANCHOR: authenticator_trait
#[async_trait::async_trait]
pub trait Authenticator: Send + Sync {
    /// Verify a credential and return the authenticated employee.
    ///
    /// `credential` is the raw string from the client's `api_key` field
    /// in `POST /auth`. For OIDC providers this is typically an ID token
    /// or authorization code; for API-key providers it is the key itself.
    async fn authenticate(&self, credential: &str) -> Result<EmployeeId, AuthError>;
}
// ANCHOR_END: authenticator_trait
