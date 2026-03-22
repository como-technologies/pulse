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
#[async_trait::async_trait]
pub trait Authenticator: Send + Sync {
    async fn authenticate(&self, credential: &str) -> Result<EmployeeId, AuthError>;
}
