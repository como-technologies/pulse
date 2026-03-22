use std::sync::Arc;

use axum::extract::FromRequestParts;
use axum::http::request::Parts;

use pulse_identity::{EmployeeId, SessionToken};

use crate::IdentityState;
use crate::error::ApiError;

/// Axum extractor that validates a session token and provides the authenticated
/// [`EmployeeId`].
///
/// Reads the `Authorization: Bearer <token>` header, validates against the
/// session store in [`IdentityState`], and returns 401 if missing or invalid.
///
/// This extractor only compiles against [`IdentityState`] — it cannot be
/// accidentally used in signal-zone handlers backed by [`SignalState`].
pub struct AuthenticatedEmployee(pub EmployeeId);

impl FromRequestParts<Arc<IdentityState>> for AuthenticatedEmployee {
    type Rejection = ApiError;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &Arc<IdentityState>,
    ) -> Result<Self, Self::Rejection> {
        let token = parts
            .headers
            .get("authorization")
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.strip_prefix("Bearer "))
            .ok_or_else(|| {
                ApiError::Unauthorized("missing or invalid Authorization header".into())
            })?;

        let session_token = SessionToken(token.to_string());
        let employee_id = state
            .session_store
            .validate(&session_token)
            .ok_or_else(|| {
                tracing::warn!("invalid or expired session token");
                ApiError::Unauthorized("invalid or expired session".into())
            })?;

        Ok(AuthenticatedEmployee(employee_id))
    }
}
