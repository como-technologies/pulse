use pulse_identity::{AuthError, Authenticator, EmployeeId};

/// Development authenticator that accepts any non-empty credential.
///
/// The credential string is used directly as the employee ID.
/// Suitable for local development and testing only.
pub struct DevAuthenticator;

#[async_trait::async_trait]
impl Authenticator for DevAuthenticator {
    #[tracing::instrument(name = "DevAuthenticator::authenticate", skip(self, credential))]
    async fn authenticate(&self, credential: &str) -> Result<EmployeeId, AuthError> {
        if credential.is_empty() {
            tracing::warn!("rejected empty credential");
            return Err(AuthError::InvalidCredentials);
        }
        tracing::info!("dev auth accepted credential");
        Ok(EmployeeId(credential.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn accepts_nonempty_credential() {
        let auth = DevAuthenticator;
        let result = auth.authenticate("alice").await;
        assert_eq!(result.unwrap(), EmployeeId("alice".into()));
    }

    #[tokio::test]
    async fn rejects_empty_credential() {
        let auth = DevAuthenticator;
        let result = auth.authenticate("").await;
        assert!(result.is_err());
    }
}
