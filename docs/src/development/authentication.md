# Authentication Providers

This guide explains how Pulse's authentication architecture works and how to implement a real-world provider such as Google OIDC.

---

## Architecture Overview

Authentication lives entirely in the **Identity zone**. The Signal zone is deliberately unauthenticated — anonymous submissions must never carry identity context.

### Key Components

| Component | Crate | Role |
|-----------|-------|------|
| `Authenticator` trait | `pulse-identity` | Verify a credential, return an `EmployeeId` |
| `SessionStore` trait | `pulse-identity` | Map session tokens to authenticated employees |
| `SessionToken` | `pulse-identity` | Opaque token returned after auth (PII-redacted) |
| `AuthenticatedEmployee` | `pulse-server` | Axum extractor — validates session, injects `EmployeeId` |
| `DevAuthenticator` | `pulse-server` | Dev-mode provider (accepts any non-empty credential) |

### Request Flow

```
Client                    Identity Zone
  |                            |
  |-- POST /auth ------------->|  Authenticator::authenticate(credential)
  |<-- { session_token } ------|  SessionStore::create(employee_id)
  |                            |
  |-- GET /question ---------->|  AuthenticatedEmployee extractor
  |   Authorization: Bearer T  |  SessionStore::validate(T) -> EmployeeId
  |<-- { question } -----------|
  |                            |
  |-- POST /token/sign ------->|  AuthenticatedEmployee extractor
  |   Authorization: Bearer T  |  employee_id from session, NOT from body
  |<-- { blind_signature } ----|
```

### Trust Zone Enforcement

The `AuthenticatedEmployee` extractor compiles only against `IdentityState`. Attempting to use it in a signal-zone handler backed by `SignalState` is a **compile error** — there is no `session_store` field to validate against.

This is intentional. Never work around it.

---

## Implementing a Provider

### The Authenticator Trait

```rust
{{#include ../../../crates/pulse-identity/src/auth.rs:authenticator_trait}}
```

### Example: Google OIDC Provider

Here's how you'd implement a Google OIDC authenticator. This validates a Google ID token and extracts the user's email as the `EmployeeId`.

**Add dependencies** to `pulse-server/Cargo.toml`:

```toml
openidconnect = "4"
reqwest = { version = "0.12", features = ["json"] }
```

**Create `pulse-server/src/google_auth.rs`:**

```rust
use openidconnect::{
    ClientId, IssuerUrl, JsonWebKeySet,
    core::CoreIdTokenVerifier,
    IdToken,
};
use pulse_identity::{AuthError, Authenticator, EmployeeId};

pub struct GoogleAuthenticator {
    client_id: ClientId,
    jwks: JsonWebKeySet,
}

impl GoogleAuthenticator {
    /// Initialize by fetching Google's JWKS (JSON Web Key Set).
    pub async fn new(client_id: String) -> Result<Self, anyhow::Error> {
        let issuer = IssuerUrl::new("https://accounts.google.com".into())?;
        let metadata = openidconnect::core::CoreProviderMetadata::discover_async(
            issuer,
            openidconnect::reqwest::async_http_client,
        ).await?;

        let jwks_uri = metadata.jwks_uri().clone();
        let jwks = JsonWebKeySet::fetch_async(
            &jwks_uri,
            openidconnect::reqwest::async_http_client,
        ).await?;

        Ok(Self {
            client_id: ClientId::new(client_id),
            jwks,
        })
    }
}

#[async_trait::async_trait]
impl Authenticator for GoogleAuthenticator {
    async fn authenticate(&self, credential: &str) -> Result<EmployeeId, AuthError> {
        // Parse the ID token from the credential string
        let id_token: IdToken</* claims type */> = credential
            .parse()
            .map_err(|_| AuthError::InvalidCredentials)?;

        // Verify signature, audience, issuer, and expiry
        let verifier = CoreIdTokenVerifier::new_public_client(
            self.client_id.clone(),
        );
        let claims = id_token
            .verify(&verifier, &self.jwks)
            .map_err(|e| AuthError::ProviderError(format!("token verification failed: {e}")))?;

        // Extract email as employee ID
        let email = claims
            .email()
            .ok_or_else(|| AuthError::ProviderError("no email claim in token".into()))?;

        Ok(EmployeeId(email.to_string()))
    }
}
```

> **Note:** This is illustrative pseudocode. The exact `openidconnect` API may differ by version. The key pattern is: parse token → verify against JWKS → extract claim → return `EmployeeId`.

### Wiring Into main.rs

Add a new match arm in the auth provider selection:

```rust
let authenticator: Arc<dyn Authenticator> = match config.auth_provider.as_str() {
    "dev" => {
        tracing::info!("Using dev authenticator");
        Arc::new(DevAuthenticator)
    }
    url if url.starts_with("oidc-google:") => {
        let client_id = &url["oidc-google:".len()..];
        tracing::info!("Using Google OIDC authenticator");
        Arc::new(GoogleAuthenticator::new(client_id.to_string()).await?)
    }
    other => anyhow::bail!("unsupported PULSE_AUTH_PROVIDER: {other:?}"),
};
```

Then set the environment variable:

```sh
PULSE_AUTH_PROVIDER=oidc-google:123456789.apps.googleusercontent.com cargo run
```

### Other Providers

The same pattern works for any OIDC provider (Okta, Auth0, Azure AD, Keycloak). The differences are:

- **Issuer URL** — each provider has its own discovery endpoint
- **Claim mapping** — some providers use `sub`, others `email`, others a custom claim
- **Client configuration** — some require a client secret (confidential clients)

You could also implement non-OIDC providers (LDAP, SAML, custom API keys) — the trait only requires returning an `EmployeeId` from a credential string.

---

## Session Store Considerations

The default `InMemorySessionStore` is suitable for development. For production, consider:

### TTL-Based Expiry

The `Session` struct includes `created_at`. A production `SessionStore::validate` implementation can check elapsed time and return `None` for expired sessions.

### SQLite-Backed Sessions

Follow the same pattern as `SqliteLedger` and `SqliteStore` — implement `SessionStore` with a `Mutex<rusqlite::Connection>` and a `sessions` table. This lets sessions survive brief restarts.

### Token Rotation

For security-sensitive deployments, consider rotating session tokens periodically or on each request. The `SessionStore` trait supports this — add a `rotate` method or have `validate` issue a new token.

---

## Rules

These are architectural invariants. Do not violate them.

1. **Never add authentication to Signal zone routes.** The Signal zone accepts anonymous submissions. The `AuthenticatedEmployee` extractor won't compile against `SignalState` — this is by design.

2. **Never merge `IdentityState` and `SignalState`.** The type split prevents auth components from leaking into the Signal zone at the composition-root level.

3. **Never expose provider internals in error responses.** `AuthError::ProviderError` details are logged server-side but the client receives only `"authentication failed"`. Do not leak OIDC error details to callers.

4. **The `Authenticator` trait lives in `pulse-identity`, implementations live in `pulse-server`.** This follows the hexagonal architecture pattern — the domain crate defines the port, the server crate provides the adapter.
