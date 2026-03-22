use std::collections::HashMap;
use std::fmt;
use std::sync::Mutex;

use serde::{Deserialize, Serialize};

use pulse_protocol::{Sensitive, UnixTimestamp};

use crate::EmployeeId;

/// Opaque session token returned after successful authentication.
///
/// Debug and Display are redacted — a session token grants access as a
/// specific employee and must not appear in logs.
#[derive(Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct SessionToken(pub String);

impl Sensitive for SessionToken {}

impl fmt::Debug for SessionToken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("SessionToken").field(&"[REDACTED]").finish()
    }
}

impl fmt::Display for SessionToken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "[REDACTED:SessionToken]")
    }
}

/// An active session linking a [`SessionToken`] to an authenticated [`EmployeeId`].
#[derive(Clone)]
pub struct Session {
    pub employee_id: EmployeeId,
    pub created_at: UnixTimestamp,
}

/// Storage backend for sessions.
///
/// Sessions are identity-zone state — they map tokens to employee IDs.
/// Methods are synchronous because session lookups are fast in-memory operations.
pub trait SessionStore: Send + Sync {
    /// Create a new session for the given employee and return its token.
    fn create(&self, employee_id: EmployeeId) -> SessionToken;
    /// Validate a session token and return the associated employee ID, or `None`.
    fn validate(&self, token: &SessionToken) -> Option<EmployeeId>;
}

/// In-memory session store backed by a `HashMap`.
///
/// Sessions do not survive server restarts — users simply re-authenticate.
pub struct InMemorySessionStore {
    sessions: Mutex<HashMap<String, Session>>,
}

impl InMemorySessionStore {
    pub fn new() -> Self {
        Self {
            sessions: Mutex::new(HashMap::new()),
        }
    }
}

impl Default for InMemorySessionStore {
    fn default() -> Self {
        Self::new()
    }
}

impl SessionStore for InMemorySessionStore {
    fn create(&self, employee_id: EmployeeId) -> SessionToken {
        let token = uuid::Uuid::new_v4().to_string();
        let session = Session {
            employee_id,
            created_at: UnixTimestamp::now(),
        };
        self.sessions
            .lock()
            .expect("session store lock poisoned")
            .insert(token.clone(), session);
        SessionToken(token)
    }

    fn validate(&self, token: &SessionToken) -> Option<EmployeeId> {
        self.sessions
            .lock()
            .expect("session store lock poisoned")
            .get(&token.0)
            .map(|s| s.employee_id.clone())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn session_token_redacts_debug_and_display() {
        let token = SessionToken("secret-token-value".into());

        let debug = format!("{token:?}");
        assert!(debug.contains("[REDACTED]"));
        assert!(!debug.contains("secret"));

        let display = format!("{token}");
        assert!(display.contains("[REDACTED"));
        assert!(!display.contains("secret"));
    }

    #[test]
    fn create_returns_unique_tokens() {
        let store = InMemorySessionStore::new();
        let emp = EmployeeId("alice".into());

        let t1 = store.create(emp.clone());
        let t2 = store.create(emp);

        assert_ne!(t1.0, t2.0, "each session should get a unique token");
    }

    #[test]
    fn validate_round_trips() {
        let store = InMemorySessionStore::new();
        let emp = EmployeeId("alice".into());

        let token = store.create(emp.clone());
        let result = store.validate(&token);

        assert_eq!(result, Some(emp));
    }

    #[test]
    fn validate_returns_none_for_unknown_token() {
        let store = InMemorySessionStore::new();
        let token = SessionToken("nonexistent".into());

        assert_eq!(store.validate(&token), None);
    }
}
