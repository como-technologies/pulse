use std::path::PathBuf;

/// Server configuration loaded from environment variables.
pub struct Config {
    /// Identity zone listen address (`PULSE_IDENTITY_ADDR`, default `127.0.0.1:8001`).
    pub identity_addr: String,
    /// Signal zone listen address (`PULSE_SIGNAL_ADDR`, default `127.0.0.1:8002`).
    pub signal_addr: String,
    /// Storage backend URI (`PULSE_DB_URL`, default `memory`).
    ///
    /// Supported schemes:
    /// - `memory` — in-memory storage, no persistence (good for local dev)
    /// - `sqlite:<path>` — SQLite file-backed storage
    pub db_url: String,
    /// Path to the PEM-encoded signing key (`PULSE_KEY_PATH`, default `pulse-signing-key.pem`).
    pub key_path: PathBuf,
    /// Current key version (`PULSE_KEY_VERSION`, default `1`).
    pub key_version: u32,
    /// Authentication provider (`PULSE_AUTH_PROVIDER`, default `dev`).
    ///
    /// Supported values:
    /// - `dev` — accepts any non-empty credential as the employee ID
    pub auth_provider: String,
}

impl Config {
    /// Load configuration from environment variables, falling back to defaults.
    pub fn from_env() -> Self {
        Self {
            identity_addr: env_or("PULSE_IDENTITY_ADDR", "127.0.0.1:8001"),
            signal_addr: env_or("PULSE_SIGNAL_ADDR", "127.0.0.1:8002"),
            db_url: env_or("PULSE_DB_URL", "memory"),
            key_path: PathBuf::from(env_or("PULSE_KEY_PATH", "pulse-signing-key.pem")),
            key_version: env_or("PULSE_KEY_VERSION", "1")
                .parse()
                .expect("PULSE_KEY_VERSION must be a positive integer"),
            auth_provider: env_or("PULSE_AUTH_PROVIDER", "dev"),
        }
    }
}

fn env_or(key: &str, default: &str) -> String {
    std::env::var(key).unwrap_or_else(|_| default.to_string())
}
