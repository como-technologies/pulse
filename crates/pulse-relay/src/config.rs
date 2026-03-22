/// Relay configuration loaded from environment variables.
pub struct Config {
    /// Relay listen address (`PULSE_RELAY_ADDR`, default `127.0.0.1:8003`).
    pub listen_addr: String,
    /// Signal zone base URL to forward responses to
    /// (`PULSE_RELAY_SIGNAL_URL`, default `http://127.0.0.1:8002`).
    pub signal_url: String,
    /// Max items per batch before flushing (`PULSE_RELAY_BATCH_SIZE`, default `10`).
    pub batch_size: usize,
    /// Seconds between periodic batch flushes (`PULSE_RELAY_BATCH_WINDOW_SECS`, default `5`).
    pub batch_window_secs: u64,
    /// Minimum per-item random forwarding delay in ms (`PULSE_RELAY_MIN_DELAY_MS`, default `0`).
    pub min_delay_ms: u64,
    /// Maximum per-item random forwarding delay in ms (`PULSE_RELAY_MAX_DELAY_MS`, default `0`).
    pub max_delay_ms: u64,
    /// Timeout for upstream POST to Signal zone in seconds
    /// (`PULSE_RELAY_REQUEST_TIMEOUT_SECS`, default `30`).
    pub request_timeout_secs: u64,
}

impl Config {
    /// Load configuration from environment variables, falling back to defaults.
    pub fn from_env() -> Self {
        Self {
            listen_addr: env_or("PULSE_RELAY_ADDR", "127.0.0.1:8003"),
            signal_url: env_or("PULSE_RELAY_SIGNAL_URL", "http://127.0.0.1:8002"),
            batch_size: env_or("PULSE_RELAY_BATCH_SIZE", "10")
                .parse()
                .expect("PULSE_RELAY_BATCH_SIZE must be a positive integer"),
            batch_window_secs: env_or("PULSE_RELAY_BATCH_WINDOW_SECS", "5")
                .parse()
                .expect("PULSE_RELAY_BATCH_WINDOW_SECS must be a positive integer"),
            min_delay_ms: env_or("PULSE_RELAY_MIN_DELAY_MS", "0")
                .parse()
                .expect("PULSE_RELAY_MIN_DELAY_MS must be a non-negative integer"),
            max_delay_ms: env_or("PULSE_RELAY_MAX_DELAY_MS", "0")
                .parse()
                .expect("PULSE_RELAY_MAX_DELAY_MS must be a non-negative integer"),
            request_timeout_secs: env_or("PULSE_RELAY_REQUEST_TIMEOUT_SECS", "30")
                .parse()
                .expect("PULSE_RELAY_REQUEST_TIMEOUT_SECS must be a positive integer"),
        }
    }
}

fn env_or(key: &str, default: &str) -> String {
    std::env::var(key).unwrap_or_else(|_| default.to_string())
}
