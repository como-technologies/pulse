pub mod batcher;
pub mod config;
pub mod routes;

use std::sync::Arc;

use batcher::Batcher;
use config::Config;

/// Relay state shared across handlers and the flush loop.
pub struct RelayState {
    pub batcher: Arc<Batcher>,
    pub config: Arc<Config>,
    pub client: reqwest::Client,
}
