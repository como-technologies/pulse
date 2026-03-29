//! Test harness and simulation framework for the Pulse protocol.
//!
//! Provides shared test infrastructure used across workspace crates:
//!
//! - **`servers`**: Consolidated test server setup (Identity + Signal zones)
//! - **`mock_transport`**: In-memory `HttpTransport` for deterministic testing
//! - **`simulation`**: Multi-tenant concurrent protocol simulation framework

pub mod mock_transport;
pub mod servers;
pub mod simulation;

pub use mock_transport::{HttpMethod, MockTransport, RecordedRequest};
pub use servers::{TestServers, start_test_servers};
