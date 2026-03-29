//! Platform-agnostic protocol client for Pulse anonymous polling.
//!
//! This crate implements the client-side protocol state machine for the
//! Pulse blind signature flow. It depends only on `pulse-protocol` (wire types)
//! and `pulse-crypto` (cryptographic primitives), never on server-side crates.
//!
//! # Architecture
//!
//! - **`engine`**: Sync protocol engine (message building, response parsing, crypto)
//! - **`transport`**: HTTP transport trait with a reqwest implementation
//! - **`token_state`**: Typestate pattern for the token lifecycle
//! - **`protocol`**: Stateless helpers (pseudonym derivation, response encryption)
//! - **`flow`**: `PulseClient<T>` → `ConnectedClient<T>` typestate orchestrators

pub mod engine;
pub mod error;
pub mod flow;
pub mod protocol;
pub mod token_state;
pub mod transport;

// Re-export key types
pub use engine::ProtocolEngine;
pub use error::ClientError;
pub use flow::{ConnectedClient, PulseClient, ServerConfig, SessionContext};
pub use protocol::{current_epoch, derive_pseudonym, encrypt_response, generate_employee_secret};
pub use pulse_protocol::messages::ResponseSubmit;
pub use token_state::{BlindedTokenState, ReadyToken, SignedTokenState};
pub use transport::{HttpTransport, TransportResponse};

#[cfg(feature = "reqwest-transport")]
pub use transport::ReqwestTransport;
