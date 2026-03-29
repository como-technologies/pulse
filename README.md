# Pulse

Verified-anonymous employee sentiment polling with cryptographic privacy guarantees.

Pulse uses blind signatures (RSA, RFC 9474) to mathematically prove that no one -- not even the system operator -- can link an employee's identity to their response. The identity zone knows WHO participated; the signal zone knows WHAT was said; neither can learn both.

## Quick Start

```sh
# Run the server with dev providers
cargo run -p pulse-server

# Run the protocol simulation (10 employees, full blind signature flow)
cargo run -p pulse-test-harness --bin pulse-simulate

# Run all tests
cargo test --workspace
```

## Documentation

- **[Book](https://como-technologies.github.io/pulse/)** -- concepts, design, development guides
- **[API Reference](https://como-technologies.github.io/pulse/api/pulse_crypto/index.html)** -- generated Rust docs (`cargo doc --workspace --no-deps --open` for local)

## Crate Structure

```
crates/
  pulse-crypto/         Cryptographic primitives (blind sigs, AEAD, pseudonyms)
  pulse-protocol/       Wire types and message definitions (postcard binary)
  pulse-identity/       Identity zone domain logic (knows WHO)
  pulse-signal/         Signal zone domain logic (knows WHAT)
  pulse-client/         Client-side protocol library (sync engine + async transport)
  pulse-server/         Axum HTTP composition root (both zones)
  pulse-relay/          Anonymizing relay (standalone, no domain deps)
  pulse-test-harness/   Test harness and simulation framework
```

## License

UNLICENSED — source is public for transparency; no license is granted.
