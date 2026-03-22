# Verification Guide

How to verify Pulse's privacy and correctness properties.

## Interactive walkthrough

The `walkthrough` example runs the full blind signature protocol in-memory with step-by-step narration:

```sh
cargo run -p pulse-server --example walkthrough
```

It demonstrates:

- Token creation, blinding, and blind signing (Phase 1)
- Unblinding, encryption, and anonymous submission (Phase 2)
- What each trust zone sees — and what it cannot see
- Replay prevention (duplicate token rejection)
- Forged signature rejection

No running server required. Read the output to build intuition about how the protocol enforces verified anonymity.

## Test suite

25 tests across 4 crates. Run all:

```sh
cargo test
```

### By crate

```sh
cargo test -p pulse-crypto      # 11 tests — blind sigs + AEAD
cargo test -p pulse-protocol    #  5 tests — wire types + token
cargo test -p pulse-signal      #  3 tests — spent-token ledger
cargo test -p pulse-server      #  6 tests — protocol flow + HTTP e2e
```

### By name

```sh
cargo test full_protocol_flow           # 14-step in-memory flow
cargo test duplicate_submission         # replay prevention
cargo test forged_signature             # signature forgery
cargo test full_http_flow               # HTTP round-trip
cargo test -- --nocapture               # show println output
```

### Integration tests only

```sh
cargo test --test protocol_flow    # in-memory protocol flow (5 tests)
cargo test --test e2e              # HTTP round-trip (1 test)
```

## What each layer proves

### Unit tests (pulse-crypto, pulse-protocol, pulse-signal)

**Crypto correctness** — Blind signature round-trips produce verifiable signatures. Wrong keys and wrong messages fail verification. AES-256-GCM encrypts and decrypts correctly; wrong keys and tampered ciphertext fail. Property-based tests (proptest) verify these hold for arbitrary inputs.

**Wire type integrity** — `TokenPayload`, `TokenRequest`, `ResponseSubmit` serialize and deserialize correctly. Expiry checks work at boundary values.

**Ledger correctness** — First spend accepted, duplicate spend rejected, distinct tokens independently accepted.

### Integration tests (protocol_flow.rs)

**Full protocol flow** — 14-step blind signature lifecycle from token creation through response storage, all in-memory.

**Trust zone isolation** — Identity zone issuance log contains employee ID but no token value. Signal zone stored responses contain encrypted blob but no employee ID. Enforced by the type system — the fields do not exist on the structs.

**Replay prevention** — Same valid token submitted twice; second submission rejected.

**Forged signature rejection** — Fabricated signature bytes rejected.

**Batch/tenant validation** — Mismatched batch ID or tenant ID rejected.

### End-to-end test (e2e.rs)

**HTTP round-trip** — Full flow over HTTP with separate Identity and Signal zone routers on random ports. Exercises serialization, routing, and status codes. Duplicate submission returns HTTP 400.

## Key properties verified

| Property | Tests |
|----------|-------|
| Blind signature round-trip | `full_blind_signature_round_trip`, `blind_sign_verify_roundtrip` (proptest) |
| Blinding unlinkability | `different_blinding_factors_produce_different_blinded_messages` |
| Wrong key/message rejection | `wrong_key_fails_verification`, `wrong_message_fails_verification` |
| Random signature rejection | `random_signature_fails_verification` |
| AEAD round-trip | `encrypt_decrypt_round_trip`, `encrypt_decrypt_roundtrip_any_data` (proptest) |
| AEAD tamper detection | `tampered_ciphertext_fails`, `wrong_key_fails_decryption` |
| Nonce uniqueness | `different_encryptions_produce_different_ciphertext` |
| Token serialization | `serialize_deserialize_round_trip`, `expiry_check` |
| Wire type fidelity | `token_request_round_trip`, `response_submit_round_trip`, `reject_reasons_serialize` |
| Spent-token ledger | `first_spend_accepted`, `duplicate_spend_rejected`, `different_tokens_both_accepted` |
| Full protocol flow | `full_protocol_flow`, `full_http_flow` |
| Replay prevention | `duplicate_submission_rejected` |
| Forged signature rejection | `forged_signature_rejected` |
| Batch/tenant mismatch | `wrong_batch_id_rejected`, `wrong_tenant_id_rejected` |
