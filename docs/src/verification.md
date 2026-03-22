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

40 tests across 4 crates. Run all:

```sh
cargo test
```

### By crate

```sh
cargo test -p pulse-crypto      # 11 tests — blind sigs + AEAD
cargo test -p pulse-protocol    #  9 tests — wire types + token + sensitive redaction
cargo test -p pulse-identity    #  3 tests — EmployeeId redaction
cargo test -p pulse-signal      #  6 tests — spent-token ledger + tracing assertions
cargo test -p pulse-server      # 11 tests — protocol flow + HTTP e2e + error responses
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
cargo test --test error_responses  # structured error responses (5 tests)
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

**HTTP round-trip** — Full flow over HTTP with separate Identity and Signal zone routers on random ports. Exercises serialization, routing, and status codes. Duplicate submission returns HTTP 422 with structured error code.

### Error response tests (error_responses.rs)

**Structured error format** — All error responses follow the `{ "code": "...", "message": "..." }` shape with exactly two fields.

**HTTP status codes** — Duplicate token → 422, forged signature → 422, batch mismatch → 422, empty API key → 401.

**Machine-readable codes** — Error codes like `RESPONSE_TOKEN_ALREADY_SPENT`, `RESPONSE_INVALID_SIGNATURE`, `UNAUTHORIZED` are stable and suitable for programmatic consumption.

### Tracing tests (response_collector)

**Observability verification** — Successful response acceptance logs "response accepted". Forged signatures do not log success. Debug-level validation steps are emitted for each stage of the pipeline.

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
| Structured error responses | `duplicate_submission_returns_422_with_error_code`, `forged_signature_returns_422`, `batch_mismatch_returns_422`, `empty_api_key_returns_401`, `error_response_has_consistent_structure` |
| Tracing observability | `accept_logs_success`, `duplicate_submission_does_not_log_success`, `forged_signature_logs_no_success` |
| Sensitive type redaction | `sensitive_types_redact_debug`, `sensitive_types_redact_display`, `sensitive_types_still_serialize_to_real_values`, `safe_types_show_real_values_in_debug`, `employee_id_redacts_debug_and_display`, `employee_id_inner_value_accessible_via_field`, `employee_id_equality_works_despite_redacted_debug` |
