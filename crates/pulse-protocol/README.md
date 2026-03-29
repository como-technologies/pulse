# pulse-protocol

Wire types and message definitions shared between Pulse client and server.

Serialized with [postcard](https://docs.rs/postcard) binary format via serde. Defines the contract between client and server without coupling to either side.

## Modules

### `messages` -- Protocol Messages

**Phase 1 (Identity zone):** `TokenRequest`, `TokenResponse`, `TokenDenied`, `QuestionDelivery`

**Phase 2 (Signal zone):** `ResponseSubmit`, `ResponseAck`, `ResponseReject`

**Payload:** `ResponsePayload`, `ResponseData` (Scale5, Binary, Emoji, FreeText)

### `newtypes` -- Domain Type Wrappers

UUID-based: `QuestionBatchId`, `TenantId`

Versioning: `KeyVersion`, `UnixTimestamp`

Cryptographic (implement `Sensitive`, redacted Debug/Display): `BlindedToken`, `BlindSig`, `TokenBytes`, `SignatureBytes`, `EncryptedBlob`, `Pseudonym`, `Nonce`

String-based: `EpochId`, `SegmentLabel`, `QuestionText`

### `token` -- Token Payload

`TokenPayload` -- the data structure blind-signed by the Token Issuer. Contains nonce, batch ID, tenant ID, expiry, segment vector, attestation class, and key version.

`AttestationClass` -- device attestation confidence level (Personal, Group, Location, Hybrid).

### `epoch` -- Epoch Configuration

`EpochConfig` -- defines pseudonym rotation period (default 90 days).

## Conventions

- All newtypes use `#[serde(transparent)]` for wire-compatible serialization
- Types containing PII or crypto material implement `Sensitive` with redacted Debug/Display
- All newtypes have `pub` inner fields for database/wire access via `.0`

## Testing

```sh
cargo test -p pulse-protocol
```
