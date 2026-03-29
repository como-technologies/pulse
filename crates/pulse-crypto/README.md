# pulse-crypto

Cryptographic primitives for the Pulse anonymous polling protocol.

## Modules

### `blind_sig` -- Blind RSA Signatures (RFC 9474)

Implements the Partially Blind RSA Signature scheme using SHA-384 and PSS padding with the Randomized variant.

| Function | Description |
|----------|-------------|
| `generate_keypair()` | Generate a 2048-bit RSA keypair |
| `blind(pk, msg)` | Client blinds a message for signing |
| `blind_sign(sk, blinded_msg)` | Server signs the blinded message |
| `finalize(pk, blind_sig, blinding_result, msg)` | Client unblinds and verifies the signature |
| `verify(pk, sig, msg_randomizer, msg)` | Server verifies a finalized signature |

Type aliases: `BrssPublicKey`, `BrssSecretKey`, `BrssKeyPair`.

### `aead` -- AES-256-GCM Authenticated Encryption

| Function | Description |
|----------|-------------|
| `encrypt(key, plaintext)` | Encrypt with random nonce (prepended to ciphertext) |
| `decrypt(key, nonce_and_ciphertext)` | Decrypt and verify |
| `generate_key()` | Generate a random 256-bit key |
| `wrap_key(wrapping_key, dek)` | Wrap a DEK under a CMK |
| `unwrap_key(wrapping_key, wrapped)` | Unwrap a DEK |

### `pseudonym` -- HMAC-SHA256 Pseudonym Derivation

| Function | Description |
|----------|-------------|
| `derive_pseudonym(secret, tenant_id, epoch_id)` | Deterministic pseudonym from employee secret |
| `generate_employee_secret()` | Generate a random 32-byte employee secret |

## Testing

```sh
cargo test -p pulse-crypto
```

Uses `proptest` for property-based testing of cryptographic operations across arbitrary inputs.
