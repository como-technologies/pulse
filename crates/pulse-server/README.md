# pulse-server

Axum HTTP composition root for Pulse. Hosts the Identity zone and Signal zone on separate ports with independent state types.

## Running

```sh
cargo run -p pulse-server
```

## Configuration

All configuration via environment variables:

| Variable | Default | Description |
|----------|---------|-------------|
| `PULSE_IDENTITY_ADDR` | `127.0.0.1:8001` | Identity zone listen address |
| `PULSE_SIGNAL_ADDR` | `127.0.0.1:8002` | Signal zone listen address |
| `PULSE_DB_URL` | `memory` | `memory` or `sqlite:<path>` |
| `PULSE_AUTH_PROVIDER` | `dev` | Authenticator backend |
| `PULSE_SAMPLING_PROVIDER` | `dev` | Sampling engine backend |
| `PULSE_CMK_PROVIDER` | `dev` | Customer master key backend |
| `PULSE_TENANT_ID` | `00000000-...0001` | Default tenant UUID |
| `PULSE_KEY_PATH` | `pulse-signing-key.pem` | Signing key file (auto-generated if missing) |
| `PULSE_KEY_VERSION` | `1` | Current signing key version |
| `PULSE_K_THRESHOLD` | `5` | K-anonymity suppression threshold |
| `PULSE_MAX_TOKENS_PER_BATCH` | `1` | Frequency cap per employee per batch |

## Architecture

Two independent state types enforce trust zone isolation at the composition-root level:

- **`IdentityState`** -- TokenIssuer, Authenticator, SessionStore, SamplingEngine (port 8001)
- **`SignalState`** -- ResponseCollector, ResponseStore, AnalyticsEngine (port 8002)

The `AuthenticatedEmployee` extractor compiles only against `IdentityState` -- using it in a signal-zone handler is a compile error.

## Dev Providers

| Provider | Description |
|----------|-------------|
| `DevAuthenticator` | Accepts any non-empty credential as the employee ID |
| `DevSamplingEngine` | Returns a fixed question batch for all employees |
| `DevCmkProvider` | Single fixed AES-256 wrapping key (not for production) |
| `InMemoryTenantKeyStore` | In-memory per-tenant keypair storage |

## Testing

```sh
cargo test -p pulse-server
```

See the [Verification Guide](../../docs/src/development/verification.md) for test categories and what each layer proves.
