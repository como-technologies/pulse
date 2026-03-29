# pulse-relay

Standalone anonymizing relay between clients and the Signal zone.

Strips source IP, timing metadata, and client-fingerprinting headers. Batches and shuffles responses for timing decorrelation. Has **no domain dependencies** -- treats all payloads as opaque bytes.

## Running

```sh
cargo run -p pulse-relay
```

## Configuration

| Variable | Default | Description |
|----------|---------|-------------|
| `PULSE_RELAY_ADDR` | `127.0.0.1:8003` | Relay listen address |
| `PULSE_RELAY_SIGNAL_URL` | `http://127.0.0.1:8002` | Upstream Signal zone URL |
| `PULSE_RELAY_BATCH_SIZE` | `10` | Max items per batch before flush |
| `PULSE_RELAY_BATCH_WINDOW_SECS` | `5` | Seconds between periodic flushes |
| `PULSE_RELAY_MIN_DELAY_MS` | `0` | Minimum per-item random forwarding delay |
| `PULSE_RELAY_MAX_DELAY_MS` | `0` | Maximum per-item random forwarding delay |
| `PULSE_RELAY_REQUEST_TIMEOUT_SECS` | `30` | Upstream request timeout |

## Architecture

- `RelayState` -- shared state: batcher, config, HTTP client
- `Batcher` -- accumulates responses, flushes on size or time threshold, shuffles before forwarding
- Content-type agnostic -- accepts `application/octet-stream`, forwards as-is

## Testing

```sh
cargo test -p pulse-relay
```

Integration tests spawn a mock Signal zone server and verify batching, shuffling, and forwarding.
