# Anonymizing Relay

The anonymizing relay is a mandatory network-level anonymizer between clients and the Signal zone. It strips all identifying metadata from anonymous submissions, batches and shuffles requests for timing decorrelation, and forwards them from its own IP address.

---

## Architecture

The relay is a standalone binary (`pulse-relay`) with **zero domain dependencies** -- it does not depend on `pulse-identity`, `pulse-signal`, `pulse-protocol`, or `pulse-crypto`. It treats all request bodies as opaque bytes.

```
Client --> [Relay] --> Signal Zone (Response Collector)
              |
              +-- Strips all client headers
              +-- Batches and shuffles requests
              +-- Forwards from relay's own IP
              +-- No payload inspection or logging
```

### What the relay does

- **Accepts** `POST /response` with an opaque byte body
- **Queues** the body in a batch queue
- **Flushes** the queue periodically or when the batch size is reached
- **Shuffles** the batch order for timing decorrelation
- **Applies** optional per-item random delay
- **Forwards** each request to the Signal zone as a fresh HTTP POST
- **Returns** the Signal zone's response (status + body) to the waiting client

### What the relay never does

- Deserialize or inspect request bodies
- Log source IP addresses, request bodies, or client headers
- Forward any client headers to the Signal zone
- Generate or propagate request IDs (fingerprinting vector)
- Maintain any state that could correlate inbound to outbound requests

---

## Configuration

| Variable | Default | Description |
|----------|---------|-------------|
| `PULSE_RELAY_ADDR` | `127.0.0.1:8003` | Address the relay listens on |
| `PULSE_RELAY_SIGNAL_URL` | `http://127.0.0.1:8002` | Signal zone base URL |
| `PULSE_RELAY_BATCH_SIZE` | `10` | Max items per batch before flushing |
| `PULSE_RELAY_BATCH_WINDOW_SECS` | `5` | Seconds between periodic batch flushes |
| `PULSE_RELAY_MIN_DELAY_MS` | `0` | Minimum per-item random forwarding delay |
| `PULSE_RELAY_MAX_DELAY_MS` | `0` | Maximum per-item random forwarding delay |
| `PULSE_RELAY_REQUEST_TIMEOUT_SECS` | `30` | Timeout for upstream POST to Signal zone |

Start the relay:

```sh
cargo run -p pulse-relay
```

---

## Batching and Shuffling

The relay accumulates incoming submissions in a queue and flushes them in shuffled batches. This decouples the submission timestamp from the arrival timestamp at the Signal zone, defeating timing correlation attacks.

**Flush triggers** (whichever comes first):
- Queue reaches `PULSE_RELAY_BATCH_SIZE` items
- `PULSE_RELAY_BATCH_WINDOW_SECS` seconds have elapsed since the last flush

**On flush:**
1. All queued requests are drained
2. The batch is randomly shuffled (permuted)
3. Each request is forwarded to the Signal zone with an optional random delay between `MIN_DELAY_MS` and `MAX_DELAY_MS`
4. The Signal zone's response is relayed back to each waiting client

Clients hold their HTTP connection open until their request is forwarded and the Signal zone responds. If the client disconnects before the flush, the request is still forwarded but the response is discarded.

---

## Client Verification

The relay does not authenticate clients. It is a transport-level anonymizer -- it passes opaque bytes through.

Invalid submissions (forged tokens, expired tokens, bad signatures) are forwarded to the Signal zone, which rejects them via its existing cryptographic verification (blind signature check, spent-token ledger, expiry check). The relay returns the Signal zone's rejection response to the client.

This design keeps the relay minimal and avoids giving it access to cryptographic material.

---

## Error Responses

The relay can return the following HTTP status codes:

| Status | Meaning |
|--------|---------|
| (proxied) | Signal zone's response (status + body) passed through as-is |
| 500 | Internal error (e.g., batch channel dropped before response received) |
| 502 | Bad gateway — upstream POST to Signal zone failed |
| 504 | Gateway timeout — Signal zone did not respond within `PULSE_RELAY_REQUEST_TIMEOUT_SECS` |

On success, the client receives the Signal zone's exact response. On relay-level failure, the client receives a plain status code with no body.

---

## Deployment Considerations

### TLS Termination

In production, a reverse proxy or load balancer (nginx, envoy, AWS ALB) should terminate TLS in front of the relay. The relay itself listens on plain HTTP. This is the standard pattern for Rust services and keeps the relay codebase minimal.

The relay creates a new TCP connection to the Signal zone via `reqwest`, achieving connection re-origination. The Signal zone sees only the relay's IP, never the client's.

### Network Segmentation

Deploy the relay in a DMZ or edge network, with the Signal zone in a private network accessible only from the relay's IP:

```
Internet --> [TLS Terminator] --> [Relay (DMZ)] --> [Signal Zone (private)]
```

Use firewall rules or security groups to ensure the Signal zone only accepts connections from the relay.

### Strict Client Tunnels

For environments requiring stronger client authentication at the transport level:

- **mTLS (mutual TLS)**: Configure the TLS terminator to require client certificates. Only devices with provisioned certificates can reach the relay. The relay itself remains unaware of TLS -- the terminator handles it.
- **VPN/WireGuard**: Place the relay behind a VPN endpoint. Only clients on the VPN can submit.
- **IP allowlisting**: Restrict the relay's inbound connections to known corporate IP ranges.

These are deployment-level controls, not application-level. The relay binary does not change.

### Source IP

All requests from the relay to the Signal zone originate from the relay's server IP. The Signal zone never sees client IPs. For additional source IP rotation, deploy multiple relay instances behind a load balancer, or use NAT with IP rotation at the infrastructure level.
