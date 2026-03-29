# pulse-test-harness

Test harness and simulation framework for the Pulse protocol.

## Quick Start

```sh
# Run a simulation: 1 tenant, 10 employees, concurrency 10
cargo run -p pulse-test-harness --bin pulse-simulate

# Stress test: 3 tenants, 500 employees each, concurrency 200
cargo run -p pulse-test-harness --bin pulse-simulate -- --stress

# Custom: 5 tenants, 100 employees each, concurrency 50
cargo run -p pulse-test-harness --bin pulse-simulate -- --tenants 5 --employees 100 --concurrency 50
```

## Components

### TestServers

Consolidated test server setup, replacing the duplicated `tests/common/mod.rs` pattern. Spins up Identity and Signal zone servers on ephemeral ports with in-memory storage and dev providers.

```rust
use pulse_test_harness::start_test_servers;

let servers = start_test_servers(true).await; // true = with analytics
// servers.identity_url, servers.signal_url, servers.pk, servers.tenant_id, etc.
```

Includes the `/config` endpoint for testing `PulseClient::connect()`.

### MockTransport

In-memory `HttpTransport` implementation for deterministic testing without network I/O. Routes are matched by HTTP method + URL substring.

```rust
use pulse_test_harness::{MockTransport, HttpMethod};
use pulse_client::TransportResponse;

let transport = MockTransport::new()
    .on(HttpMethod::PostJson, "/auth", TransportResponse {
        status: 200,
        body: br#"{"session_token":"tok-123"}"#.to_vec(),
    })
    .on(HttpMethod::Get, "/question", TransportResponse {
        status: 200,
        body: postcard::to_allocvec(&questions).unwrap(),
    });

// After use, assert on recorded requests:
transport.assert_request_count("/auth", 1);
let requests = transport.requests();
```

### Simulation Framework

Multi-tenant concurrent protocol simulation with per-operation timing and percentile statistics.

**Configuration:**

```rust
use pulse_test_harness::simulation::*;

let config = SimulationConfig {
    tenants: vec![
        TenantSetup {
            name: "Acme Corp".into(),
            employee_count: 500,
            question_batches: vec![QuestionBatchSetup { ... }],
            max_tokens_per_batch: 1,
        },
    ],
    concurrency: 100,
    with_analytics: true,
};
```

**Execution:**

```rust
let cluster = SimulationCluster::start(&config).await;
let runner = SimulationRunner::new(cluster, config.concurrency);
let report = runner.run().await;
report.print_summary();
```

**Report output:**

```
============================================================
  Pulse Protocol Simulation Report
============================================================

  Total flows: 500  |  Passed: 500  |  Failed: 0
  Wall-clock time: 1.23s

  Aggregate Timings (successful flows):
    authenticate     p50=1.20ms   p90=2.10ms   p99=3.50ms   max=4.80ms
    fetch_questions  p50=0.60ms   p90=1.00ms   p99=1.80ms   max=2.20ms
    blind_and_sign   p50=28.00ms  p90=35.00ms  p99=42.00ms  max=50.00ms
    encrypt_submit   p50=1.80ms   p90=2.50ms   p99=3.20ms   max=4.00ms
    total_flow       p50=32.00ms  p90=40.00ms  p99=48.00ms  max=55.00ms
```

## Using as a Dev Dependency

Add to your crate's `Cargo.toml`:

```toml
[dev-dependencies]
pulse-test-harness = { path = "../pulse-test-harness", features = ["reqwest-transport"] }
```

Then in your integration tests:

```rust
use pulse_test_harness::start_test_servers;

#[tokio::test]
async fn my_test() {
    let servers = start_test_servers(false).await;
    // Use servers.identity_url, servers.signal_url, etc.
}
```
