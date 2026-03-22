# Sampling Engine Providers

This guide explains how Pulse's sampling architecture works and how to implement a custom provider for workforce roster management, question assignment, frequency caps, and k-anonymity enforcement.

---

## Architecture Overview

The Sampling Engine lives entirely in the **Identity zone**. It knows WHO gets which questions but never sees response content. The trait is defined in `pulse-identity` and implementations live in `pulse-server` (the composition root), following the hexagonal pattern.

### Key Components

| Component | Crate | Role |
|-----------|-------|------|
| `SamplingEngine` trait | `pulse-identity` | Decide question assignments and authorize token issuance |
| `SamplingDecision` | `pulse-identity` | Output: question + coarsened segments for one assignment |
| `SamplingError` | `pulse-identity` | Typed errors: `NotAssigned`, `FrequencyCapExceeded`, `BatchExpired` |
| `InMemorySamplingEngine` | `pulse-identity` | Test/example implementation with explicit roster setup |
| `DevSamplingEngine` | `pulse-server` | Dev-mode provider (accepts any employee, returns default question) |
| `QuestionBatch` | `pulse-identity` | Question batch definition (id, text, response type, expiry) |
| `FrequencyPolicy` | `pulse-identity` | Frequency cap configuration |

### Provider Selection

The `PULSE_SAMPLING_PROVIDER` environment variable controls which provider is used:

```sh
# Dev mode (default) -- accepts any employee, returns one default question
PULSE_SAMPLING_PROVIDER=dev cargo run
```

The string value is the extension point. Adding a new provider means adding a new match arm in `main.rs`.

### Integration with TokenIssuer

The `SamplingEngine` is injected into `TokenIssuer` via `TokenIssuer::with_sampling()`. When a client requests a blind signature (`POST /token/sign`), the issuer calls `authorize_and_record_issuance()` before signing. This ensures authorization and frequency cap enforcement happen atomically with the signing operation.

```
Client                           Identity Zone
  |                                   |
  |-- GET /question ----------------->| SamplingEngine::assignments_for(employee_id)
  |<-- [QuestionDelivery + segments]--| Returns batches with coarsened segment_vector
  |                                   |
  |-- POST /token/sign -------------->| TokenIssuer::sign_token()
  |   {blinded_token, batch_id}       |   -> SamplingEngine::authorize_and_record_issuance()
  |                                   |   -> blind_sign() if authorized
  |<-- {blind_signature, key_version}-|
```

---

## The SamplingEngine Trait

```rust
pub trait SamplingEngine: Send + Sync {
    /// Get question assignments for an employee.
    /// Returns batches with coarsened segment vectors.
    /// Excludes expired batches and batches where the frequency cap is hit.
    fn assignments_for(&self, employee_id: &EmployeeId) -> Vec<SamplingDecision>;

    /// Atomically authorize issuance AND record it.
    /// Checks: assignment exists, frequency cap, batch not expired.
    /// On Ok, the issuance count is incremented.
    fn authorize_and_record_issuance(
        &self,
        employee_id: &EmployeeId,
        question_batch_id: &QuestionBatchId,
    ) -> Result<(), SamplingError>;
}
```

### Contract

- **`assignments_for`** is called by `GET /question`. Returns all active, non-expired, non-capped assignments for the employee, each with a coarsened `segment_vector` for k-anonymity.

- **`authorize_and_record_issuance`** is called by `TokenIssuer::sign_token`. The check and count increment **must be atomic** -- a single lock or database transaction must cover both. This prevents TOCTOU double-issuance where two concurrent requests both pass the frequency cap check before either records the issuance.

- **Error mapping**: `SamplingError` variants map to `TokenDeniedReason` in the issuer:
  - `NotAssigned` -> `TokenDeniedReason::NotAuthorized` (HTTP 403)
  - `FrequencyCapExceeded` -> `TokenDeniedReason::FrequencyCap` (HTTP 403)
  - `BatchExpired` -> `TokenDeniedReason::BatchExpired` (HTTP 403)

---

## K-Anonymity Coarsening

Segment identifiers are embedded in the token at **issuance time**, not derived at response time. For groups below the k-anonymity threshold, the Sampling Engine coarsens the segment label by walking up the organizational hierarchy.

### Algorithm

For each of an employee's leaf segments:

1. Count how many roster employees share this segment (or any descendant)
2. If count >= k, keep the label
3. If count < k, walk up to the parent segment and recount
4. Repeat until count >= k or the root is reached

**Example:** If Team Alpha has 3 people and k=5, the segment is coarsened to "Engineering > Backend" (the parent with >= 5 members). The Response Collector and Analytics Engine never receive "Team Alpha".

This enforces k-anonymity **at the data level** -- the Analytics Engine cannot accidentally expose small-group data because it never receives sub-threshold segment labels.

---

## Implementing a Provider

### Example: Postgres-Backed Sampling Engine

Here's how you'd implement a database-backed sampling engine using `sqlx`.

**Schema:**

```sql
CREATE TABLE segments (
    label TEXT PRIMARY KEY,
    parent_label TEXT REFERENCES segments(label)
);

CREATE TABLE roster (
    employee_id TEXT NOT NULL,
    segment_label TEXT NOT NULL REFERENCES segments(label),
    PRIMARY KEY (employee_id, segment_label)
);

CREATE TABLE question_batches (
    id UUID PRIMARY KEY,
    question_text TEXT NOT NULL,
    response_type TEXT NOT NULL,
    expiry BIGINT NOT NULL
);

CREATE TABLE assignments (
    employee_id TEXT NOT NULL,
    question_batch_id UUID NOT NULL REFERENCES question_batches(id),
    PRIMARY KEY (employee_id, question_batch_id)
);

CREATE TABLE issuance_counts (
    employee_id TEXT NOT NULL,
    question_batch_id UUID NOT NULL REFERENCES question_batches(id),
    count INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (employee_id, question_batch_id)
);
```

**Create `pulse-server/src/postgres_sampling.rs`:**

```rust
use pulse_identity::{
    EmployeeId, SamplingDecision, SamplingEngine, SamplingError,
};
use pulse_protocol::QuestionBatchId;
use sqlx::PgPool;
use std::sync::Arc;

pub struct PostgresSamplingEngine {
    pool: Arc<PgPool>,
    k_threshold: usize,
    max_tokens_per_batch: u32,
}

impl SamplingEngine for PostgresSamplingEngine {
    fn assignments_for(&self, employee_id: &EmployeeId) -> Vec<SamplingDecision> {
        tokio::task::block_in_place(|| {
            let rt = tokio::runtime::Handle::current();
            rt.block_on(async {
                // Query assigned batches, join with issuance counts,
                // filter expired and capped, compute coarsened segments
                // ...
                todo!("implement query + coarsening")
            })
        })
    }

    fn authorize_and_record_issuance(
        &self,
        employee_id: &EmployeeId,
        question_batch_id: &QuestionBatchId,
    ) -> Result<(), SamplingError> {
        tokio::task::block_in_place(|| {
            let rt = tokio::runtime::Handle::current();
            rt.block_on(async {
                // Use a database transaction to atomically:
                // 1. Check assignment exists
                // 2. Check batch not expired
                // 3. Check count < max_tokens_per_batch
                // 4. Increment count (INSERT ON CONFLICT UPDATE)
                let mut tx = self.pool.begin().await
                    .expect("sampling db error");
                // ... transactional logic ...
                tx.commit().await.expect("sampling db error");
                Ok(())
            })
        })
    }
}
```

> **Note:** The `block_in_place` pattern wraps async calls for the synchronous trait interface, matching the existing storage provider pattern. Use a database transaction in `authorize_and_record_issuance` to ensure atomicity -- `INSERT ... ON CONFLICT` or `SELECT FOR UPDATE` prevents double-issuance under concurrency.

### Wiring Into main.rs

Add a new match arm in the sampling provider selection:

```rust
let sampling_engine: Arc<dyn SamplingEngine> = match config.sampling_provider.as_str() {
    "dev" => { /* ... existing ... */ }
    url if url.starts_with("postgres://") => {
        tracing::info!("Using Postgres sampling engine");
        let pool = Arc::new(PgPool::connect(url).await?);
        Arc::new(PostgresSamplingEngine::new(
            pool, config.k_threshold, config.max_tokens_per_batch
        ))
    }
    other => anyhow::bail!("unsupported PULSE_SAMPLING_PROVIDER: {other:?}"),
};
```

Then set the environment variable:

```sh
PULSE_SAMPLING_PROVIDER=postgres://user:pass@localhost/pulse cargo run
```

---

## Configuration

| Variable | Default | Description |
|----------|---------|-------------|
| `PULSE_SAMPLING_PROVIDER` | `dev` | Sampling engine provider |
| `PULSE_K_THRESHOLD` | `5` | K-anonymity threshold (minimum group size) |
| `PULSE_MAX_TOKENS_PER_BATCH` | `1` | Max tokens per employee per question batch |

---

## Rules

These are architectural invariants. Do not violate them.

1. **The `SamplingEngine` trait lives in `pulse-identity`, implementations live in `pulse-server`.** This follows the hexagonal architecture pattern -- the domain crate defines the port, the server crate provides the adapter.

2. **`authorize_and_record_issuance` must be atomic.** Two concurrent requests for the same employee and batch must never both succeed if the frequency cap is 1. Use database transactions or mutex locks to ensure this.

3. **Sampling is identity-zone only.** Never import sampling types into signal-zone code. The Cargo dependency graph enforces this -- `pulse-signal` cannot depend on `pulse-identity`.

4. **K-anonymity coarsening must happen at issuance time, not display time.** The coarsened segment_vector is embedded in the token payload before blind signing. The Analytics Engine never receives sub-threshold segment labels -- this is enforced at the data level, not the UI level.

5. **The `DevSamplingEngine` is for development only.** It skips roster and assignment checks. Never use it in production -- it bypasses the authorization model that protects against unauthorized token issuance.
