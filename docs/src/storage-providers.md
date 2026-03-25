# Storage Providers

This guide explains how Pulse's storage architecture works and how to implement custom backends for different infrastructure (Postgres, DynamoDB, Oracle, etc.).

---

## Architecture Overview

Storage lives entirely in the **Signal zone**. The two storage traits are defined in `pulse-signal` and implemented in `pulse-server` (the composition root). This follows the hexagonal pattern — domain crates define ports, the server provides adapters.

### Key Components

| Component | Crate | Role |
|-----------|-------|------|
| `SpentTokenLedger` trait | `pulse-signal` | Atomic check-and-spend for token replay prevention |
| `ResponseStore` trait | `pulse-signal` | Append-only storage for encrypted response blobs |
| `InMemoryLedger` | `pulse-signal` | Dev-mode ledger (`HashSet` behind `Mutex`) |
| `InMemoryStore` | `pulse-signal` | Dev-mode store (`Vec` behind `Mutex`) |
| `SqliteLedger` | `pulse-server` | SQLite-backed ledger (WAL mode, STRICT tables) |
| `SqliteStore` | `pulse-server` | SQLite-backed response store |

### Backend Selection

The `PULSE_DB_URL` environment variable controls which backend is used:

```sh
# In-memory (default) — no persistence, good for local dev
PULSE_DB_URL=memory cargo run

# SQLite — file-backed persistence
PULSE_DB_URL=sqlite:pulse.db cargo run
```

The URI scheme is the extension point. Adding a new provider means adding a new scheme (e.g., `postgres://`, `dynamodb://`).

---

## Trait Contracts

### SpentTokenLedger

```rust
{{#include ../../crates/pulse-signal/src/ledger.rs:spent_token_ledger}}

{{#include ../../crates/pulse-signal/src/ledger.rs:spend_result}}
```

### ResponseStore

```rust
{{#include ../../crates/pulse-signal/src/store.rs:response_store}}

{{#include ../../crates/pulse-signal/src/store.rs:stored_response}}
```

---

## Implementing a Provider

### Example: Postgres Backend

Here's how you'd implement Postgres-backed storage using `sqlx`.

**Add dependencies** to `pulse-server/Cargo.toml`:

```toml
sqlx = { version = "0.8", features = ["runtime-tokio", "postgres"] }
```

**Create `pulse-server/src/postgres_ledger.rs`:**

```rust
use pulse_signal::{SpendResult, SpentTokenLedger, TokenHash};
use sqlx::PgPool;
use std::sync::Arc;

pub struct PostgresLedger {
    pool: Arc<PgPool>,
}

impl PostgresLedger {
    pub async fn new(pool: Arc<PgPool>) -> Result<Self, sqlx::Error> {
        sqlx::query(
            "CREATE TABLE IF NOT EXISTS spent_tokens (
                token_hash BYTEA PRIMARY KEY NOT NULL
            )"
        )
        .execute(pool.as_ref())
        .await?;
        Ok(Self { pool })
    }
}

impl SpentTokenLedger for PostgresLedger {
    fn check_and_spend(&self, hash: TokenHash) -> SpendResult {
        // Note: the trait is synchronous. For async DB drivers,
        // use tokio::task::block_in_place or make the trait async
        // when the codebase is ready for that migration.
        tokio::task::block_in_place(|| {
            let rt = tokio::runtime::Handle::current();
            rt.block_on(async {
                let result = sqlx::query(
                    "INSERT INTO spent_tokens (token_hash) VALUES ($1)
                     ON CONFLICT DO NOTHING"
                )
                .bind(hash.0.as_slice())
                .execute(self.pool.as_ref())
                .await
                .expect("spent-token ledger db error");

                if result.rows_affected() > 0 {
                    SpendResult::Accepted
                } else {
                    SpendResult::AlreadySpent
                }
            })
        })
    }
}
```

**Create `pulse-server/src/postgres_store.rs`:**

```rust
use pulse_protocol::{EncryptedBlob, QuestionBatchId, TenantId, UnixTimestamp};
use pulse_signal::{ResponseStore, StoredResponse};
use sqlx::PgPool;
use std::sync::Arc;

pub struct PostgresStore {
    pool: Arc<PgPool>,
}

impl PostgresStore {
    pub async fn new(pool: Arc<PgPool>) -> Result<Self, sqlx::Error> {
        sqlx::query(
            "CREATE TABLE IF NOT EXISTS responses (
                id BIGSERIAL PRIMARY KEY,
                encrypted_blob BYTEA NOT NULL,
                question_batch_id UUID NOT NULL,
                tenant_id UUID NOT NULL,
                received_at BIGINT NOT NULL
            )"
        )
        .execute(pool.as_ref())
        .await?;
        Ok(Self { pool })
    }
}

impl ResponseStore for PostgresStore {
    fn store(&self, response: StoredResponse) {
        tokio::task::block_in_place(|| {
            let rt = tokio::runtime::Handle::current();
            rt.block_on(async {
                sqlx::query(
                    "INSERT INTO responses (encrypted_blob, question_batch_id, tenant_id, received_at)
                     VALUES ($1, $2, $3, $4)"
                )
                .bind(&response.encrypted_blob.0)
                .bind(response.question_batch_id.0)
                .bind(response.tenant_id.0)
                .bind(response.received_at.0 as i64)
                .execute(self.pool.as_ref())
                .await
                .expect("response store db error");
            })
        });
    }

    fn count(&self) -> usize {
        tokio::task::block_in_place(|| {
            let rt = tokio::runtime::Handle::current();
            rt.block_on(async {
                let (count,): (i64,) = sqlx::query_as(
                    "SELECT COUNT(*) FROM responses"
                )
                .fetch_one(self.pool.as_ref())
                .await
                .expect("response store db error");
                count as usize
            })
        })
    }

    fn list(&self) -> Vec<StoredResponse> {
        tokio::task::block_in_place(|| {
            let rt = tokio::runtime::Handle::current();
            rt.block_on(async {
                sqlx::query_as::<_, (Vec<u8>, uuid::Uuid, uuid::Uuid, i64)>(
                    "SELECT encrypted_blob, question_batch_id, tenant_id, received_at
                     FROM responses ORDER BY id"
                )
                .fetch_all(self.pool.as_ref())
                .await
                .expect("response store db error")
                .into_iter()
                .map(|(blob, batch_id, tid, received_at)| StoredResponse {
                    encrypted_blob: EncryptedBlob(blob),
                    question_batch_id: QuestionBatchId::from_uuid(batch_id),
                    tenant_id: TenantId::from_uuid(tid),
                    received_at: UnixTimestamp(received_at as u64),
                })
                .collect()
            })
        })
    }
}
```

> **Note:** This is illustrative. The `block_in_place` pattern wraps async calls for the synchronous trait interface. If the traits are later made async, the wrapper can be removed. The `ON CONFLICT DO NOTHING` pattern in Postgres provides the same atomicity as SQLite's unique constraint violation.

### Wiring Into main.rs

Add a new match arm in the storage backend selection:

```rust
let (ledger, store): (Arc<dyn SpentTokenLedger>, Arc<dyn ResponseStore>) =
    match config.db_url.as_str() {
        "memory" => { /* ... existing ... */ }
        url if url.starts_with("sqlite:") => { /* ... existing ... */ }
        url if url.starts_with("postgres://") => {
            tracing::info!("Using Postgres storage");
            let pool = Arc::new(PgPool::connect(url).await?);
            let ledger = Arc::new(PostgresLedger::new(pool.clone()).await?);
            let store = Arc::new(PostgresStore::new(pool).await?);
            (ledger, store)
        }
        other => anyhow::bail!("unsupported PULSE_DB_URL: {other:?}"),
    };
```

Then set the environment variable:

```sh
PULSE_DB_URL=postgres://user:pass@localhost/pulse cargo run
```

---

## Provider Crate Pattern

For production deployments, storage providers can live in their own crates:

```
crates/
  pulse-storage-postgres/    # Postgres via sqlx
  pulse-storage-dynamodb/    # AWS DynamoDB
  pulse-storage-cosmosdb/    # Azure CosmosDB
```

Each crate depends on `pulse-signal` (for the traits) and its database driver. The `pulse-server` composition root depends on whichever provider crates it needs and selects based on `PULSE_DB_URL`.

This keeps the core crates free of database driver dependencies and lets organizations bring their own storage backend.

---

## Rules

1. **Storage traits live in `pulse-signal`, implementations live in `pulse-server`** (or provider crates). The domain crate defines the port, adapters provide the implementation.

2. **Both traits must be implemented together.** If you implement `SpentTokenLedger` for Postgres, you should also implement `ResponseStore`. They share the same database in the default setup, and both must be durable for the system to function correctly.

3. **`check_and_spend` must be atomic.** Two concurrent requests with the same token hash must never both return `Accepted`. Use database-level uniqueness constraints, not application-level checks.

4. **Database errors are fatal.** Use `.expect()` on database operations. A silent failure in the spent-token ledger could allow double-voting, which violates the protocol's security guarantees. Crash and let the process supervisor restart.

5. **The Signal zone never decrypts response content.** Your storage implementation should treat `encrypted_blob` as opaque bytes. Never add decryption logic to a storage provider.
