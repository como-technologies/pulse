use std::path::Path;
use std::sync::Mutex;

use pulse_signal::{SpendResult, SpentTokenLedger, TokenHash};
use rusqlite::Connection;

/// SQLite-backed spent-token ledger.
///
/// Uses a single `spent_tokens` table with the token hash as the primary key.
/// Duplicate detection relies on the PRIMARY KEY constraint — an INSERT that
/// violates uniqueness means the token was already spent.
pub struct SqliteLedger {
    conn: Mutex<Connection>,
}

impl SqliteLedger {
    /// Open (or create) a SQLite database at `path` and initialize the schema.
    pub fn open(path: &Path) -> Result<Self, rusqlite::Error> {
        let conn = Connection::open(path)?;
        conn.execute_batch(
            "\
            PRAGMA journal_mode = WAL;\
            PRAGMA synchronous = NORMAL;\
            PRAGMA foreign_keys = ON;\
            CREATE TABLE IF NOT EXISTS spent_tokens (\
                token_hash BLOB PRIMARY KEY NOT NULL\
            ) STRICT;",
        )?;
        Ok(Self {
            conn: Mutex::new(conn),
        })
    }
}

impl SpentTokenLedger for SqliteLedger {
    fn check_and_spend(&self, hash: TokenHash) -> SpendResult {
        let conn = self.conn.lock().expect("ledger db lock poisoned");
        let result = conn.execute(
            "INSERT INTO spent_tokens (token_hash) VALUES (?1)",
            [hash.0.as_slice()],
        );
        match result {
            Ok(_) => SpendResult::Accepted,
            Err(rusqlite::Error::SqliteFailure(err, _))
                if err.code == rusqlite::ErrorCode::ConstraintViolation =>
            {
                SpendResult::AlreadySpent
            }
            Err(e) => panic!("spent-token ledger db error: {e}"),
        }
    }
}
