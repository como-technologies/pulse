use std::path::Path;
use std::sync::Mutex;

use pulse_protocol::{EncryptedBlob, QuestionBatchId, TenantId, UnixTimestamp};
use pulse_signal::{ResponseStore, StoredResponse};
use rusqlite::Connection;

/// SQLite-backed encrypted response store.
///
/// Responses are stored as rows in a `responses` table. The encrypted blob is
/// opaque — the Signal zone never decrypts it.
pub struct SqliteStore {
    conn: Mutex<Connection>,
}

impl SqliteStore {
    /// Open (or create) a SQLite database at `path` and initialize the schema.
    pub fn open(path: &Path) -> Result<Self, rusqlite::Error> {
        let conn = Connection::open(path)?;
        conn.execute_batch(
            "\
            PRAGMA journal_mode = WAL;\
            PRAGMA synchronous = NORMAL;\
            PRAGMA foreign_keys = ON;\
            CREATE TABLE IF NOT EXISTS responses (\
                id INTEGER PRIMARY KEY AUTOINCREMENT,\
                encrypted_blob BLOB NOT NULL,\
                question_batch_id TEXT NOT NULL,\
                tenant_id TEXT NOT NULL,\
                received_at INTEGER NOT NULL\
            ) STRICT;",
        )?;
        Ok(Self {
            conn: Mutex::new(conn),
        })
    }
}

impl ResponseStore for SqliteStore {
    fn list_by_batch(
        &self,
        question_batch_id: &QuestionBatchId,
        tenant_id: &TenantId,
    ) -> Vec<StoredResponse> {
        let conn = self.conn.lock().expect("store db lock poisoned");
        let mut stmt = conn
            .prepare(
                "SELECT encrypted_blob, question_batch_id, tenant_id, received_at \
                 FROM responses WHERE question_batch_id = ?1 AND tenant_id = ?2 ORDER BY id",
            )
            .expect("response store db error");
        stmt.query_map(
            rusqlite::params![question_batch_id.0.to_string(), tenant_id.0.to_string(),],
            |row| {
                let blob: Vec<u8> = row.get(0)?;
                let batch_id_str: String = row.get(1)?;
                let tenant_id_str: String = row.get(2)?;
                let received_at: u64 = row.get(3)?;
                Ok(StoredResponse {
                    encrypted_blob: EncryptedBlob(blob),
                    question_batch_id: QuestionBatchId::from_uuid(
                        uuid::Uuid::parse_str(&batch_id_str)
                            .expect("invalid UUID in responses table"),
                    ),
                    tenant_id: TenantId::from_uuid(
                        uuid::Uuid::parse_str(&tenant_id_str)
                            .expect("invalid UUID in responses table"),
                    ),
                    received_at: UnixTimestamp(received_at),
                })
            },
        )
        .expect("response store db error")
        .collect::<Result<Vec<_>, _>>()
        .expect("response store db error")
    }

    fn store(&self, response: StoredResponse) {
        let conn = self.conn.lock().expect("store db lock poisoned");
        conn.execute(
            "INSERT INTO responses (encrypted_blob, question_batch_id, tenant_id, received_at) VALUES (?1, ?2, ?3, ?4)",
            rusqlite::params![
                response.encrypted_blob.0,
                response.question_batch_id.0.to_string(),
                response.tenant_id.0.to_string(),
                response.received_at.0,
            ],
        )
        .expect("response store db error");
    }

    fn count(&self) -> usize {
        let conn = self.conn.lock().expect("store db lock poisoned");
        conn.query_row("SELECT COUNT(*) FROM responses", [], |row| {
            row.get::<_, i64>(0)
        })
        .expect("response store db error") as usize
    }

    fn list(&self) -> Vec<StoredResponse> {
        let conn = self.conn.lock().expect("store db lock poisoned");
        let mut stmt = conn
            .prepare(
                "SELECT encrypted_blob, question_batch_id, tenant_id, received_at FROM responses ORDER BY id",
            )
            .expect("response store db error");
        stmt.query_map([], |row| {
            let blob: Vec<u8> = row.get(0)?;
            let batch_id_str: String = row.get(1)?;
            let tenant_id_str: String = row.get(2)?;
            let received_at: u64 = row.get(3)?;
            Ok(StoredResponse {
                encrypted_blob: EncryptedBlob(blob),
                question_batch_id: QuestionBatchId::from_uuid(
                    uuid::Uuid::parse_str(&batch_id_str).expect("invalid UUID in responses table"),
                ),
                tenant_id: TenantId::from_uuid(
                    uuid::Uuid::parse_str(&tenant_id_str).expect("invalid UUID in responses table"),
                ),
                received_at: UnixTimestamp(received_at),
            })
        })
        .expect("response store db error")
        .collect::<Result<Vec<_>, _>>()
        .expect("response store db error")
    }
}
