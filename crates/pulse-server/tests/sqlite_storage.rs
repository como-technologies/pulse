use std::sync::Arc;

use pulse_protocol::{EncryptedBlob, QuestionBatchId, UnixTimestamp};
use pulse_signal::{ResponseStore, SpendResult, SpentTokenLedger, StoredResponse};

use pulse_server::sqlite_ledger::SqliteLedger;
use pulse_server::sqlite_store::SqliteStore;

fn test_hash(byte: u8) -> pulse_signal::TokenHash {
    pulse_signal::TokenHash([byte; 32])
}

// ── SqliteLedger ────────────────────────────────────────────

#[test]
fn sqlite_ledger_accepts_first_spend() {
    let dir = tempfile::tempdir().unwrap();
    let ledger = SqliteLedger::open(&dir.path().join("test.db")).unwrap();

    assert_eq!(ledger.check_and_spend(test_hash(1)), SpendResult::Accepted);
}

#[test]
fn sqlite_ledger_rejects_duplicate() {
    let dir = tempfile::tempdir().unwrap();
    let ledger = SqliteLedger::open(&dir.path().join("test.db")).unwrap();

    assert_eq!(ledger.check_and_spend(test_hash(1)), SpendResult::Accepted);
    assert_eq!(
        ledger.check_and_spend(test_hash(1)),
        SpendResult::AlreadySpent
    );
}

#[test]
fn sqlite_ledger_tracks_distinct_hashes() {
    let dir = tempfile::tempdir().unwrap();
    let ledger = SqliteLedger::open(&dir.path().join("test.db")).unwrap();

    assert_eq!(ledger.check_and_spend(test_hash(1)), SpendResult::Accepted);
    assert_eq!(ledger.check_and_spend(test_hash(2)), SpendResult::Accepted);
    assert_eq!(
        ledger.check_and_spend(test_hash(1)),
        SpendResult::AlreadySpent
    );
}

// ── SqliteStore ─────────────────────────────────────────────

fn make_response(blob: &[u8]) -> StoredResponse {
    StoredResponse {
        encrypted_blob: EncryptedBlob(blob.to_vec()),
        question_batch_id: QuestionBatchId::from_uuid(uuid::Uuid::new_v4()),
        received_at: UnixTimestamp(1_700_000_000),
    }
}

#[test]
fn sqlite_store_round_trips_responses() {
    let dir = tempfile::tempdir().unwrap();
    let store = SqliteStore::open(&dir.path().join("test.db")).unwrap();

    let resp = make_response(b"encrypted-data");
    let batch_id = resp.question_batch_id;
    store.store(resp);

    let stored = store.list();
    assert_eq!(stored.len(), 1);
    assert_eq!(stored[0].encrypted_blob.0, b"encrypted-data");
    assert_eq!(stored[0].question_batch_id, batch_id);
    assert_eq!(stored[0].received_at.0, 1_700_000_000);
}

#[test]
fn sqlite_store_count() {
    let dir = tempfile::tempdir().unwrap();
    let store = SqliteStore::open(&dir.path().join("test.db")).unwrap();

    assert_eq!(store.count(), 0);
    store.store(make_response(b"a"));
    assert_eq!(store.count(), 1);
    store.store(make_response(b"b"));
    assert_eq!(store.count(), 2);
}

// ── Persistence across reopens ──────────────────────────────

#[test]
fn sqlite_ledger_survives_reopen() {
    let dir = tempfile::tempdir().unwrap();
    let db_path = dir.path().join("test.db");

    {
        let ledger = SqliteLedger::open(&db_path).unwrap();
        assert_eq!(ledger.check_and_spend(test_hash(1)), SpendResult::Accepted);
    }
    // Ledger dropped, connection closed

    {
        let ledger = SqliteLedger::open(&db_path).unwrap();
        assert_eq!(
            ledger.check_and_spend(test_hash(1)),
            SpendResult::AlreadySpent,
            "token should still be spent after reopen"
        );
        // New tokens still work
        assert_eq!(ledger.check_and_spend(test_hash(2)), SpendResult::Accepted);
    }
}

#[test]
fn sqlite_store_survives_reopen() {
    let dir = tempfile::tempdir().unwrap();
    let db_path = dir.path().join("test.db");
    let batch_id = QuestionBatchId::from_uuid(uuid::Uuid::new_v4());

    {
        let store = SqliteStore::open(&db_path).unwrap();
        store.store(StoredResponse {
            encrypted_blob: EncryptedBlob(b"persisted-data".to_vec()),
            question_batch_id: batch_id,
            received_at: UnixTimestamp(1_700_000_000),
        });
        assert_eq!(store.count(), 1);
    }
    // Store dropped, connection closed

    {
        let store = SqliteStore::open(&db_path).unwrap();
        assert_eq!(store.count(), 1, "count should persist after reopen");
        let stored = store.list();
        assert_eq!(stored[0].encrypted_blob.0, b"persisted-data");
        assert_eq!(stored[0].question_batch_id, batch_id);
    }
}

// ── Shared database file ────────────────────────────────────

#[test]
fn sqlite_ledger_and_store_share_database_file() {
    let dir = tempfile::tempdir().unwrap();
    let db_path = dir.path().join("shared.db");

    let ledger = SqliteLedger::open(&db_path).unwrap();
    let store = SqliteStore::open(&db_path).unwrap();

    assert_eq!(ledger.check_and_spend(test_hash(1)), SpendResult::Accepted);
    store.store(make_response(b"test"));

    assert_eq!(
        ledger.check_and_spend(test_hash(1)),
        SpendResult::AlreadySpent
    );
    assert_eq!(store.count(), 1);
}

// ── Trait object compatibility ──────────────────────────────

#[test]
fn sqlite_impls_work_as_trait_objects() {
    let dir = tempfile::tempdir().unwrap();
    let db_path = dir.path().join("trait.db");

    let ledger: Arc<dyn SpentTokenLedger> = Arc::new(SqliteLedger::open(&db_path).unwrap());
    let store: Arc<dyn pulse_signal::ResponseStore> =
        Arc::new(SqliteStore::open(&db_path).unwrap());

    assert_eq!(ledger.check_and_spend(test_hash(1)), SpendResult::Accepted);
    store.store(make_response(b"via-trait"));
    assert_eq!(store.count(), 1);
}
