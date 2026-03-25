use sha2::{Digest, Sha256};
use std::collections::HashSet;
use std::sync::Mutex;

/// Hash of a spent token — the only thing stored in the ledger.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct TokenHash(pub [u8; 32]);

impl TokenHash {
    /// Compute the hash of a serialized token payload.
    pub fn from_token_bytes(token_bytes: &[u8]) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(token_bytes);
        let result = hasher.finalize();
        TokenHash(result.into())
    }
}

// ANCHOR: spend_result
/// Result of attempting to spend a token.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SpendResult {
    /// Token was accepted and recorded as spent.
    Accepted,
    /// Token was already spent (duplicate submission).
    AlreadySpent,
}
// ANCHOR_END: spend_result

// ANCHOR: spent_token_ledger
/// Append-only spent-token ledger for replay prevention.
///
/// Tracks which token hashes have been spent. Once a token is spent, it can
/// never be un-spent — there is no delete or unspend operation.
///
/// [`TokenHash`] is a `[u8; 32]` SHA-256 hash of the serialized token.
/// Store it as raw bytes.
///
/// # Implementor requirements
///
/// - [`check_and_spend`](Self::check_and_spend) must be **atomic**: two
///   concurrent requests with the same hash must not both return
///   [`SpendResult::Accepted`]. Use database-level uniqueness constraints
///   or mutex locks.
/// - Database errors are catastrophic — use `.expect("...")` to crash the
///   process. A silent failure during check-and-spend could allow
///   double-voting.
pub trait SpentTokenLedger: Send + Sync {
    /// Atomically check if `hash` is already spent; if not, mark it as spent.
    ///
    /// Returns [`SpendResult::Accepted`] on first use and
    /// [`SpendResult::AlreadySpent`] on duplicates. The check and recording
    /// must happen in a single atomic operation to prevent concurrent
    /// double-acceptance.
    fn check_and_spend(&self, hash: TokenHash) -> SpendResult;
}
// ANCHOR_END: spent_token_ledger

/// In-memory implementation of the spent-token ledger for development and testing.
pub struct InMemoryLedger {
    spent: Mutex<HashSet<TokenHash>>,
}

impl InMemoryLedger {
    pub fn new() -> Self {
        Self {
            spent: Mutex::new(HashSet::new()),
        }
    }
}

impl Default for InMemoryLedger {
    fn default() -> Self {
        Self::new()
    }
}

impl SpentTokenLedger for InMemoryLedger {
    fn check_and_spend(&self, hash: TokenHash) -> SpendResult {
        let mut spent = self.spent.lock().expect("ledger lock poisoned");
        if spent.insert(hash) {
            SpendResult::Accepted
        } else {
            SpendResult::AlreadySpent
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn first_spend_accepted() {
        let ledger = InMemoryLedger::new();
        let hash = TokenHash::from_token_bytes(b"token-1");
        assert_eq!(ledger.check_and_spend(hash), SpendResult::Accepted);
    }

    #[test]
    fn duplicate_spend_rejected() {
        let ledger = InMemoryLedger::new();
        let hash1 = TokenHash::from_token_bytes(b"token-1");
        let hash2 = TokenHash::from_token_bytes(b"token-1");
        assert_eq!(ledger.check_and_spend(hash1), SpendResult::Accepted);
        assert_eq!(ledger.check_and_spend(hash2), SpendResult::AlreadySpent);
    }

    #[test]
    fn different_tokens_both_accepted() {
        let ledger = InMemoryLedger::new();
        let hash1 = TokenHash::from_token_bytes(b"token-1");
        let hash2 = TokenHash::from_token_bytes(b"token-2");
        assert_eq!(ledger.check_and_spend(hash1), SpendResult::Accepted);
        assert_eq!(ledger.check_and_spend(hash2), SpendResult::Accepted);
    }
}
