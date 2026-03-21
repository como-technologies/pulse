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

/// Result of attempting to spend a token.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SpendResult {
    /// Token was accepted and recorded as spent.
    Accepted,
    /// Token was already spent (duplicate submission).
    AlreadySpent,
}

/// Append-only spent-token ledger.
/// Tracks which tokens have been used to prevent replay/duplicate submission.
pub trait SpentTokenLedger: Send + Sync {
    /// Atomically check if a token hash is already spent, and if not, mark it as spent.
    fn check_and_spend(&self, hash: TokenHash) -> SpendResult;
}

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
