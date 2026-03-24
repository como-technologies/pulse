use crate::{EpochId, UnixTimestamp};

/// Default epoch duration: 90 days in seconds (quarterly).
pub const DEFAULT_EPOCH_DURATION_SECS: u64 = 90 * 24 * 60 * 60;

/// Epoch duration configuration for pseudonym rotation.
///
/// Pseudonyms are scoped to epochs — the same employee secret produces different
/// pseudonyms in different epochs, bounding the longitudinal correlation window.
#[derive(Debug, Clone, Copy)]
pub struct EpochConfig {
    /// Duration of each epoch in seconds.
    pub duration_secs: u64,
}

impl Default for EpochConfig {
    fn default() -> Self {
        Self {
            duration_secs: DEFAULT_EPOCH_DURATION_SECS,
        }
    }
}

impl EpochConfig {
    /// Compute the epoch ID for a given timestamp.
    pub fn epoch_at(&self, timestamp: &UnixTimestamp) -> EpochId {
        let epoch_number = timestamp.0 / self.duration_secs;
        EpochId(format!("epoch-{epoch_number}"))
    }

    /// Compute the epoch ID for the current time.
    pub fn current_epoch(&self) -> EpochId {
        self.epoch_at(&UnixTimestamp::now())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn epoch_at_default_config() {
        let config = EpochConfig::default();
        // Epoch 0: timestamps 0..7_776_000
        assert_eq!(
            config.epoch_at(&UnixTimestamp(0)),
            EpochId("epoch-0".into())
        );
        assert_eq!(
            config.epoch_at(&UnixTimestamp(7_775_999)),
            EpochId("epoch-0".into())
        );
        // Epoch 1: timestamps 7_776_000..15_552_000
        assert_eq!(
            config.epoch_at(&UnixTimestamp(7_776_000)),
            EpochId("epoch-1".into())
        );
    }

    #[test]
    fn epoch_at_custom_duration() {
        let config = EpochConfig {
            duration_secs: 3600, // 1 hour
        };
        assert_eq!(
            config.epoch_at(&UnixTimestamp(0)),
            EpochId("epoch-0".into())
        );
        assert_eq!(
            config.epoch_at(&UnixTimestamp(3600)),
            EpochId("epoch-1".into())
        );
        assert_eq!(
            config.epoch_at(&UnixTimestamp(7200)),
            EpochId("epoch-2".into())
        );
    }

    #[test]
    fn same_timestamp_same_epoch() {
        let config = EpochConfig::default();
        let ts = UnixTimestamp(1_000_000);
        assert_eq!(config.epoch_at(&ts), config.epoch_at(&ts));
    }

    #[test]
    fn current_epoch_returns_valid_id() {
        let config = EpochConfig::default();
        let epoch = config.current_epoch();
        assert!(epoch.0.starts_with("epoch-"));
    }
}
