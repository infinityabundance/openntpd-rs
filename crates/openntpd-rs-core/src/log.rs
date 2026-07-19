use alloc::string::String;
use core::sync::atomic::{AtomicU8, Ordering};

/// Log severity levels, ordered from most to least severe.
///
/// The discriminant values match OpenNTPD's convention so that a simple
/// integer comparison `level <= threshold` selects messages to emit.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum LogLevel {
    Error = 0,
    Warn = 1,
    Info = 2,
    Debug = 3,
    Debug2 = 4,
    Debug3 = 5,
}

/// A structured log event.
#[derive(Debug, Clone)]
pub struct LogMessage {
    pub level: LogLevel,
    pub message: String,
    /// Unix timestamp (seconds since epoch) when the message was generated.
    pub timestamp: u64,
}

/// Global threshold: only messages whose `LogLevel` discriminant is **at or
/// below** this value will be emitted.  Initialised to `Info`.
static LOG_THRESHOLD: AtomicU8 = AtomicU8::new(LogLevel::Info as u8);

/// Set a new global log threshold.
pub fn set_log_threshold(level: LogLevel) {
    LOG_THRESHOLD.store(level as u8, Ordering::Relaxed);
}

/// Return the current global log threshold.
pub fn get_log_threshold() -> LogLevel {
    match LOG_THRESHOLD.load(Ordering::Relaxed) {
        0 => LogLevel::Error,
        1 => LogLevel::Warn,
        2 => LogLevel::Info,
        3 => LogLevel::Debug,
        4 => LogLevel::Debug2,
        5 => LogLevel::Debug3,
        // Safety: we only ever store valid `LogLevel` discriminants.
        _ => LogLevel::Info,
    }
}

/// Adjtime threshold from OpenNTPD: 32 ms expressed in microseconds.
///
/// Adjustments whose absolute value is at or above this threshold are
/// considered large enough to warrant logging.
pub const ADJTIME_THRESHOLD_US: i64 = 32000;

/// Returns `true` when the given adjustment (in microseconds) is large enough
/// to be logged — i.e., its absolute value is at or above
/// [`ADJTIME_THRESHOLD_US`].
///
/// Tiny adjustments below the threshold are suppressed to avoid log noise.
pub fn should_log_adjtime(adjustment_us: i64) -> bool {
    adjustment_us.unsigned_abs() >= ADJTIME_THRESHOLD_US as u64
}

#[cfg(test)]
mod tests {
    use super::*;

    // ------------------------------------------------------------------
    // LogLevel ordering
    // ------------------------------------------------------------------

    #[test]
    fn test_log_level_discriminants() {
        assert_eq!(LogLevel::Error as u8, 0);
        assert_eq!(LogLevel::Warn as u8, 1);
        assert_eq!(LogLevel::Info as u8, 2);
        assert_eq!(LogLevel::Debug as u8, 3);
        assert_eq!(LogLevel::Debug2 as u8, 4);
        assert_eq!(LogLevel::Debug3 as u8, 5);
    }

    #[test]
    fn test_log_level_ordering() {
        assert!(LogLevel::Error < LogLevel::Warn);
        assert!(LogLevel::Warn < LogLevel::Info);
        assert!(LogLevel::Info < LogLevel::Debug);
        assert!(LogLevel::Debug < LogLevel::Debug2);
        assert!(LogLevel::Debug2 < LogLevel::Debug3);
    }

    #[test]
    fn test_log_level_partial_eq() {
        assert_eq!(LogLevel::Error, LogLevel::Error);
        assert_ne!(LogLevel::Error, LogLevel::Info);
    }

    // ------------------------------------------------------------------
    // Threshold filtering
    // ------------------------------------------------------------------

    #[test]
    fn test_default_threshold_is_info() {
        assert_eq!(get_log_threshold(), LogLevel::Info);
    }

    #[test]
    fn test_set_and_get_threshold() {
        set_log_threshold(LogLevel::Debug);
        assert_eq!(get_log_threshold(), LogLevel::Debug);

        // Restore for other tests
        set_log_threshold(LogLevel::Info);
        assert_eq!(get_log_threshold(), LogLevel::Info);
    }

    #[test]
    fn test_set_every_level() {
        for level in &[
            LogLevel::Error,
            LogLevel::Warn,
            LogLevel::Info,
            LogLevel::Debug,
            LogLevel::Debug2,
            LogLevel::Debug3,
        ] {
            set_log_threshold(*level);
            assert_eq!(get_log_threshold(), *level);
        }
        set_log_threshold(LogLevel::Info);
    }

    /// Messages at levels *at or below* the threshold should be emitted.
    #[test]
    fn test_threshold_inclusive() {
        set_log_threshold(LogLevel::Warn);
        // Error (0) ≤ Warn (1) → logged
        assert!(LogLevel::Error <= get_log_threshold());
        // Warn (1) ≤ Warn (1) → logged
        assert!(LogLevel::Warn <= get_log_threshold());
        // Info (2) > Warn (1) → NOT logged
        assert!(LogLevel::Info > get_log_threshold());

        set_log_threshold(LogLevel::Info);
    }

    // ------------------------------------------------------------------
    // Adjtime threshold
    // ------------------------------------------------------------------

    #[test]
    fn test_adjtime_threshold_constant() {
        assert_eq!(ADJTIME_THRESHOLD_US, 32000);
    }

    #[test]
    fn test_should_log_adjtime_at_threshold() {
        // Exactly at threshold → should log
        assert!(should_log_adjtime(32000));
        assert!(should_log_adjtime(-32000));
    }

    #[test]
    fn test_should_log_adjtime_above_threshold() {
        assert!(should_log_adjtime(32001));
        assert!(should_log_adjtime(-32001));
        assert!(should_log_adjtime(i64::MAX));
        assert!(should_log_adjtime(i64::MIN));
    }

    #[test]
    fn test_should_not_log_adjtime_below_threshold() {
        assert!(!should_log_adjtime(0));
        assert!(!should_log_adjtime(1));
        assert!(!should_log_adjtime(31999));
        assert!(!should_log_adjtime(-1));
        assert!(!should_log_adjtime(-31999));
    }

    #[test]
    fn test_should_log_adjtime_positive_and_negative_consistency() {
        // Symmetric behaviour for positive and negative values
        for val in &[0i64, 1, 31999, 32000, 32001, 100000] {
            assert_eq!(
                should_log_adjtime(*val),
                should_log_adjtime(-*val),
                "mismatch for val={}",
                val
            );
        }
    }
}
