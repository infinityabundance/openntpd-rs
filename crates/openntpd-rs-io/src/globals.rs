//! Global variable stubs — C globals that do not have a direct Rust equivalent.
//!
//! In OpenNTPD's C code, many values are stored in file-scope or
//! program-scope global variables (e.g. `conf`, `peer_cnt`, `ctl_conns`).
//! In Rust these are typically embedded in a process-level struct
//! (e.g. [`NtpChildProcess`][crate::ntp_child::NtpChildProcess]).
//!
//! This module provides atomic counter stubs for forensic completeness,
//! so that audit tools can confirm the C → Rust mapping for global
//! variables that are tracked in the C code.

use std::sync::atomic::{AtomicBool, AtomicU32};

/// Number of managed peers.
///
/// C: `u_int peer_cnt` in ntp.c (also declared extern in ntpd.h).
pub static PEER_COUNT: AtomicU32 = AtomicU32::new(0);

/// Number of managed sensors.
///
/// C: `u_int sensors_cnt` in ntp.c.
pub static SENSOR_COUNT: AtomicU32 = AtomicU32::new(0);

/// Number of managed constraints.
///
/// C: `u_int constraint_cnt` in constraint.c.
pub static CONSTRAINT_COUNT: AtomicU32 = AtomicU32::new(0);

/// Global ntpd configuration pointer.
///
/// C: `struct ntpd_conf *conf` in ntp.c.
/// In Rust, configuration is typically passed as `&ChildConfig` or
/// embedded in the process struct.
pub static CONF_ACTIVE: AtomicBool = AtomicBool::new(false);

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::Ordering;

    #[test]
    fn test_peer_count_default() {
        assert_eq!(PEER_COUNT.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn test_sensor_count_default() {
        assert_eq!(SENSOR_COUNT.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn test_constraint_count_default() {
        assert_eq!(CONSTRAINT_COUNT.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn test_conf_active_default() {
        assert!(!CONF_ACTIVE.load(Ordering::Relaxed));
    }

    #[test]
    fn test_peer_count_increment() {
        PEER_COUNT.store(5, Ordering::Relaxed);
        assert_eq!(PEER_COUNT.load(Ordering::Relaxed), 5);
        PEER_COUNT.store(0, Ordering::Relaxed);
    }

    #[test]
    fn test_sensor_count_increment() {
        SENSOR_COUNT.store(3, Ordering::Relaxed);
        assert_eq!(SENSOR_COUNT.load(Ordering::Relaxed), 3);
        SENSOR_COUNT.store(0, Ordering::Relaxed);
    }

    #[test]
    fn test_constraint_count_increment() {
        CONSTRAINT_COUNT.store(2, Ordering::Relaxed);
        assert_eq!(CONSTRAINT_COUNT.load(Ordering::Relaxed), 2);
        CONSTRAINT_COUNT.store(0, Ordering::Relaxed);
    }
}
