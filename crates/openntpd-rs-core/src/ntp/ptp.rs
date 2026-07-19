//! PTP (IEEE 1588) hardware timestamping types and abstractions.
//!
//! Provides no_std-friendly types for representing PTP hardware clocks,
//! timestamps, and clock identities.  These types are used by the
//! I/O layer (`openntpd_rs_io::ptp_io`) for enabling hardware
//! timestamping on NICs and interacting with
//! PTP hardware clock (PHC) devices under `/dev/ptp*`.
//!
//! ## Hardware timestamping modes
//!
//! Hardware timestamping allows NICs to timestamp NTP packets at the
//! physical layer, providing sub-microsecond accuracy that is essential
//! for precision time synchronization.
//!
//! ## References
//!
//! - IEEE 1588-2008 (PTPv2)
//! - Linux `SOF_TIMESTAMPING` socket option
//! - Linux PTP hardware clock API (`/dev/ptp*`, `PTP_SYS_OFFSET`)

use core::fmt;

// ---------------------------------------------------------------------------
// Hardware timestamp mode
// ---------------------------------------------------------------------------

/// Hardware timestamping capability modes for NTP packets.
///
/// This enum represents the range of timestamping methods, from no
/// hardware support through full PTP hardware clock integration.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HwTimestampMode {
    /// No hardware timestamping — software-only timestamps.
    None,
    /// Software timestamping via `SO_TIMESTAMP` / `SO_TIMESTAMPNS`.
    Software,
    /// Hardware timestamping via `SOF_TIMESTAMPING` (Linux).
    Hardware,
    /// PTP hardware clock via `PTP_SYS_OFFSET` ioctl.
    PtpHardwareClock,
}

// ---------------------------------------------------------------------------
// Hardware timestamp
// ---------------------------------------------------------------------------

/// A timestamp obtained from network hardware (NIC PHC or software
/// fallback).
///
/// Carries the seconds/nanoseconds pair together with a source
/// identifier so that multi-port NICs or multi-clock systems can
/// distinguish which clock produced the timestamp.
#[derive(Debug, Clone)]
pub struct HwTimestamp {
    /// Seconds since Unix epoch.
    pub sec: u64,
    /// Nanoseconds within the second (0 .. 999_999_999).
    pub nsec: u32,
    /// Source identifier — typically the PHC index or port number.
    pub source: u16,
}

// ---------------------------------------------------------------------------
// PTP clock identity
// ---------------------------------------------------------------------------

/// A PTP clock identity as defined by IEEE 1588-2008 §7.5.2.2.
///
/// The clock identity is an 8-byte (EUI-64) value derived from the
/// 6-byte MAC address of the clock's port by inserting `0xFF` and
/// `0xFE` between the first three and last three bytes of the MAC.
///
/// # Example
///
/// MAC `00:1b:21:5c:6d:88` produces the identity `00:1b:21:ff:fe:5c:6d:88`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct PtpClockIdentity(pub [u8; 8]);

impl PtpClockIdentity {
    /// Construct a PTP clock identity from a 6-byte MAC address.
    ///
    /// Inserts `0xFF, 0xFE` between bytes 3 and 4 of the MAC per
    /// IEEE 1588-2008 §7.5.2.2.
    #[must_use]
    pub fn from_mac(mac: &[u8; 6]) -> Self {
        Self([mac[0], mac[1], mac[2], 0xFF, 0xFE, mac[3], mac[4], mac[5]])
    }

    /// Return the raw 8-byte clock identity.
    #[must_use]
    pub fn to_bytes(&self) -> [u8; 8] {
        self.0
    }
}

impl fmt::LowerHex for PtpClockIdentity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for (i, byte) in self.0.iter().enumerate() {
            if i > 0 {
                f.write_str(":")?;
            }
            write!(f, "{byte:02x}")?;
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// PTP timestamp
// ---------------------------------------------------------------------------

/// A raw timestamp read directly from a PTP hardware clock (PHC) device.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct PtpTimestamp {
    /// Seconds since Unix epoch (or PTP epoch, depending on clock base).
    pub seconds: u64,
    /// Nanoseconds within the second (0 .. 999_999_999).
    pub nanoseconds: u32,
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::format;

    #[test]
    fn test_ptp_clock_identity_from_mac() {
        let mac = [0x00, 0x1b, 0x21, 0x5c, 0x6d, 0x88];
        let id = PtpClockIdentity::from_mac(&mac);
        assert_eq!(
            id.to_bytes(),
            [0x00, 0x1b, 0x21, 0xff, 0xfe, 0x5c, 0x6d, 0x88]
        );
    }

    #[test]
    fn test_ptp_clock_identity_zero_mac() {
        let mac = [0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
        let id = PtpClockIdentity::from_mac(&mac);
        assert_eq!(
            id.to_bytes(),
            [0x00, 0x00, 0x00, 0xff, 0xfe, 0x00, 0x00, 0x00]
        );
    }

    #[test]
    fn test_ptp_clock_identity_all_ones_mac() {
        let mac = [0xff, 0xff, 0xff, 0xff, 0xff, 0xff];
        let id = PtpClockIdentity::from_mac(&mac);
        assert_eq!(
            id.to_bytes(),
            [0xff, 0xff, 0xff, 0xff, 0xfe, 0xff, 0xff, 0xff]
        );
    }

    #[test]
    fn test_ptp_clock_identity_display_hex() {
        let mac = [0x00, 0x1b, 0x21, 0x5c, 0x6d, 0x88];
        let id = PtpClockIdentity::from_mac(&mac);
        let hex = format!("{id:x}");
        assert_eq!(hex, "00:1b:21:ff:fe:5c:6d:88");
    }

    #[test]
    fn test_ptp_clock_identity_to_bytes_roundtrip() {
        let expected = [0x00, 0x1b, 0x21, 0xff, 0xfe, 0x5c, 0x6d, 0x88];
        let id = PtpClockIdentity(expected);
        assert_eq!(id.to_bytes(), expected);
    }

    #[test]
    fn test_hw_timestamp_creation() {
        let ts = HwTimestamp {
            sec: 1_700_000_000,
            nsec: 123_456_789,
            source: 0,
        };
        assert_eq!(ts.sec, 1_700_000_000);
        assert_eq!(ts.nsec, 123_456_789);
        assert_eq!(ts.source, 0);
    }

    #[test]
    fn test_hw_timestamp_source_field() {
        let ts0 = HwTimestamp {
            sec: 100,
            nsec: 0,
            source: 0,
        };
        let ts1 = HwTimestamp {
            sec: 100,
            nsec: 0,
            source: 1,
        };
        assert_ne!(ts0.source, ts1.source);
    }

    #[test]
    fn test_ptp_timestamp_creation() {
        let ts = PtpTimestamp {
            seconds: 1_700_000_000,
            nanoseconds: 999_999_999,
        };
        assert_eq!(ts.seconds, 1_700_000_000);
        assert_eq!(ts.nanoseconds, 999_999_999);
    }

    #[test]
    fn test_hw_timestamp_mode_variants_distinct() {
        assert_ne!(HwTimestampMode::None, HwTimestampMode::Software);
        assert_ne!(HwTimestampMode::None, HwTimestampMode::Hardware);
        assert_ne!(HwTimestampMode::None, HwTimestampMode::PtpHardwareClock);
        assert_ne!(HwTimestampMode::Software, HwTimestampMode::Hardware);
        assert_ne!(HwTimestampMode::Software, HwTimestampMode::PtpHardwareClock);
        assert_ne!(HwTimestampMode::Hardware, HwTimestampMode::PtpHardwareClock);
    }

    #[test]
    fn test_ptp_timestamp_clone() {
        let ts = PtpTimestamp {
            seconds: 42,
            nanoseconds: 100,
        };
        let cloned = ts;
        assert_eq!(ts, cloned);
    }
}
