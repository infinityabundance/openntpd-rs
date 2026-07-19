//! Reference clock driver framework — local time sources.
//!
//! Reference clocks are local time sources such as GPS receivers,
//! IRIG time-code readers, PPS (Pulse Per Second) devices, and
//! PTP hardware clocks.  This module provides the type definitions
//! and abstractions for representing reference clock drivers in a
//! no_std environment.
//!
//! The framework corresponds roughly to OpenNTPD's `refclock.h` and
//! provides:
//!
//! - [`RefClockType`] — driver type enumeration
//! - [`RefClockId`] — 4-byte NTP reference identifier
//! - Well-known reference identifiers ([`ids`])
//! - [`RefClock`] — a configured reference clock driver instance
//!
//! ## NTP Reference Identifiers
//!
//! In the NTP protocol, the reference identifier field (`refid`) of
//! an NTP packet identifies the source of time.  For reference clocks
//! (stratum 1 servers), the refid is a 4-byte ASCII code such as
//! `"GPS\0"`, `"PPS\0"`, or `"NMEA"`.

use alloc::string::String;
use core::fmt;

// ---------------------------------------------------------------------------
// Reference clock driver types
// ---------------------------------------------------------------------------

/// The type of a reference clock driver.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RefClockType {
    /// Pulse Per Second via GPIO or serial DCD line.
    Pps,
    /// NMEA 0183 GPS receiver (typically over serial).
    Nmea,
    /// IRIG time-code reader.
    Irig,
    /// PTP hardware clock (IEEE 1588).
    Ptp,
    /// A custom / application-specific driver.
    Other(&'static str),
}

// ---------------------------------------------------------------------------
// Reference clock identifier
// ---------------------------------------------------------------------------

/// A 4-byte NTP reference identifier, as used in the `refid` field of
/// NTP packets (RFC 5905 §7.3).
///
/// For stratum 1 servers, this is typically a 4-character ASCII code
/// identifying the reference source (e.g. `GPS\0`, `PPS\0`, `NMEA`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct RefClockId(pub [u8; 4]);

impl RefClockId {
    /// Create a new `RefClockId` from a string slice.
    ///
    /// The string must be exactly 4 bytes long.  Returns an error if
    /// the input is not exactly 4 bytes.
    ///
    /// # Errors
    ///
    /// Returns `Err` if `id.len() != 4`.
    pub fn new(id: &str) -> Result<Self, &'static str> {
        let bytes = id.as_bytes();
        if bytes.len() != 4 {
            return Err("RefClockId must be exactly 4 bytes");
        }
        let mut buf = [0u8; 4];
        buf.copy_from_slice(bytes);
        Ok(Self(buf))
    }

    /// Return a reference to the raw 4-byte array.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8; 4] {
        &self.0
    }

    /// Convert the 4-byte refid to a string (lossy — replaces non-ASCII
    /// bytes with the Unicode replacement character).
    #[must_use]
    pub fn to_string_lossy(&self) -> alloc::string::String {
        core::str::from_utf8(&self.0)
            .map(alloc::string::String::from)
            .unwrap_or_else(|_| {
                let mut s = alloc::string::String::with_capacity(4);
                for &b in &self.0 {
                    s.push(if b.is_ascii() {
                        char::from(b)
                    } else {
                        core::char::REPLACEMENT_CHARACTER
                    });
                }
                s
            })
    }
}

impl fmt::Display for RefClockId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for &b in &self.0 {
            if b.is_ascii_graphic() || b == b' ' {
                f.write_str(core::str::from_utf8(&[b]).unwrap())?;
            } else {
                write!(f, "\\x{b:02x}")?;
            }
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Well-known reference identifiers
// ---------------------------------------------------------------------------

/// Well-known NTP reference clock identifiers.
///
/// These constants match the identifiers used by ntpd and defined in
/// RFC 5905.
pub mod ids {
    use super::RefClockId;

    /// Global Positioning System.
    pub const GPS: RefClockId = RefClockId(*b"GPS\0");
    /// Pulse Per Second.
    pub const PPS: RefClockId = RefClockId(*b"PPS\0");
    /// NMEA GPS receiver.
    pub const NMEA: RefClockId = RefClockId(*b"NMEA");
    /// IRIG time code.
    pub const IRIG: RefClockId = RefClockId(*b"IRIG");
    /// PTP hardware clock (IEEE 1588).
    pub const PTP: RefClockId = RefClockId(*b"PTP\0");
    /// WWVB (US LF time broadcast).
    pub const WWVB: RefClockId = RefClockId(*b"WWVB");
    /// DCF77 (German LF time broadcast).
    pub const DCF: RefClockId = RefClockId(*b"DCF\0");
    /// CHU (Canadian HF time broadcast).
    pub const CHU: RefClockId = RefClockId(*b"CHU\0");
    /// MSF (UK LF time broadcast).
    pub const MSF: RefClockId = RefClockId(*b"MSF\0");
}

// ---------------------------------------------------------------------------
// Reference clock driver instance
// ---------------------------------------------------------------------------

/// A configured reference clock driver instance.
///
/// Represents a local hardware time source that has been discovered
/// and configured for use by the NTP daemon.
#[derive(Debug, Clone)]
pub struct RefClock {
    /// The driver type (PPS, NMEA, etc.).
    pub driver_type: RefClockType,
    /// The 4-byte NTP reference identifier.
    pub id: RefClockId,
    /// The device path (e.g. `/dev/pps0`, `/dev/ttyUSB0`).
    pub device: String,
    /// The NTP stratum level to advertise (typically 1 for ref clocks).
    pub stratum: u8,
    /// The precision in log₂ seconds (e.g. -20 for ~1 µs).
    pub precision: i8,
    /// Whether the clock has been configured by the user.
    pub is_configured: bool,
    /// The most recent clock offset, if available (seconds).
    pub last_offset: Option<f64>,
}

impl RefClock {
    /// Create a new reference clock driver instance with defaults.
    ///
    /// Stratum defaults to 1 (stratum 1 = directly attached ref clock),
    /// precision defaults to -20 (≈ 1 µs), and `is_configured` is set
    /// to `false` until the driver is explicitly configured.
    #[must_use]
    pub fn new(driver_type: RefClockType, device: &str) -> Self {
        let id = match driver_type {
            RefClockType::Pps => ids::PPS,
            RefClockType::Nmea => ids::NMEA,
            RefClockType::Irig => ids::IRIG,
            RefClockType::Ptp => ids::PTP,
            RefClockType::Other(_) => RefClockId(*b"LOCL"),
        };
        Self {
            driver_type,
            id,
            device: String::from(device),
            stratum: 1,
            precision: -20,
            is_configured: false,
            last_offset: None,
        }
    }

    /// Return the 4-byte reference identifier for this clock.
    #[must_use]
    pub fn refid(&self) -> [u8; 4] {
        self.id.0
    }

    /// Update the last measured clock offset.
    pub fn set_offset(&mut self, offset: f64) {
        self.last_offset = Some(offset);
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use alloc::format;
    use super::*;

    // ── RefClockId ────────────────────────────────────────────────────

    #[test]
    fn test_refclock_id_new_valid() {
        let id = RefClockId::new("GPS\0").unwrap();
        assert_eq!(id.as_bytes(), b"GPS\0");
    }

    #[test]
    fn test_refclock_id_new_valid_nmea() {
        let id = RefClockId::new("NMEA").unwrap();
        assert_eq!(id.as_bytes(), b"NMEA");
    }

    #[test]
    fn test_refclock_id_new_too_short() {
        assert!(RefClockId::new("GPS").is_err());
    }

    #[test]
    fn test_refclock_id_new_too_long() {
        assert!(RefClockId::new("WWVBX").is_err());
    }

    #[test]
    fn test_refclock_id_new_empty() {
        assert!(RefClockId::new("").is_err());
    }

    #[test]
    fn test_refclock_id_display() {
        assert_eq!(format!("{}", ids::GPS), "GPS\\x00");
        assert_eq!(format!("{}", ids::NMEA), "NMEA");
    }

    #[test]
    fn test_refclock_id_to_string_lossy_ascii() {
        let id = ids::NMEA;
        assert_eq!(id.to_string_lossy(), "NMEA");
    }

    // ── Well-known IDs ────────────────────────────────────────────────

    #[test]
    fn test_well_known_gps() {
        assert_eq!(ids::GPS.as_bytes(), b"GPS\0");
    }

    #[test]
    fn test_well_known_pps() {
        assert_eq!(ids::PPS.as_bytes(), b"PPS\0");
    }

    #[test]
    fn test_well_known_nmea() {
        assert_eq!(ids::NMEA.as_bytes(), b"NMEA");
    }

    #[test]
    fn test_well_known_irig() {
        assert_eq!(ids::IRIG.as_bytes(), b"IRIG");
    }

    #[test]
    fn test_well_known_ptp() {
        assert_eq!(ids::PTP.as_bytes(), b"PTP\0");
    }

    #[test]
    fn test_well_known_wwvb() {
        assert_eq!(ids::WWVB.as_bytes(), b"WWVB");
    }

    #[test]
    fn test_well_known_dcf() {
        assert_eq!(ids::DCF.as_bytes(), b"DCF\0");
    }

    #[test]
    fn test_well_known_chu() {
        assert_eq!(ids::CHU.as_bytes(), b"CHU\0");
    }

    #[test]
    fn test_well_known_msf() {
        assert_eq!(ids::MSF.as_bytes(), b"MSF\0");
    }

    #[test]
    fn test_well_known_ids_are_distinct() {
        let all = [
            ids::GPS,
            ids::PPS,
            ids::NMEA,
            ids::IRIG,
            ids::PTP,
            ids::WWVB,
            ids::DCF,
            ids::CHU,
            ids::MSF,
        ];
        for i in 0..all.len() {
            for j in (i + 1)..all.len() {
                assert_ne!(all[i], all[j], "refclock IDs {i} and {j} should differ");
            }
        }
    }

    // ── RefClock ──────────────────────────────────────────────────────

    #[test]
    fn test_refclock_new_pps() {
        let clock = RefClock::new(RefClockType::Pps, "/dev/pps0");
        assert_eq!(clock.driver_type, RefClockType::Pps);
        assert_eq!(clock.id, ids::PPS);
        assert_eq!(clock.device, "/dev/pps0");
        assert_eq!(clock.stratum, 1);
        assert_eq!(clock.precision, -20);
        assert!(!clock.is_configured);
        assert!(clock.last_offset.is_none());
    }

    #[test]
    fn test_refclock_new_nmea() {
        let clock = RefClock::new(RefClockType::Nmea, "/dev/ttyUSB0");
        assert_eq!(clock.id, ids::NMEA);
        assert_eq!(clock.device, "/dev/ttyUSB0");
    }

    #[test]
    fn test_refclock_new_irig() {
        let clock = RefClock::new(RefClockType::Irig, "/dev/irig0");
        assert_eq!(clock.id, ids::IRIG);
    }

    #[test]
    fn test_refclock_new_ptp() {
        let clock = RefClock::new(RefClockType::Ptp, "/dev/ptp0");
        assert_eq!(clock.id, ids::PTP);
    }

    #[test]
    fn test_refclock_new_other() {
        let clock = RefClock::new(RefClockType::Other("CUSTOM"), "/dev/custom0");
        assert_eq!(clock.id, RefClockId(*b"LOCL"));
    }

    #[test]
    fn test_refclock_refid() {
        let clock = RefClock::new(RefClockType::Pps, "/dev/pps0");
        assert_eq!(clock.refid(), *b"PPS\0");
    }

    #[test]
    fn test_refclock_set_offset() {
        let mut clock = RefClock::new(RefClockType::Pps, "/dev/pps0");
        assert!(clock.last_offset.is_none());
        clock.set_offset(0.001234);
        assert_eq!(clock.last_offset, Some(0.001234));
        clock.set_offset(-0.000567);
        assert_eq!(clock.last_offset, Some(-0.000567));
    }

    #[test]
    fn test_refclock_stratum_customizable() {
        let mut clock = RefClock::new(RefClockType::Nmea, "/dev/ttyS0");
        clock.stratum = 2;
        assert_eq!(clock.stratum, 2);
    }

    #[test]
    fn test_refclock_precision_customizable() {
        let mut clock = RefClock::new(RefClockType::Pps, "/dev/pps0");
        clock.precision = -30;
        assert_eq!(clock.precision, -30);
    }

    #[test]
    fn test_refclock_is_configured_flag() {
        let mut clock = RefClock::new(RefClockType::Ptp, "/dev/ptp0");
        clock.is_configured = true;
        assert!(clock.is_configured);
    }
}
