//! Utility types and helpers — fixed-point arithmetic, time
//! conversions, address formatting, NTP timestamp math.
//!
//! This module corresponds to OpenNTPD's
//! [`util.c`](https://github.com/openntpd-portable/openntpd-openbsd/blob/master/src/usr.sbin/ntpd/util.c).
//!
//! ## Offset representation
//!
//! OpenNTPD uses a 64-bit signed frequency value representing
//! nanoseconds per second (ns/s), left-shifted by 32 to preserve
//! sub-ns precision.  This is the **OpenBSD internal** representation.
//!
//! **Linux `adjtimex(2)` uses a different unit:** scaled ppm, where
//! 1 ppm = 2¹⁶.  The conversion is:
//!
//! ```text
//! linux_scaled_ppm = openbsd_freq / (1000 × 2¹⁶)
//! openbsd_freq = linux_scaled_ppm × (1000 × 2¹⁶)
//! ```
//!
//! All I/O boundary conversions live in `openntpd-rs-io::clock`.
//! The core `Frequency` type uses only the OpenBSD internal
//! representation.
//!
//! ## NTP fixed-point conversions
//!
//! These functions replicate the C `lfp_to_d`, `d_to_lfp`, `sfp_to_d`, and
//! `d_to_sfp` from OpenNTPD's `util.c`.  They operate on raw integer
//! int/frac parts (host byte order) and apply era-resolution logic.

use core::fmt;

// ---------------------------------------------------------------------------
// NTP fixed-point constants
// ---------------------------------------------------------------------------

/// Denominator for 32.32 fixed-point: 2³² = 4 294 967 296.
const L_DENOMINATOR: f64 = 4_294_967_296.0;

/// Seconds in one NTP era: 2³².
const SECS_IN_ERA: f64 = 4_294_967_296.0;

/// Denominator for 16.16 fixed-point: 2¹⁶ = 65 536.
const S_DENOMINATOR: f64 = 65_536.0;

// ---------------------------------------------------------------------------
// NTP fixed-point conversions  (matching OpenNTPD's lfp_to_d / d_to_lfp / …)
// ---------------------------------------------------------------------------

/// Convert NTP 32.32 unsigned fixed-point `(int_part, frac)` to `f64`
/// seconds.
///
/// Applies era-resolution logic matching the C `lfp_to_d()`:
/// if `int_part ≤ INT32_MAX` the value is assumed to be in NTP era 1
/// (i.e. 2³² s are added).
#[must_use]
pub fn lfp_to_d(int_part: u32, frac: u32) -> f64 {
    // The C code performs ntohl on both fields.  We treat the parameters
    // as host-order, applying the same era-resolution logic.
    let base: u64 = if int_part <= i32::MAX as u32 { 1 } else { 0 };
    (base as f64) * SECS_IN_ERA + (int_part as f64) + (frac as f64) / L_DENOMINATOR
}

/// Convert `f64` seconds to NTP 32.32 unsigned fixed-point `(int_part,
/// frac)`, wrapping into one NTP era.
///
/// Matches the C `d_to_lfp()`.  Repeatedly subtracts `SECS_IN_ERA`
/// until the value fits in one era.
#[must_use]
pub fn d_to_lfp(d: f64) -> (u32, u32) {
    let mut d = d;
    while d > SECS_IN_ERA {
        d -= SECS_IN_ERA;
    }
    let int_part = d as u32;
    let frac = ((d - int_part as f64) * L_DENOMINATOR) as u32;
    (int_part, frac)
}

/// Convert NTP 16.16 **signed** fixed-point `(int_part, frac)` to `f64`
/// seconds.
///
/// Matches the C `sfp_to_d()`.  The integer part is signed (i16) and the
/// fractional part is unsigned (u16).
#[must_use]
pub fn sfp_to_d(int_part: i16, frac: u16) -> f64 {
    (int_part as f64) + (frac as f64) / S_DENOMINATOR
}

/// Convert `f64` seconds to NTP 16.16 **signed** fixed-point
/// `(i16, u16)`.
///
/// Matches the C `d_to_sfp()`.  Uses correct two's-complement
/// arithmetic so that negative values roundtrip correctly
/// (unlike the C original which has undefined behaviour for negative
/// inputs via float-to-unsigned casts).
#[must_use]
pub fn d_to_sfp(d: f64) -> (i16, u16) {
    let total = (d * S_DENOMINATOR) as i32;
    let int_part = (total >> 16) as i16;
    let frac = total as u16;
    (int_part, frac)
}

// ---------------------------------------------------------------------------
// Clock offset and frequency types
// ---------------------------------------------------------------------------

/// Clock offset in seconds (signed, can be negative when the local
/// clock is ahead of reference).
#[derive(Clone, Copy, Default, PartialEq, PartialOrd, Debug)]
pub struct Offset(pub f64);

/// Clock frequency adjustment in the **OpenBSD internal** representation:
/// ns/s × 2³².
///
/// ## Platform boundary
///
/// This type holds the OpenBSD/kernel-independent value.  Conversions
/// to/from platform-specific units (Linux scaled‑ppm, macOS
/// `mach_timebase`, etc.) MUST be performed at the I/O boundary in
/// `openntpd-rs-io::clock`, never in core logic.
///
/// ### Linux conversion formula (from `compat/adjfreq_linux.c`)
///
/// ```c
/// tx.freq = openbsd_freq / 1000 / 65536;  // 65536 = 2^16
/// ```
///
/// So the correct conversion is:
/// - `openbsd_freq → linux_scaled_ppm`: divide by (1000 × 2¹⁶)
/// - `linux_scaled_ppm → openbsd_freq`: multiply by (1000 × 2¹⁶)
///
/// At 1 ppm:
/// - OpenBSD:  4,294,967,296,000  (1 × 1000 × 2³²)
/// - Linux:              65,536  (2¹⁶)
/// - Error if confused: 65,536,000×
#[derive(Clone, Copy, Default, PartialEq, Eq, PartialOrd, Debug)]
pub struct Frequency(i64);

impl Frequency {
    /// The OpenBSD scale factor: ns/s × 2³².
    pub const OPENBSD_SCALE: i64 = 1i64 << 32;

    /// Linux adjtimex further divides by 1000 × 2¹⁶ to get its
    /// scaled-ppm unit.
    pub const LINUX_DIVISOR: i64 = 1000 * (1i64 << 16);

    /// Maximum safe frequency for Linux adjtimex (≤ 32-bit signed).
    pub const LINUX_MAX: i64 = (i32::MAX as i64) * Self::LINUX_DIVISOR;

    /// Minimum safe frequency for Linux adjtimex (≥ 32-bit signed).
    pub const LINUX_MIN: i64 = (i32::MIN as i64) * Self::LINUX_DIVISOR;

    /// Create from the raw OpenBSD-internal value.
    #[must_use]
    pub const fn from_raw(raw: i64) -> Self {
        Self(raw)
    }

    /// Return the raw OpenBSD-internal value.
    #[must_use]
    pub const fn raw(self) -> i64 {
        self.0
    }

    /// Create from parts-per-million (ppm).
    ///
    /// 1 ppm = 1000 ns/s → 1000 × 2³² in OpenBSD units.
    #[must_use]
    pub fn from_ppm(ppm: f64) -> Self {
        Self((ppm * 1000.0 * Self::OPENBSD_SCALE as f64) as i64)
    }

    /// Convert to parts-per-million (ppm).
    #[must_use]
    pub fn to_ppm(self) -> f64 {
        self.0 as f64 / (1000.0 * Self::OPENBSD_SCALE as f64)
    }

    /// Convert to ns/s.
    #[must_use]
    pub fn to_ns_per_s(self) -> f64 {
        self.0 as f64 / Self::OPENBSD_SCALE as f64
    }

    /// Convert to Linux `adjtimex.freq` scaled-ppm units.
    ///
    /// # Panics
    ///
    /// Panics if `self.0` overflows or underflows the Linux i32
    /// scaled-ppm range.  Use [`try_to_linux`](Self::try_to_linux)
    /// for a fallible version.
    #[must_use]
    pub fn to_linux(self) -> i64 {
        self.try_to_linux()
            .expect("frequency out of Linux adjtimex range")
    }

    /// Fallible conversion to Linux `adjtimex.freq` scaled-ppm units.
    ///
    /// Returns `None` if `self.0` would overflow or underflow the
    /// `timex.freq` field (a `c_long`; on 64-bit Linux the hardware
    /// clamp is applied by the kernel, but we guard against gross
    /// overflow here).
    #[must_use]
    pub fn try_to_linux(self) -> Option<i64> {
        // The kernel clamps to ±i32 max, but check our divided value
        let divided = self.0 / Self::LINUX_DIVISOR;
        if divided > i32::MAX as i64 || divided < i32::MIN as i64 {
            return None;
        }
        Some(self.0 / Self::LINUX_DIVISOR)
    }

    /// Convert from Linux `adjtimex.freq` scaled-ppm units.
    ///
    /// # Panics
    ///
    /// Panics if `linux_freq * LINUX_DIVISOR` overflows `i64`.
    /// Use [`from_linux_checked`](Self::from_linux_checked) for a
    /// fallible version.
    #[must_use]
    pub fn from_linux(linux_freq: i64) -> Self {
        Self::from_linux_checked(linux_freq).expect("Frequency::from_linux: overflow")
    }

    /// Convert from Linux `adjtimex.freq` scaled-ppm with overflow
    /// checking.
    #[must_use]
    pub fn from_linux_checked(linux_freq: i64) -> Option<Self> {
        Some(Self(linux_freq.checked_mul(Self::LINUX_DIVISOR)?))
    }
}

// ---------------------------------------------------------------------------
// Time value helpers
// ---------------------------------------------------------------------------

/// A normalized timespec: `nsec` is always in `[0, 1_000_000_000)`.
///
/// Negative times are represented with a negative `secs` and a
/// non-negative `nsec`, matching OpenNTPD's `d_to_tv()` normalization.
///
/// # Invariant
///
/// `nsec` is always `< 1_000_000_000`.  Construction via [`new`](Self::new)
/// or [`from_f64`](Self::from_f64) enforces this.  Direct field mutation
/// may violate the invariant.
#[derive(Clone, Copy, Default, PartialEq, Eq, Debug)]
pub struct Timespec {
    /// Seconds (may be negative).
    pub secs: i64,
    /// Nanoseconds, always in `[0, 1_000_000_000)`.
    nsec: u32,
}

impl Timespec {
    /// Create a new normalized Timespec.
    ///
    /// Normalizes so that `nsec` is in `[0, 1_000_000_000)`.
    /// Returns `None` if `secs + carry` overflows `i64`.
    #[must_use]
    pub fn new(secs: i64, nsec: u32) -> Option<Self> {
        let carry = i64::from(nsec / 1_000_000_000);
        Some(Self {
            secs: secs.checked_add(carry)?,
            nsec: nsec % 1_000_000_000,
        })
    }

    /// Create a normalized Timespec with potential borrow for negative
    /// subsecond values (matching OpenNTPD's `d_to_tv`).
    #[must_use]
    fn normalize(secs: i64, nsec: i64) -> Self {
        let mut s = secs;
        let mut ns = nsec;
        if ns >= 1_000_000_000 {
            s = s.saturating_add(ns / 1_000_000_000);
            ns %= 1_000_000_000;
        } else if ns < 0 {
            // Borrow from secs: e.g. -1.5s → secs=-2, nsec=500_000_000
            let borrow = (-ns + 999_999_999) / 1_000_000_000;
            s = s.saturating_sub(borrow);
            ns += borrow * 1_000_000_000;
        }
        Self {
            secs: s,
            nsec: ns as u32,
        }
    }

    /// Nanoseconds component (always `< 1_000_000_000`).
    #[must_use]
    pub fn nsec(&self) -> u32 {
        self.nsec
    }

    /// Convert to `f64` seconds.
    #[must_use]
    pub fn to_f64(self) -> f64 {
        self.secs as f64 + f64::from(self.nsec) / 1_000_000_000.0
    }

    /// Create from `f64` seconds.
    ///
    /// Returns `None` for NaN, infinity, or values outside the
    /// `i64` seconds range.
    #[must_use]
    pub fn from_f64(t: f64) -> Option<Self> {
        if !t.is_finite() {
            return None;
        }
        // Reject values outside i64 range before truncation.
        // i64::MAX as f64 rounds to 2^63, so use an exclusive upper
        // bound to catch exactly 2^63 and above.
        if !(-9_223_372_036_854_775_808.0..9_223_372_036_854_775_808.0).contains(&t) {
            return None;
        }
        let truncated = libm::trunc(t);
        let secs = truncated as i64;
        let nsec = ((t - truncated) * 1_000_000_000.0) as i64;
        Some(Self::normalize(secs, nsec))
    }
}

// ---------------------------------------------------------------------------
// Double-to-timespec conversion (matching OpenNTPD's d_to_tv)
// ---------------------------------------------------------------------------

/// Convert a double (seconds) into normalized `Timespec`.
///
/// This matches OpenNTPD's `d_to_tv()`:
/// - Negative values are normalized so that `nsec ≥ 0`.
///   E.g. `-1.5` → `secs=-2, nsec=500_000_000`.
/// - NaN and Infinity return `None`.
/// - Values outside `i64` range return `None`.
#[must_use]
pub fn d_to_timespec(d: f64) -> Option<Timespec> {
    Timespec::from_f64(d)
}

/// Convert `Timespec` back to double.
#[must_use]
pub fn timespec_to_d(ts: Timespec) -> f64 {
    ts.to_f64()
}

// ---------------------------------------------------------------------------
// Address formatting
// ---------------------------------------------------------------------------

/// A parsed socket address (IPv4 or IPv6) used in the control protocol.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub enum SockAddr {
    /// IPv4 address and port.
    V4 { addr: [u8; 4], port: u16 },
    /// IPv6 address and port.
    V6 { addr: [u8; 16], port: u16 },
    /// Unspecified / invalid.
    Unspec,
}

impl fmt::Display for SockAddr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::V4 { addr, port } => {
                write!(
                    f,
                    "{}.{}.{}.{}:{}",
                    addr[0], addr[1], addr[2], addr[3], port
                )
            }
            Self::V6 { addr, port } => {
                // Proper IPv6 formatting: colon-separated hex groups
                write!(f, "[")?;
                for (i, chunk) in addr.chunks(2).enumerate() {
                    if i > 0 {
                        write!(f, ":")?;
                    }
                    write!(f, "{:02x}{:02x}", chunk[0], chunk[1])?;
                }
                write!(f, "]:{}", port)
            }
            Self::Unspec => write!(f, "*:*"),
        }
    }
}

impl fmt::Debug for SockAddr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, f)
    }
}

// ---------------------------------------------------------------------------
// Log level matching OpenNTPD's log.c
// ---------------------------------------------------------------------------

/// Log severity levels matching OpenNTPD's `log.h`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum LogLevel {
    /// Emergency (syslog LOG_EMERG).
    Emergency = 0,
    /// Alert (syslog LOG_ALERT).
    Alert = 1,
    /// Critical (syslog LOG_CRIT).
    Critical = 2,
    /// Error (syslog LOG_ERR).
    Error = 3,
    /// Warning (syslog LOG_WARNING).
    Warning = 4,
    /// Notice (syslog LOG_NOTICE).
    Notice = 5,
    /// Info (syslog LOG_INFO).
    Info = 6,
    /// Debug (syslog LOG_DEBUG).
    Debug = 7,
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_frequency_ppm_roundtrip() {
        let ppm = 100.0;
        let freq = Frequency::from_ppm(ppm);
        let back = freq.to_ppm();
        assert!((back - ppm).abs() < 1e-9);
    }

    #[test]
    fn test_frequency_linux_conversion_known_value() {
        // At 1 ppm:
        //   OpenBSD = 1000 * 2^32 = 4_294_967_296_000
        //   Linux   = 2^16        = 65_536
        let freq = Frequency::from_ppm(1.0);
        assert_eq!(freq.raw(), 1000 * (1i64 << 32));
        assert_eq!(freq.to_linux(), 1i64 << 16);
    }

    #[test]
    fn test_frequency_linux_roundtrip() {
        let linux_freq: i64 = 65_536; // 1 ppm in Linux units
        let freq = Frequency::from_linux(linux_freq);
        let back = freq.to_linux();
        assert_eq!(back, linux_freq);
        let ppm = freq.to_ppm();
        assert!((ppm - 1.0).abs() < 1e-9);
    }

    #[test]
    fn test_frequency_linux_overflow_rejection() {
        // i32::MAX + 1 should be rejected
        let huge = Frequency::from_raw((i32::MAX as i64 + 1) * Frequency::LINUX_DIVISOR);
        assert!(huge.try_to_linux().is_none());
    }

    #[test]
    fn test_timespec_normalize_positive() {
        let ts = Timespec::new(5, 1_500_000_000).unwrap();
        assert_eq!(ts.secs, 6);
        assert_eq!(ts.nsec(), 500_000_000);
    }

    #[test]
    fn test_timespec_new_overflow_rejected() {
        // i64::MAX + 1s carry should be None
        assert!(Timespec::new(i64::MAX, 1_000_000_000).is_none());
    }

    #[test]
    fn test_timespec_normalize_negative() {
        // OpenNTPD normalizes -1.5s to secs=-2, µs=500,000
        let ts = Timespec::from_f64(-1.5).unwrap();
        assert_eq!(ts.secs, -2);
        assert_eq!(ts.nsec(), 500_000_000);
    }

    #[test]
    fn test_timespec_from_f64() {
        let ts = Timespec::from_f64(1234.567_890_123).unwrap();
        assert_eq!(ts.secs, 1234);
        assert!((ts.nsec() as i64 - 567_890_123).abs() < 1000);
    }

    #[test]
    fn test_timespec_nan_inf_rejected() {
        assert!(Timespec::from_f64(f64::NAN).is_none());
        assert!(Timespec::from_f64(f64::INFINITY).is_none());
        assert!(Timespec::from_f64(f64::NEG_INFINITY).is_none());
    }

    #[test]
    fn test_d_to_timespec_negative() {
        // OpenNTPD's d_to_tv(-1.5) → secs=-2, usec=500000
        let ts = d_to_timespec(-1.5).unwrap();
        assert_eq!(ts.secs, -2);
        assert_eq!(ts.nsec(), 500_000_000);
    }

    #[test]
    fn test_timespec_roundtrip() {
        let values = [0.0, 1.0, -1.0, 1.5, -1.5, 123456.789, -0.001];
        for v in values {
            let ts = Timespec::from_f64(v).unwrap();
            let back = ts.to_f64();
            assert!(
                (back - v).abs() < 1e-9,
                "roundtrip failed for {v}: got {back}"
            );
        }
    }

    #[test]
    fn test_timespec_out_of_range_rejected() {
        // Values outside i64 range should be rejected
        assert!(Timespec::from_f64(1e300).is_none());
        assert!(Timespec::from_f64(-1e300).is_none());
    }

    // ------------------------------------------------------------------
    // NTP fixed-point conversions
    // ------------------------------------------------------------------

    #[test]
    fn test_lfp_to_d_basic() {
        // int_part=0, frac=0 → 0.0 (era 0, base=0 since 0 <= INT32_MAX → base=1)
        // lfp_to_d(0, 0): base=1, ret = 1*2^32 + 0 + 0 = 2^32
        let result = lfp_to_d(0, 0);
        assert!((result - SECS_IN_ERA).abs() < 1e-9);
    }

    #[test]
    fn test_lfp_to_d_small_int() {
        // int_part=1, frac=0, base=1 (since 1 <= INT32_MAX)
        // ret = 2^32 + 1
        let result = lfp_to_d(1, 0);
        assert!((result - (SECS_IN_ERA + 1.0)).abs() < 1e-9);
    }

    #[test]
    fn test_lfp_to_d_high_int() {
        // int_part > INT32_MAX → base=0 (era 0)
        let result = lfp_to_d(1u32 << 31, 0);
        assert!((result - (1u32 << 31) as f64).abs() < 1e-9);
    }

    #[test]
    fn test_lfp_to_d_with_fraction() {
        // int_part=0, frac=2^31 → 0.5
        let result = lfp_to_d(0, 1u32 << 31);
        assert!((result - (SECS_IN_ERA + 0.5)).abs() < 1e-9);
    }

    #[test]
    fn test_lfp_to_d_frac_max() {
        // frac = u32::MAX ≈ 0.999999999767
        let result = lfp_to_d(0, u32::MAX);
        let expected = SECS_IN_ERA + (u32::MAX as f64) / L_DENOMINATOR;
        assert!((result - expected).abs() < 1e-9);
    }

    #[test]
    fn test_d_to_lfp_zero() {
        let (int_part, frac) = d_to_lfp(0.0);
        assert_eq!(int_part, 0);
        assert_eq!(frac, 0);
    }

    #[test]
    fn test_d_to_lfp_small() {
        let (int_part, frac) = d_to_lfp(1.5);
        assert_eq!(int_part, 1);
        // 0.5 * 2^32 = 2^31
        assert_eq!(frac, 1u32 << 31);
    }

    #[test]
    fn test_d_to_lfp_wraps_era() {
        // A value > SECS_IN_ERA should be wrapped
        let val = SECS_IN_ERA + 42.0;
        let (int_part, frac) = d_to_lfp(val);
        assert_eq!(int_part, 42);
        assert_eq!(frac, 0);
    }

    #[test]
    fn test_lfp_roundtrip() {
        // Pick a value that maps to era 0 (< INT32_MAX doesn't matter
        // since after wrapping they're all era-reduced)
        let values = [
            0.0,
            1.0,
            0.5,
            1234.567,
            3.141592653589793,
            SECS_IN_ERA - 1.0,
            SECS_IN_ERA + 1000.0,
            0x1_0000_0000u64 as f64 * 3.0 + 42.0,
        ];
        for v in values {
            let (int_part, frac) = d_to_lfp(v);
            let back = lfp_to_d(int_part, frac);
            let expected = v % SECS_IN_ERA;
            if expected >= 0.0 && expected < SECS_IN_ERA {
                assert!(
                    (back - (SECS_IN_ERA + expected)).abs() < 1e-6
                        || (back - expected).abs() < 1e-6
                        || (back - (SECS_IN_ERA * 2.0 + expected)).abs() < 1e-6,
                    "roundtrip failed for {v}: int={int_part} frac={frac} back={back}"
                );
            }
        }
    }

    #[test]
    fn test_d_to_lfp_large_multiple_eras() {
        // 3 full eras + 42 seconds
        let val = 3.0 * SECS_IN_ERA + 42.0;
        let (int_part, frac) = d_to_lfp(val);
        assert_eq!(int_part, 42);
        assert_eq!(frac, 0);
    }

    #[test]
    fn test_sfp_to_d_positive() {
        let result = sfp_to_d(1, 0);
        assert!((result - 1.0).abs() < 1e-9);
    }

    #[test]
    fn test_sfp_to_d_positive_frac() {
        // 0.5 = 32768 / 65536
        let result = sfp_to_d(1, 32768);
        assert!((result - 1.5).abs() < 1e-9);
    }

    #[test]
    fn test_sfp_to_d_negative() {
        let result = sfp_to_d(-1, 0);
        assert!((result - (-1.0)).abs() < 1e-9);
    }

    #[test]
    fn test_d_to_sfp_positive() {
        let (int_part, frac) = d_to_sfp(1.5);
        assert_eq!(int_part, 1);
        assert_eq!(frac, 32768);
    }

    #[test]
    fn test_d_to_sfp_negative() {
        let (int_part, frac) = d_to_sfp(-1.5);
        // -1.5 * 65536 = -98304 = 0xFFFE8000 as i32
        // int = -2 (0xFFFE), frac = 32768 (0x8000)
        assert_eq!(int_part, -2);
        assert_eq!(frac, 32768);
    }

    #[test]
    fn test_sfp_roundtrip() {
        let values = [
            0.0, 1.0, -1.0, 1.5, -1.5, 0.125, -0.125, 32767.999, -32768.0,
        ];
        for v in values {
            let (int_part, frac) = d_to_sfp(v);
            let back = sfp_to_d(int_part, frac);
            assert!(
                (back - v).abs() < 1e-4,
                "sfp roundtrip failed for {v}: ({int_part}, {frac}) -> {back}"
            );
        }
    }

    #[test]
    fn test_d_to_sfp_zero() {
        let (int_part, frac) = d_to_sfp(0.0);
        assert_eq!(int_part, 0);
        assert_eq!(frac, 0);
    }

    #[test]
    fn test_d_to_sfp_max_positive() {
        // i16::MAX = 32767, so max is 32767.9999847...
        let max_val = i16::MAX as f64 + (u16::MAX as f64) / S_DENOMINATOR;
        let (int_part, frac) = d_to_sfp(max_val);
        assert_eq!(int_part, i16::MAX);
        assert_eq!(frac, u16::MAX);
    }
}
