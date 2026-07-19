//! NTP protocol definitions — wire-format structures, constants,
//! encode/decode helpers.
//!
//! This module is the Rust equivalent of OpenNTPD's
//! [`ntp.h`](https://github.com/openntpd-portable/openntpd-openbsd/blob/master/src/usr.sbin/ntpd/ntp.h)
//! and [`ntp_msg.c`](https://github.com/openntpd-portable/openntpd-openbsd/blob/master/src/usr.sbin/ntpd/ntp_msg.c).
//!
//! ## Forensic notes
//!
//! OpenNTPD accepts exactly two packet lengths:
//! - **48 bytes**: unauthenticated NTPv4 header.
//! - **68 bytes**: authenticated header + 4-byte key ID + 16-byte MD5 digest.
//!
//! Any other length is rejected.  The `root_delay` field is signed
//! 16.16 fixed-point, while `root_dispersion` is *unsigned* 16.16
//! fixed-point in the NTPv4 specification.
//!
//! ## References
//!
//! - RFC 5905: NTPv4 protocol specification.
//! - OpenNTPD `ntp.h`: `s_fixedpt` and `u_fixedpt` types.
//! - OpenNTPD `ntp_msg.c`: `ntp_getmsg()` / `ntp_sendmsg()`.

use core::fmt;

// ---------------------------------------------------------------------------
// NTP constants
// ---------------------------------------------------------------------------

/// NTP port number.
pub const NTP_PORT: u16 = 123;

/// Minimum NTP packet size (header only, no extensions).
pub const NTP_PACKET_MIN_SIZE: usize = 48;

/// Authenticated NTP packet size (header + key ID + MD5 digest).
pub const NTP_PACKET_AUTH_SIZE: usize = 68;

/// Maximum authenticated packet size.
pub const NTP_PACKET_MAX_SIZE: usize = 68;

/// Key ID + digest suffix length.
pub const NTP_AUTH_SUFFIX_LEN: usize = 20;

/// NTPv4 version number.
pub const NTP_VERSION: u8 = 4;

/// NTP timestamp era in seconds (2³²).
pub const NTP_ERA: u64 = 0x1_0000_0000;

/// JAN_1970 — Seconds between NTP epoch (1900-01-01) and Unix epoch (1970-01-01).
/// Same as [`NTP_UNIX_EPOCH_DELTA`]; this alias matches the C `ntp.h` name.
pub const JAN_1970: u64 = 2_208_988_800;

/// Seconds between 1900-01-01 (NTP epoch) and 1970-01-01 (Unix epoch).
pub const NTP_UNIX_EPOCH_DELTA: u64 = 2_208_988_800;

/// NTP long/timestamp format denominator (2³²).
/// Used for converting between NTP fixed-point and `f64`.
/// C: `#define L_DENOMINATOR (UINT32_MAX + 1ULL)`
pub const L_DENOMINATOR: f64 = 4_294_967_296.0;

/// NTP short format denominator (2¹⁶).
/// Used for converting short fixed-point values to `f64`.
/// C: `#define S_DENOMINATOR (UINT16_MAX + 1)`
pub const S_DENOMINATOR: f64 = 65_536.0;

/// Seconds in one NTP era (2³² seconds ≈ 136 years).
/// C: `#define SECS_IN_ERA (UINT32_MAX + 1ULL)`
pub const SECS_IN_ERA: u64 = 4_294_967_296;

/// Leap indicator mask — top 2 bits of byte 0.
/// C: `#define LIMASK (3 << 6)`
pub const LIMASK: u8 = 0xC0;

/// Mode field mask — bottom 3 bits of byte 0.
/// C: `#define MODEMASK (7 << 0)`
pub const MODEMASK: u8 = 0x07;

/// Version number mask — bits 3-5 of byte 0.
/// C: `#define VERSIONMASK (7 << 3)`
pub const VERSIONMASK: u8 = 0x38;

/// Maximum dispersion (16 seconds).
pub const NTP_MAX_DISPERSION: f64 = 16.0;

/// Maximum clock skew (1000 ppm = 1 ms/s).
pub const NTP_MAX_SKEW: f64 = 1000e-6;

// Leap indicator (LI) values — top 2 bits of byte 0.
pub mod li {
    /// No warning.
    pub const NO_WARNING: u8 = 0;
    /// Last minute has 61 seconds.
    pub const PLUS_61_SEC: u8 = 1;
    /// Last minute has 59 seconds.
    pub const MINUS_59_SEC: u8 = 2;
    /// Alarm condition (clock not synchronized).
    pub const ALARM: u8 = 3;
}

// Mode values — bottom 3 bits of byte 0.
pub mod mode {
    /// Reserved.
    pub const RESERVED: u8 = 0;
    /// Symmetric active.
    pub const SYMMETRIC_ACTIVE: u8 = 1;
    /// Symmetric passive.
    pub const SYMMETRIC_PASSIVE: u8 = 2;
    /// Client.
    pub const CLIENT: u8 = 3;
    /// Server.
    pub const SERVER: u8 = 4;
    /// Broadcast.
    pub const BROADCAST: u8 = 5;
    /// NTP control message.
    pub const CONTROL: u8 = 6;
    /// Private (reserved for implementation use).
    pub const PRIVATE: u8 = 7;
}

// ---------------------------------------------------------------------------
// NTP wire format
// ---------------------------------------------------------------------------

/// A 32.32 fixed-point NTP timestamp (seconds and fractional seconds).
#[derive(Clone, Copy, Default, PartialEq, Eq, Hash)]
pub struct NtpTimestamp {
    /// Seconds part (unsigned 32-bit, wraps at 2³²).
    pub secs: u32,
    /// Fractional seconds part (1/2³² second units).
    pub frac: u32,
}

impl NtpTimestamp {
    /// Create a new NTP timestamp from seconds and fractional parts.
    #[must_use]
    pub const fn new(secs: u32, frac: u32) -> Self {
        Self { secs, frac }
    }

    /// The zero timestamp (1900-01-01 00:00:00).
    #[must_use]
    pub const fn zero() -> Self {
        Self { secs: 0, frac: 0 }
    }

    /// Convert to 64-bit wire representation (big-endian).
    #[must_use]
    pub fn to_wire(self) -> [u8; 8] {
        let mut buf = [0u8; 8];
        buf[0..4].copy_from_slice(&self.secs.to_be_bytes());
        buf[4..8].copy_from_slice(&self.frac.to_be_bytes());
        buf
    }

    /// Read from 64-bit big-endian wire representation.
    #[must_use]
    pub fn from_wire(buf: &[u8; 8]) -> Self {
        let secs = u32::from_be_bytes(buf[0..4].try_into().unwrap());
        let frac = u32::from_be_bytes(buf[4..8].try_into().unwrap());
        Self { secs, frac }
    }

    /// Convert to `f64` seconds since NTP epoch (approximate).
    #[must_use]
    pub fn to_f64(self) -> f64 {
        f64::from(self.secs) + f64::from(self.frac) / 4_294_967_296.0
    }

    /// Create from `f64` seconds since NTP epoch.
    #[must_use]
    pub fn from_f64(t: f64) -> Self {
        let truncated = libm::trunc(t);
        let secs = truncated as u32;
        let frac = ((t - truncated) * 4_294_967_296.0) as u32;
        Self { secs, frac }
    }
}

impl fmt::Debug for NtpTimestamp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "NtpTimestamp({}.{:08x})", self.secs, self.frac)
    }
}

/// A 16.16 **signed** fixed-point value (used for root delay).
#[derive(Clone, Copy, Default, PartialEq, Eq, Hash, Debug)]
pub struct NtpShortSigned {
    /// Integer part (signed 16-bit).
    pub int: i16,
    /// Fractional part (1/65536 second units, unsigned).
    pub frac: u16,
}

impl NtpShortSigned {
    #[must_use]
    pub const fn new(int: i16, frac: u16) -> Self {
        Self { int, frac }
    }

    /// Convert to `f64` seconds.
    #[must_use]
    pub fn to_f64(self) -> f64 {
        f64::from(self.int) + f64::from(self.frac) / 65_536.0
    }

    /// Create from 4 big-endian wire bytes.
    #[must_use]
    pub fn from_be_bytes(buf: &[u8; 4]) -> Self {
        let int = i16::from_be_bytes([buf[0], buf[1]]);
        let frac = u16::from_be_bytes([buf[2], buf[3]]);
        Self { int, frac }
    }

    /// Convert to 4 big-endian wire bytes.
    #[must_use]
    pub fn to_be_bytes(self) -> [u8; 4] {
        let mut buf = [0u8; 4];
        buf[0..2].copy_from_slice(&self.int.to_be_bytes());
        buf[2..4].copy_from_slice(&self.frac.to_be_bytes());
        buf
    }
}

/// A 16.16 **unsigned** fixed-point value (used for root dispersion).
#[derive(Clone, Copy, Default, PartialEq, Eq, Hash, Debug)]
pub struct NtpShortUnsigned {
    /// Integer part (unsigned 16-bit).
    pub int: u16,
    /// Fractional part (1/65536 second units).
    pub frac: u16,
}

impl NtpShortUnsigned {
    #[must_use]
    pub const fn new(int: u16, frac: u16) -> Self {
        Self { int, frac }
    }

    /// Convert to `f64` seconds.
    #[must_use]
    pub fn to_f64(self) -> f64 {
        f64::from(self.int) + f64::from(self.frac) / 65_536.0
    }

    /// Create from 4 big-endian wire bytes.
    #[must_use]
    pub fn from_be_bytes(buf: &[u8; 4]) -> Self {
        let int = u16::from_be_bytes([buf[0], buf[1]]);
        let frac = u16::from_be_bytes([buf[2], buf[3]]);
        Self { int, frac }
    }

    /// Convert to 4 big-endian wire bytes.
    #[must_use]
    pub fn to_be_bytes(self) -> [u8; 4] {
        let mut buf = [0u8; 4];
        buf[0..2].copy_from_slice(&self.int.to_be_bytes());
        buf[2..4].copy_from_slice(&self.frac.to_be_bytes());
        buf
    }
}

// ---------------------------------------------------------------------------
// NTP v4 packet header (48 bytes)
// ---------------------------------------------------------------------------

/// The 48-byte NTPv4 packet header.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct NtpPacket {
    /// Leap Indicator (2 bits), Version (3 bits), Mode (3 bits).
    pub li_vn_mode: u8,
    /// Stratum (0 = kiss-o'-death, 1 = primary, 2–15 = secondary).
    pub stratum: u8,
    /// Poll interval in log₂ seconds (signed).
    pub poll: i8,
    /// Precision in log₂ seconds (signed).
    pub precision: i8,
    /// Root delay in 16.16 signed seconds.
    pub root_delay: NtpShortSigned,
    /// Root dispersion in 16.16 **unsigned** seconds (per RFC 5905).
    pub root_dispersion: NtpShortUnsigned,
    /// Reference clock identifier.
    pub reference_id: [u8; 4],
    /// Reference timestamp.
    pub reference_ts: NtpTimestamp,
    /// Origin timestamp (client's transmit timestamp echoed by server).
    pub origin_ts: NtpTimestamp,
    /// Receive timestamp (server's receipt time).
    pub receive_ts: NtpTimestamp,
    /// Transmit timestamp (packet departure time).
    pub transmit_ts: NtpTimestamp,
}

impl NtpPacket {
    /// Create a zeroed-out NTP packet.
    #[must_use]
    pub fn zero() -> Self {
        Self {
            li_vn_mode: 0,
            stratum: 0,
            poll: 0,
            precision: 0,
            root_delay: NtpShortSigned::default(),
            root_dispersion: NtpShortUnsigned::default(),
            reference_id: [0u8; 4],
            reference_ts: NtpTimestamp::zero(),
            origin_ts: NtpTimestamp::zero(),
            receive_ts: NtpTimestamp::zero(),
            transmit_ts: NtpTimestamp::zero(),
        }
    }

    /// Encode the packet into a 48-byte buffer (big-endian).
    #[must_use]
    pub fn encode(&self) -> [u8; NTP_PACKET_MIN_SIZE] {
        let mut buf = [0u8; NTP_PACKET_MIN_SIZE];
        buf[0] = self.li_vn_mode;
        buf[1] = self.stratum;
        buf[2] = self.poll as u8;
        buf[3] = self.precision as u8;
        buf[4..8].copy_from_slice(&self.root_delay.to_be_bytes());
        buf[8..12].copy_from_slice(&self.root_dispersion.to_be_bytes());
        buf[12..16].copy_from_slice(&self.reference_id);
        buf[16..24].copy_from_slice(&self.reference_ts.to_wire());
        buf[24..32].copy_from_slice(&self.origin_ts.to_wire());
        buf[32..40].copy_from_slice(&self.receive_ts.to_wire());
        buf[40..48].copy_from_slice(&self.transmit_ts.to_wire());
        buf
    }
}

// ---------------------------------------------------------------------------
// NTP datagram (with optional authentication)
// ---------------------------------------------------------------------------

/// An NTP datagram as OpenNTPD processes it: either unauthenticated
/// (48 bytes) or authenticated (68 bytes with key ID + digest).
///
/// OpenNTPD rejects any other length.
#[derive(Clone, Debug, PartialEq)]
pub enum NtpDatagram {
    /// 48-byte unauthenticated packet.
    Unauthenticated(NtpPacket),
    /// 68-byte authenticated packet (header + key ID + 16-byte MD5).
    Authenticated {
        /// The NTP packet header.
        packet: NtpPacket,
        /// Key identifier (4 bytes, big-endian u32).
        key_id: u32,
        /// 16-byte MD5 digest.
        digest: [u8; 16],
    },
}

impl NtpDatagram {
    /// Decode a datagram from a byte buffer.
    ///
    /// Returns `None` if the length is not 48 or 68 bytes, or if
    /// the header itself is malformed.
    #[must_use]
    pub fn decode(buf: &[u8]) -> Option<Self> {
        match buf.len() {
            NTP_PACKET_MIN_SIZE => {
                let packet = decode_header(buf)?;
                Some(Self::Unauthenticated(packet))
            }
            NTP_PACKET_AUTH_SIZE => {
                let packet = decode_header(buf)?;
                let key_id = u32::from_be_bytes(buf[48..52].try_into().ok()?);
                let mut digest = [0u8; 16];
                digest.copy_from_slice(&buf[52..68]);
                Some(Self::Authenticated {
                    packet,
                    key_id,
                    digest,
                })
            }
            _ => None,
        }
    }

    /// Encode to bytes.
    #[must_use]
    pub fn encode(&self) -> alloc::vec::Vec<u8> {
        match self {
            Self::Unauthenticated(pkt) => pkt.encode().to_vec(),
            Self::Authenticated {
                packet,
                key_id,
                digest,
            } => {
                let mut buf = packet.encode().to_vec();
                buf.extend_from_slice(&key_id.to_be_bytes());
                buf.extend_from_slice(digest);
                buf
            }
        }
    }
}

/// Decode the 48-byte header from a buffer ≥ 48 bytes.
fn decode_header(buf: &[u8]) -> Option<NtpPacket> {
    Some(NtpPacket {
        li_vn_mode: buf[0],
        stratum: buf[1],
        poll: buf[2] as i8,
        precision: buf[3] as i8,
        root_delay: NtpShortSigned::from_be_bytes(buf[4..8].try_into().ok()?),
        root_dispersion: NtpShortUnsigned::from_be_bytes(buf[8..12].try_into().ok()?),
        reference_id: buf[12..16].try_into().ok()?,
        reference_ts: NtpTimestamp::from_wire(buf[16..24].try_into().ok()?),
        origin_ts: NtpTimestamp::from_wire(buf[24..32].try_into().ok()?),
        receive_ts: NtpTimestamp::from_wire(buf[32..40].try_into().ok()?),
        transmit_ts: NtpTimestamp::from_wire(buf[40..48].try_into().ok()?),
    })
}

// --- Field accessors on NtpPacket ---

impl NtpPacket {
    /// Extract the Leap Indicator (top 2 bits of byte 0).
    #[must_use]
    pub fn leap_indicator(&self) -> u8 {
        self.li_vn_mode >> 6
    }

    /// Extract the Version Number (bits 5..3).
    #[must_use]
    pub fn version(&self) -> u8 {
        (self.li_vn_mode >> 3) & 0x07
    }

    /// Extract the Mode (bottom 3 bits).
    #[must_use]
    pub fn mode(&self) -> u8 {
        self.li_vn_mode & 0x07
    }

    /// Set LI, VN, and Mode in the `li_vn_mode` byte.
    pub fn set_li_vn_mode(&mut self, li: u8, vn: u8, md: u8) {
        self.li_vn_mode = (li << 6) | ((vn & 0x07) << 3) | (md & 0x07);
    }
}

// ---------------------------------------------------------------------------
// Kiss-o'-Death codes
// ---------------------------------------------------------------------------

/// Well-known Kiss-o'-Death reference identifiers.
pub mod kiss {
    /// Rate limit — reduce polling frequency.
    pub const RATE: [u8; 4] = *b"RATE";
    /// Deny access.
    pub const DENY: [u8; 4] = *b"DENY";
    /// Access denied by server.
    pub const RESTRICT: [u8; 4] = *b"RSTR";
    /// Drop — access control violation.
    pub const DROP: [u8; 4] = *b"DROP";
    /// Server has no stratum source.
    pub const NSTR: [u8; 4] = *b"NSTR";

    /// Convenience `u32` variants of the same codes.
    pub mod id {
        /// Rate limit — reduce polling frequency.
        pub const RATE: u32 = u32::from_be_bytes(super::RATE);
        /// Deny access.
        pub const DENY: u32 = u32::from_be_bytes(super::DENY);
        /// Access denied by server.
        pub const RESTRICT: u32 = u32::from_be_bytes(super::RESTRICT);
        /// Drop — access control violation.
        pub const DROP: u32 = u32::from_be_bytes(super::DROP);
        /// Server has no stratum source.
        pub const NSTR: u32 = u32::from_be_bytes(super::NSTR);
    }
}

// ---------------------------------------------------------------------------
// NTP timestamp conversion helpers
// ---------------------------------------------------------------------------

/// Compute an absolute NTP-era offset for a raw seconds value.
///
/// NTP timestamps wrap every 2³² seconds (≈136 years).  The correct
/// era is determined by comparing the raw 32-bit field against an
/// **absolute** reference `now_abs_ntp_secs` (u64, spanning multiple
/// eras).  This is necessary after the 2036 rollover, where the raw
/// `u32` seconds field wraps.
///
/// Returns `None` if no candidate era is within reasonable bounds.
///
/// The algorithm computes the current reference era (`now / 2³²`) and
/// tests three candidates: `ref_era - 1`, `ref_era`, and `ref_era + 1`.
/// This works for any era, not just 0/1.
#[must_use]
pub fn resolve_era(raw_secs: u32, now_abs_ntp_secs: u64) -> Option<u64> {
    let reference_era = now_abs_ntp_secs / NTP_ERA;
    let candidates = [
        reference_era.saturating_sub(1) * NTP_ERA + raw_secs as u64,
        reference_era * NTP_ERA + raw_secs as u64,
        reference_era.saturating_add(1) * NTP_ERA + raw_secs as u64,
    ];
    candidates
        .into_iter()
        .map(|c| (c, c.abs_diff(now_abs_ntp_secs)))
        .min_by(|&(ca, da), &(cb, db)| {
            da.cmp(&db).then_with(|| {
                // When equidistant, prefer same-era candidate
                let era_a = ca / NTP_ERA;
                let era_b = cb / NTP_ERA;
                let ref_era = now_abs_ntp_secs / NTP_ERA;
                (era_a != ref_era).cmp(&(era_b != ref_era))
            })
        })
        .map(|(c, _)| c)
}

/// Convert NTP timestamp to Unix timespec (seconds, nanoseconds),
/// with era resolution against an absolute reference.
///
/// `ntp_secs` and `ntp_frac` are the raw NTP timestamp fields.
/// `now_abs_ntp_secs` is the current absolute NTP time (u64,
/// spanning multiple eras, e.g. from the system clock).
#[must_use]
pub fn ntp_to_unix_era(ntp_secs: u32, ntp_frac: u32, now_abs_ntp_secs: u64) -> Option<(i64, u32)> {
    let abs_secs = resolve_era(ntp_secs, now_abs_ntp_secs)?;
    let unix_secs = abs_secs as i64 - NTP_UNIX_EPOCH_DELTA as i64;
    let nsec = ((u64::from(ntp_frac) * 1_000_000_000) >> 32) as u32;
    Some((unix_secs, nsec))
}

/// Convert NTP timestamp to Unix timespec without era resolution
/// (assumes current era).  For pre-2036 timestamps this is correct.
#[must_use]
pub fn ntp_to_unix(secs: u32, frac: u32) -> (i64, u32) {
    let unix_secs = secs as i64 - NTP_UNIX_EPOCH_DELTA as i64;
    let nsec = ((u64::from(frac) * 1_000_000_000) >> 32) as u32;
    (unix_secs, nsec)
}

/// Convert Unix timespec to NTP timestamp.
#[must_use]
pub fn unix_to_ntp(unix_secs: i64, nsec: u32) -> (u32, u32) {
    let secs = (unix_secs + NTP_UNIX_EPOCH_DELTA as i64) as u32;
    let frac = ((u64::from(nsec) << 32) / 1_000_000_000) as u32;
    (secs, frac)
}

// ---------------------------------------------------------------------------
// Submodules
// ---------------------------------------------------------------------------

pub mod auth;
pub mod broadcast;
pub mod clock;
pub mod engine;
pub mod msg;
pub mod query;

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ntp_timestamp_wire_roundtrip() {
        let ts = NtpTimestamp::new(0x1234_5678, 0x9ABC_DEF0);
        let wire = ts.to_wire();
        let ts2 = NtpTimestamp::from_wire(&wire);
        assert_eq!(ts, ts2);
    }

    #[test]
    fn test_packet_encode_decode_roundtrip() {
        let pkt = NtpPacket {
            li_vn_mode: (li::NO_WARNING << 6) | (NTP_VERSION << 3) | mode::CLIENT,
            stratum: 0,
            poll: 6,
            precision: -10,
            root_delay: NtpShortSigned::new(0, 0),
            root_dispersion: NtpShortUnsigned::new(1, 0),
            reference_id: [0u8; 4],
            reference_ts: NtpTimestamp::zero(),
            origin_ts: NtpTimestamp::new(100, 0),
            receive_ts: NtpTimestamp::zero(),
            transmit_ts: NtpTimestamp::new(200, 0),
        };
        let encoded = pkt.encode();
        let decoded = NtpDatagram::decode(&encoded).unwrap();
        match decoded {
            NtpDatagram::Unauthenticated(d) => assert_eq!(pkt, d),
            _ => panic!("expected unauthenticated"),
        }
    }

    #[test]
    fn test_ntp_to_unix_known_value() {
        // NTP timestamp 0 = 1900-01-01 00:00:00
        let (secs, nsec) = ntp_to_unix(0, 0);
        assert_eq!(secs, -(NTP_UNIX_EPOCH_DELTA as i64));
        assert_eq!(nsec, 0);
    }

    #[test]
    fn test_unix_to_ntp_epoch() {
        let (secs, frac) = unix_to_ntp(0, 0);
        assert_eq!(secs, NTP_UNIX_EPOCH_DELTA as u32);
        assert_eq!(frac, 0);
    }

    #[test]
    fn test_roundtrip_unix_ntp_unix() {
        let test_cases = [
            (0i64, 0u32),
            (1_000_000_000, 0u32),
            (1_000_000_000, 250_000_000),
            (-2_208_988_800, 0),
            (1_700_000_000, 500_000_000),
        ];
        for (unix_secs, nsec) in test_cases {
            let (ntp_s, ntp_f) = unix_to_ntp(unix_secs, nsec);
            let (back_s, back_ns) = ntp_to_unix(ntp_s, ntp_f);
            assert_eq!(back_s, unix_secs);
            let diff = (back_ns as i64 - nsec as i64).abs();
            assert!(diff <= 1, "ns mismatch: got {back_ns}, expected {nsec}");
        }
    }

    #[test]
    fn test_datagram_rejects_bad_lengths() {
        assert!(NtpDatagram::decode(&[0u8; 47]).is_none());
        assert!(NtpDatagram::decode(&[0u8; 49]).is_none());
        assert!(NtpDatagram::decode(&[0u8; 67]).is_none());
        assert!(NtpDatagram::decode(&[0u8; 69]).is_none());
        assert!(NtpDatagram::decode(&[0u8; 100]).is_none());
    }

    #[test]
    fn test_datagram_accepts_48_and_68() {
        assert!(NtpDatagram::decode(&[0u8; 48]).is_some());
        assert!(NtpDatagram::decode(&[0u8; 68]).is_some());
    }

    #[test]
    fn test_authenticated_roundtrip() {
        let pkt = NtpPacket::zero();
        let dgram = NtpDatagram::Authenticated {
            packet: pkt,
            key_id: 42,
            digest: [0xAB; 16],
        };
        let encoded = dgram.encode();
        assert_eq!(encoded.len(), NTP_PACKET_AUTH_SIZE);
        let decoded = NtpDatagram::decode(&encoded).unwrap();
        assert_eq!(dgram, decoded);
    }

    #[test]
    fn test_era_resolution_current_era() {
        // Current absolute NTP time: ~4,095,000,000 (2026-ish)
        let now_abs = 4_095_000_000u64;
        // A timestamp from the same era
        let ts_same = 4_095_000_100u32;
        let resolved = resolve_era(ts_same, now_abs).unwrap();
        assert_eq!(resolved, 4_095_000_100);
    }

    #[test]
    fn test_era_resolution_post_2036() {
        // After the February 2036 rollover, the raw 32-bit NTP field
        // wraps.  Absolute NTP time could be, say, 4_500_000_000 + 2^32.
        // The raw u32 received in the packet is (4_500_000_000 + 2^32) as u32
        // = (4_500_000_000 + 4_294_967_296) as u32 = 8_794_967_296 as u32
        // = 8_794_967_296 - 2^32 = 8_794_967_296 - 4_294_967_296 = 4_500_000_000.
        let now_abs: u64 = NTP_ERA + 100_000_000; // well into era 1
        let packet_raw: u32 = 100_000_000; // the wrapped value
        let resolved = resolve_era(packet_raw, now_abs).unwrap();
        assert_eq!(resolved, NTP_ERA + 100_000_000);
    }

    #[test]
    fn test_era_resolution_previous_era() {
        // If we receive a packet with a timestamp from the previous era
        // (e.g. a 1995 timestamp when the current time is 2026):
        let now_abs: u64 = 4_095_000_000;
        let packet_raw: u32 = 3_000_000_000; // 1995
        let resolved = resolve_era(packet_raw, now_abs).unwrap();
        assert_eq!(resolved, 3_000_000_000);
    }

    #[test]
    fn test_era_resolution_era_boundary_crossing() {
        // Shortly after the 2036 rollover: now_abs is in era 1
        // but the packet was sent just before the rollover (near u32::MAX).
        let now_abs: u64 = NTP_ERA + 100_000; // era 1
        let packet_raw: u32 = u32::MAX - 10_000; // just before rollover, era 0
        let resolved = resolve_era(packet_raw, now_abs).unwrap();
        // Should resolve to era 0, near u32::MAX
        assert_eq!(resolved, 0 + u32::MAX as u64 - 10_000);
    }

    #[test]
    fn test_era_resolution_era_2() {
        // Both reference and packet are in era 2 (far future)
        let now_abs: u64 = 2 * NTP_ERA + 100_000_000;
        let packet_raw: u32 = 100_050_000;
        let resolved = resolve_era(packet_raw, now_abs).unwrap();
        assert_eq!(resolved, 2 * NTP_ERA + 100_050_000);
    }

    // ── Kiss-o'-Death constants ───────────────────────────────────────

    #[test]
    fn test_kiss_rate_code() {
        assert_eq!(kiss::RATE, *b"RATE");
        assert_eq!(kiss::id::RATE, u32::from_be_bytes(*b"RATE"));
    }

    #[test]
    fn test_kiss_deny_code() {
        assert_eq!(kiss::DENY, *b"DENY");
        assert_eq!(kiss::id::DENY, u32::from_be_bytes(*b"DENY"));
    }

    #[test]
    fn test_kiss_restrict_code() {
        assert_eq!(kiss::RESTRICT, *b"RSTR");
        assert_eq!(kiss::id::RESTRICT, u32::from_be_bytes(*b"RSTR"));
    }

    #[test]
    fn test_kiss_drop_code() {
        assert_eq!(kiss::DROP, *b"DROP");
        assert_eq!(kiss::id::DROP, u32::from_be_bytes(*b"DROP"));
    }

    #[test]
    fn test_kiss_nstr_code() {
        assert_eq!(kiss::NSTR, *b"NSTR");
        assert_eq!(kiss::id::NSTR, u32::from_be_bytes(*b"NSTR"));
    }

    #[test]
    fn test_kiss_id_constants_are_distinct() {
        let ids = [
            kiss::id::RATE,
            kiss::id::DENY,
            kiss::id::RESTRICT,
            kiss::id::DROP,
            kiss::id::NSTR,
        ];
        for i in 0..ids.len() {
            for j in (i + 1)..ids.len() {
                assert_ne!(ids[i], ids[j], "kiss codes {i} and {j} should differ");
            }
        }
    }
}
