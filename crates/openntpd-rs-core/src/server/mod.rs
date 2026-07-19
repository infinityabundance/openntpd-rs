//! NTP mode 4 server responder — corresponding to OpenNTPD's
//! [`server.c`](https://github.com/openntpd-portable/openntpd-openbsd/blob/master/src/usr.sbin/ntpd/server.c).
//!
//! Handles incoming NTP mode 3 client queries and produces mode 4
//! server responses with correct timestamp exchange semantics.
//!
//! ## Server peer tracking
//!
//! [`ServerPeer`] records per-client state: the raw IP address, the
//! most recent request/receive timestamps, and a cumulative packet
//! count.  This can be used for rate-limiting or access-control
//! policies in higher layers.
//!
//! ## Response construction
//!
//! [`prepare_response`] builds a mode 4 server packet from a mode 3
//! client request and the current system time state.  The timestamp
//! fields are set per RFC 5905 Section 8:
//!
//! | Response field          | Source                                |
//! |-------------------------|---------------------------------------|
//! | Leap Indicator (LI)     | system leap state                     |
//! | Version Number (VN)     | copied from the request               |
//! | Mode                    | 4 (server)                            |
//! | Stratum                 | system stratum                        |
//! | Poll                    | copied from the request               |
//! | Precision               | system precision                      |
//! | Root delay              | system root delay                     |
//! | Root dispersion         | system root dispersion                |
//! | Reference ID            | system reference ID                   |
//! | Reference timestamp     | system reference time                 |
//! | Origin timestamp        | client's transmit timestamp (echoed)  |
//! | Receive timestamp       | time the request was received         |
//! | Transmit timestamp      | time the response is sent             |

use crate::ntp::{
    li, mode, NtpPacket, NtpShortSigned, NtpShortUnsigned, NtpTimestamp, NTP_VERSION,
};

use core::fmt;

// ---------------------------------------------------------------------------
// Server peer tracking
// ---------------------------------------------------------------------------

/// Per-client state for an NTP server peer.
///
/// Each distinct client (identified by its raw IP address) has a
/// [`ServerPeer`] that records the last request and response timestamps
/// alongside a cumulative packet count.
#[derive(Clone, Debug, PartialEq)]
pub struct ServerPeer {
    /// Raw IP address bytes (16 bytes: IPv4 mapped as IPv4-mapped
    /// IPv6, or native IPv6).
    pub address: [u8; 16],
    /// Transmit timestamp of the most recent client request.
    pub last_request: NtpTimestamp,
    /// Transmit timestamp of the most recent server response.
    pub last_response: NtpTimestamp,
    /// Cumulative number of valid packets received from this peer.
    pub packet_count: u64,
}

impl ServerPeer {
    /// Create a new [`ServerPeer`] with the given raw IP address.
    ///
    /// All timestamps are initialised to zero and the packet count
    /// starts at 0.
    #[must_use]
    pub fn new(address: [u8; 16]) -> Self {
        Self {
            address,
            last_request: NtpTimestamp::zero(),
            last_response: NtpTimestamp::zero(),
            packet_count: 0,
        }
    }
}

// ---------------------------------------------------------------------------
// Error type
// ---------------------------------------------------------------------------

/// Errors that can occur when validating or processing an incoming
/// client NTP request.
#[derive(Clone, Debug, PartialEq)]
pub enum ServerError {
    /// The packet's mode field is not [`mode::CLIENT`](crate::ntp::mode::CLIENT).
    WrongMode(u8),
    /// The packet's version number is not recognised (must be 1–4).
    InvalidVersion,
    /// The packet's stratum field is 0, indicating a kiss-o'-death.
    /// The server refuses to respond to kiss-o'-death packets.
    KissOfDeath,
}

impl fmt::Display for ServerError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::WrongMode(m) => write!(f, "wrong mode: expected client (3), got {m}"),
            Self::InvalidVersion => write!(f, "invalid NTP version"),
            Self::KissOfDeath => write!(f, "kiss-o'-death packet (stratum 0)"),
        }
    }
}

// ---------------------------------------------------------------------------
// Validation
// ---------------------------------------------------------------------------

/// Validate an incoming NTP packet for server processing.
///
/// Returns the mode field (always [`mode::CLIENT`](crate::ntp::mode::CLIENT))
/// on success, or a [`ServerError`] describing the rejection.
///
/// # Validation rules
///
/// 1. The mode **must** be [`mode::CLIENT`](crate::ntp::mode::CLIENT) (3).
/// 2. The version **must** be in the range 1–4 (NTPv1 through NTPv4).
/// 3. The stratum **must not** be 0 (kiss-o'-death).
///
/// These checks correspond to OpenNTPD's server input validation in
/// `server.c`.
pub fn validate_client_request(packet: &NtpPacket) -> Result<u8, ServerError> {
    let md = packet.mode();
    if md != mode::CLIENT {
        return Err(ServerError::WrongMode(md));
    }

    let ver = packet.version();
    if ver == 0 || ver > NTP_VERSION {
        return Err(ServerError::InvalidVersion);
    }

    if packet.stratum == 0 {
        return Err(ServerError::KissOfDeath);
    }

    Ok(md)
}

// ---------------------------------------------------------------------------
// Response preparation
// ---------------------------------------------------------------------------

/// Prepare a mode 4 server response to a mode 3 client request.
///
/// Takes the client's request packet, the current receive time, and
/// the system clock state, and produces a response packet with correct
/// timestamps per RFC 5905:
///
/// - **origin timestamp** = client's transmit timestamp (echoed back)
/// - **receive timestamp** = the time the request was received
/// - **transmit timestamp** = the time the response is sent
///
/// When the server responds immediately (within the same processing
/// tick), `recv_time` is used for both the receive and transmit
/// timestamps.
#[must_use]
pub fn prepare_response(
    request: &NtpPacket,
    recv_time: NtpTimestamp,
    system_li: u8,
    system_stratum: u8,
    system_precision: i8,
    system_root_delay: f64,
    system_root_dispersion: f64,
    system_reference_id: u32,
    system_reference_time: NtpTimestamp,
) -> NtpPacket {
    let vn = request.version();

    NtpPacket {
        li_vn_mode: (system_li << 6) | ((vn & 0x07) << 3) | mode::SERVER,
        stratum: system_stratum,
        poll: request.poll,
        precision: system_precision,
        root_delay: f64_to_short_signed(system_root_delay),
        root_dispersion: f64_to_short_unsigned(system_root_dispersion),
        reference_id: system_reference_id.to_be_bytes(),
        reference_ts: system_reference_time,
        origin_ts: request.transmit_ts,
        receive_ts: recv_time,
        transmit_ts: recv_time,
    }
}

// ---------------------------------------------------------------------------
// Internal helpers — f64 ↔ 16.16 fixed-point conversion
// ---------------------------------------------------------------------------

/// Convert an `f64` seconds value to [`NtpShortSigned`] (16.16 signed
/// fixed-point, used for root delay).
fn f64_to_short_signed(v: f64) -> NtpShortSigned {
    // Clamp to the representable range before rounding to avoid
    // overflow in the multiplication → i32 step.
    // The 16.16 signed range is approx [-32768.0, +32767.99998474].
    let clamped = v.clamp(-32768.0, 32767.999_984_741_210_937_5);
    let scaled = libm::round(clamped * 65_536.0) as i32;
    NtpShortSigned::new((scaled >> 16) as i16, (scaled & 0xFFFF) as u16)
}

/// Convert an `f64` seconds value to [`NtpShortUnsigned`] (16.16
/// unsigned fixed-point, used for root dispersion).
fn f64_to_short_unsigned(v: f64) -> NtpShortUnsigned {
    // Clamp to the representable range: [0.0, 65535.99998474].
    let clamped = v.clamp(0.0, 65_535.999_984_741_210_937_5);
    let scaled = libm::round(clamped * 65_536.0) as u32;
    NtpShortUnsigned::new((scaled >> 16) as u16, (scaled & 0xFFFF) as u16)
}

// ---------------------------------------------------------------------------
// Server status (system state for response construction)
// ---------------------------------------------------------------------------

/// System clock status used when building server responses.
///
/// Corresponds to `struct ntp_status` in OpenNTPD's `ntpd.h`.
#[derive(Clone, Debug, PartialEq)]
pub struct ServerStatus {
    /// Whether the clock is synchronized to an upstream source.
    pub synced: bool,
    /// Leap indicator (0–3).
    pub leap: u8,
    /// System stratum (0 = unsynchronized, 1 = primary, 2+ = secondary).
    pub stratum: u8,
    /// System precision in log₂ seconds.
    pub precision: i8,
    /// Reference timestamp (NTP seconds since 1900).
    pub reftime: f64,
    /// Root delay in seconds.
    pub rootdelay: f64,
    /// Reference ID as a `u32`.
    pub refid: u32,
}

impl ServerStatus {
    /// Create a new `ServerStatus` with default (unsynchronized) values.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            synced: false,
            leap: li::ALARM,
            stratum: 0,
            precision: 0,
            reftime: 0.0,
            rootdelay: 0.0,
            refid: 0,
        }
    }
}

impl Default for ServerStatus {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Server dispatch — build mode 4 response
// ---------------------------------------------------------------------------

/// Dispatch an incoming server query and build the appropriate mode 4
/// (server) or mode 2 (symmetric passive) response.
///
/// Corresponds to OpenNTPD's `server_dispatch()` in `server.c`.
///
/// # Logic (matching C source)
///
/// 1. If the system is **not** synchronized, set LI = ALARM (3).
/// 2. Copy the version number from the request.
/// 3. If the request is `MODE_CLIENT` (3), respond with `MODE_SERVER` (4).
/// 4. If the request is `MODE_SYM_ACT` (1), respond with `MODE_SYM_PAS` (2).
/// 5. For any other mode, return `None` (packet is ignored).
/// 6. Fill response fields from `ServerStatus`.
#[must_use]
pub fn server_dispatch(
    request: &NtpPacket,
    recv_time: f64,
    system_status: &ServerStatus,
) -> Option<NtpPacket> {
    let req_mode = request.mode();
    let resp_mode = match req_mode {
        mode::CLIENT => mode::SERVER,
        mode::SYMMETRIC_ACTIVE => mode::SYMMETRIC_PASSIVE,
        _ => return None, // ignore all other modes (e.g. broadcast)
    };

    let leap = if system_status.synced {
        system_status.leap
    } else {
        li::ALARM
    };

    let vn = request.version();

    let response = NtpPacket {
        li_vn_mode: (leap << 6) | ((vn & 0x07) << 3) | resp_mode,
        stratum: system_status.stratum,
        poll: request.poll,
        precision: system_status.precision,
        root_delay: f64_to_short_signed(system_status.rootdelay),
        root_dispersion: f64_to_short_unsigned(0.0),
        reference_id: system_status.refid.to_be_bytes(),
        reference_ts: NtpTimestamp::from_f64(system_status.reftime),
        origin_ts: request.transmit_ts,
        receive_ts: NtpTimestamp::from_f64(recv_time),
        transmit_ts: NtpTimestamp::from_f64(recv_time),
    };

    Some(response)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ntp::{li, mode, NtpTimestamp, NTP_VERSION};

    // -----------------------------------------------------------------------
    // ServerPeer tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_server_peer_new_defaults() {
        let addr = [0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
        let peer = ServerPeer::new(addr);
        assert_eq!(peer.address, addr);
        assert_eq!(peer.last_request, NtpTimestamp::zero());
        assert_eq!(peer.last_response, NtpTimestamp::zero());
        assert_eq!(peer.packet_count, 0);
    }

    #[test]
    fn test_server_peer_tracks_usage() {
        let addr = [0; 16];
        let mut peer = ServerPeer::new(addr);

        peer.last_request = NtpTimestamp::new(1_000_000, 500_000);
        peer.last_response = NtpTimestamp::new(1_000_001, 0);
        peer.packet_count = 42;

        assert_eq!(peer.last_request.secs, 1_000_000);
        assert_eq!(peer.last_response.frac, 0);
        assert_eq!(peer.packet_count, 42);
    }

    // -----------------------------------------------------------------------
    // Validation tests
    // -----------------------------------------------------------------------

    fn make_client_packet(vn: u8, stratum: u8) -> NtpPacket {
        let mut pkt = NtpPacket::zero();
        pkt.set_li_vn_mode(li::NO_WARNING, vn, mode::CLIENT);
        pkt.stratum = stratum;
        pkt
    }

    #[test]
    fn test_validate_valid_client_request() {
        let pkt = make_client_packet(NTP_VERSION, 3);
        let result = validate_client_request(&pkt);
        assert_eq!(result, Ok(mode::CLIENT));
    }

    #[test]
    fn test_validate_valid_ntpv3_request() {
        let pkt = make_client_packet(3, 2);
        let result = validate_client_request(&pkt);
        assert_eq!(result, Ok(mode::CLIENT));
    }

    #[test]
    fn test_validate_rejects_wrong_mode() {
        // Symmetric active — not a client request
        let mut pkt = NtpPacket::zero();
        pkt.set_li_vn_mode(li::NO_WARNING, NTP_VERSION, mode::SYMMETRIC_ACTIVE);
        pkt.stratum = 3;
        let result = validate_client_request(&pkt);
        assert_eq!(result, Err(ServerError::WrongMode(mode::SYMMETRIC_ACTIVE)));
    }

    #[test]
    fn test_validate_rejects_server_mode() {
        let mut pkt = NtpPacket::zero();
        pkt.set_li_vn_mode(li::NO_WARNING, NTP_VERSION, mode::SERVER);
        pkt.stratum = 3;
        let result = validate_client_request(&pkt);
        assert_eq!(result, Err(ServerError::WrongMode(mode::SERVER)));
    }

    #[test]
    fn test_validate_rejects_broadcast() {
        let mut pkt = NtpPacket::zero();
        pkt.set_li_vn_mode(li::NO_WARNING, NTP_VERSION, mode::BROADCAST);
        pkt.stratum = 3;
        let result = validate_client_request(&pkt);
        assert_eq!(result, Err(ServerError::WrongMode(mode::BROADCAST)));
    }

    #[test]
    fn test_validate_rejects_control() {
        let mut pkt = NtpPacket::zero();
        pkt.set_li_vn_mode(li::NO_WARNING, NTP_VERSION, mode::CONTROL);
        pkt.stratum = 3;
        let result = validate_client_request(&pkt);
        assert_eq!(result, Err(ServerError::WrongMode(mode::CONTROL)));
    }

    #[test]
    fn test_validate_rejects_private() {
        let mut pkt = NtpPacket::zero();
        pkt.set_li_vn_mode(li::NO_WARNING, NTP_VERSION, mode::PRIVATE);
        pkt.stratum = 3;
        let result = validate_client_request(&pkt);
        assert_eq!(result, Err(ServerError::WrongMode(mode::PRIVATE)));
    }

    #[test]
    fn test_validate_rejects_reserved_mode() {
        let mut pkt = NtpPacket::zero();
        pkt.set_li_vn_mode(li::NO_WARNING, NTP_VERSION, mode::RESERVED);
        pkt.stratum = 3;
        let result = validate_client_request(&pkt);
        assert_eq!(result, Err(ServerError::WrongMode(mode::RESERVED)));
    }

    #[test]
    fn test_validate_rejects_version_zero() {
        let pkt = make_client_packet(0, 3);
        let result = validate_client_request(&pkt);
        assert_eq!(result, Err(ServerError::InvalidVersion));
    }

    #[test]
    fn test_validate_rejects_version_five() {
        let pkt = make_client_packet(5, 3);
        let result = validate_client_request(&pkt);
        assert_eq!(result, Err(ServerError::InvalidVersion));
    }

    #[test]
    fn test_validate_rejects_kiss_of_death() {
        let pkt = make_client_packet(NTP_VERSION, 0);
        let result = validate_client_request(&pkt);
        assert_eq!(result, Err(ServerError::KissOfDeath));
    }

    // -----------------------------------------------------------------------
    // Response preparation tests
    // -----------------------------------------------------------------------

    /// Build a minimal client request with a given transmit timestamp.
    fn client_request(vn: u8, stratum: u8, poll: i8, xmit_ts: NtpTimestamp) -> NtpPacket {
        let mut pkt = NtpPacket::zero();
        pkt.set_li_vn_mode(li::NO_WARNING, vn, mode::CLIENT);
        pkt.stratum = stratum;
        pkt.poll = poll;
        pkt.transmit_ts = xmit_ts;
        pkt
    }

    #[test]
    fn test_prepare_response_basic() {
        let client_xmit = NtpTimestamp::new(1_000_000, 123_456);
        let recv_time = NtpTimestamp::new(1_000_001, 654_321);
        let ref_time = NtpTimestamp::new(999_000, 0);

        let req = client_request(NTP_VERSION, 3, 6, client_xmit);

        let resp = prepare_response(
            &req,
            recv_time,
            li::NO_WARNING, // system LI
            2,              // system stratum (stratum 2 = secondary, GPS)
            -18,            // system precision
            0.025,          // system root delay (25 ms)
            0.001,          // system root dispersion (1 ms)
            0x47505300,     // reference ID "GPS\0" in big-endian
            ref_time,
        );

        // LI+VM+Mode: LI=NO_WARNING, VN=4, Mode=SERVER
        assert_eq!(resp.leap_indicator(), li::NO_WARNING);
        assert_eq!(resp.version(), NTP_VERSION);
        assert_eq!(resp.mode(), mode::SERVER);

        // Stratum/poll/precision
        assert_eq!(resp.stratum, 2);
        assert_eq!(resp.poll, 6);
        assert_eq!(resp.precision, -18);

        // Root delay and dispersion (approximate f64 comparisons)
        let delay = resp.root_delay.to_f64();
        assert!(
            (delay - 0.025).abs() < 0.000_02,
            "root delay mismatch: {delay}"
        );
        let disp = resp.root_dispersion.to_f64();
        assert!(
            (disp - 0.001).abs() < 0.000_02,
            "root dispersion mismatch: {disp}"
        );

        // Reference ID: u32 big-endian → [u8; 4]
        assert_eq!(resp.reference_id, [0x47, 0x50, 0x53, 0x00]);

        // Reference timestamp
        assert_eq!(resp.reference_ts, ref_time);

        // Timestamp correctness per RFC 5905 Section 8
        assert_eq!(
            resp.origin_ts, client_xmit,
            "origin timestamp must echo client's transmit timestamp"
        );
        assert_eq!(
            resp.receive_ts, recv_time,
            "receive timestamp must equal recv_time"
        );
        assert_eq!(
            resp.transmit_ts, recv_time,
            "transmit timestamp must equal recv_time (immediate response)"
        );
    }

    #[test]
    fn test_prepare_response_version_propagated() {
        // NTPv3 client -> server should respond with VN=3
        let req = client_request(3, 3, 6, NtpTimestamp::new(100, 0));
        let resp = prepare_response(
            &req,
            NtpTimestamp::new(200, 0),
            li::NO_WARNING,
            2,
            -20,
            0.0,
            0.0,
            0,
            NtpTimestamp::zero(),
        );
        assert_eq!(resp.version(), 3);
        assert_eq!(resp.mode(), mode::SERVER);
    }

    #[test]
    fn test_prepare_response_stratum_propagated() {
        // Primary server (stratum 1)
        let req = client_request(NTP_VERSION, 3, 6, NtpTimestamp::new(100, 0));
        let resp = prepare_response(
            &req,
            NtpTimestamp::new(200, 0),
            li::NO_WARNING,
            1,
            -20,
            0.0,
            0.0,
            0x50505300, // "PPS\0"
            NtpTimestamp::new(500, 0),
        );
        assert_eq!(resp.stratum, 1);
        assert_eq!(resp.reference_id, [0x50, 0x50, 0x53, 0x00]);
    }

    #[test]
    fn test_prepare_response_poll_reflects_request() {
        let req = client_request(NTP_VERSION, 3, 10, NtpTimestamp::new(100, 0));
        let resp = prepare_response(
            &req,
            NtpTimestamp::new(200, 0),
            li::NO_WARNING,
            2,
            -18,
            0.0,
            0.0,
            0,
            NtpTimestamp::zero(),
        );
        // Server echoes the client's poll value
        assert_eq!(resp.poll, 10);
    }

    #[test]
    fn test_prepare_response_alarm_state() {
        // When the system clock is unsynchronized, LI = ALARM
        let req = client_request(NTP_VERSION, 3, 6, NtpTimestamp::new(100, 0));
        let resp = prepare_response(
            &req,
            NtpTimestamp::new(200, 0),
            li::ALARM,
            0, // stratum 0 when unsynchronized
            0,
            0.0,
            0.0,
            0,
            NtpTimestamp::zero(),
        );
        assert_eq!(resp.leap_indicator(), li::ALARM);
        assert_eq!(resp.stratum, 0);
    }

    // -----------------------------------------------------------------------
    // Timestamp correctness — detailed multi-request scenario
    // -----------------------------------------------------------------------

    #[test]
    fn test_prepare_response_timestamp_independence() {
        // Two consecutive requests with different xmit timestamps
        // must produce responses with the correct per-request echo.
        let recv_a = NtpTimestamp::new(10_000, 100_000);
        let recv_b = NtpTimestamp::new(10_001, 200_000);
        let xmit_a = NtpTimestamp::new(9_000, 500_000);
        let xmit_b = NtpTimestamp::new(9_010, 750_000);

        let req_a = client_request(NTP_VERSION, 3, 6, xmit_a);
        let req_b = client_request(NTP_VERSION, 3, 6, xmit_b);

        let resp_a = prepare_response(
            &req_a,
            recv_a,
            li::NO_WARNING,
            2,
            -18,
            0.05,
            0.002,
            0x47505300,
            NtpTimestamp::new(8_000, 0),
        );
        let resp_b = prepare_response(
            &req_b,
            recv_b,
            li::NO_WARNING,
            2,
            -18,
            0.05,
            0.002,
            0x47505300,
            NtpTimestamp::new(8_000, 0),
        );

        // Each response echoes its own request's xmit timestamp
        assert_eq!(resp_a.origin_ts, xmit_a);
        assert_eq!(resp_b.origin_ts, xmit_b);

        // Each response has its own receive/transmit timestamps
        assert_eq!(resp_a.receive_ts, recv_a);
        assert_eq!(resp_a.transmit_ts, recv_a);
        assert_eq!(resp_b.receive_ts, recv_b);
        assert_eq!(resp_b.transmit_ts, recv_b);

        // Responses must not be identical
        assert_ne!(resp_a.origin_ts, resp_b.origin_ts);
        assert_ne!(resp_a.receive_ts, resp_b.receive_ts);
        assert_ne!(resp_a.transmit_ts, resp_b.transmit_ts);
    }

    // -----------------------------------------------------------------------
    // End-to-end request/response matching (with validation)
    // -----------------------------------------------------------------------

    #[test]
    fn test_request_response_roundtrip() {
        let client_xmit = NtpTimestamp::new(42_000_000, 123_456_789);
        let recv_time = NtpTimestamp::new(42_000_001, 987_654_321);

        let mut req = NtpPacket::zero();
        req.set_li_vn_mode(li::NO_WARNING, NTP_VERSION, mode::CLIENT);
        req.stratum = 3;
        req.poll = 6;
        req.precision = -18;
        req.transmit_ts = client_xmit;

        // Validate
        assert_eq!(validate_client_request(&req), Ok(mode::CLIENT));

        // Prepare response
        let resp = prepare_response(
            &req,
            recv_time,
            li::NO_WARNING,
            2,
            -20,
            0.015_625,   // 1/64 second
            0.007_812_5, // 1/128 second
            0x4C4F434C,  // "LOCL"
            NtpTimestamp::new(41_900_000, 0),
        );

        // The response must be a valid server packet
        assert_eq!(resp.leap_indicator(), li::NO_WARNING);
        assert_eq!(resp.version(), NTP_VERSION);
        assert_eq!(resp.mode(), mode::SERVER);
        assert_eq!(resp.stratum, 2);
        assert_eq!(resp.poll, 6);
        assert_eq!(resp.precision, -20);

        // Verify wire-format roundtrip
        let encoded = resp.encode();
        let decoded = crate::ntp::NtpDatagram::decode(&encoded).unwrap();
        match decoded {
            crate::ntp::NtpDatagram::Unauthenticated(p) => assert_eq!(p, resp),
            _ => panic!("expected unauthenticated"),
        }
    }

    // -----------------------------------------------------------------------
    // Edge cases: zero timestamps, boundary values
    // -----------------------------------------------------------------------

    #[test]
    fn test_prepare_response_zero_timestamps() {
        // Client sends a packet with zero transmit timestamp
        let req = client_request(NTP_VERSION, 3, 6, NtpTimestamp::zero());
        let recv_time = NtpTimestamp::new(1, 0);

        let resp = prepare_response(
            &req,
            recv_time,
            li::NO_WARNING,
            2,
            -18,
            0.0,
            0.0,
            0,
            NtpTimestamp::zero(),
        );

        // Zero origin is still echoed correctly
        assert_eq!(resp.origin_ts, NtpTimestamp::zero());
    }

    #[test]
    fn test_prepare_response_large_root_delay() {
        let req = client_request(NTP_VERSION, 3, 6, NtpTimestamp::new(100, 0));
        let resp = prepare_response(
            &req,
            NtpTimestamp::new(200, 0),
            li::NO_WARNING,
            2,
            -18,
            0.5, // 500 ms — well within range
            0.25,
            0,
            NtpTimestamp::zero(),
        );

        let delay = resp.root_delay.to_f64();
        assert!((delay - 0.5).abs() < 0.000_02);

        let disp = resp.root_dispersion.to_f64();
        assert!((disp - 0.25).abs() < 0.000_02);
    }

    #[test]
    fn test_prepare_response_negative_root_delay() {
        // Root delay can be negative in some pathological cases
        let req = client_request(NTP_VERSION, 3, 6, NtpTimestamp::new(100, 0));
        let resp = prepare_response(
            &req,
            NtpTimestamp::new(200, 0),
            li::NO_WARNING,
            2,
            -18,
            -0.001, // -1 ms
            0.0,
            0,
            NtpTimestamp::zero(),
        );

        let delay = resp.root_delay.to_f64();
        assert!(
            (delay - (-0.001)).abs() < 0.000_02,
            "negative root delay mismatch: {delay}"
        );
    }

    // -----------------------------------------------------------------------
    // KN stratus / reference ID propagation
    // -----------------------------------------------------------------------

    #[test]
    fn test_prepare_response_reference_id_known_codes() {
        let known_ids = [
            (0x41434F4Du32, "ACOM"),  // "ACOM"
            (0x43445349u32, "CDSI"),  // "CDSI"
            (0x44474553u32, "DGES"),  // "DGES"
            (0x47505300u32, "GPS\0"), // GPS
            (0x474F4553u32, "GOES"),  // GOES
            (0x484F4F4Du32, "HOOM"),  // "HOOM" (stratum 1)
            (0x49424D43u32, "IBMC"),  // "IBMC"
            (0x4C4F434Cu32, "LOCL"),  // local clock
            (0x4C4F4D53u32, "LOMS"),  // "LOMS"
            (0x50505300u32, "PPS\0"), // PPS
            (0x50545342u32, "PTSB"),  // "PTSB"
            (0x53504253u32, "SPBS"),  // "SPBS"
            (0x54465400u32, "TFT\0"), // "TFT\0" (Stratum 0)
            (0x55544300u32, "UTC\0"), // UTC
            (0x57575656u32, "WWVV"),  // "WWVV"
        ];

        for (id_bytes, expected_str) in known_ids {
            let req = client_request(NTP_VERSION, 3, 6, NtpTimestamp::new(100, 0));
            let resp = prepare_response(
                &req,
                NtpTimestamp::new(200, 0),
                li::NO_WARNING,
                2,
                -18,
                0.0,
                0.0,
                id_bytes,
                NtpTimestamp::zero(),
            );
            assert_eq!(
                &resp.reference_id,
                expected_str.as_bytes(),
                "reference ID mismatch for {expected_str}"
            );
        }
    }

    // -----------------------------------------------------------------------
    // Server peer tracking with request processing
    // -----------------------------------------------------------------------

    #[test]
    fn test_peer_tracking_multiple_requests() {
        let addr_a = [0x20, 0x01, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
        let addr_b = [0x20, 0x01, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2];

        let mut peer_a = ServerPeer::new(addr_a);
        let mut peer_b = ServerPeer::new(addr_b);

        // Simulate request 1 from peer_a
        let req_a1 = client_request(NTP_VERSION, 3, 6, NtpTimestamp::new(1_000, 0));
        let recv_a1 = NtpTimestamp::new(1_001, 0);
        let _resp_a1 = prepare_response(
            &req_a1,
            recv_a1,
            li::NO_WARNING,
            2,
            -18,
            0.05,
            0.001,
            0x47505300,
            NtpTimestamp::new(900, 0),
        );
        peer_a.last_request = req_a1.transmit_ts;
        peer_a.last_response = recv_a1;
        peer_a.packet_count += 1;

        assert_eq!(peer_a.packet_count, 1);
        assert_eq!(peer_a.last_request, NtpTimestamp::new(1_000, 0));
        assert_eq!(peer_a.last_response, NtpTimestamp::new(1_001, 0));

        // Simulate request 1 from peer_b
        let req_b1 = client_request(NTP_VERSION, 3, 6, NtpTimestamp::new(2_000, 0));
        let recv_b1 = NtpTimestamp::new(2_001, 0);
        let _resp_b1 = prepare_response(
            &req_b1,
            recv_b1,
            li::NO_WARNING,
            2,
            -18,
            0.05,
            0.001,
            0x47505300,
            NtpTimestamp::new(900, 0),
        );
        peer_b.last_request = req_b1.transmit_ts;
        peer_b.last_response = recv_b1;
        peer_b.packet_count += 1;

        assert_eq!(peer_b.packet_count, 1);

        // Simulate request 2 from peer_a
        let req_a2 = client_request(NTP_VERSION, 3, 6, NtpTimestamp::new(3_000, 0));
        let recv_a2 = NtpTimestamp::new(3_001, 0);
        let _resp_a2 = prepare_response(
            &req_a2,
            recv_a2,
            li::NO_WARNING,
            2,
            -18,
            0.05,
            0.001,
            0x47505300,
            NtpTimestamp::new(900, 0),
        );
        peer_a.last_request = req_a2.transmit_ts;
        peer_a.last_response = recv_a2;
        peer_a.packet_count += 1;

        assert_eq!(peer_a.packet_count, 2);
        assert_eq!(peer_a.last_request, NtpTimestamp::new(3_000, 0));
        assert_eq!(peer_a.last_response, NtpTimestamp::new(3_001, 0));

        // peer_b should be unchanged
        assert_eq!(peer_b.packet_count, 1);
        assert_eq!(peer_b.last_request, NtpTimestamp::new(2_000, 0));

        // Peers are distinct objects
        assert_ne!(peer_a, peer_b);
    }

    // -----------------------------------------------------------------------
    // Error display
    // -----------------------------------------------------------------------

    #[test]
    fn test_server_error_display() {
        let err = ServerError::WrongMode(mode::SYMMETRIC_ACTIVE);
        let msg = alloc::format!("{err}");
        assert!(msg.contains("wrong mode"));
        assert!(msg.contains("1")); // SYMMETRIC_ACTIVE = 1

        let err = ServerError::InvalidVersion;
        let msg = alloc::format!("{err}");
        assert!(msg.contains("invalid NTP version"));

        let err = ServerError::KissOfDeath;
        let msg = alloc::format!("{err}");
        assert!(msg.contains("kiss-o'-death"));
    }

    // -----------------------------------------------------------------------
    // ServerStatus tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_server_status_defaults() {
        let status = ServerStatus::new();
        assert!(!status.synced);
        assert_eq!(status.leap, li::ALARM);
        assert_eq!(status.stratum, 0);
        assert_eq!(status.precision, 0);
        assert_eq!(status.reftime, 0.0);
        assert_eq!(status.rootdelay, 0.0);
        assert_eq!(status.refid, 0);
    }

    #[test]
    fn test_server_status_default_impl() {
        let status = ServerStatus::default();
        assert_eq!(status.synced, ServerStatus::new().synced);
    }

    #[test]
    fn test_server_status_custom() {
        let status = ServerStatus {
            synced: true,
            leap: li::NO_WARNING,
            stratum: 2,
            precision: -18,
            reftime: 3_900_000_000.0,
            rootdelay: 0.025,
            refid: 0x47505300,
        };
        assert!(status.synced);
        assert_eq!(status.leap, 0);
        assert_eq!(status.stratum, 2);
    }

    // -----------------------------------------------------------------------
    // server_dispatch tests
    // -----------------------------------------------------------------------

    /// Build a minimal client request.
    fn make_request(vn: u8, md: u8, poll: i8, xmit_secs: u32) -> NtpPacket {
        let mut pkt = NtpPacket::zero();
        pkt.set_li_vn_mode(li::NO_WARNING, vn, md);
        pkt.stratum = 3;
        pkt.poll = poll;
        pkt.precision = -18;
        pkt.transmit_ts = NtpTimestamp::new(xmit_secs, 0);
        pkt
    }

    fn synced_status() -> ServerStatus {
        ServerStatus {
            synced: true,
            leap: li::NO_WARNING,
            stratum: 2,
            precision: -20,
            reftime: 3_900_000_000.0,
            rootdelay: 0.015,
            refid: 0x47505300,
        }
    }

    #[test]
    fn test_server_dispatch_mode_client() {
        let req = make_request(NTP_VERSION, mode::CLIENT, 6, 1_000_000);
        let status = synced_status();
        let resp = server_dispatch(&req, 1_000_001.5, &status).unwrap();

        assert_eq!(resp.mode(), mode::SERVER);
        assert_eq!(resp.version(), NTP_VERSION);
        assert_eq!(resp.leap_indicator(), li::NO_WARNING);
        assert_eq!(resp.stratum, 2);
        assert_eq!(resp.poll, 6);
        assert_eq!(resp.precision, -20);
        // Origin echoes client's transmit timestamp
        assert_eq!(resp.origin_ts, req.transmit_ts);
    }

    #[test]
    fn test_server_dispatch_mode_symmetric_active() {
        let req = make_request(NTP_VERSION, mode::SYMMETRIC_ACTIVE, 6, 1_000_000);
        let status = synced_status();
        let resp = server_dispatch(&req, 1_000_001.5, &status).unwrap();

        assert_eq!(resp.mode(), mode::SYMMETRIC_PASSIVE);
        assert_eq!(resp.version(), NTP_VERSION);
    }

    #[test]
    fn test_server_dispatch_alarm_when_unsynced() {
        let req = make_request(NTP_VERSION, mode::CLIENT, 6, 1_000_000);
        let status = ServerStatus::new(); // unsynced by default
        let resp = server_dispatch(&req, 1_000_001.5, &status).unwrap();

        assert_eq!(resp.leap_indicator(), li::ALARM);
        assert_eq!(resp.stratum, 0);
    }

    #[test]
    fn test_server_dispatch_ignores_broadcast() {
        let req = make_request(NTP_VERSION, mode::BROADCAST, 6, 1_000_000);
        let status = synced_status();
        assert!(server_dispatch(&req, 1_000_001.5, &status).is_none());
    }

    #[test]
    fn test_server_dispatch_ignores_control() {
        let req = make_request(NTP_VERSION, mode::CONTROL, 6, 1_000_000);
        let status = synced_status();
        assert!(server_dispatch(&req, 1_000_001.5, &status).is_none());
    }

    #[test]
    fn test_server_dispatch_ignores_private() {
        let req = make_request(NTP_VERSION, mode::PRIVATE, 6, 1_000_000);
        let status = synced_status();
        assert!(server_dispatch(&req, 1_000_001.5, &status).is_none());
    }

    #[test]
    fn test_server_dispatch_ignores_server_mode() {
        let req = make_request(NTP_VERSION, mode::SERVER, 6, 1_000_000);
        let status = synced_status();
        assert!(server_dispatch(&req, 1_000_001.5, &status).is_none());
    }

    #[test]
    fn test_server_dispatch_version_propagated_v3() {
        let req = make_request(3, mode::CLIENT, 6, 1_000_000);
        let status = synced_status();
        let resp = server_dispatch(&req, 1_000_001.5, &status).unwrap();
        assert_eq!(resp.version(), 3);
    }

    #[test]
    fn test_server_dispatch_version_propagated_v4() {
        let req = make_request(NTP_VERSION, mode::CLIENT, 6, 1_000_000);
        let status = synced_status();
        let resp = server_dispatch(&req, 1_000_001.5, &status).unwrap();
        assert_eq!(resp.version(), NTP_VERSION);
    }

    #[test]
    fn test_server_dispatch_root_delay_propagated() {
        let req = make_request(NTP_VERSION, mode::CLIENT, 6, 1_000_000);
        let status = ServerStatus {
            synced: true,
            leap: li::NO_WARNING,
            stratum: 2,
            precision: -20,
            reftime: 3_900_000_000.0,
            rootdelay: 0.125,
            refid: 0x47505300,
        };
        let resp = server_dispatch(&req, 1_000_001.5, &status).unwrap();
        let delay = resp.root_delay.to_f64();
        assert!((delay - 0.125).abs() < 0.000_02);
    }

    #[test]
    fn test_server_dispatch_refid_propagated() {
        let req = make_request(NTP_VERSION, mode::CLIENT, 6, 1_000_000);
        let status = ServerStatus {
            synced: true,
            leap: li::NO_WARNING,
            stratum: 2,
            precision: -20,
            reftime: 3_900_000_000.0,
            rootdelay: 0.015,
            refid: 0x4C4F434C, // "LOCL"
        };
        let resp = server_dispatch(&req, 1_000_001.5, &status).unwrap();
        assert_eq!(resp.reference_id, [0x4C, 0x4F, 0x43, 0x4C]);
    }

    #[test]
    fn test_server_dispatch_refid_zero() {
        let req = make_request(NTP_VERSION, mode::CLIENT, 6, 1_000_000);
        let status = ServerStatus {
            synced: true,
            leap: li::NO_WARNING,
            stratum: 1,
            precision: -20,
            reftime: 3_900_000_000.0,
            rootdelay: 0.0,
            refid: 0,
        };
        let resp = server_dispatch(&req, 1_000_001.5, &status).unwrap();
        assert_eq!(resp.reference_id, [0, 0, 0, 0]);
    }

    #[test]
    fn test_server_dispatch_precision_propagated() {
        let req = make_request(NTP_VERSION, mode::CLIENT, 6, 1_000_000);
        let status = ServerStatus {
            synced: true,
            leap: li::NO_WARNING,
            stratum: 2,
            precision: -18,
            reftime: 3_900_000_000.0,
            rootdelay: 0.015,
            refid: 0,
        };
        let resp = server_dispatch(&req, 1_000_001.5, &status).unwrap();
        assert_eq!(resp.precision, -18);
    }

    #[test]
    fn test_server_dispatch_reftime_propagated() {
        let req = make_request(NTP_VERSION, mode::CLIENT, 6, 1_000_000);
        let status = ServerStatus {
            synced: true,
            leap: li::NO_WARNING,
            stratum: 2,
            precision: -20,
            reftime: 3_900_000_000.5,
            rootdelay: 0.015,
            refid: 0x47505300,
        };
        let resp = server_dispatch(&req, 1_000_001.5, &status).unwrap();
        // The reference timestamp is written as NtpTimestamp
        let ref_ts = resp.reference_ts.to_f64();
        assert!((ref_ts - 3_900_000_000.5).abs() < 0.001);
    }

    #[test]
    fn test_server_dispatch_origin_echo() {
        let req = make_request(NTP_VERSION, mode::CLIENT, 6, 42_000_000);
        let status = synced_status();
        let resp = server_dispatch(&req, 1_000_001.5, &status).unwrap();
        // Origin timestamp must echo client's transmit timestamp
        assert_eq!(resp.origin_ts, req.transmit_ts);
    }

    #[test]
    fn test_server_dispatch_receive_transmit_timestamps() {
        let req = make_request(NTP_VERSION, mode::CLIENT, 6, 1_000_000);
        let status = synced_status();
        let resp = server_dispatch(&req, 1_000_001.5, &status).unwrap();
        // Receive and transmit timestamps are set to recv_time
        let recv = resp.receive_ts.to_f64();
        let xmit = resp.transmit_ts.to_f64();
        assert!((recv - 1_000_001.5).abs() < 0.001);
        assert!((xmit - 1_000_001.5).abs() < 0.001);
    }

    // -----------------------------------------------------------------------
    // Edge cases for server_dispatch
    // -----------------------------------------------------------------------

    #[test]
    fn test_server_dispatch_mode_reserved_ignored() {
        let req = make_request(NTP_VERSION, mode::RESERVED, 6, 1_000_000);
        let status = synced_status();
        assert!(server_dispatch(&req, 1_000_001.5, &status).is_none());
    }

    #[test]
    fn test_server_dispatch_unsynced_leap_alarm_propagates() {
        // Even with synced=false and a custom leap value, LI must be ALARM
        let req = make_request(NTP_VERSION, mode::CLIENT, 6, 1_000_000);
        let status = ServerStatus {
            synced: false,
            leap: li::NO_WARNING, // would be NO_WARNING, but overridden
            stratum: 0,
            precision: -20,
            reftime: 0.0,
            rootdelay: 0.0,
            refid: 0,
        };
        let resp = server_dispatch(&req, 1_000_001.5, &status).unwrap();
        assert_eq!(resp.leap_indicator(), li::ALARM);
    }

    // -----------------------------------------------------------------------
    // Roundtrip: validate_client_request + server_dispatch
    // -----------------------------------------------------------------------

    #[test]
    fn test_validate_and_dispatch_roundtrip() {
        let mut req = NtpPacket::zero();
        req.set_li_vn_mode(li::NO_WARNING, NTP_VERSION, mode::CLIENT);
        req.stratum = 3;
        req.poll = 6;
        req.precision = -18;
        req.transmit_ts = NtpTimestamp::new(42_000_000, 123_456_789);

        // Validate first
        assert_eq!(validate_client_request(&req), Ok(mode::CLIENT));

        // Dispatch
        let status = synced_status();
        let resp = server_dispatch(&req, 42_000_001.987, &status).unwrap();

        // Verify response
        assert_eq!(resp.mode(), mode::SERVER);
        assert_eq!(resp.version(), NTP_VERSION);
        assert_eq!(resp.leap_indicator(), li::NO_WARNING);
        assert_eq!(resp.stratum, 2);

        // Wire-format roundtrip
        let encoded = resp.encode();
        let decoded = crate::ntp::NtpDatagram::decode(&encoded).unwrap();
        match decoded {
            crate::ntp::NtpDatagram::Unauthenticated(p) => assert_eq!(p, resp),
            _ => panic!("expected unauthenticated"),
        }
    }
}
