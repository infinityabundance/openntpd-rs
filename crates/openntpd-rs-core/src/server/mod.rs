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

use crate::ntp::{mode, NtpPacket, NtpShortSigned, NtpShortUnsigned, NtpTimestamp, NTP_VERSION};

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
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ntp::li;
    use crate::ntp::NtpTimestamp;

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
}
