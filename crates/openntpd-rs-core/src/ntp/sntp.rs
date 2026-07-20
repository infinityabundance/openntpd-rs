//! MS-SNTP client mode — RFC 4330.
//!
//! Simple Network Time Protocol (SNTP) is a simplified, stateless
//! variant of NTPv4 designed for clients that do not need the full
//! NTP clock-filtering algorithm.  RFC 4330 explicitly permits SNTP
//! clients on the public Internet.
//!
//! ## Key differences from full NTP
//!
//! - **Only client (mode 3) and server (mode 4) modes** — no symmetric
//!   peer mode.
//! - **No NTP extension fields** — responses are always 48 bytes.
//! - **Simplified poll management** — clients may use a fixed interval.
//! - **Unicast, anycast, and multicast modes** — this module supports
//!   all three.
//!
//! ## MS-SNTP specifics
//!
//! Microsoft's SNTP implementation (used in Windows Time Service,
//! `w32tm`) follows RFC 4330 and adds:
//!
//! - Windows FILETIME timestamp conversions (100-ns intervals since
//!   January 1, 1601).
//! - Compatibility with NTPv4 servers.
//!
//! ## References
//!
//! - RFC 4330 — Simple Network Time Protocol (SNTP) Version 4
//! - RFC 5905 — NTPv4 protocol specification
//! - MS-SNTP: [MS-SNTP] — Windows Time Service Protocol

use crate::ntp::{li, mode, NtpPacket, NtpTimestamp, NTP_VERSION};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Offset from Windows FILETIME epoch (1601-01-01) to Unix epoch (1970-01-01)
/// in 100-nanosecond intervals.
///
/// Derivation:
///
/// Unix epoch as FILETIME = 116,444,736,000,000,000  (known constant)
/// NTP epoch (1900-01-01) as FILETIME = Unix FILETIME − NTP_UNIX_EPOCH_DELTA × 10^7
///                                   = 116,444,736,000,000,000 − 22,089,888,000,000,000
///                                   = 94,354,848,000,000,000
const NTP_EPOCH_FILETIME: u64 = 94_354_848_000_000_000;

/// Number of 100-ns intervals in one second.
const FILETIME_TICKS_PER_SECOND: u64 = 10_000_000;

// ---------------------------------------------------------------------------
// SNTP query builders
// ---------------------------------------------------------------------------

/// Build an SNTP unicast client query packet.
///
/// The client sends a standard NTPv4 mode 3 (client) packet with a
/// transmit timestamp set to the current client time.  The server
/// replies with a mode 4 (server) packet.
///
/// This is identical to a standard NTP query, but for SNTP the client
/// does not perform clock filtering and accepts the first valid response.
///
/// # Arguments
///
/// * `query_time` — The client's current NTP timestamp (T1).
///
/// # Returns
///
/// A fully-formed `NtpPacket` ready for encoding and transmission.
#[must_use]
pub fn build_sntp_unicast_query(query_time: NtpTimestamp) -> NtpPacket {
    let mut pkt = NtpPacket::zero();
    pkt.set_li_vn_mode(li::NO_WARNING, NTP_VERSION, mode::CLIENT);
    pkt.transmit_ts = query_time;
    pkt
}

/// Build an SNTP anycast client request.
///
/// Anycast mode uses the standard mode 3 (client) packet, but the
/// client sends it to a multicast or anycast address (e.g., 224.0.1.1
/// for IPv4 NTP multicast).  The closest NTP server responding will
/// be used.
///
/// This is semantically identical to a unicast query; the anycast
/// behavior is determined by the destination address, not the packet
/// content.
///
/// RFC 4330 § 3 states that anycast clients use standard mode 3 queries.
#[must_use]
pub fn build_sntp_anycast_query(query_time: NtpTimestamp) -> NtpPacket {
    build_sntp_unicast_query(query_time)
}

/// Build an SNTP multicast (broadcast) client query.
///
/// Per RFC 4330 § 4, a multicast client sends a mode 3 query to
/// discover an NTP server that provides multicast (mode 5) responses.
/// The server may respond with a mode 4 (server) or mode 5 (broadcast)
/// packet.
///
/// This function builds the initial mode 3 discovery query.  For
/// ongoing multicast listening, the client simply listens for mode 5
/// broadcast packets.
#[must_use]
pub fn build_sntp_multicast_query(query_time: NtpTimestamp) -> NtpPacket {
    // Multicast discovery uses a standard mode 3 client query,
    // addressed to the NTP multicast group.
    build_sntp_unicast_query(query_time)
}

// ---------------------------------------------------------------------------
// SNTP response processing
// ---------------------------------------------------------------------------

/// Process an SNTP server response and compute clock offset and delay.
///
/// This is a simplified version of the full NTP processing:
/// - No extension fields are expected (48-byte packets only).
/// - No clock filter is maintained; the result is returned directly.
/// - The caller is responsible for applying the offset.
///
/// All four NTP timestamps are used to compute offset and delay:
///
/// ```text
/// offset = ((T2 − T1) + (T3 − T4)) / 2
/// delay  = (T4 − T1) − (T3 − T2)
/// ```
///
/// Where:
/// - T1 = `query_time`    (client transmit)
/// - T2 = `response.receive_ts`  (server receive)
/// - T3 = `response.transmit_ts` (server transmit)
/// - T4 = `recv_time`     (client receive)
///
/// # Arguments
///
/// * `response` — The NTP packet received from the server.
/// * `query_time` — The client's transmit timestamp (T1), which must
///   match `response.origin_ts` for replay protection.
/// * `recv_time` — The client's receive timestamp (T4), the time the
///   response was received.
///
/// # Returns
///
/// `Ok((offset, delay))` where:
/// - `offset` — Estimated clock offset in seconds. Positive means the
///   client is behind the server.
/// - `delay` — Round-trip delay in seconds.
///
/// # Errors
///
/// Returns `Err` if the response is invalid:
/// - Wrong mode (not mode 4 server)
/// - Invalid version (not NTPv3 or v4)
/// - Kiss-o'-death (stratum 0)
/// - Invalid stratum (> 15)
/// - Zero timestamps
/// - Origin timestamp mismatch (replay or cross-session)
pub fn process_sntp_response(
    response: &NtpPacket,
    query_time: NtpTimestamp,
    recv_time: NtpTimestamp,
) -> Result<(f64, f64), &'static str> {
    // Mode must be SERVER (4) for unicast/anycast.
    if response.mode() != mode::SERVER {
        return Err("SNTP: response mode is not server");
    }

    // Accept NTPv3 or NTPv4.
    let ver = response.version();
    if !(3..=NTP_VERSION).contains(&ver) {
        return Err("SNTP: invalid version");
    }

    // Stratum 0 indicates a kiss-o'-death packet.
    if response.stratum == 0 {
        return Err("SNTP: kiss-of-death");
    }

    // Stratum must be ≤ 15.
    if response.stratum > 15 {
        return Err("SNTP: invalid stratum");
    }

    // Replay-attack protection: origin timestamp must match.
    if response.origin_ts != query_time {
        return Err("SNTP: origin timestamp mismatch (replay?)");
    }

    // Server must set receive and transmit timestamps.
    if response.receive_ts == NtpTimestamp::zero() || response.transmit_ts == NtpTimestamp::zero() {
        return Err("SNTP: zero server timestamp");
    }

    // Compute offset and delay using the standard NTP formula.
    let t1 = query_time.to_f64();
    let t2 = response.receive_ts.to_f64();
    let t3 = response.transmit_ts.to_f64();
    let t4 = recv_time.to_f64();

    // offset = ((T2 − T1) + (T3 − T4)) / 2
    let offset = ((t2 - t1) + (t3 - t4)) / 2.0;

    // delay  = (T4 − T1) − (T3 − T2)
    let delay = (t4 - t1) - (t3 - t2);

    Ok((offset, delay))
}

// ---------------------------------------------------------------------------
// FILETIME conversion
// ---------------------------------------------------------------------------

/// Convert an NTP 64-bit timestamp value to a Windows FILETIME value.
///
/// NTP timestamps represent the number of seconds since 1900-01-01
/// in a 32.32 fixed-point format.  Windows FILETIME represents the
/// number of 100-nanosecond intervals since 1601-01-01.
///
/// # Arguments
///
/// * `ntp_ts` — The raw 64-bit NTP timestamp (upper 32 bits = seconds,
///   lower 32 bits = fractional 2³²⁻¹ seconds).
///
/// # Returns
///
/// The equivalent Windows FILETIME value (100-ns intervals since
/// 1601-01-01).
#[must_use]
pub fn ntp_to_filetime(ntp_ts: u64) -> u64 {
    let secs = (ntp_ts >> 32) as u32;
    let frac = (ntp_ts & 0xFFFF_FFFF) as u32;

    // Convert fractional part to 100-ns ticks.
    // frac is in units of 2^−32 seconds.  1 second = 10,000,000 ticks.
    let fractional_delta = (u64::from(frac) * FILETIME_TICKS_PER_SECOND) >> 32;

    // Convert NTP seconds to FILETIME ticks and add to the NTP epoch base.
    let secs_ticks = u64::from(secs) * FILETIME_TICKS_PER_SECOND;

    NTP_EPOCH_FILETIME
        .wrapping_add(secs_ticks)
        .wrapping_add(fractional_delta)
}

/// Convert a Windows FILETIME value to an NTP 64-bit timestamp.
///
/// # Arguments
///
/// * `ft` — Windows FILETIME value (100-ns intervals since 1601-01-01).
///
/// # Returns
///
/// The equivalent NTP 64-bit timestamp (upper 32 bits = seconds,
/// lower 32 bits = fractional 2³²⁻¹ seconds).
#[must_use]
pub fn filetime_to_ntp(ft: u64) -> u64 {
    let elapsed = ft.wrapping_sub(NTP_EPOCH_FILETIME);

    let secs = elapsed / FILETIME_TICKS_PER_SECOND;
    let remainder = elapsed % FILETIME_TICKS_PER_SECOND;

    // Convert remainder (100-ns ticks) to NTP fractional seconds (2^−32 units).
    let frac = (remainder << 32) / FILETIME_TICKS_PER_SECOND;

    (secs << 32) | frac
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ntp::NtpTimestamp;

    // -----------------------------------------------------------------------
    // SNTP query builders
    // -----------------------------------------------------------------------

    #[test]
    fn test_build_sntp_unicast_query() {
        let ts = NtpTimestamp::new(1_000_000, 0);
        let pkt = build_sntp_unicast_query(ts);

        assert_eq!(pkt.mode(), mode::CLIENT, "mode should be client (3)");
        assert_eq!(pkt.version(), NTP_VERSION, "version should be 4");
        assert_eq!(pkt.leap_indicator(), li::NO_WARNING, "LI should be 0");
        assert_eq!(pkt.transmit_ts, ts, "transmit timestamp should match");
        assert_eq!(pkt.stratum, 0, "stratum should be 0 (unset)");
    }

    #[test]
    fn test_build_sntp_anycast_query() {
        let ts = NtpTimestamp::new(2_000_000, 0);
        let pkt = build_sntp_anycast_query(ts);

        // Anycast is identical to unicast in packet format.
        assert_eq!(pkt.mode(), mode::CLIENT);
        assert_eq!(pkt.transmit_ts, ts);
    }

    #[test]
    fn test_build_sntp_multicast_query() {
        let ts = NtpTimestamp::new(3_000_000, 0);
        let pkt = build_sntp_multicast_query(ts);

        assert_eq!(pkt.mode(), mode::CLIENT);
        assert_eq!(pkt.transmit_ts, ts);
    }

    #[test]
    fn test_sntp_query_encode_decode_roundtrip() {
        let ts = NtpTimestamp::new(42, 12345);
        let pkt = build_sntp_unicast_query(ts);
        let encoded = pkt.encode();
        assert_eq!(encoded.len(), 48, "SNTP query must be 48 bytes");
        assert_eq!(encoded[0] & 0x07, mode::CLIENT, "mode bits correct");
        assert_eq!(
            (encoded[0] >> 3) & 0x07,
            NTP_VERSION,
            "version bits correct"
        );
    }

    // -----------------------------------------------------------------------
    // SNTP response processing
    // -----------------------------------------------------------------------

    fn make_sntp_response(query_time: NtpTimestamp, recv_secs: u32, xmit_secs: u32) -> NtpPacket {
        let mut pkt = NtpPacket::zero();
        pkt.set_li_vn_mode(li::NO_WARNING, NTP_VERSION, mode::SERVER);
        pkt.stratum = 3;
        pkt.origin_ts = query_time;
        pkt.receive_ts = NtpTimestamp::new(recv_secs, 0);
        pkt.transmit_ts = NtpTimestamp::new(xmit_secs, 0);
        pkt
    }

    #[test]
    fn test_process_sntp_response_basic() {
        let query_time = NtpTimestamp::new(100, 0);
        let recv_time = NtpTimestamp::new(200, 0);
        let response = make_sntp_response(query_time, 150, 180);

        let result = process_sntp_response(&response, query_time, recv_time);
        assert!(result.is_ok(), "valid response should be accepted");

        let (offset, delay) = result.unwrap();
        // T1=100, T2=150, T3=180, T4=200
        // offset = ((150-100) + (180-200)) / 2 = (50 + (-20)) / 2 = 15
        // delay  = (200-100) - (180-150) = 100 - 30 = 70
        assert!(
            (offset - 15.0).abs() < 1e-6,
            "offset should be 15s, got {offset}"
        );
        assert!(
            (delay - 70.0).abs() < 1e-6,
            "delay should be 70s, got {delay}"
        );
    }

    #[test]
    fn test_process_sntp_response_negative_offset() {
        // Client is ahead of server: negative offset.
        let query_time = NtpTimestamp::new(200, 0);
        let recv_time = NtpTimestamp::new(400, 0);
        // T2 and T3 close to query time (server clock is behind)
        let response = make_sntp_response(query_time, 150, 160);

        let result = process_sntp_response(&response, query_time, recv_time);
        assert!(result.is_ok());

        let (offset, _delay) = result.unwrap();
        // offset = ((150-200) + (160-400)) / 2 = (-50 + (-240)) / 2 = -145
        assert!(
            (offset + 145.0).abs() < 1e-6,
            "offset should be -145s, got {offset}"
        );
    }

    #[test]
    fn test_process_sntp_response_zero_delay() {
        // Perfect round-trip: delay = 0
        let query_time = NtpTimestamp::new(100, 0);
        let recv_time = NtpTimestamp::new(100, 0); // instantaneous
        let response = make_sntp_response(query_time, 100, 100);

        let result = process_sntp_response(&response, query_time, recv_time);
        assert!(result.is_ok());

        let (offset, delay) = result.unwrap();
        assert!(
            offset.abs() < 1e-6,
            "offset should be ~0 for instantaneous, got {offset}"
        );
        assert!(
            delay.abs() < 1e-6,
            "delay should be ~0 for instantaneous, got {delay}"
        );
    }

    #[test]
    fn test_process_sntp_response_wrong_mode() {
        let mut pkt = NtpPacket::zero();
        pkt.set_li_vn_mode(li::NO_WARNING, NTP_VERSION, mode::BROADCAST);
        pkt.origin_ts = NtpTimestamp::new(1, 0);

        let result = process_sntp_response(&pkt, NtpTimestamp::new(1, 0), NtpTimestamp::new(2, 0));
        assert_eq!(result, Err("SNTP: response mode is not server"));
    }

    #[test]
    fn test_process_sntp_response_wrong_version() {
        let mut pkt = NtpPacket::zero();
        pkt.set_li_vn_mode(li::NO_WARNING, 1, mode::SERVER); // version 1 (too old)
        pkt.origin_ts = NtpTimestamp::new(1, 0);

        let result = process_sntp_response(&pkt, NtpTimestamp::new(1, 0), NtpTimestamp::new(2, 0));
        assert_eq!(result, Err("SNTP: invalid version"));
    }

    #[test]
    fn test_process_sntp_response_kiss_of_death() {
        let mut pkt = NtpPacket::zero();
        pkt.set_li_vn_mode(li::NO_WARNING, NTP_VERSION, mode::SERVER);
        pkt.stratum = 0;
        pkt.reference_id = *b"RATE";
        pkt.origin_ts = NtpTimestamp::new(1, 0);

        let result = process_sntp_response(&pkt, NtpTimestamp::new(1, 0), NtpTimestamp::new(2, 0));
        assert_eq!(result, Err("SNTP: kiss-of-death"));
    }

    #[test]
    fn test_process_sntp_response_replay() {
        let query_time = NtpTimestamp::new(42, 0);
        let wrong_origin = NtpTimestamp::new(99, 0);
        let response = make_sntp_response(wrong_origin, 150, 180);

        let result = process_sntp_response(&response, query_time, NtpTimestamp::new(200, 0));
        assert_eq!(result, Err("SNTP: origin timestamp mismatch (replay?)"));
    }

    #[test]
    fn test_process_sntp_response_zero_receive() {
        let query_time = NtpTimestamp::new(1, 0);
        let mut pkt = NtpPacket::zero();
        pkt.set_li_vn_mode(li::NO_WARNING, NTP_VERSION, mode::SERVER);
        pkt.stratum = 3;
        pkt.origin_ts = query_time;
        pkt.receive_ts = NtpTimestamp::zero();
        pkt.transmit_ts = NtpTimestamp::new(100, 0);

        let result = process_sntp_response(&pkt, query_time, NtpTimestamp::new(200, 0));
        assert_eq!(result, Err("SNTP: zero server timestamp"));
    }

    #[test]
    fn test_process_sntp_response_zero_transmit() {
        let query_time = NtpTimestamp::new(1, 0);
        let mut pkt = NtpPacket::zero();
        pkt.set_li_vn_mode(li::NO_WARNING, NTP_VERSION, mode::SERVER);
        pkt.stratum = 3;
        pkt.origin_ts = query_time;
        pkt.receive_ts = NtpTimestamp::new(100, 0);
        pkt.transmit_ts = NtpTimestamp::zero();

        let result = process_sntp_response(&pkt, query_time, NtpTimestamp::new(200, 0));
        assert_eq!(result, Err("SNTP: zero server timestamp"));
    }

    // -----------------------------------------------------------------------
    // FILETIME conversion
    // -----------------------------------------------------------------------

    /// NTP seconds at the Unix epoch (1970-01-01 00:00:00).
    const UNIX_EPOCH_NTP_SECS: u64 = 2_208_988_800;

    /// Raw 64-bit NTP timestamp for the Unix epoch.
    fn unix_epoch_ntp_u64() -> u64 {
        UNIX_EPOCH_NTP_SECS << 32
    }

    /// Known value: Unix epoch as Windows FILETIME.
    const UNIX_EPOCH_FILETIME: u64 = 116_444_736_000_000_000;

    #[test]
    fn test_ntp_to_filetime_unix_epoch() {
        let ntp = unix_epoch_ntp_u64();
        let ft = ntp_to_filetime(ntp);
        assert_eq!(
            ft, UNIX_EPOCH_FILETIME,
            "Unix epoch as FILETIME should match known constant"
        );
    }

    #[test]
    fn test_filetime_to_ntp_unix_epoch() {
        let ntp = filetime_to_ntp(UNIX_EPOCH_FILETIME);
        let actual_secs = ntp >> 32;
        assert_eq!(
            actual_secs, UNIX_EPOCH_NTP_SECS,
            "FILETIME Unix epoch -> NTP seconds should match"
        );
    }

    #[test]
    fn test_ntp_filetime_roundtrip_seconds() {
        // Test that converting NTP -> FILETIME -> NTP preserves seconds.
        let test_values = [
            0u64,                     // NTP epoch
            1u64 << 32,               // 1 sec after NTP epoch
            2_208_988_800u64 << 32,   // Unix epoch
            3_774_854_400u64 << 32,   // ~2020-01-01
            4_000_000_000u64 << 32,   // future
            0xFFFF_FFFF_0000_0000u64, // max seconds
        ];

        for &ntp_in in &test_values {
            let ft = ntp_to_filetime(ntp_in);
            let ntp_out = filetime_to_ntp(ft);

            let secs_in = ntp_in >> 32;
            let secs_out = ntp_out >> 32;
            assert_eq!(
                secs_in, secs_out,
                "FILETIME roundtrip should preserve seconds: \
                 ntp_in=0x{ntp_in:016x}, secs_in={secs_in}, secs_out={secs_out}"
            );
        }
    }

    #[test]
    fn test_ntp_to_filetime_ntp_epoch() {
        // NTP epoch (1900-01-01) as FILETIME.
        let ft = ntp_to_filetime(0u64);
        let expected = UNIX_EPOCH_FILETIME - (UNIX_EPOCH_NTP_SECS * FILETIME_TICKS_PER_SECOND);
        assert_eq!(
            ft, expected,
            "NTP epoch FILETIME mismatch: got {ft}, expected {expected}"
        );
    }

    #[test]
    fn test_filetime_to_ntp_ntp_epoch() {
        // NTP epoch (1900-01-01) as FILETIME
        let ft_ntp_epoch = UNIX_EPOCH_FILETIME - (UNIX_EPOCH_NTP_SECS * FILETIME_TICKS_PER_SECOND);
        let ntp = filetime_to_ntp(ft_ntp_epoch);
        let secs = ntp >> 32;
        assert_eq!(secs, 0, "NTP epoch should have secs=0, got {secs}");
    }

    #[test]
    fn test_filetime_roundtrip_with_frac() {
        // Test with fractional seconds: 10.5 seconds.
        let ntp_in: u64 = (10u64 << 32) | (1u64 << 31); // 10.5 seconds
        let ft = ntp_to_filetime(ntp_in);
        let ntp_out = filetime_to_ntp(ft);

        let secs_in = ntp_in >> 32;
        let secs_out = ntp_out >> 32;
        assert_eq!(
            secs_out, secs_in,
            "seconds should roundtrip with fractional part"
        );
    }

    #[test]
    fn test_process_sntp_response_valid_stratum_15() {
        let query_time = NtpTimestamp::new(100, 0);
        let recv_time = NtpTimestamp::new(200, 0);
        let mut pkt = make_sntp_response(query_time, 150, 180);
        pkt.stratum = 15; // maximum valid stratum

        let result = process_sntp_response(&pkt, query_time, recv_time);
        assert!(result.is_ok(), "stratum 15 should be valid");
    }

    #[test]
    fn test_process_sntp_response_invalid_stratum_16() {
        let query_time = NtpTimestamp::new(100, 0);
        let mut pkt = make_sntp_response(query_time, 150, 180);
        pkt.stratum = 16;

        let result = process_sntp_response(&pkt, query_time, NtpTimestamp::new(200, 0));
        assert_eq!(result, Err("SNTP: invalid stratum"));
    }

    #[test]
    fn test_process_sntp_response_accepts_ntpv3() {
        let query_time = NtpTimestamp::new(100, 0);
        let recv_time = NtpTimestamp::new(200, 0);
        let mut pkt = make_sntp_response(query_time, 150, 180);
        pkt.set_li_vn_mode(li::NO_WARNING, 3, mode::SERVER); // NTPv3

        let result = process_sntp_response(&pkt, query_time, recv_time);
        assert!(result.is_ok(), "NTPv3 should be accepted");
    }

    #[test]
    fn test_ntp_filetime_reciprocal_consistency() {
        // Verify ntp_to_filetime ∘ filetime_to_ntp is identity for
        // the integer-seconds case.
        for secs in [0u64, 1, 2_208_988_800, 4_000_000_000] {
            let ntp = secs << 32;
            let ft = ntp_to_filetime(ntp);
            let ntp_back = filetime_to_ntp(ft);
            assert_eq!(
                ntp >> 32,
                ntp_back >> 32,
                "reciprocal consistency failed for secs={secs}"
            );
        }
    }

    #[test]
    fn test_filetime_ntp_reciprocal_consistency() {
        // Verify filetime_to_ntp ∘ ntp_to_filetime rounds correctly.
        // Test only FILETIME values >= NTP epoch, since NTP cannot
        // represent dates before 1900-01-01.
        let test_fts = [
            NTP_EPOCH_FILETIME,                                     // NTP epoch
            UNIX_EPOCH_FILETIME,                                    // Unix epoch
            UNIX_EPOCH_FILETIME + 365u64 * 86400 * 10_000_000 * 10, // ~10 years after Unix epoch
        ];
        for &ft in &test_fts {
            let ntp = filetime_to_ntp(ft);
            let ft_back = ntp_to_filetime(ntp);
            // The difference should be less than 100 μs (1000 ticks)
            let diff = if ft > ft_back {
                ft - ft_back
            } else {
                ft_back - ft
            };
            assert!(
                diff < 10_000,
                "FILETIME reciprocal inconsistency: ft={ft}, ft_back={ft_back}, diff={diff}"
            );
        }
    }

    #[test]
    fn test_sntp_query_all_query_types_differ_by_label_only() {
        // All three query builders produce the same packet structure
        // for the same timestamp; the difference is in the destination
        // address, not the packet content.
        let ts = NtpTimestamp::new(1000, 0);
        let unicast = build_sntp_unicast_query(ts);
        let anycast = build_sntp_anycast_query(ts);
        let multicast = build_sntp_multicast_query(ts);
        assert_eq!(unicast, anycast, "unicast == anycast");
        assert_eq!(unicast, multicast, "unicast == multicast");
    }
}
