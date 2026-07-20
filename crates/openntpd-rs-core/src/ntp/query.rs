//! NTP mode 3 client query engine.
//!
//! Implements the client side of the NTP protocol: building mode 3
//! query packets, validating and processing mode 4 server responses,
//! and tracking in-flight queries via [`QueryState`].
//!
//! This module is `no_std` + `deny(unsafe_code)`.

use crate::ntp::{li, mode, NtpPacket, NtpTimestamp, NTP_VERSION};
use crate::peer::{
    Peer, MAX_DELAY, MAX_OFFSET, MAX_STRATUM, PFLASH_PEERDELAY, PFLASH_PEERNOQUERY,
    PFLASH_PEEROFFSET, PFLASH_PEERSTRAT,
};

use core::fmt;

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Build a mode 3 client query packet.
///
/// The transmit timestamp is set to `recv_time` (the client's current
/// time when preparing the packet).  The leap indicator is
/// [`li::NO_WARNING`], version is [`NTP_VERSION`] (4), and mode is
/// [`mode::CLIENT`] (3).
#[must_use]
pub fn build_query(recv_time: NtpTimestamp) -> NtpPacket {
    let mut pkt = NtpPacket::zero();
    pkt.set_li_vn_mode(li::NO_WARNING, NTP_VERSION, mode::CLIENT);
    // The NTP RFC says the client sets the transmit timestamp to its
    // current time; the server copies this into the origin timestamp of
    // its response.
    pkt.transmit_ts = recv_time;
    pkt
}

/// Validate and process a mode 4 server response, updating the peer
/// state.
///
/// # Arguments
///
/// * `peer` — The peer to update (clock filter, reachability, flash
///   bits, poll interval).
/// * `response` — The received NTP packet to validate.
/// * `recv_time` — The client's receive timestamp (`T4`).
/// * `query_time` — The client's transmit timestamp (`T1`); must
///   match `response.origin_ts` for replay protection.
///
/// # Returns
///
/// `Ok((offset, delay))` in seconds on success.
///
/// # Errors
///
/// See [`QueryError`] for the various rejection reasons.
pub fn process_response(
    peer: &mut Peer,
    response: &NtpPacket,
    recv_time: NtpTimestamp,
    query_time: NtpTimestamp,
) -> Result<(f64, f64), QueryError> {
    // --- Validation -------------------------------------------------------

    // Mode must be SERVER (4).
    if response.mode() != mode::SERVER {
        return Err(QueryError::WrongMode(response.mode()));
    }

    // Accept NTPv3 or NTPv4.
    let ver = response.version();
    if !(3..=NTP_VERSION).contains(&ver) {
        return Err(QueryError::InvalidVersion);
    }

    // Stratum 0 indicates a kiss-o'-death packet.
    if response.stratum == 0 {
        return Err(QueryError::KissOfDeath);
    }

    // Stratum must be ≤ 15 (MAX_STRATUM).
    if response.stratum > MAX_STRATUM {
        return Err(QueryError::InvalidStratum);
    }

    // Replay-attack / cross-session protection: the origin timestamp
    // must exactly match the timestamp we transmitted.
    if response.origin_ts != query_time {
        return Err(QueryError::ReplayAttack);
    }

    // Server must set receive and transmit timestamps.
    if response.receive_ts == NtpTimestamp::zero() || response.transmit_ts == NtpTimestamp::zero() {
        return Err(QueryError::BadTimestamp);
    }

    // --- Compute offset and delay ----------------------------------------
    //
    //   offset = ((T2 − T1) + (T3 − T4)) / 2
    //   delay  = (T4 − T1) − (T3 − T2)
    //
    // T1 = query_time  (client transmit)
    // T2 = receive_ts  (server receive)
    // T3 = transmit_ts (server transmit)
    // T4 = recv_time   (client receive)
    let (offset, delay) = Peer::compute_offset(
        query_time,
        response.receive_ts,
        response.transmit_ts,
        recv_time,
    );

    // --- Update peer state ------------------------------------------------

    // We got a valid response — clear the no-query flash.
    peer.clear_flash(PFLASH_PEERNOQUERY);

    // Copy server metadata into the peer.
    peer.stratum = response.stratum;
    peer.precision = response.precision;
    peer.root_delay = response.root_delay.to_f64();
    peer.root_dispersion = response.root_dispersion.to_f64();
    peer.reference_id = u32::from_be_bytes(response.reference_id);

    // Clear quality-related flash bits, then conditionally re-set.
    peer.clear_flash(PFLASH_PEERSTRAT | PFLASH_PEERDELAY | PFLASH_PEEROFFSET);

    if response.stratum > MAX_STRATUM {
        peer.set_flash(PFLASH_PEERSTRAT);
    }

    if !(0.0..=MAX_DELAY).contains(&delay) {
        peer.set_flash(PFLASH_PEERDELAY);
    }

    if offset.abs() > MAX_OFFSET {
        peer.set_flash(PFLASH_PEEROFFSET);
    }

    // Add the new sample to the clock filter ring buffer.
    // Use a per-sample dispersion based on the system precision.
    // RFC 5905 § 8 suggests initial dispersion of 1 second for a new
    // sample; we use `MAX_DISPERSION` as a conservative estimate.
    let dispersion = crate::peer::MAX_DISPERSION;
    peer.add_sample(offset, delay, dispersion);

    // Update reachability (success = set LSB to 1).
    peer.update_reach(true);

    // Update poll interval state machine.
    peer.update_poll(true);

    Ok((offset, delay))
}

// ---------------------------------------------------------------------------
// Error type
// ---------------------------------------------------------------------------

/// Errors that can occur when processing an NTP server response.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum QueryError {
    /// Response mode is not [`mode::SERVER`] (4).
    /// Contains the actual mode value received.
    WrongMode(u8),
    /// Server sent a kiss-o'-death packet (stratum = 0).
    KissOfDeath,
    /// Server stratum exceeds [`MAX_STRATUM`] (15).
    InvalidStratum,
    /// Response has an unexpected NTP version.
    InvalidVersion,
    /// Server timestamps are zero / invalid.
    BadTimestamp,
    /// Origin timestamp mismatch — possible replay or cross-session
    /// response.
    ReplayAttack,
}

impl fmt::Display for QueryError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::WrongMode(m) => write!(f, "unexpected response mode: {m}"),
            Self::KissOfDeath => write!(f, "kiss-o'-death received"),
            Self::InvalidStratum => write!(f, "invalid stratum"),
            Self::InvalidVersion => write!(f, "invalid NTP version"),
            Self::BadTimestamp => write!(f, "bad server timestamps"),
            Self::ReplayAttack => write!(f, "origin timestamp mismatch (possible replay)"),
        }
    }
}

// ---------------------------------------------------------------------------
// Query state machine
// ---------------------------------------------------------------------------

/// Tracks the state of an in-flight NTP mode 3 query.
///
/// This is the client-side state for a single peer: it records whether
/// a query is outstanding, what transmit timestamp was used (for replay
/// detection), and when the query was sent (for timeout detection).
#[derive(Debug, Clone)]
pub struct QueryState {
    /// Whether a query is currently in flight.
    pub outstanding: bool,
    /// The transmit timestamp (`T1`) from the last query.  Used to
    /// validate the origin timestamp in the response.
    pub query_time: NtpTimestamp,
    /// The wall-clock timestamp when the last query was sent.  Used
    /// for timeout detection.
    pub query_sent: NtpTimestamp,
}

impl QueryState {
    /// Create a new idle [`QueryState`] with no outstanding query.
    #[must_use]
    pub fn new() -> Self {
        Self {
            outstanding: false,
            query_time: NtpTimestamp::zero(),
            query_sent: NtpTimestamp::zero(),
        }
    }

    /// Begin a new query.
    ///
    /// Builds a mode 3 client packet with `now` as the transmit
    /// timestamp, records the state as outstanding, and returns the
    /// packet to send.
    ///
    /// If a query was already outstanding it is silently replaced
    /// (the caller should check [`is_timed_out`](Self::is_timed_out)
    /// first).
    #[must_use]
    pub fn send_query(&mut self, now: NtpTimestamp) -> NtpPacket {
        let pkt = build_query(now);
        self.outstanding = true;
        self.query_time = pkt.transmit_ts;
        self.query_sent = now;
        pkt
    }

    /// Receive a response and process it.
    ///
    /// On success the `outstanding` flag is cleared and the peer state
    /// is updated.  On error the outstanding flag is preserved so the
    /// caller can retry or time out the query.
    pub fn receive_response(
        &mut self,
        peer: &mut Peer,
        response: &NtpPacket,
        recv_time: NtpTimestamp,
    ) -> Result<(f64, f64), QueryError> {
        let result = process_response(peer, response, recv_time, self.query_time);
        if result.is_ok() {
            self.outstanding = false;
        }
        result
    }

    /// Check if the outstanding query has timed out.
    ///
    /// Returns `false` if no query is outstanding or if the time since
    /// `query_sent` is less than `timeout` seconds.
    #[must_use]
    pub fn is_timed_out(&self, now: NtpTimestamp, timeout: u64) -> bool {
        if !self.outstanding {
            return false;
        }
        // Use f64 subtraction; wrapping is not a concern for practical
        // timeout intervals (seconds to minutes).
        let elapsed = now.to_f64() - self.query_sent.to_f64();
        elapsed >= timeout as f64
    }
}

impl Default for QueryState {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::directive::ConfigString;
    use crate::ntp::{mode, NtpDatagram, NTP_PACKET_MIN_SIZE};
    use crate::peer::{PFLASH_PEERDELAY, PFLASH_PEERNOQUERY, PFLASH_PEEROFFSET, PFLASH_PEERSTRAT};
    // -----------------------------------------------------------------------
    // Helpers
    // -----------------------------------------------------------------------

    fn addr(s: &str) -> ConfigString {
        ConfigString::new(s.as_bytes().to_vec()).unwrap()
    }

    /// Build a valid mode-4 server response for a given client query.
    fn make_server_response(
        client_tx: NtpTimestamp,
        server_rx_offset: u32,
        server_tx_offset: u32,
    ) -> NtpPacket {
        let mut pkt = NtpPacket::zero();
        pkt.set_li_vn_mode(li::NO_WARNING, NTP_VERSION, mode::SERVER);
        pkt.stratum = 2;
        pkt.poll = 6;
        pkt.precision = -10;
        pkt.root_delay = crate::ntp::NtpShortSigned::new(0, 0);
        pkt.root_dispersion = crate::ntp::NtpShortUnsigned::new(0, 0x1000);
        pkt.reference_id = [0xAC, 0x10, 0x00, 0x01];
        pkt.reference_ts = NtpTimestamp::new(4_000_000, 0);
        pkt.origin_ts = client_tx;
        pkt.receive_ts = NtpTimestamp::new(
            client_tx.secs.wrapping_add(server_rx_offset),
            client_tx.frac.wrapping_add(server_rx_offset >> 1),
        );
        pkt.transmit_ts = NtpTimestamp::new(
            client_tx.secs.wrapping_add(server_tx_offset),
            client_tx.frac,
        );
        pkt
    }

    fn default_peer() -> Peer {
        Peer::new(addr("192.0.2.1"), 1, false)
    }

    // -----------------------------------------------------------------------
    // build_query
    // -----------------------------------------------------------------------

    #[test]
    fn test_build_query_correct_mode_version() {
        let ts = NtpTimestamp::new(4_000_000_000, 0x8000_0000);
        let pkt = build_query(ts);

        assert_eq!(pkt.mode(), mode::CLIENT, "mode must be CLIENT (3)");
        assert_eq!(pkt.version(), NTP_VERSION, "version must be 4");
        assert_eq!(pkt.leap_indicator(), li::NO_WARNING, "LI must be 0");
        assert_eq!(pkt.transmit_ts, ts, "transmit timestamp must match");
    }

    #[test]
    fn test_build_query_all_fields_sane() {
        let ts = NtpTimestamp::new(42, 12345);
        let pkt = build_query(ts);

        // Query packet should have zero in most fields.
        assert_eq!(pkt.stratum, 0);
        assert_eq!(pkt.poll, 0);
        assert_eq!(pkt.precision, 0);
        assert_eq!(pkt.origin_ts, NtpTimestamp::zero());
        assert_eq!(pkt.receive_ts, NtpTimestamp::zero());
        assert_eq!(pkt.reference_ts, NtpTimestamp::zero());
        assert_eq!(pkt.root_delay, crate::ntp::NtpShortSigned::default());
        assert_eq!(pkt.root_dispersion, crate::ntp::NtpShortUnsigned::default());

        // The packet should encode to exactly 48 bytes.
        let encoded = pkt.encode();
        assert_eq!(encoded.len(), NTP_PACKET_MIN_SIZE);
    }

    #[test]
    fn test_build_query_zero_timestamp() {
        let pkt = build_query(NtpTimestamp::zero());
        assert_eq!(pkt.transmit_ts, NtpTimestamp::zero());
        assert_eq!(pkt.mode(), mode::CLIENT);
    }

    // -----------------------------------------------------------------------
    // process_response — happy path
    // -----------------------------------------------------------------------

    #[test]
    fn test_process_response_updates_peer() {
        let mut peer = default_peer();
        let query_ts = NtpTimestamp::new(4_000_000_000, 0);
        let response = make_server_response(query_ts, 10, 20);
        let recv_ts = NtpTimestamp::new(
            query_ts.secs.wrapping_add(30),
            query_ts.frac.wrapping_add(1000),
        );

        let result = process_response(&mut peer, &response, recv_ts, query_ts);
        assert!(result.is_ok(), "expected Ok, got {:?}", result);

        let (offset, delay) = result.unwrap();
        // offset = ((T2 − T1) + (T3 − T4)) / 2
        // T1 = 4000000000, T2 = 4000000010, T3 = 4000000020, T4 = 4000000030
        // offset = ((10) + (20 - 30)) / 2 = (10 - 10) / 2 = 0
        // delay  = (30 - 0) - (20 - 10) = 30 - 10 = 20
        assert!((offset - 0.0).abs() < 1e-9, "offset should be ~0: {offset}");
        assert!((delay - 20.0).abs() < 1e-9, "delay should be ~20: {delay}");

        // Peer should have a sample in the filter.
        assert!(!peer.has_flash(PFLASH_PEERNOQUERY), "FLASH_NOQUERY cleared");
        assert!(peer.reach != 0, "reachability should be non-zero");
        assert_eq!(peer.stratum, 2, "stratum copied from response");
    }

    #[test]
    fn test_process_response_updates_filter() {
        let mut peer = default_peer();
        let query_ts = NtpTimestamp::new(1_000_000, 0);
        let recv_ts = NtpTimestamp::new(1_000_030, 0);
        let response = make_server_response(query_ts, 10, 20);

        assert!(peer
            .best_sample()
            .is_none_or(|s| s.offset == 0.0 && s.delay == 0.0));

        process_response(&mut peer, &response, recv_ts, query_ts).unwrap();

        let best = peer.best_sample().expect("filter should have a sample");
        // offset ≈ 0, delay ≈ 20
        assert!(
            (best.offset).abs() < 1.0,
            "unexpected offset: {}",
            best.offset
        );
        assert!(
            (best.delay - 20.0).abs() < 1.0,
            "unexpected delay: {}",
            best.delay
        );
    }

    // -----------------------------------------------------------------------
    // process_response — error cases
    // -----------------------------------------------------------------------

    #[test]
    fn test_process_response_wrong_mode() {
        let mut peer = default_peer();
        let query_ts = NtpTimestamp::new(1_000_000, 0);
        let recv_ts = NtpTimestamp::new(1_000_030, 0);

        let mut response = make_server_response(query_ts, 10, 20);
        // Set mode to SYMMETRIC_ACTIVE (1) instead of SERVER (4).
        response.set_li_vn_mode(li::NO_WARNING, NTP_VERSION, mode::SYMMETRIC_ACTIVE);

        let err = process_response(&mut peer, &response, recv_ts, query_ts)
            .expect_err("should reject wrong mode");
        assert_eq!(err, QueryError::WrongMode(mode::SYMMETRIC_ACTIVE));
    }

    #[test]
    fn test_process_response_kiss_of_death() {
        let mut peer = default_peer();
        let query_ts = NtpTimestamp::new(1_000_000, 0);
        let recv_ts = NtpTimestamp::new(1_000_030, 0);

        let mut response = make_server_response(query_ts, 10, 20);
        response.stratum = 0; // Kiss-o'-death

        let err = process_response(&mut peer, &response, recv_ts, query_ts)
            .expect_err("should reject KOD");
        assert_eq!(err, QueryError::KissOfDeath);
    }

    #[test]
    fn test_process_response_invalid_stratum() {
        let mut peer = default_peer();
        let query_ts = NtpTimestamp::new(1_000_000, 0);
        let recv_ts = NtpTimestamp::new(1_000_030, 0);

        let mut response = make_server_response(query_ts, 10, 20);
        response.stratum = 16; // > MAX_STRATUM (15)

        let err = process_response(&mut peer, &response, recv_ts, query_ts)
            .expect_err("should reject invalid stratum");
        assert_eq!(err, QueryError::InvalidStratum);
    }

    #[test]
    fn test_process_response_invalid_version() {
        let mut peer = default_peer();
        let query_ts = NtpTimestamp::new(1_000_000, 0);
        let recv_ts = NtpTimestamp::new(1_000_030, 0);

        let mut response = make_server_response(query_ts, 10, 20);
        // Set version to 2 (too old).
        response.set_li_vn_mode(li::NO_WARNING, 2, mode::SERVER);

        let err = process_response(&mut peer, &response, recv_ts, query_ts)
            .expect_err("should reject old version");
        assert_eq!(err, QueryError::InvalidVersion);
    }

    #[test]
    fn test_process_response_replay_attack() {
        let mut peer = default_peer();
        let query_ts = NtpTimestamp::new(1_000_000, 0);
        let recv_ts = NtpTimestamp::new(1_000_030, 0);

        let response = make_server_response(NtpTimestamp::new(999_999, 0), 10, 20);

        let err = process_response(&mut peer, &response, recv_ts, query_ts)
            .expect_err("should reject replay");
        assert_eq!(err, QueryError::ReplayAttack);
    }

    #[test]
    fn test_process_response_bad_timestamp_zero_receive() {
        let mut peer = default_peer();
        let query_ts = NtpTimestamp::new(1_000_000, 0);
        let recv_ts = NtpTimestamp::new(1_000_030, 0);

        let mut response = make_server_response(query_ts, 10, 20);
        response.receive_ts = NtpTimestamp::zero();

        let err = process_response(&mut peer, &response, recv_ts, query_ts)
            .expect_err("should reject zero receive_ts");
        assert_eq!(err, QueryError::BadTimestamp);
    }

    #[test]
    fn test_process_response_bad_timestamp_zero_transmit() {
        let mut peer = default_peer();
        let query_ts = NtpTimestamp::new(1_000_000, 0);
        let recv_ts = NtpTimestamp::new(1_000_030, 0);

        let mut response = make_server_response(query_ts, 10, 20);
        response.transmit_ts = NtpTimestamp::zero();

        let err = process_response(&mut peer, &response, recv_ts, query_ts)
            .expect_err("should reject zero transmit_ts");
        assert_eq!(err, QueryError::BadTimestamp);
    }

    // -----------------------------------------------------------------------
    // process_response — flash bits
    // -----------------------------------------------------------------------

    #[test]
    fn test_process_response_sets_delay_flash() {
        let mut peer = default_peer();
        let query_ts = NtpTimestamp::new(1_000_000, 0);
        // Create a response with a huge delay: recv_time will be far in the future.
        let response = make_server_response(query_ts, 10, 20);
        // T4 = T1 + huge_delta => delay = (T4 − T1) − (T3 − T2) = huge
        let recv_ts = NtpTimestamp::new(query_ts.secs.wrapping_add(100_000), query_ts.frac);

        let result = process_response(&mut peer, &response, recv_ts, query_ts);
        assert!(result.is_ok(), "high-delay response should still be Ok");
        let (_offset, delay) = result.unwrap();
        assert!(delay > 2.0, "delay should exceed max: {delay}");
        assert!(
            peer.has_flash(PFLASH_PEERDELAY),
            "PFLASH_PEERDELAY should be set"
        );
    }

    #[test]
    fn test_process_response_sets_offset_flash() {
        let mut peer = default_peer();
        let query_ts = NtpTimestamp::new(1_000_000, 0);
        // Server says T2 and T3 are far from T1 => large offset.
        let big_secs = 1_000_000u32;
        let response = make_server_response(query_ts, big_secs, big_secs + 1);
        let recv_ts = NtpTimestamp::new(query_ts.secs.wrapping_add(big_secs + 2), query_ts.frac);

        let result = process_response(&mut peer, &response, recv_ts, query_ts);
        assert!(result.is_ok(), "large-offset response should still be Ok");
        let (offset, _delay) = result.unwrap();
        assert!(offset.abs() > 1.0, "offset should be large: {offset}");
        assert!(
            peer.has_flash(PFLASH_PEEROFFSET),
            "PFLASH_PEEROFFSET should be set"
        );
    }

    #[test]
    fn test_process_response_no_flash_for_good_response() {
        let mut peer = default_peer();
        // Start with all standard error flags set.
        peer.set_flash(PFLASH_PEERSTRAT | PFLASH_PEERDELAY | PFLASH_PEEROFFSET);

        // Use sub-second offsets so delay < MAX_DELAY (2.0) and
        // offset < MAX_OFFSET (1.0).
        // T1 = 1_000_000.0, T2 = T1 + 0.010, T3 = T1 + 0.020, T4 = T1 + 0.030
        // => offset ≈ 0.0, delay ≈ 0.020 (both well within limits)
        let frac_unit = 4_294_967_296.0; // 2^32
        let query_ts = NtpTimestamp::new(1_000_000, 0);
        let response = NtpPacket {
            li_vn_mode: (li::NO_WARNING << 6) | (NTP_VERSION << 3) | mode::SERVER,
            stratum: 2,
            poll: 6,
            precision: -10,
            root_delay: crate::ntp::NtpShortSigned::default(),
            root_dispersion: crate::ntp::NtpShortUnsigned::default(),
            reference_id: [0xAC, 0x10, 0x00, 0x01],
            reference_ts: NtpTimestamp::zero(),
            origin_ts: query_ts,
            receive_ts: NtpTimestamp::new(query_ts.secs, (0.010 * frac_unit) as u32),
            transmit_ts: NtpTimestamp::new(query_ts.secs, (0.020 * frac_unit) as u32),
        };
        let recv_ts = NtpTimestamp::new(query_ts.secs, (0.030 * frac_unit) as u32);

        process_response(&mut peer, &response, recv_ts, query_ts).unwrap();

        // All flash bits should be cleared now (good response).
        assert!(!peer.has_flash(PFLASH_PEERNOQUERY));
        assert!(!peer.has_flash(PFLASH_PEERSTRAT));
        assert!(!peer.has_flash(PFLASH_PEERDELAY));
        assert!(!peer.has_flash(PFLASH_PEEROFFSET));
    }

    // -----------------------------------------------------------------------
    // QueryState
    // -----------------------------------------------------------------------

    #[test]
    fn test_query_state_new_is_idle() {
        let state = QueryState::new();
        assert!(!state.outstanding);
        assert_eq!(state.query_time, NtpTimestamp::zero());
        assert_eq!(state.query_sent, NtpTimestamp::zero());
    }

    #[test]
    fn test_query_state_send_query() {
        let mut state = QueryState::new();
        let now = NtpTimestamp::new(4_000_000_000, 0x1234_5678);
        let pkt = state.send_query(now);

        assert!(state.outstanding);
        assert_eq!(state.query_time, pkt.transmit_ts);
        assert_eq!(state.query_sent, now);
        assert_eq!(pkt.mode(), mode::CLIENT);
    }

    #[test]
    fn test_query_state_send_receive_cycle() {
        let mut state = QueryState::new();
        let mut peer = default_peer();
        let now = NtpTimestamp::new(4_000_000_000, 0);

        // Send.
        let _pkt = state.send_query(now);
        assert!(state.outstanding);

        // Build a valid response.
        let response = make_server_response(state.query_time, 10, 20);
        let recv_ts = NtpTimestamp::new(now.secs.wrapping_add(30), now.frac.wrapping_add(1000));

        // Receive.
        let result = state.receive_response(&mut peer, &response, recv_ts);
        assert!(result.is_ok(), "receive failed: {:?}", result);
        assert!(!state.outstanding, "outstanding should be cleared");
    }

    #[test]
    fn test_query_state_rejects_wrong_origin() {
        let mut state = QueryState::new();
        let mut peer = default_peer();
        let now = NtpTimestamp::new(4_000_000_000, 0);

        let _pkt = state.send_query(now);
        assert!(state.outstanding);

        // Response with a different origin timestamp.
        let mut response = make_server_response(state.query_time, 10, 20);
        response.origin_ts = NtpTimestamp::new(999_999, 0);

        let recv_ts = NtpTimestamp::new(now.secs.wrapping_add(30), now.frac.wrapping_add(1000));

        let result = state.receive_response(&mut peer, &response, recv_ts);
        assert_eq!(result, Err(QueryError::ReplayAttack));
        // Outstanding should remain true so caller can retry/timeout.
        assert!(state.outstanding);
    }

    #[test]
    fn test_query_state_timeout_not_outstanding() {
        let state = QueryState::new();
        let now = NtpTimestamp::new(4_000_000_100, 0);
        assert!(!state.is_timed_out(now, 5));
    }

    #[test]
    fn test_query_state_timeout_elapsed() {
        let mut state = QueryState::new();
        let now = NtpTimestamp::new(4_000_000_000, 0);
        let _ = state.send_query(now);

        // Enough time passed.
        let later = NtpTimestamp::new(4_000_000_010, 0);
        assert!(
            state.is_timed_out(later, 5),
            "should have timed out after 10s with timeout=5"
        );
    }

    #[test]
    fn test_query_state_no_timeout_before_deadline() {
        let mut state = QueryState::new();
        let now = NtpTimestamp::new(4_000_000_000, 0);
        let _ = state.send_query(now);

        let slightly_later = NtpTimestamp::new(4_000_000_003, 0);
        assert!(
            !state.is_timed_out(slightly_later, 5),
            "should NOT have timed out after 3s with timeout=5"
        );
    }

    #[test]
    fn test_query_state_timeout_exact_boundary() {
        let mut state = QueryState::new();
        let now = NtpTimestamp::new(4_000_000_000, 0);
        let _ = state.send_query(now);

        let at_boundary = NtpTimestamp::new(4_000_000_005, 0);
        assert!(
            state.is_timed_out(at_boundary, 5),
            "should have timed out at exactly timeout seconds"
        );
    }

    // -----------------------------------------------------------------------
    // Integration — full lifecycle
    // -----------------------------------------------------------------------

    #[test]
    fn test_full_query_lifecycle() {
        let mut state = QueryState::new();
        let mut peer = default_peer();

        // Simulate the system time moving forward.
        let t1 = NtpTimestamp::new(4_000_000_000, 0);
        let pkt = state.send_query(t1);
        assert!(state.outstanding);
        assert_eq!(pkt.transmit_ts, t1);

        // Simulate network round-trip: server responds after 30 ms.
        // T1 = 4_000_000_000.0, T2 = 4_000_000_000.010, T3 = 4_000_000_000.020
        // T4 = 4_000_000_000.030
        let response = make_server_response(
            t1, 10, // server receives 10 sec later
            20, // server transmits 20 sec later
        );
        let t4 = NtpTimestamp::new(t1.secs.wrapping_add(30), t1.frac);

        let (offset, delay) = state
            .receive_response(&mut peer, &response, t4)
            .expect("full lifecycle response should succeed");
        assert!(!state.outstanding);

        // offset ≈ 0, delay ≈ 20
        assert!((offset).abs() < 0.1, "offset: {offset}");
        assert!((delay - 20.0).abs() < 0.1, "delay: {delay}");

        // Peer should be reachable and have a sample.
        assert!(peer.reachable());
        assert!(peer.best_sample().is_some());
    }

    #[test]
    fn test_integration_multiple_queries_fill_filter() {
        let mut state = QueryState::new();
        let mut peer = default_peer();

        // Perform 8 queries to fill the ring buffer.
        let base_secs = 4_000_000_000u32;
        for i in 0..8 {
            let t1 = NtpTimestamp::new(base_secs + i * 100, 0);
            let _pkt = state.send_query(t1);

            // Each response has a slightly different delay pattern.
            let delay_offset = i as u32 * 5;
            let response =
                make_server_response(state.query_time, 10 + delay_offset, 20 + delay_offset);
            let t4 = NtpTimestamp::new(t1.secs.wrapping_add(30 + 2 * delay_offset), t1.frac);

            state
                .receive_response(&mut peer, &response, t4)
                .expect("query should succeed");
        }

        // Filter should have 8 samples.
        let sample_count = peer.filter.iter().flatten().count();
        assert_eq!(sample_count, 8, "filter should have 8 samples");

        // Peer should have a reasonable best estimate.
        let best = peer.best_sample().expect("should have best sample");
        assert!((best.offset).abs() < 1.0, "best offset: {}", best.offset);
        // With our delays, the lowest-delay samples have delay ~20-30.
        assert!(
            best.delay > 0.0 && best.delay < 50.0,
            "best delay: {}",
            best.delay
        );

        // Peer state should be consistent.
        assert!(peer.reachable());
        assert!(!peer.has_flash(PFLASH_PEERNOQUERY));
    }

    #[test]
    fn test_integration_consecutive_queries() {
        let mut state = QueryState::new();
        let mut peer = default_peer();

        // Do two back-to-back queries, each processed successfully.
        for i in 0..3 {
            let t1 = NtpTimestamp::new(4_000_000_000 + i * 200, 0);
            let _ = state.send_query(t1);

            let response = make_server_response(state.query_time, 10, 20);
            let t4 = NtpTimestamp::new(t1.secs.wrapping_add(30), t1.frac);
            state
                .receive_response(&mut peer, &response, t4)
                .expect("consecutive query should succeed");
        }

        // Peer should have 3 samples.
        let count = peer.filter.iter().flatten().count();
        assert_eq!(count, 3);
        assert!(peer.reachable());
    }

    #[test]
    fn test_integration_error_response_does_not_clear_outstanding() {
        let mut state = QueryState::new();
        let mut peer = default_peer();
        let t1 = NtpTimestamp::new(4_000_000_000, 0);
        let _ = state.send_query(t1);

        // Send back a KOD response.
        let mut response = make_server_response(state.query_time, 10, 20);
        response.stratum = 0;

        let t4 = NtpTimestamp::new(t1.secs.wrapping_add(30), t1.frac);
        let result = state.receive_response(&mut peer, &response, t4);
        assert_eq!(result, Err(QueryError::KissOfDeath));
        // Outstanding should still be set so caller can retry.
        assert!(state.outstanding, "outstanding should remain on error");
    }

    // -----------------------------------------------------------------------
    // Edge cases
    // -----------------------------------------------------------------------

    #[test]
    fn test_edge_zero_origin_timestamp() {
        let mut peer = default_peer();
        let query_ts = NtpTimestamp::zero();
        let recv_ts = NtpTimestamp::new(30, 0);
        let response = make_server_response(query_ts, 10, 20);

        let result = process_response(&mut peer, &response, recv_ts, query_ts);
        // Using zero as query_time is valid (no replay check issue
        // since it matches), and the timestamps are all consistent.
        assert!(
            result.is_ok(),
            "zero query_time should be valid: {result:?}"
        );
    }

    #[test]
    fn test_edge_negative_delay_does_not_set_flash() {
        let mut peer = default_peer();
        let query_ts = NtpTimestamp::new(1_000_000, 0);
        let recv_ts = NtpTimestamp::new(1_000_005, 0); // Only 5 sec later

        // T2 = 1_000_020, T3 = 1_000_010 (T3 < T2 is unusual but valid in NTP)
        // delay = (5 - 0) - (10 - 20) = 5 - (-10) = 15  => positive
        // But let's craft a truly negative delay:
        // delay = (T4 - T1) - (T3 - T2) = 5 - (10 - 20) = 5 - (-10) = 15 (positive)
        // To get a negative delay, we need T3 much larger than T4 relative to T2.
        // Let's use a different setup.
        let response = make_server_response(query_ts, 2, 100);
        // T2 = query + 2, T3 = query + 100, T4 = query + 5
        // delay = 5 - (100 - 2) = 5 - 98 = -93
        let result = process_response(&mut peer, &response, recv_ts, query_ts);
        assert!(result.is_ok(), "negative delay should still be accepted");
        assert!(
            peer.has_flash(PFLASH_PEERDELAY),
            "negative delay should set PFLASH_PEERDELAY"
        );
    }

    #[test]
    fn test_edge_wrapping_timestamps() {
        // Test with timestamps that wrap around u32 boundary.
        let mut peer = default_peer();
        let query_ts = NtpTimestamp::new(u32::MAX - 5, 0);
        let recv_ts = NtpTimestamp::new(10, 0); // Wrapped around
        let response = make_server_response(query_ts, 2, 4);
        // T2 = u32::MAX - 3, T3 = u32::MAX - 1
        // T4 = 10 (wrapped)
        // In f64 land: T1 ≈ 4294967290, T2 ≈ 4294967292, T3 ≈ 4294967294, T4 ≈ 10
        // The compute_offset will produce a large negative offset and delay
        // because it doesn't do era resolution. That's fine — we just verify
        // the system doesn't crash or panic.
        let result = process_response(&mut peer, &response, recv_ts, query_ts);
        // May or may not be Ok (the result depends on f64 wrapping behavior);
        // the important thing is we don't panic.
        if let Ok((offset, delay)) = result {
            // If it succeeds, the values should be finite.
            assert!(offset.is_finite(), "offset should be finite: {offset}");
            assert!(delay.is_finite(), "delay should be finite: {delay}");
        }
    }

    #[test]
    fn test_edge_very_large_offset() {
        let mut peer = default_peer();
        let query_ts = NtpTimestamp::new(1_000_000, 0);
        let huge_delta = 1_000_000u32; // 1 million seconds
        let response = make_server_response(query_ts, huge_delta, huge_delta);
        let recv_ts = NtpTimestamp::new(query_ts.secs.wrapping_add(huge_delta + 1), query_ts.frac);

        let result = process_response(&mut peer, &response, recv_ts, query_ts);
        assert!(result.is_ok(), "large offset should be accepted");
        let (offset, _delay) = result.unwrap();
        assert!(offset.abs() > 100_000.0, "offset should be large: {offset}");
        assert!(
            peer.has_flash(PFLASH_PEEROFFSET),
            "PFLASH_PEEROFFSET should be set"
        );
    }

    #[test]
    fn test_edge_zero_delay() {
        let mut peer = default_peer();
        let query_ts = NtpTimestamp::new(1_000_000, 0);
        let _recv_ts = NtpTimestamp::new(1_000_020, 0);
        // T2 = 1_000_010, T3 = 1_000_010
        // delay = (20 - 0) - (10 - 10) = 20 - 0 = 20
        // Not zero. To get zero delay:
        // T4 - T1 = T3 - T2
        // Let's use T2 = 1_000_010, T3 = 1_000_015, T4 = 1_000_005
        // delay = (5 - 0) - (15 - 10) = 5 - 5 = 0 ✓
        let mut response = make_server_response(query_ts, 10, 15);
        response.origin_ts = query_ts;
        response.receive_ts = NtpTimestamp::new(query_ts.secs.wrapping_add(10), query_ts.frac);
        response.transmit_ts = NtpTimestamp::new(query_ts.secs.wrapping_add(15), query_ts.frac);
        let recv_ts_adj = NtpTimestamp::new(query_ts.secs.wrapping_add(5), query_ts.frac);

        let result = process_response(&mut peer, &response, recv_ts_adj, query_ts);
        assert!(result.is_ok(), "zero delay should be accepted");
        let (_offset, delay) = result.unwrap();
        assert!((delay).abs() < 1e-9, "delay should be ~0 but got: {delay}");
    }

    #[test]
    fn test_edge_kiss_code_check() {
        // Verify that stratum 0 with various reference IDs is still
        // rejected as KissOfDeath (the reference_id content doesn't
        // matter for our validation).
        let mut peer = default_peer();
        let query_ts = NtpTimestamp::new(1_000_000, 0);
        let recv_ts = NtpTimestamp::new(1_000_030, 0);

        let mut response = make_server_response(query_ts, 10, 20);
        response.stratum = 0;
        response.reference_id = *b"RATE";

        let err = process_response(&mut peer, &response, recv_ts, query_ts)
            .expect_err("KOD with RATE code");
        assert_eq!(err, QueryError::KissOfDeath);

        response.reference_id = *b"DENY";
        let err = process_response(&mut peer, &response, recv_ts, query_ts)
            .expect_err("KOD with DENY code");
        assert_eq!(err, QueryError::KissOfDeath);
    }

    #[test]
    fn test_edge_round_trip_encode_decode_response() {
        // Build a full query, encode to bytes, then decode and verify
        // we can still process the response.
        let mut peer = default_peer();
        let query_ts = NtpTimestamp::new(4_000_000_000, 0x8000_0000);
        let response = make_server_response(query_ts, 10, 20);
        let recv_ts = NtpTimestamp::new(
            query_ts.secs.wrapping_add(30),
            query_ts.frac.wrapping_add(0x4000_0000),
        );

        // Encode to bytes and decode back.
        let encoded = response.encode();
        let decoded = NtpDatagram::decode(&encoded).unwrap();
        let decoded_pkt = match decoded {
            NtpDatagram::Unauthenticated(pkt) => pkt,
            _ => panic!("expected unauthenticated"),
        };

        let result = process_response(&mut peer, &decoded_pkt, recv_ts, query_ts);
        assert!(result.is_ok(), "encoded/decode round trip: {result:?}");
    }

    #[test]
    fn test_edge_outstanding_query_replace() {
        // Sending a new query while one is outstanding should silently
        // replace the old one.
        let mut state = QueryState::new();
        let t1 = NtpTimestamp::new(4_000_000_000, 0);
        let _ = state.send_query(t1);
        assert!(state.outstanding);

        let t2 = NtpTimestamp::new(4_000_000_100, 0);
        let pkt = state.send_query(t2);
        assert!(state.outstanding);
        assert_eq!(state.query_time, pkt.transmit_ts);
        assert_eq!(state.query_time, t2);

        // The old query_time is lost; a response for the old query
        // will be rejected via replay detection.
    }

    #[test]
    fn test_edge_display_error() {
        // Ensure all error variants have a proper Display impl.
        let err = QueryError::WrongMode(1);
        let msg = alloc::format!("{err}");
        assert!(!msg.is_empty());

        let err = QueryError::KissOfDeath;
        let msg = alloc::format!("{err}");
        assert!(!msg.is_empty());

        let err = QueryError::InvalidStratum;
        let msg = alloc::format!("{err}");
        assert!(!msg.is_empty());

        let err = QueryError::InvalidVersion;
        let msg = alloc::format!("{err}");
        assert!(!msg.is_empty());

        let err = QueryError::BadTimestamp;
        let msg = alloc::format!("{err}");
        assert!(!msg.is_empty());

        let err = QueryError::ReplayAttack;
        let msg = alloc::format!("{err}");
        assert!(!msg.is_empty());
    }

    #[test]
    fn test_query_state_default() {
        let state = QueryState::default();
        assert!(!state.outstanding);
        assert_eq!(state.query_time, NtpTimestamp::zero());
        assert_eq!(state.query_sent, NtpTimestamp::zero());
    }
}
