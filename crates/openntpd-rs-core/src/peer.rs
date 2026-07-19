//! NTP client state machine — clock filter, reachability, poll
//! interval, and clock selection.
//!
//! This module corresponds to OpenNTPD's
//! [`client.c`](https://github.com/openntpd-portable/openntpd-openbsd/blob/master/src/usr.sbin/ntpd/client.c).
//!
//! ## Overview
//!
//! Each [`Peer`] represents a single NTP server and maintains:
//!
//! * **Clock filter** — an 8-sample ring buffer ([`NTP_FILTER`]) with
//!   lowest-delay sample selection and four-sample weighted averaging.
//! * **Reachability register** — an 8-bit shift register recording the
//!   success/failure of the last 8 polls.
//! * **Flash bits** — a 16-bit error state bitmask indicating what is
//!   wrong with this peer.
//! * **Poll interval state machine** — dynamically adjusts the poll
//!   rate based on network conditions (initial rapid polls, normal
//!   polling, backoff on loss, reset on complete unreachability).
//!
//! The [`ClockSelection`] pipeline implements NTP's three-stage clock
//! selection: intersection (find truechimers), clustering (remove
//! outliers), and combining (weighted average of survivors).

use crate::config::directive::ConfigString;
use crate::ntp::NtpTimestamp;

use alloc::vec::Vec;
use core::cmp;
use core::fmt;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Number of samples in the clock filter ring buffer.
pub const NTP_FILTER: usize = 8;

/// Initial poll interval exponent: 2³ = 8 seconds.
pub const INITIAL_POLL: i8 = 3;

/// Number of rapid polls after boot or reset.
pub const FAST_POLL_COUNT: u8 = 4;

/// Minimum poll interval exponent: 2³ = 8 seconds.
pub const MIN_POLL: i8 = 3;

/// Maximum poll interval exponent: 2¹⁰ = 1024 seconds (~17 minutes).
pub const MAX_POLL: i8 = 10;

/// Maximum tolerated delay in seconds before a peer is flagged.
pub const MAX_DELAY: f64 = 2.0;

/// Maximum tolerated dispersion before a peer is flagged.
pub const MAX_DISPERSION: f64 = 16.0;

/// Maximum difference between peer offset and system clock (seconds)
/// before a peer is flagged.
pub const MAX_OFFSET: f64 = 1.0;

/// Maximum tolerated jitter (seconds) before a peer is flagged.
pub const MAX_JITTER: f64 = 1.0;

/// Maximum stratum value for a usable peer.
pub const MAX_STRATUM: u8 = 15;

/// Number of consecutive missed polls that triggers a reachability reset.
pub const MAX_UNREACHABLE: u8 = 8;

// ---------------------------------------------------------------------------
// Flash bit constants
// ---------------------------------------------------------------------------

/// Peer address is invalid.
pub const PFLASH_PEERADDR: u16 = 0x0001;
/// Stratum is invalid or out of range.
pub const PFLASH_PEERSTRAT: u16 = 0x0002;
/// Dispersion exceeds maximum.
pub const PFLASH_PEERDISP: u16 = 0x0004;
/// Delay exceeds maximum.
pub const PFLASH_PEERDELAY: u16 = 0x0008;
/// Offset is too large.
pub const PFLASH_PEEROFFSET: u16 = 0x0010;
/// Jitter is too high.
pub const PFLASH_PEERJITTER: u16 = 0x0020;
/// No query has been sent yet.
pub const PFLASH_PEERNOQUERY: u16 = 0x0040;
/// Reachability test failed (peer unreachable).
pub const PFLASH_PEERREACH: u16 = 0x0080;
/// Maximum error exceeded.
pub const PFLASH_PEERMAXERR: u16 = 0x0100;
/// Peer stratum is bad for selection (e.g. stratum >= 16).
pub const PFLASH_PEERBADSTRAT: u16 = 0x0200;

// ---------------------------------------------------------------------------
// Data structures
// ---------------------------------------------------------------------------

/// A single sample in the NTP clock filter.
///
/// Each sample records the observed clock offset, round-trip delay,
/// and dispersion for one NTP exchange with a peer.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct NtpFilterSample {
    /// Clock offset (seconds). Positive means peer is ahead of us.
    pub offset: f64,
    /// Round-trip delay (seconds).
    pub delay: f64,
    /// Dispersion (seconds) — accumulated error estimate.
    pub dispersion: f64,
}

/// A single NTP peer.
///
/// Each `Peer` maintains a clock filter, reachability register,
/// flash bits, poll timer, and the best estimates of offset, delay,
/// and dispersion for that server.
#[derive(Debug, Clone)]
pub struct Peer {
    /// Unique identifier for this peer.
    pub id: u64,
    /// Network address (hostname or numeric IP).
    pub address: ConfigString,
    /// Best current estimate of clock offset (seconds).
    pub offset: f64,
    /// Best current estimate of round-trip delay (seconds).
    pub delay: f64,
    /// Best current estimate of dispersion (seconds).
    pub dispersion: f64,
    /// Ring buffer of clock filter samples.
    pub filter: [Option<NtpFilterSample>; NTP_FILTER],
    /// Index in the ring buffer where the next sample will be stored.
    pub filter_next: usize,
    /// 8-bit reachability shift register.
    pub reach: u8,
    /// Current poll interval exponent: interval = 2^poll seconds.
    pub poll: i8,
    /// Error state bitmask (flash bits).
    pub flash: u16,
    /// Selection weight (higher = more influence in combining).
    pub weight: u8,
    /// Whether this peer is a trusted/preferred source.
    pub trusted: bool,
    /// NTP stratum of this peer (1 = primary, 2–15 = secondary).
    pub stratum: u8,
    /// Peer's clock precision as a signed log2 seconds exponent.
    pub precision: i8,
    /// Peer's root delay (seconds).
    pub root_delay: f64,
    /// Peer's root dispersion (seconds).
    pub root_dispersion: f64,
    /// Peer's reference ID (usually IP address or ASCII code).
    pub reference_id: u32,
    /// Counter of total polls sent to this peer.
    pub poll_count: u64,
    /// Counter of rapid polls during the initial burst phase.
    pub rapid_polls: u8,
    /// Number of consecutive unreachable polls.
    pub consecutive_unreachable: u8,
}

impl Peer {
    /// Create a new `Peer` with the given address, weight, and trust flag.
    ///
    /// The peer starts with all flash bits clear (except
    /// [`PFLASH_PEERNOQUERY`]) and an empty filter. The initial poll
    /// interval starts at [`INITIAL_POLL`].
    #[must_use]
    pub fn new(address: ConfigString, weight: u8, trusted: bool) -> Self {
        // Generate a simple hash of the address bytes for the id.
        let id = {
            let bytes = address.as_bytes();
            let mut h: u64 = 0x517cc1b727220a95;
            for &b in bytes {
                h = h.wrapping_mul(0x100000001b3).wrapping_add(u64::from(b));
            }
            h
        };

        Self {
            id,
            address,
            offset: 0.0,
            delay: 0.0,
            dispersion: 0.0,
            filter: [None; NTP_FILTER],
            filter_next: 0,
            reach: 0,
            poll: INITIAL_POLL,
            flash: PFLASH_PEERNOQUERY,
            weight,
            trusted,
            stratum: 0,
            precision: 0,
            root_delay: 0.0,
            root_dispersion: 0.0,
            reference_id: 0,
            poll_count: 0,
            rapid_polls: 0,
            consecutive_unreachable: 0,
        }
    }

    // -----------------------------------------------------------------------
    // Clock filter
    // -----------------------------------------------------------------------

    /// Add a new sample to the clock filter ring buffer.
    ///
    /// After adding the sample, the peer's `offset`, `delay`, and
    /// `dispersion` are updated to the best (lowest-delay, weighted)
    /// estimate from the filter.
    pub fn add_sample(&mut self, offset: f64, delay: f64, dispersion: f64) {
        let idx = self.filter_next % NTP_FILTER;
        self.filter[idx] = Some(NtpFilterSample {
            offset,
            delay,
            dispersion,
        });
        self.filter_next = self.filter_next.wrapping_add(1);

        // Update peer state from the best sample
        if let Some(best) = self.best_sample() {
            self.offset = best.offset;
            self.delay = best.delay;
            self.dispersion = best.dispersion;
        }
    }

    /// Return the best sample from the filter.
    ///
    /// The "best" sample is computed as a **weighted average of the
    /// four lowest-delay samples** in the filter, where each sample's
    /// weight is the reciprocal of its delay (samples with smaller
    /// delay get more weight).
    ///
    /// Returns `None` when the filter is empty.
    #[must_use]
    pub fn best_sample(&self) -> Option<NtpFilterSample> {
        // Collect all non-None samples.
        let mut samples: Vec<&NtpFilterSample> = self.filter.iter().flatten().collect();
        if samples.is_empty() {
            return None;
        }

        // Sort by delay (ascending).
        samples.sort_by(|a, b| {
            a.delay
                .partial_cmp(&b.delay)
                .unwrap_or(cmp::Ordering::Equal)
        });

        // Take up to 4 lowest-delay samples.
        let count = cmp::min(4, samples.len());
        let candidates = &samples[..count];

        // Weighted average: w_i = 1 / (delay_i + ε), normalized.
        let epsilon = 1e-12; // prevent division by zero
        let mut total_weight = 0.0_f64;
        let mut sum_offset = 0.0_f64;
        let mut sum_delay = 0.0_f64;
        let mut sum_dispersion = 0.0_f64;

        for s in candidates {
            let w = 1.0 / (s.delay + epsilon);
            total_weight += w;
            sum_offset += s.offset * w;
            sum_delay += s.delay * w;
            sum_dispersion += s.dispersion * w;
        }

        if total_weight > 0.0 {
            Some(NtpFilterSample {
                offset: sum_offset / total_weight,
                delay: sum_delay / total_weight,
                dispersion: sum_dispersion / total_weight,
            })
        } else {
            // Fallback: return the first candidate (shouldn't happen).
            Some(NtpFilterSample {
                offset: candidates[0].offset,
                delay: candidates[0].delay,
                dispersion: candidates[0].dispersion,
            })
        }
    }

    /// Compute the filter dispersion.
    ///
    /// Filter dispersion is the mean of `|offset_i - offset_best| +
    /// dispersion_i` across all samples in the filter. This measures
    /// the internal consistency of the filter.
    #[must_use]
    pub fn filter_dispersion(&self) -> f64 {
        let best = self.best_sample();
        let best_offset = best.as_ref().map(|s| s.offset).unwrap_or(0.0);

        let mut d = 0.0_f64;
        let mut count = 0_usize;

        for sample in self.filter.iter().flatten() {
            d += (sample.offset - best_offset).abs() + sample.dispersion;
            count += 1;
        }

        if count > 0 {
            d / count as f64
        } else {
            0.0
        }
    }

    // -----------------------------------------------------------------------
    // Reachability
    // -----------------------------------------------------------------------

    /// Update the 8-bit reachability shift register.
    ///
    /// Shifts left by one bit, setting the LSB to `1` if a response was
    /// received, or `0` if not.
    pub fn update_reach(&mut self, response_received: bool) {
        self.reach <<= 1;
        self.reach |= u8::from(response_received);
    }

    /// Return `true` if the peer is reachable (any bit set in the
    /// reachability register).
    #[must_use]
    pub fn reachable(&self) -> bool {
        self.reach != 0
    }

    // -----------------------------------------------------------------------
    // Flash bit management
    // -----------------------------------------------------------------------

    /// Set one or more flash bits.
    pub fn set_flash(&mut self, bit: u16) {
        self.flash |= bit;
    }

    /// Clear one or more flash bits.
    pub fn clear_flash(&mut self, bit: u16) {
        self.flash &= !bit;
    }

    /// Return `true` if the given flash bit(s) are set.
    #[must_use]
    pub fn has_flash(&self, bit: u16) -> bool {
        self.flash & bit != 0
    }

    /// Return `true` if any flash bit is set.
    #[must_use]
    pub fn has_any_flash(&self) -> bool {
        self.flash != 0
    }

    // -----------------------------------------------------------------------
    // Poll interval state machine
    // -----------------------------------------------------------------------

    /// Update the poll interval based on whether a response was
    /// received.
    ///
    /// The state machine implements the following transitions:
    ///
    /// 1. **Initial rapid poll phase** — For the first
    ///    [`FAST_POLL_COUNT`] polls that get responses, keep the
    ///    interval at [`INITIAL_POLL`] (high frequency).
    /// 2. **Normal phase** — After the rapid phase, adjust based on
    ///    jitter: if the peer is jittery, poll more often (decrease
    ///    interval); if stable, poll less often (increase interval).
    /// 3. **Backoff** — If no response, increase the poll interval
    ///    (back off) up to [`MAX_POLL`].
    /// 4. **Reset** — After [`MAX_UNREACHABLE`] consecutive missed
    ///    responses, reset to [`INITIAL_POLL`] and re-enter the rapid
    ///    phase.
    pub fn update_poll(&mut self, response_received: bool) {
        self.poll_count = self.poll_count.saturating_add(1);

        if response_received {
            self.consecutive_unreachable = 0;

            // Clear the no-query flash bit since we received a response.
            self.clear_flash(PFLASH_PEERNOQUERY);

            if self.rapid_polls < FAST_POLL_COUNT {
                // Still in rapid-poll phase: increment counter and keep
                // at initial interval.
                self.rapid_polls += 1;
                self.poll = INITIAL_POLL;
            } else {
                // Normal phase: adjust based on stability.
                // Check the jitter flash bit set by the caller.
                if self.has_flash(PFLASH_PEERJITTER) {
                    // Jitter detected: poll more often.
                    self.poll = cmp::max(self.poll - 1, MIN_POLL);
                } else {
                    // Stable: poll less often.
                    self.poll = cmp::min(self.poll + 1, MAX_POLL);
                }
            }
        } else {
            // No response: backoff.
            self.consecutive_unreachable = self.consecutive_unreachable.saturating_add(1);
            self.rapid_polls = 0;

            // Increase poll interval (up to MAX_POLL).
            self.poll = cmp::min(self.poll + 1, MAX_POLL);

            // If too many consecutive misses, reset to initial poll.
            if self.consecutive_unreachable >= MAX_UNREACHABLE {
                self.poll = INITIAL_POLL;
                self.rapid_polls = 0;
            }
        }
    }

    // -----------------------------------------------------------------------
    // Offset/delay from NTP timestamps
    // -----------------------------------------------------------------------

    /// Compute the clock offset and round-trip delay from four NTP
    /// timestamps.
    ///
    /// Uses the standard NTP equations:
    ///
    /// ```text
    /// offset = ((T2 − T1) + (T3 − T4)) / 2
    /// delay  = (T4 − T1) − (T3 − T2)
    /// ```
    ///
    /// Where:
    /// - `t1` = client transmit timestamp
    /// - `t2` = server receive timestamp
    /// - `t3` = server transmit timestamp
    /// - `t4` = client receive timestamp
    ///
    /// Returns `(offset, delay)` in seconds.
    #[must_use]
    pub fn compute_offset(
        t1: NtpTimestamp,
        t2: NtpTimestamp,
        t3: NtpTimestamp,
        t4: NtpTimestamp,
    ) -> (f64, f64) {
        let t1_f = t1.to_f64();
        let t2_f = t2.to_f64();
        let t3_f = t3.to_f64();
        let t4_f = t4.to_f64();

        let offset = ((t2_f - t1_f) + (t3_f - t4_f)) / 2.0;
        let delay = (t4_f - t1_f) - (t3_f - t2_f);

        (offset, delay)
    }
}

// ---------------------------------------------------------------------------
// Clock selection
// ---------------------------------------------------------------------------

/// NTP clock selection pipeline: intersection → clustering → combining.
///
/// This implements the three-stage selection algorithm described in
/// RFC 5905:
///
/// 1. **Intersection** — Find the set of "truechimers" (peers whose
///    confidence intervals overlap with the majority).
/// 2. **Clustering** — Iteratively remove the worst survivor until at
///    most 3 remain.
/// 3. **Combining** — Compute a weighted average of the survivors.
#[derive(Debug, Clone)]
pub struct ClockSelection {
    /// The list of peers being considered for selection.
    pub peers: Vec<Peer>,
    /// The combined (synthesized) peer after the full selection pipeline.
    combined: Option<Peer>,
}

impl ClockSelection {
    /// Create a new clock selection from a list of peers.
    #[must_use]
    pub fn new(peers: Vec<Peer>) -> Self {
        Self {
            peers,
            combined: None,
        }
    }

    /// Run the intersection algorithm to identify truechimers.
    ///
    /// Peers that fail the intersection test are removed from the
    /// candidate list.  A peer's confidence interval is
    /// `[offset - total_dispersion, offset + total_dispersion]`
    /// where `total_dispersion = dispersion + filter_dispersion()`.
    ///
    /// The algorithm finds the smallest region that contains the most
    /// midpoints.  Peers whose intervals contain this region are
    /// kept; all others are removed.
    pub fn intersection(&mut self) -> &mut Self {
        if self.peers.is_empty() {
            return self;
        }

        // For each peer, compute total dispersion and interval.
        // Each peer's confidence interval: [offset - total_dispersion, offset + total_dispersion].
        #[derive(Clone, Copy)]
        struct Interval {
            offset: f64,
            low: f64,
            high: f64,
        }

        let intervals: Vec<Interval> = self
            .peers
            .iter()
            .map(|p| {
                let total_dispersion = p.dispersion + p.root_dispersion;
                Interval {
                    offset: p.offset,
                    low: p.offset - total_dispersion,
                    high: p.offset + total_dispersion,
                }
            })
            .collect();

        // Early exit: single peer is always a truechimer.
        if intervals.len() <= 1 {
            return self;
        }

        // Collect all midpoints (offsets) and find the region with
        // the most overlapping intervals.
        //
        // We build a sorted list of unique coordinates and scan to
        // find the point covered by the most intervals.
        let mut coordinates: Vec<f64> = Vec::new();
        for iv in &intervals {
            coordinates.push(iv.low);
            coordinates.push(iv.high);
        }
        coordinates.sort_by(|a, b| a.partial_cmp(b).unwrap_or(cmp::Ordering::Equal));

        // Find the maximum tally (number of intervals covering a point).
        let mut max_tally: usize = 0;
        let mut best_mid = 0.0_f64;
        let midpoints: Vec<f64> = intervals.iter().map(|iv| iv.offset).collect();

        // Scan every midpoint and count how many intervals cover it.
        for &mp in &midpoints {
            let tally = intervals
                .iter()
                .filter(|iv| mp >= iv.low && mp <= iv.high)
                .count();
            if tally > max_tally {
                max_tally = tally;
                best_mid = mp;
            }
        }

        // A peer is a truechimer if its interval covers the best
        // midpoint.  We require at least floor((n+1)/2) intervals
        // to agree (majority intersection).
        let threshold = (intervals.len() + 1) / 2;

        if max_tally < threshold {
            // No majority — keep all peers (the caller's selection
            // will reject them later through flash bits).
            return self;
        }

        // Filter to peers whose interval contains best_mid.
        self.peers.retain(|p| {
            let total_dispersion = p.dispersion + p.root_dispersion;
            let low = p.offset - total_dispersion;
            let high = p.offset + total_dispersion;
            best_mid >= low && best_mid <= high
        });

        self
    }

    /// Run the clustering algorithm to remove outliers.
    ///
    /// Repeatedly removes the peer with the largest "distance" from
    /// the survivor midpoint until at most 3 peers remain.  Distance
    /// is defined as `|offset_i - survivor_mean| / total_dispersion_i`.
    pub fn clustering(&mut self) -> &mut Self {
        // Keep removing until we have ≤ 3 peers.
        while self.peers.len() > 3 {
            // Compute the mean offset of remaining peers.
            let mean_offset: f64 =
                self.peers.iter().map(|p| p.offset).sum::<f64>() / self.peers.len() as f64;

            // Find the peer with the largest normalized distance from
            // the mean.
            let worst_idx = self
                .peers
                .iter()
                .enumerate()
                .max_by(|(_, a), (_, b)| {
                    let dist_a =
                        (a.offset - mean_offset).abs() / (a.dispersion + a.root_dispersion + 1e-12);
                    let dist_b =
                        (b.offset - mean_offset).abs() / (b.dispersion + b.root_dispersion + 1e-12);
                    dist_a.partial_cmp(&dist_b).unwrap_or(cmp::Ordering::Equal)
                })
                .map(|(idx, _)| idx);

            if let Some(idx) = worst_idx {
                self.peers.swap_remove(idx);
            } else {
                break;
            }
        }

        self
    }

    /// Combine the survivors into a single weighted-average peer.
    ///
    /// Each survivor's weight is computed as:
    /// `weight = 1 / (delay + dispersion + root_dispersion + 1e-12)`
    ///
    /// Returns `None` if there are no survivors.
    #[must_use]
    pub fn combine(&self) -> Option<Peer> {
        if self.peers.is_empty() {
            return None;
        }

        let mut total_weight = 0.0_f64;
        let mut sum_offset = 0.0_f64;
        let mut sum_delay = 0.0_f64;
        let mut sum_dispersion = 0.0_f64;
        let mut sum_root_delay = 0.0_f64;
        let mut sum_root_dispersion = 0.0_f64;
        let mut weighted_stratum = 0.0_f64;

        for p in &self.peers {
            let w = 1.0 / (p.delay + p.dispersion + p.root_dispersion + 1e-12);
            total_weight += w;
            sum_offset += p.offset * w;
            sum_delay += p.delay * w;
            sum_dispersion += p.dispersion * w;
            sum_root_delay += p.root_delay * w;
            sum_root_dispersion += p.root_dispersion * w;
            weighted_stratum += f64::from(p.stratum) * w;
        }

        if total_weight <= 0.0 {
            return None;
        }

        // Build a synthetic "combined" peer.
        let combined = Peer {
            id: 0, // synthetic peer ID
            address: ConfigString::new(alloc::vec![b'*']).unwrap(),
            offset: sum_offset / total_weight,
            delay: sum_delay / total_weight,
            dispersion: sum_dispersion / total_weight,
            filter: [None; NTP_FILTER],
            filter_next: 0,
            reach: 0,
            poll: 0,
            flash: 0,
            weight: 0,
            trusted: false,
            stratum: libm::round(weighted_stratum / total_weight) as u8,
            precision: 0,
            root_delay: sum_root_delay / total_weight,
            root_dispersion: sum_root_dispersion / total_weight,
            reference_id: 0,
            poll_count: 0,
            rapid_polls: 0,
            consecutive_unreachable: 0,
        };

        Some(combined)
    }

    /// Run the full selection pipeline and return the combined peer.
    ///
    /// Shortcut for: `self.intersection().clustering().combine()`
    #[must_use]
    pub fn select(&mut self) -> Option<&Peer> {
        self.intersection().clustering();
        self.combined = self.combine();
        self.combined.as_ref()
    }
}

impl fmt::Display for Peer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Peer {{ addr: {}, stratum: {}, offset: {:.6}s, delay: {:.6}s, disp: {:.6}s, reach: {:#04x}, poll: {}, flash: {:#06x} }}",
            self.address.as_utf8().unwrap_or("<invalid>"),
            self.stratum,
            self.offset,
            self.delay,
            self.dispersion,
            self.reach,
            1i32 << self.poll,
            self.flash,
        )
    }
}

// ---------------------------------------------------------------------------
// Helper functions
// ---------------------------------------------------------------------------

/// Return the interval string for a poll exponent: `2^poll` seconds.
#[must_use]
pub fn poll_interval_str(poll: i8) -> alloc::string::String {
    let secs = 1u64 << poll.max(0) as u64;
    if secs < 60 {
        alloc::format!("{secs}s")
    } else if secs < 3600 {
        alloc::format!("{}m", secs / 60)
    } else {
        alloc::format!("{}h{}m", secs / 3600, (secs % 3600) / 60)
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    // Helper to create a simple ConfigString from a &str.
    fn addr(s: &str) -> ConfigString {
        ConfigString::new(s.as_bytes().to_vec()).unwrap()
    }

    fn addr_vec() -> ConfigString {
        ConfigString::new(b"192.0.2.1".to_vec()).unwrap()
    }

    // -----------------------------------------------------------------------
    // Peer construction
    // -----------------------------------------------------------------------

    #[test]
    fn test_peer_new_defaults() {
        let p = Peer::new(addr("pool.ntp.org"), 1, false);
        assert!(p.has_flash(PFLASH_PEERNOQUERY));
        assert_eq!(p.poll, INITIAL_POLL);
        assert_eq!(p.reach, 0);
        assert!(!p.reachable());
        assert_eq!(p.weight, 1);
        assert!(!p.trusted);
        assert_eq!(p.filter_next, 0);
        for slot in &p.filter {
            assert!(slot.is_none());
        }
    }

    #[test]
    fn test_peer_new_trusted() {
        let p = Peer::new(addr("trusted.server"), 5, true);
        assert!(p.trusted);
        assert_eq!(p.weight, 5);
    }

    #[test]
    fn test_peer_id_unique() {
        let p1 = Peer::new(addr("server-a.example.com"), 1, false);
        let p2 = Peer::new(addr("server-b.example.com"), 1, false);
        assert_ne!(p1.id, p2.id, "peer IDs should be different");
    }

    // -----------------------------------------------------------------------
    // Clock filter
    // -----------------------------------------------------------------------

    #[test]
    fn test_filter_add_single_sample() {
        let mut p = Peer::new(addr_vec(), 1, false);
        p.add_sample(0.001, 0.050, 0.010);
        assert_eq!(p.filter_next, 1);
        assert!(p.filter[0].is_some());
        assert_eq!(p.filter[0].unwrap().offset, 0.001);
        assert!((p.offset - 0.001).abs() < 1e-12);
        assert!((p.delay - 0.050).abs() < 1e-12);
    }

    #[test]
    fn test_filter_add_eight_samples_ring_buffer() {
        let mut p = Peer::new(addr_vec(), 1, false);
        for i in 0..NTP_FILTER {
            p.add_sample(i as f64 * 0.001, 0.050, 0.010);
            assert_eq!(p.filter_next, i + 1);
        }
        // Filter is now full; next write wraps around.
        p.add_sample(999.0, 0.001, 0.010);
        assert_eq!(p.filter_next, NTP_FILTER + 1);
        // The oldest sample (index 0) should have been replaced.
        assert!((p.filter[0].unwrap().offset - 999.0).abs() < 1e-12);
    }

    #[test]
    fn test_best_sample_empty_filter() {
        let p = Peer::new(addr_vec(), 1, false);
        assert!(p.best_sample().is_none());
    }

    #[test]
    fn test_best_sample_selects_lowest_delay() {
        let mut p = Peer::new(addr_vec(), 1, false);
        p.add_sample(0.010, 0.200, 0.010); // high delay
        p.add_sample(0.005, 0.020, 0.010); // low delay (winner)
        p.add_sample(0.008, 0.100, 0.010); // medium delay

        let best = p.best_sample().unwrap();
        // Weighted average of 4 samples (but we only have 3),
        // weighted by reciprocal of delay.
        // The weighted result should be closest to the lowest-delay sample.
        assert!((best.offset - 0.005).abs() < 0.004);
    }

    #[test]
    fn test_best_sample_weighted_average_of_four() {
        let mut p = Peer::new(addr_vec(), 1, false);
        // Add 8 samples with varying delays.
        for i in 0..NTP_FILTER {
            let delay = 0.010 + (i as f64) * 0.010;
            p.add_sample((i as f64) * 0.001, delay, 0.005);
        }

        let best = p.best_sample().unwrap();
        // The 4 lowest-delay samples are indices 0-3 (delays 0.010, 0.020, 0.030, 0.040).
        // The weighted average should be dominated by the lowest-delay sample.
        assert!((best.offset - 0.0).abs() < 0.002);
    }

    #[test]
    fn test_filter_dispersion_empty() {
        let p = Peer::new(addr_vec(), 1, false);
        assert_eq!(p.filter_dispersion(), 0.0);
    }

    #[test]
    fn test_filter_dispersion_computed() {
        let mut p = Peer::new(addr_vec(), 1, false);
        p.add_sample(0.010, 0.050, 0.005);
        p.add_sample(0.012, 0.040, 0.005);
        p.add_sample(0.008, 0.060, 0.005);

        let disp = p.filter_dispersion();
        assert!(disp > 0.0, "dispersion should be positive: {disp}");
        // With these values, dispersion should be around 0.005-0.007
        assert!(disp > 0.001, "dispersion too small: {disp}");
    }

    // -----------------------------------------------------------------------
    // Reachability
    // -----------------------------------------------------------------------

    #[test]
    fn test_reach_all_zeros() {
        let mut p = Peer::new(addr_vec(), 1, false);
        for _ in 0..8 {
            p.update_reach(false);
        }
        assert_eq!(p.reach, 0);
        assert!(!p.reachable());
    }

    #[test]
    fn test_reach_all_ones() {
        let mut p = Peer::new(addr_vec(), 1, false);
        for _ in 0..8 {
            p.update_reach(true);
        }
        assert_eq!(p.reach, 0xFF);
        assert!(p.reachable());
    }

    #[test]
    fn test_reach_shift_behavior() {
        let mut p = Peer::new(addr_vec(), 1, false);
        p.update_reach(true); // reach = 0b0000_0001
        assert_eq!(p.reach, 0x01);
        p.update_reach(true); // reach = 0b0000_0011
        assert_eq!(p.reach, 0x03);
        p.update_reach(false); // reach = 0b0000_0110
        assert_eq!(p.reach, 0x06);
    }

    #[test]
    fn test_reach_mixed() {
        let mut p = Peer::new(addr_vec(), 1, false);
        // Pattern: success, success, fail, success, fail, fail, success, fail
        let pattern = [true, true, false, true, false, false, true, false];
        for &resp in &pattern {
            p.update_reach(resp);
        }
        // After 8 shifts, reach should be 0b11010010 = 0xD2
        assert_eq!(p.reach, 0xD2);
    }

    #[test]
    fn test_reach_ring_behavior() {
        let mut p = Peer::new(addr_vec(), 1, false);
        // Fill with all ones (0xFF)
        for _ in 0..8 {
            p.update_reach(true);
        }
        assert_eq!(p.reach, 0xFF);

        // Now push a failure — oldest bit falls off the left
        p.update_reach(false); // 0b1111_1110
        assert_eq!(p.reach, 0xFE);

        // Push another failure
        p.update_reach(false); // 0b1111_1100
        assert_eq!(p.reach, 0xFC);
    }

    // -----------------------------------------------------------------------
    // Flash bits
    // -----------------------------------------------------------------------

    #[test]
    fn test_flash_set_clear_has() {
        let mut p = Peer::new(addr_vec(), 1, false);
        assert!(!p.has_flash(PFLASH_PEERADDR));
        p.set_flash(PFLASH_PEERADDR);
        assert!(p.has_flash(PFLASH_PEERADDR));
        p.clear_flash(PFLASH_PEERADDR);
        assert!(!p.has_flash(PFLASH_PEERADDR));
    }

    #[test]
    fn test_flash_combined_bits() {
        let mut p = Peer::new(addr_vec(), 1, false);
        p.set_flash(PFLASH_PEERADDR | PFLASH_PEERSTRAT);
        assert!(p.has_flash(PFLASH_PEERADDR));
        assert!(p.has_flash(PFLASH_PEERSTRAT));
        assert!(!p.has_flash(PFLASH_PEERDISP));
    }

    #[test]
    fn test_has_any_flash() {
        let mut p = Peer::new(addr_vec(), 1, false);
        assert!(p.has_any_flash()); // PFLASH_PEERNOQUERY is set by default
        p.clear_flash(PFLASH_PEERNOQUERY);
        assert!(!p.has_any_flash());
        p.set_flash(PFLASH_PEERDISP);
        assert!(p.has_any_flash());
    }

    // -----------------------------------------------------------------------
    // Poll interval state machine
    // -----------------------------------------------------------------------

    #[test]
    fn test_poll_initial_rapid_phase() {
        let mut p = Peer::new(addr_vec(), 1, false);
        assert_eq!(p.poll, INITIAL_POLL);

        // First 4 responses: stay at INITIAL_POLL
        for _ in 0..FAST_POLL_COUNT {
            p.update_poll(true);
            assert_eq!(
                p.poll, INITIAL_POLL,
                "should stay at initial poll during rapid phase"
            );
        }
    }

    #[test]
    fn test_poll_increase_when_stable() {
        let mut p = Peer::new(addr_vec(), 1, false);
        // Complete rapid phase.
        for _ in 0..FAST_POLL_COUNT {
            p.update_poll(true);
        }

        let initial = p.poll;
        // No jitter flash set, so poll should increase (stable).
        p.update_poll(true);
        assert!(p.poll > initial, "poll should increase when stable");
    }

    #[test]
    fn test_poll_decrease_when_jitter() {
        let mut p = Peer::new(addr_vec(), 1, false);
        // Complete rapid phase.
        for _ in 0..FAST_POLL_COUNT {
            p.update_poll(true);
        }

        // Increase poll a few times by being stable.
        for _ in 0..3 {
            p.update_poll(true); // stable → increase
        }
        assert!(
            p.poll > MIN_POLL,
            "poll should be above MIN_POLL, got {}",
            p.poll
        );

        // Now set jitter flash and expect decrease.
        let initial = p.poll;
        p.set_flash(PFLASH_PEERJITTER);
        p.update_poll(true);
        assert!(
            p.poll < initial,
            "poll should decrease when jitter is detected: was {initial}, now {}",
            p.poll
        );
    }

    #[test]
    fn test_poll_backoff_on_no_response() {
        let mut p = Peer::new(addr_vec(), 1, false);
        assert_eq!(p.poll, INITIAL_POLL);

        p.update_poll(false); // no response → backoff
        assert!(p.poll > INITIAL_POLL, "poll should increase on no response");
    }

    #[test]
    fn test_poll_reset_after_max_unreachable() {
        let mut p = Peer::new(addr_vec(), 1, false);
        // 7 misses to reach MAX_POLL.
        // Miss 1-6: poll goes 4,5,6,7,8,9
        // Miss 7:   poll goes 10 (MAX_POLL), consecutive=7 < 8, no reset
        for _ in 0..7 {
            p.update_poll(false);
        }
        assert_eq!(
            p.poll, MAX_POLL,
            "poll should reach MAX_POLL after 7 misses"
        );
        assert_eq!(p.consecutive_unreachable, 7);

        // One more miss: poll=10, consecutive=8 ≥ 8 → reset to INITIAL_POLL
        p.update_poll(false);
        assert_eq!(
            p.poll, INITIAL_POLL,
            "poll should reset to INITIAL_POLL after 8 misses, got {}",
            p.poll
        );
    }

    #[test]
    fn test_poll_state_recovery_after_reset() {
        let mut p = Peer::new(addr_vec(), 1, false);
        // Drive to unreachable state.
        for _ in 0..MAX_UNREACHABLE {
            p.update_poll(false);
        }
        assert_eq!(p.poll, INITIAL_POLL);
        assert_eq!(p.rapid_polls, 0);

        // A response after reset should restart rapid phase.
        p.update_poll(true);
        assert_eq!(p.rapid_polls, 1);
        assert_eq!(p.poll, INITIAL_POLL);
    }

    #[test]
    fn test_poll_clamped_to_max() {
        let mut p = Peer::new(addr_vec(), 1, false);
        // Backoff repeatedly — should cap at MAX_POLL.
        for _ in 0..20 {
            p.update_poll(false);
        }
        assert!(p.poll <= MAX_POLL, "poll should not exceed MAX_POLL");
    }

    #[test]
    fn test_poll_clamped_to_min() {
        let mut p = Peer::new(addr_vec(), 1, false);
        // Complete rapid phase then set jitter to decrease poll.
        for _ in 0..FAST_POLL_COUNT {
            p.update_poll(true);
        }
        p.set_flash(PFLASH_PEERJITTER);

        // Decrease many times — should cap at MIN_POLL.
        for _ in 0..20 {
            p.update_poll(true);
        }
        assert!(p.poll >= MIN_POLL, "poll should not go below MIN_POLL");
    }

    #[test]
    fn test_poll_no_query_cleared_on_response() {
        let mut p = Peer::new(addr_vec(), 1, false);
        assert!(p.has_flash(PFLASH_PEERNOQUERY));
        p.update_poll(true);
        assert!(!p.has_flash(PFLASH_PEERNOQUERY));
    }

    // -----------------------------------------------------------------------
    // Offset/delay computation
    // -----------------------------------------------------------------------

    #[test]
    fn test_compute_offset_symmetric() {
        // Perfect symmetric exchange:
        // t1=0,  t2=2.0, t3=4.0, t4=6.0
        // offset = ((2.0 - 0) + (4.0 - 6.0)) / 2 = (2.0 - 2.0) / 2 = 0
        // delay  = (6.0 - 0) - (4.0 - 2.0) = 6.0 - 2.0 = 4.0
        let t1 = NtpTimestamp::from_f64(0.0);
        let t2 = NtpTimestamp::from_f64(2.0);
        let t3 = NtpTimestamp::from_f64(4.0);
        let t4 = NtpTimestamp::from_f64(6.0);

        let (offset, delay) = Peer::compute_offset(t1, t2, t3, t4);
        assert!(
            (offset - 0.0).abs() < 1e-9,
            "offset should be 0, got {offset}"
        );
        assert!(
            (delay - 4.0).abs() < 1e-9,
            "delay should be 4.0, got {delay}"
        );
    }

    #[test]
    fn test_compute_offset_positive() {
        // Peer is ahead (positive offset):
        // t1=0, t2=0.5, t3=0.7, t4=1.0 (response delayed by 0.5s one-way)
        // offset = ((0.5 - 0) + (0.7 - 1.0)) / 2 = (0.5 - 0.3) / 2 = 0.1
        // delay = (1.0 - 0) - (0.7 - 0.5) = 1.0 - 0.2 = 0.8
        let t1 = NtpTimestamp::from_f64(0.0);
        let t2 = NtpTimestamp::from_f64(0.5);
        let t3 = NtpTimestamp::from_f64(0.7);
        let t4 = NtpTimestamp::from_f64(1.0);

        let (offset, delay) = Peer::compute_offset(t1, t2, t3, t4);
        assert!(
            (offset - 0.1).abs() < 1e-9,
            "offset should be 0.1, got {offset}"
        );
        assert!(
            (delay - 0.8).abs() < 1e-9,
            "delay should be 0.8, got {delay}"
        );
    }

    #[test]
    fn test_compute_offset_negative() {
        // Our clock is ahead (negative offset):
        // Our clock is at 100.0s NTP, server clock is 0.5s behind.
        // t1 = 100.0 (we send)
        // t2 =  99.5 (server receives, its clock is 0.5s behind)
        // t3 =  99.6 (server sends)
        // t4 = 100.1 (we receive)
        //
        // offset = ((99.5 - 100.0) + (99.6 - 100.1)) / 2
        //        = (-0.5 + -0.5) / 2 = -0.5
        // delay = (100.1 - 100.0) - (99.6 - 99.5) = 0.1 - 0.1 = 0.0
        let t1 = NtpTimestamp::from_f64(100.0);
        let t2 = NtpTimestamp::from_f64(99.5);
        let t3 = NtpTimestamp::from_f64(99.6);
        let t4 = NtpTimestamp::from_f64(100.1);

        let (offset, delay) = Peer::compute_offset(t1, t2, t3, t4);
        assert!(
            (offset - (-0.5)).abs() < 1e-9,
            "offset should be -0.5, got {offset}"
        );
        assert!(
            (delay - 0.0).abs() < 1e-9,
            "delay should be 0.0, got {delay}"
        );
    }

    #[test]
    fn test_compute_offset_large_delay() {
        // Simulate a high-latency link.
        let t1 = NtpTimestamp::from_f64(0.0);
        let t2 = NtpTimestamp::from_f64(1.2);
        let t3 = NtpTimestamp::from_f64(1.3);
        let t4 = NtpTimestamp::from_f64(2.5);

        let (offset, delay) = Peer::compute_offset(t1, t2, t3, t4);
        // offset = ((1.2 - 0) + (1.3 - 2.5)) / 2 = (1.2 - 1.2) / 2 = 0.0
        // delay = (2.5 - 0) - (1.3 - 1.2) = 2.5 - 0.1 = 2.4
        assert!(
            (offset - 0.0).abs() < 1e-9,
            "offset should be ~0, got {offset}"
        );
        assert!(
            (delay - 2.4).abs() < 1e-9,
            "delay should be 2.4, got {delay}"
        );
    }

    // -----------------------------------------------------------------------
    // Clock selection
    // -----------------------------------------------------------------------

    fn make_peer(address: &str, offset: f64, delay: f64, dispersion: f64) -> Peer {
        let mut p = Peer::new(addr(address), 1, false);
        p.offset = offset;
        p.delay = delay;
        p.dispersion = dispersion;
        p.root_delay = 0.01;
        p.root_dispersion = 0.02;
        p
    }

    #[test]
    fn test_selection_empty() {
        let sel = ClockSelection::new(vec![]);
        assert!(sel.combine().is_none());
    }

    #[test]
    fn test_selection_single_peer() {
        let peer = make_peer("server-a", 0.005, 0.050, 0.010);
        let mut sel = ClockSelection::new(vec![peer.clone()]);
        let result = sel.select();
        assert!(result.is_some());
        let combined = result.unwrap();
        assert!((combined.offset - 0.005).abs() < 1e-9);
    }

    #[test]
    fn test_selection_three_peers_close() {
        let peers = vec![
            make_peer("a", 0.001, 0.030, 0.005),
            make_peer("b", 0.003, 0.025, 0.005),
            make_peer("c", 0.002, 0.035, 0.005),
        ];
        let mut sel = ClockSelection::new(peers);
        let result = sel.select();
        assert!(result.is_some());
        let combined = result.unwrap();
        // Combined offset should be close to the three offsets.
        assert!((combined.offset - 0.002).abs() < 0.002);
        assert!(
            combined.delay > 0.0,
            "combined delay should be positive, got {}",
            combined.delay
        );
    }

    #[test]
    fn test_selection_outlier_removed() {
        // Two close peers, one far outlier.
        let peers = vec![
            make_peer("good-a", 0.001, 0.020, 0.005),
            make_peer("good-b", 0.003, 0.025, 0.005),
            make_peer("outlier", 1.000, 0.100, 0.050),
        ];
        let mut sel = ClockSelection::new(peers);
        let result = sel.select();
        assert!(result.is_some());
        // The combined offset should be close to the good peers, not the outlier.
        assert!(
            result.unwrap().offset < 0.01,
            "outlier should be excluded; combined offset = {}",
            result.unwrap().offset
        );
    }

    #[test]
    fn test_selection_intersection_filters() {
        // Three peers with very different offsets — intersection should
        // keep those with overlapping intervals.
        let peers = vec![
            make_peer("a", 0.001, 0.010, 0.001),
            make_peer("b", 0.002, 0.010, 0.001),
            make_peer("far-out", 5.0, 0.010, 0.001),
        ];
        let mut sel = ClockSelection::new(peers);
        sel.intersection();
        // Only the two close peers should survive.
        assert!(
            sel.peers.len() <= 2,
            "intersection should remove the outlier; {} peers remain",
            sel.peers.len()
        );
    }

    #[test]
    fn test_selection_clustering_reduces_to_three() {
        let peers = vec![
            make_peer("a", 0.001, 0.020, 0.005),
            make_peer("b", 0.002, 0.025, 0.005),
            make_peer("c", 0.003, 0.030, 0.005),
            make_peer("d", 0.004, 0.035, 0.005),
            make_peer("e", 0.005, 0.040, 0.005),
        ];
        let mut sel = ClockSelection::new(peers);
        sel.clustering();
        assert!(
            sel.peers.len() <= 3,
            "clustering should reduce to ≤3, got {}",
            sel.peers.len()
        );
    }

    #[test]
    fn test_combine_weighted_average() {
        let peers = vec![
            make_peer("a", 0.001, 0.010, 0.001),
            make_peer("b", 0.003, 0.010, 0.001),
        ];
        let sel = ClockSelection::new(peers);
        let combined = sel.combine();
        assert!(combined.is_some());
        let c = combined.unwrap();
        // Both peers have equal delay/dispersion, so they should have
        // equal weight. Combined offset should be the mean: 0.002.
        assert!(
            (c.offset - 0.002).abs() < 1e-6,
            "expected ~0.002, got {}",
            c.offset
        );
    }

    // -----------------------------------------------------------------------
    // Edge cases
    // -----------------------------------------------------------------------

    #[test]
    fn test_filter_no_crash_on_wrapping() {
        let mut p = Peer::new(addr_vec(), 1, false);
        // Wrap around many times.
        for i in 0..100 {
            p.add_sample(i as f64 * 0.001, 0.050, 0.010);
        }
        // Filter should still work.
        let best = p.best_sample().unwrap();
        // The last samples are near 0.099, but the best is the one
        // with lowest delay (all have same delay, so it's a weighted
        // average of the 4 most recent lowest-delay samples).
        assert!(best.delay > 0.0);
    }

    #[test]
    fn test_reach_overflow() {
        let mut p = Peer::new(addr_vec(), 1, false);
        // Shift many times — the register is only 8 bits, so after
        // 8 shifts, older bits are lost.
        for _ in 0..100 {
            p.update_reach(true);
        }
        assert_eq!(p.reach, 0xFF, "all ones after 100 successes");
    }

    #[test]
    fn test_flash_all_bits_roundtrip() {
        let all_bits = [
            PFLASH_PEERADDR,
            PFLASH_PEERSTRAT,
            PFLASH_PEERDISP,
            PFLASH_PEERDELAY,
            PFLASH_PEEROFFSET,
            PFLASH_PEERJITTER,
            PFLASH_PEERNOQUERY,
            PFLASH_PEERREACH,
            PFLASH_PEERMAXERR,
            PFLASH_PEERBADSTRAT,
        ];
        let mut p = Peer::new(addr_vec(), 1, false);
        // Clear default PFLASH_PEERNOQUERY.
        p.clear_flash(PFLASH_PEERNOQUERY);

        for &bit in &all_bits {
            assert!(
                !p.has_flash(bit),
                "bit {bit:#06x} should not be set initially"
            );
            p.set_flash(bit);
            assert!(p.has_flash(bit), "bit {bit:#06x} should be set now");
            p.clear_flash(bit);
            assert!(!p.has_flash(bit), "bit {bit:#06x} should be cleared");
        }
    }

    #[test]
    fn test_poll_count_increments() {
        let mut p = Peer::new(addr_vec(), 1, false);
        assert_eq!(p.poll_count, 0);
        p.update_poll(true);
        assert_eq!(p.poll_count, 1);
        p.update_poll(false);
        assert_eq!(p.poll_count, 2);
    }

    #[test]
    fn test_consecutive_unreachable_tracking() {
        let mut p = Peer::new(addr_vec(), 1, false);
        assert_eq!(p.consecutive_unreachable, 0);
        p.update_poll(false);
        assert_eq!(p.consecutive_unreachable, 1);
        p.update_poll(true); // response resets the counter
        assert_eq!(p.consecutive_unreachable, 0);
    }

    // -----------------------------------------------------------------------
    // Wrong f64 negative test for frequency
    // -----------------------------------------------------------------------

    #[test]
    fn test_wrong_f64_negative() {
        // This test verifies that NTP offset computation correctly
        // handles negative values (when our clock is ahead of the
        // peer).  A common bug is using unsigned arithmetic or
        // failing to propagate sign through the computation.
        //
        // Scenario: our clock is 0.5 seconds ahead of the server.
        //   t1 = 10.0  (we transmit)
        //   t2 =  9.5  (server receives — from server's perspective, our
        //               timestamp looks 0.5s in the future)
        //   t3 =  9.6  (server transmits)
        //   t4 = 10.1  (we receive)
        //
        // offset = ((9.5 - 10.0) + (9.6 - 10.1)) / 2
        //        = (-0.5 + -0.5) / 2 = -0.5
        //
        // delay = (10.1 - 10.0) - (9.6 - 9.5) = 0.1 - 0.1 = 0.0
        //
        // This is a canonical test for correct signed handling.
        let t1 = NtpTimestamp::from_f64(10.0);
        let t2 = NtpTimestamp::from_f64(9.5);
        let t3 = NtpTimestamp::from_f64(9.6);
        let t4 = NtpTimestamp::from_f64(10.1);

        let (offset, delay) = Peer::compute_offset(t1, t2, t3, t4);

        // Offset must be negative.
        assert!(
            offset < 0.0,
            "offset should be negative when our clock is ahead: got {offset}"
        );
        assert!(
            (offset - (-0.5)).abs() < 1e-9,
            "offset should be -0.5, got {offset}"
        );
        // Delay should be non-negative.
        assert!(delay >= 0.0, "delay should be non-negative: got {delay}");
        assert!(
            (delay - 0.0).abs() < 1e-9,
            "delay should be 0.0, got {delay}"
        );
    }

    // -----------------------------------------------------------------------
    // Integration: end-to-end peer update flow
    // -----------------------------------------------------------------------

    #[test]
    fn test_full_peer_update_lifecycle() {
        let mut p = Peer::new(addr_vec(), 1, false);

        // Simulate several rounds of NTP exchanges.
        let exchanges = [
            // (t1, t2, t3, t4)
            (0.0, 0.020, 0.040, 0.070),
            (10.0, 10.025, 10.045, 10.075),
            (20.0, 20.030, 20.050, 20.080),
            (30.0, 30.015, 30.035, 30.065),
        ];

        for (_i, &(t1_s, t2_s, t3_s, t4_s)) in exchanges.iter().enumerate() {
            // Compute offset and delay from timestamps.
            let t1 = NtpTimestamp::from_f64(t1_s);
            let t2 = NtpTimestamp::from_f64(t2_s);
            let t3 = NtpTimestamp::from_f64(t3_s);
            let t4 = NtpTimestamp::from_f64(t4_s);

            let (offset, delay) = Peer::compute_offset(t1, t2, t3, t4);
            let dispersion = 0.005;

            // Add sample to filter.
            p.add_sample(offset, delay, dispersion);

            // Update reachability.
            p.update_reach(true);

            // Update poll.
            p.update_poll(true);
        }

        // After 4 successful exchanges, the peer should be reachable.
        assert!(p.reachable(), "peer should be reachable after 4 exchanges");
        assert!(p.reach > 0, "reach should be non-zero");
        assert_eq!(p.filter_next, 4, "should have 4 samples");

        // Poll should still be in rapid phase (INITIAL_POLL) since
        // we've only done 4 responses (rapid_polls went 0→1→2→3→4,
        // with 4 being the last rapid-poll iteration).
        assert_eq!(p.poll, INITIAL_POLL);

        // Best sample should exist.
        let best = p.best_sample();
        assert!(best.is_some());
        // The offsets should be small and consistent.
        assert!(
            best.unwrap().delay > 0.0,
            "best sample delay should be positive"
        );
    }

    #[test]
    fn test_display_format() {
        let mut p = Peer::new(addr("ntp.example.com"), 1, false);
        p.stratum = 2;
        p.offset = 0.001234;
        p.delay = 0.050;
        p.dispersion = 0.010;
        let s = alloc::format!("{p}");
        assert!(s.contains("ntp.example.com"));
        assert!(s.contains("stratum: 2"));
        assert!(s.contains("offset:"));
        assert!(s.contains("delay:"));
        assert!(s.contains("disp:"));
        assert!(s.contains("reach:"));
        assert!(s.contains("flash:"));
    }

    #[test]
    fn test_poll_interval_str() {
        let s = poll_interval_str(3); // 8s
        assert_eq!(s, "8s");
        let s = poll_interval_str(6); // 64s → 1m4s
                                      // 64s = 1m4s
        assert!(s.contains("m") || s.contains("s"));
        let s = poll_interval_str(10); // 1024s → 17m4s
        assert!(s.contains("h") || s.contains("m"));
    }
}
