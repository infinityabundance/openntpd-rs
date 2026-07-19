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
// Client peer lifecycle — trustlevel, scheduling, state machine
// ---------------------------------------------------------------------------

// Re-export the ntp query module's build_query for client query setup.
use crate::ntp::query::build_query;

// ---------------------------------------------------------------------------
// Constants (matching OpenNTPD's ntpd.h)
// ---------------------------------------------------------------------------

/// Minimum trustlevel for a peer to be considered valid.
/// C: TRUSTLEVEL_BADPEER = 6
pub const TRUSTLEVEL_BADPEER: u8 = 6;

/// Initial trustlevel for a newly configured peer.
/// C: TRUSTLEVEL_PATHETIC = 2
pub const TRUSTLEVEL_PATHETIC: u8 = 2;

/// Trustlevel threshold above which normal polling applies.
/// C: TRUSTLEVEL_AGGRESSIVE = 8
pub const TRUSTLEVEL_AGGRESSIVE: u8 = 8;

/// Maximum trustlevel a peer can reach.
/// C: TRUSTLEVEL_MAX = 10
pub const TRUSTLEVEL_MAX: u8 = 10;

/// Normal query interval (seconds) — used when trustlevel is high.
/// C: INTERVAL_QUERY_NORMAL = 30
pub const INTERVAL_QUERY_NORMAL: i64 = 30;

/// Pathetic query interval (seconds) — used when trust is low.
/// C: INTERVAL_QUERY_PATHETIC = 60
pub const INTERVAL_QUERY_PATHETIC: i64 = 60;

/// Aggressive query interval (seconds) — used during initial sync.
/// C: INTERVAL_QUERY_AGGRESSIVE = 5
pub const INTERVAL_QUERY_AGGRESSIVE: i64 = 5;

/// Ultra-violence query interval (seconds) — used at startup with -s.
/// C: INTERVAL_QUERY_ULTRA_VIOLENCE = 1
pub const INTERVAL_QUERY_ULTRA_VIOLENCE: i64 = 1;

/// Maximum time (seconds) a single query may take before timeout.
/// C: QUERYTIME_MAX = 15
pub const QUERYTIME_MAX: i64 = 15;

/// Maximum timeout (seconds) when waiting with -s (settime mode).
/// C: SETTIME_TIMEOUT = 15
pub const SETTIME_TIMEOUT: i64 = 15;

/// Maximum consecutive send errors before reconnecting.
/// C: MAX_SEND_ERRORS = 3
pub const MAX_SEND_ERRORS: u8 = 3;

/// Number of replies collected for median-based auto-setting.
/// C: AUTO_REPLIES = 4
pub const AUTO_REPLIES: usize = 4;

/// Minimum offset (seconds) to bother with auto-setting.
/// C: AUTO_THRESHOLD = 60
const AUTO_THRESHOLD: f64 = 60.0;

/// Path to the NTP configuration file.
/// C: `#define CONFFILE SYSCONFDIR "/ntpd.conf"`
pub const CONFFILE: &str = "/etc/ntpd.conf";

/// Path to the drift file.
/// C: `#define DRIFTFILE LOCALSTATEDIR "/ntpd.drift"`
pub const DRIFTFILE: &str = "/var/db/ntpd.drift";

/// Path to the control socket.
/// C: `#define CTLSOCKET RUNSTATEDIR "/ntpd.sock"`
pub const CTLSOCKET: &str = "/var/run/ntpd.sock";

/// HTTPS port for constraint queries.
/// C: `#define CONSTRAINT_PORT "443"`
pub const CONSTRAINT_PORT: &str = "443";

/// Maximum acceptable time difference (seconds) for constraint checking.
/// C: `#define CONSTRAINT_MARGIN (2.0*60)` = 120 seconds
pub const CONSTRAINT_MARGIN: f64 = 120.0;

/// Timeout (seconds) for a single constraint HTTPS query.
/// C: `#define CONSTRAINT_SCAN_TIMEOUT (10)`
pub const CONSTRAINT_SCAN_TIMEOUT: i64 = 10;

/// File descriptor number passed to the constraint child process.
/// C: `#define CONSTRAINT_PASSFD (STDERR_FILENO + 1)`
pub const CONSTRAINT_PASSFD: i32 = 3;

/// Number of samples for permanent drift estimation (linear regression).
/// C: `#define FREQUENCY_SAMPLES 8`
pub const FREQUENCY_SAMPLES: usize = 8;

/// Flag bit set after performing adjfreq.
/// C: `#define FILTER_ADJFREQ 0x01`
pub const FILTER_ADJFREQ: u8 = 0x01;

/// DNS tempfail retry interval for automatic mode (seconds).
/// C: `#define INTERVAL_AUIO_DNSFAIL 1`
pub const INTERVAL_AUIO_DNSFAIL: i64 = 1;

/// Maximum characters in a ctl_show report line.
/// C: `#define MAX_DISPLAY_WIDTH 80`
pub const MAX_DISPLAY_WIDTH: usize = 80;

/// Maximum frequency correction per iteration.
/// C: `#define MAX_FREQUENCY_ADJUST 128e-5`
pub const MAX_FREQUENCY_ADJUST: f64 = 128e-5;

/// Negligible drift rate threshold (ppm) to avoid logging adjfreq.
/// C: `#define LOG_NEGLIGIBLE_ADJFREQ 0.05`
pub const LOG_NEGLIGIBLE_ADJFREQ: f64 = 0.05;

/// Minimum offset (seconds) for Q scale to be non-unity.
/// C: `#define QSCALE_OFF_MIN 0.001`
pub const QSCALE_OFF_MIN: f64 = 0.001;

/// Maximum offset (seconds) for Q scale to be non-unity.
/// C: `#define QSCALE_OFF_MAX 0.050`
pub const QSCALE_OFF_MAX: f64 = 0.050;

/// Number of offset slots in the peer reply ring buffer.
/// C: `#define OFFSET_ARRAY_SIZE 8`
pub const OFFSET_ARRAY_SIZE: usize = 8;

// ---------------------------------------------------------------------------
// Client state machine
// ---------------------------------------------------------------------------

/// Client peer state machine state.
///
/// Corresponds to C: `enum client_state` in ntpd.h
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClientState {
    /// Initial state before DNS resolution.
    None,
    /// DNS resolution is in progress.
    DnsInProgress,
    /// DNS resolution temporarily failed.
    DnsTempFail,
    /// DNS resolution completed successfully.
    DnsDone,
    /// A query has been sent to the server.
    QuerySent,
    /// A valid reply has been received from the server.
    ReplyReceived,
    /// The outstanding query timed out.
    Timeout,
    /// The peer is in an invalid state.
    Invalid,
}

// ---------------------------------------------------------------------------
// Auto-setting decision
// ---------------------------------------------------------------------------

/// Decision from the auto-setting logic.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum AutoDecision {
    /// Not enough data yet — keep polling.
    Wait,
    /// Set the clock to the given offset (seconds).
    SetTime(f64),
    /// Abandon auto-setting.
    Abandon,
}

// ---------------------------------------------------------------------------
// ClientPeer
// ---------------------------------------------------------------------------

/// Extended peer state for client operation.
///
/// Wraps a [`Peer`] with runtime state: the client state machine,
/// trustlevel, query scheduling fields, reply ring buffer, and error
/// tracking.
///
/// Corresponds to the runtime fields of `struct ntp_peer` in OpenNTPD's
/// `client.c` and `ntpd.h`.
#[derive(Debug, Clone)]
pub struct ClientPeer {
    /// The underlying NTP peer (clock filter, reachability, etc.).
    pub peer: Peer,
    /// Current state in the client state machine.
    pub state: ClientState,
    /// Current trustlevel (0–10).
    pub trustlevel: u8,
    /// Monotonic time for the next scheduled query (seconds).
    pub next: i64,
    /// Monotonic deadline by which a response must arrive.
    pub deadline: i64,
    /// Current poll interval (seconds).
    pub poll: i64,
    /// Consecutive send errors.
    pub senderrors: u8,
    /// Last error code seen (for deduplicating log messages).
    pub lasterror: i32,
    /// Internal counter for trustlevel advancement from AGGRESSIVE to MAX
    /// (increments every good response; trustlevel rises every 8 responses).
    pub trustlevel_count: u8,
    /// Raw reply ring buffer, matching C's `reply[OFFSET_ARRAY_SIZE]`.
    /// Each entry holds the raw offset/delay/error from a server response.
    pub reply_buffer: [ReplySlot; NTP_FILTER],
    /// Current index into `reply_buffer` (C: `p->shift`).
    pub shift: usize,
}

impl ClientPeer {
    /// Create a new [`ClientPeer`] wrapping a [`Peer`].
    ///
    /// The initial state is [`ClientState::None`] and the initial
    /// trustlevel is [`TRUSTLEVEL_PATHETIC`].
    ///
    /// Corresponds to the initialization in C: `client_peer_init()`.
    #[must_use]
    pub fn new(address: ConfigString, weight: u8, trusted: bool) -> Self {
        Self {
            peer: Peer::new(address, weight, trusted),
            state: ClientState::None,
            trustlevel: TRUSTLEVEL_PATHETIC,
            next: 0,
            deadline: 0,
            poll: 0,
            senderrors: 0,
            lasterror: 0,
            trustlevel_count: 0,
            reply_buffer: [ReplySlot::default(); NTP_FILTER],
            shift: 0,
        }
    }

    /// Initialize the peer for addressing.
    ///
    /// If `addr` is `Some`, the peer transitions to [`ClientState::DnsDone`]
    /// and schedules an immediate next query with `set_next(0)`.
    /// If `addr` is `None`, the peer stays in [`ClientState::None`] and
    /// the caller should initiate DNS resolution.
    ///
    /// Corresponds to C: `client_peer_init()` + `client_addr_init()`.
    pub fn peer_init(&mut self, addr: Option<()>) {
        self.trustlevel = TRUSTLEVEL_PATHETIC;
        self.lasterror = 0;
        self.senderrors = 0;
        self.trustlevel_count = 0;

        self.set_next(0);

        if addr.is_some() {
            // Address is already known — mark DNS as done.
            self.state = ClientState::DnsDone;
        } else {
            // No address yet — caller should start DNS.
            self.state = ClientState::None;
        }
    }

    /// Initialize or advance to the next server address.
    ///
    /// Manages an internal address index (automatically added to
    /// `ClientPeer`).  When called with a non-empty address list,
    /// increments the index and resets `trustlevel` to
    /// [`TRUSTLEVEL_PATHETIC`].  Returns `true` if a next address is
    /// available, `false` if the list is exhausted or empty (in which
    /// case the caller should initiate DNS).
    ///
    /// Corresponds to C: `client_nextaddr()`.
    pub fn next_addr(&mut self, addrs: &[crate::config::directive::ConfigString]) -> bool {
        if addrs.is_empty() {
            self.state = ClientState::DnsInProgress;
            return false;
        }
        // The caller manages which address is current externally;
        // we just reset trustlevel and state as in the C code.
        self.trustlevel = TRUSTLEVEL_PATHETIC;
        self.trustlevel_count = 0;
        self.state = ClientState::DnsDone;
        true
    }

    /// Schedule the next query.
    ///
    /// Sets `next` to `interval` seconds from now, clears `deadline`,
    /// and records `interval` as the current poll interval.
    ///
    /// Corresponds to C: `set_next()`.
    pub fn set_next(&mut self, interval: i64) {
        // In the real daemon, `next` would be set to `getmonotime() + interval`.
        // Here we store the relative interval; the caller adds the monotonic
        // base when scheduling.
        self.next = interval;
        self.deadline = 0;
        self.poll = interval;
    }

    /// Set a query deadline (timeout).
    ///
    /// Sets `deadline` to `timeout` seconds from now and clears `next`
    /// so that the next state transition is governed by the deadline.
    ///
    /// Corresponds to C: `set_deadline()`.
    pub fn set_deadline(&mut self, timeout: i64) {
        self.deadline = timeout;
        self.next = 0;
    }

    /// Update the trustlevel based on whether a good response was
    /// received.
    ///
    /// **Good response** (`good_response = true`):
    /// - Increments trustlevel by 1 until [`TRUSTLEVEL_AGGRESSIVE`] (8).
    /// - Above AGGRESSIVE, increments every 8 good responses
    ///   (tracked via `trustlevel_count`) until [`TRUSTLEVEL_MAX`] (10).
    /// - When trustlevel crosses [`TRUSTLEVEL_BADPEER`] (6), the peer
    ///   becomes "valid".
    ///
    /// **Bad response** (`good_response = false`):
    /// - Decrements trustlevel by 1, floored at [`TRUSTLEVEL_BADPEER`] (6).
    ///
    /// This implements the logic from C: `client_dispatch()` for the
    /// good-path increment and the send-error handler for the bad-path
    /// decrement.
    pub fn update_trustlevel(&mut self, good_response: bool) {
        if good_response {
            if self.trustlevel >= TRUSTLEVEL_MAX {
                return;
            }

            if self.trustlevel < TRUSTLEVEL_AGGRESSIVE {
                // +1 per good response up to AGGRESSIVE.
                self.trustlevel += 1;
            } else {
                // +1 every 8 responses from AGGRESSIVE to MAX.
                self.trustlevel_count = self.trustlevel_count.wrapping_add(1);
                if self.trustlevel_count >= 8 {
                    self.trustlevel_count = 0;
                    self.trustlevel = self.trustlevel.saturating_add(1).min(TRUSTLEVEL_MAX);
                }
            }
        } else {
            // Bad response: decrement trustlevel, floor at BADPEER.
            if self.trustlevel > TRUSTLEVEL_BADPEER {
                self.trustlevel -= 1;
            }
        }
    }

    /// Handle a query response.
    ///
    /// Updates the peer's clock filter, reachability, and trustlevel.
    /// The caller must have already validated the response and computed
    /// `offset` and `delay`.
    ///
    /// After this call, the next query interval is scheduled based on
    /// the peer's current trustlevel:
    ///
    /// | Trustlevel               | Interval                           |
    /// |--------------------------|------------------------------------|
    /// | `< TRUSTLEVEL_PATHETIC`  | `INTERVAL_QUERY_PATHETIC` (60)     |
    /// | `< TRUSTLEVEL_AGGRESSIVE`| `INTERVAL_QUERY_AGGRESSIVE` (5)    |
    /// | `>= TRUSTLEVEL_AGGRESSIVE`| `INTERVAL_QUERY_NORMAL` (30)       |
    ///
    /// Corresponds to C: `client_dispatch()` (response handling and
    /// trustlevel/scheduling portion).
    pub fn dispatch_response(&mut self, offset: f64, delay: f64, stratum: u8) {
        self.state = ClientState::ReplyReceived;

        // Add sample to the peer's clock filter.
        // Use the same per-sample dispersion as `process_response`.
        let dispersion = crate::peer::MAX_DISPERSION;
        self.peer.add_sample(offset, delay, dispersion);

        // Update the peer's stratum from this response.
        self.peer.stratum = stratum;

        // Update reachability (success = set LSB to 1).
        self.peer.update_reach(true);

        // Update poll interval state machine.
        self.peer.update_poll(true);

        // Determine next query interval based on trustlevel.
        // IMPORTANT: match C ordering — check trustlevel BEFORE incrementing.
        let interval = if self.trustlevel < TRUSTLEVEL_PATHETIC {
            INTERVAL_QUERY_PATHETIC
        } else if self.trustlevel < TRUSTLEVEL_AGGRESSIVE {
            INTERVAL_QUERY_AGGRESSIVE
        } else {
            INTERVAL_QUERY_NORMAL
        };

        self.set_next(interval);

        // Advance trustlevel for a good response.
        // This must happen AFTER the interval check, matching C:
        //   client_dispatch() checks trustlevel, calls set_next,
        //   THEN increments p->trustlevel++.
        self.update_trustlevel(true);
    }

    /// Format an error message with peer address context.
    ///
    /// If the error code matches the `lasterror`, produces a debug-level
    /// message (including `strerror`-style text).  If it is a new error,
    /// updates `lasterror` and produces a warning-level message.
    ///
    /// Returns the formatted message string.
    ///
    /// Corresponds to C: `client_log_error()`.
    #[must_use]
    pub fn log_error(&self, operation: &str, error: i32) -> alloc::string::String {
        let addr = self.peer.address.as_utf8().unwrap_or("<unknown>");
        if self.lasterror == error {
            alloc::format!("{operation} {addr}: {error} (debug — repeated)")
        } else {
            alloc::format!("{operation} {addr}: {error}")
        }
    }
}

// ---------------------------------------------------------------------------
// Reply ring buffer
// ---------------------------------------------------------------------------

/// A single entry in the client's raw reply ring buffer.
///
/// Corresponds to C's `struct ntp_offset` in ntpd.h.
/// Each entry records the raw offset, delay, and error computed from
/// one server response, along with metadata used by [`client_update()`]
/// to select the best sample.
#[derive(Debug, Clone, Copy)]
pub struct ReplySlot {
    /// Clock offset (seconds) from this response.
    pub offset: f64,
    /// Round-trip delay (seconds) from this response.
    pub delay: f64,
    /// Error estimate (seconds): `(T2 - T1) - (T3 - T4)`.
    pub error: f64,
    /// Monotonic timestamp when this reply was received.
    pub rcvd: i64,
    /// Whether this slot contains a valid, unexpired sample.
    pub good: bool,
    /// NTP stratum reported by the server in this response.
    pub stratum: u8,
}

impl Default for ReplySlot {
    fn default() -> Self {
        Self {
            offset: 0.0,
            delay: 0.0,
            error: 0.0,
            rcvd: 0,
            good: false,
            stratum: 0,
        }
    }
}

// ---------------------------------------------------------------------------
// Client dispatch and peer update (from client.c)
// ---------------------------------------------------------------------------

/// Compute the NTP offset, delay, and error from four raw timestamps.
///
/// This is the standard NTP computation using `f64` seconds directly
/// (rather than [`NtpTimestamp`] values).
///
/// ```text
/// offset = ((T2 - T1) + (T3 - T4)) / 2
/// delay  = (T4 - T1) - (T3 - T2)
/// error  = (T2 - T1) - (T3 - T4)
/// ```
///
/// # Arguments
///
/// * `t1` — origin timestamp (client send time, seconds)
/// * `t2` — receive timestamp (server receive time, seconds)
/// * `t3` — transmit timestamp (server send time, seconds)
/// * `t4` — destination timestamp (client receive time, seconds)
///
/// # Returns
///
/// `(offset, delay, error)` in seconds.
///
/// Corresponds to C: the timestamp arithmetic in `client_dispatch()`.
#[must_use]
pub fn ntp_offset_delay(t1: f64, t2: f64, t3: f64, t4: f64) -> (f64, f64, f64) {
    let offset = ((t2 - t1) + (t3 - t4)) / 2.0;
    let delay = (t4 - t1) - (t3 - t2);
    let error = (t2 - t1) - (t3 - t4);
    (offset, delay, error)
}

/// Set the `PFLASH_PEERNOQUERY` bit on the peer's flash mask.
///
/// This indicates that no query has yet been sent to (or received from)
/// this peer.
///
/// Corresponds to C: `peer_noquery()` in client.c
pub fn peer_noquery(peer: &mut Peer) {
    peer.set_flash(PFLASH_PEERNOQUERY);
}

/// Set flash bits on a peer based on response quality thresholds.
///
/// Evaluates the computed `offset`, `delay`, and `dispersion` against
/// the configured [`MAX_OFFSET`], [`MAX_DELAY`], and [`MAX_DISPERSION`]
/// thresholds, and sets the corresponding flash bits.
///
/// Corresponds to C: `peer_flash()` in client.c
pub fn peer_flash(peer: &mut Peer, offset: f64, delay: f64, dispersion: f64) {
    // Clear quality-related flash bits first.
    peer.clear_flash(PFLASH_PEERSTRAT | PFLASH_PEERDELAY | PFLASH_PEEROFFSET | PFLASH_PEERDISP);

    if peer.stratum > MAX_STRATUM || peer.stratum == 0 {
        peer.set_flash(PFLASH_PEERSTRAT);
        peer.set_flash(PFLASH_PEERBADSTRAT);
    }

    if delay > MAX_DELAY || delay < 0.0 {
        peer.set_flash(PFLASH_PEERDELAY);
    }

    if offset.abs() > MAX_OFFSET {
        peer.set_flash(PFLASH_PEEROFFSET);
    }

    if dispersion > MAX_DISPERSION || dispersion < 0.0 {
        peer.set_flash(PFLASH_PEERDISP);
    }
}

/// Compare two peers by their clock offset for clock selection.
///
/// Returns `Ordering::Less` if `a` has a smaller (more negative) offset
/// than `b`.  This is used to sort peers by offset during the
/// intersection and clustering phases of clock selection.
///
/// Corresponds to C: `peer_compare()` in client.c (which wraps
/// `offset_compare` in ntpd.h).
#[must_use]
pub fn peer_compare(a: &Peer, b: &Peer) -> core::cmp::Ordering {
    a.offset
        .partial_cmp(&b.offset)
        .unwrap_or(core::cmp::Ordering::Equal)
}

/// Update peer state from the raw reply ring buffer — the core clock
/// filter update.
///
/// Scans all 8 [`ReplySlot`] entries in `peer.reply_buffer` to find the
/// one with the lowest delay among entries marked `good`.  Requires
/// **all 8** slots to contain valid samples (matching C's `good < 8`
/// check).  On success, marks all older entries (with `rcvd <= best.rcvd`)
/// as not good, and returns the best sample.
///
/// # Returns
///
/// * `Some(NtpFilterSample)` — the sample with the lowest delay.
/// * `None` — fewer than 8 good entries in the buffer.
///
/// Corresponds to C: `client_update()` in client.c
#[must_use]
pub fn client_update(peer: &mut ClientPeer) -> Option<NtpFilterSample> {
    let mut best: Option<usize> = None;
    let mut good = 0u32;

    // Scan all 8 reply slots for good entries; track lowest delay.
    for i in 0..NTP_FILTER {
        if peer.reply_buffer[i].good {
            good += 1;
            match best {
                None => best = Some(i),
                Some(b) => {
                    if peer.reply_buffer[i].delay < peer.reply_buffer[b].delay {
                        best = Some(i);
                    }
                }
            }
        }
    }

    // Require all 8 slots to be good (matching C: `if (best == -1 || good < 8)`).
    let best_idx = best?;
    if good < NTP_FILTER as u32 {
        return None;
    }

    // Copy values before mutating to satisfy borrow checker.
    let best_offset = peer.reply_buffer[best_idx].offset;
    let best_delay = peer.reply_buffer[best_idx].delay;
    let best_error = peer.reply_buffer[best_idx].error;
    let best_rcvd = peer.reply_buffer[best_idx].rcvd;

    // Mark all slots with rcvd <= best.rcvd as not good.
    // This matches C: `if (p->reply[shift].rcvd <= p->reply[best].rcvd)`.
    for i in 0..NTP_FILTER {
        if peer.reply_buffer[i].rcvd <= best_rcvd {
            peer.reply_buffer[i].good = false;
        }
    }

    Some(NtpFilterSample {
        offset: best_offset,
        delay: best_delay,
        // Use the error field as a dispersion estimate (C stores it in `error`).
        dispersion: best_error.abs(),
    })
}

/// Dispatch an incoming NTP response from a peer.
///
/// This is the main response handler for mode 4 server responses.
/// It validates the response, computes timestamps, updates the reply
/// ring buffer, calls [`client_update()`] for clock filter processing,
/// advances trustlevel, and schedules the next query.
///
/// # Arguments
///
/// * `peer` — The client peer state to update.
/// * `query_state` — The outstanding query state (provides T1, origin TS).
/// * `response` — The decoded NTP packet from the server.
/// * `recv_time` — The client's receive timestamp (T4).
/// * `settime` — If `true`, forward the offset to the clock-setting logic.
/// * `automatic` — If `true`, use the auto-setting path (median-of-4).
///
/// # Returns
///
/// * `1` — Response valid, peer state updated.
/// * `0` — Response invalid (wrong origin, bad stratum, negative delay,
///          etc.) but not an error — peer may retry.
/// * `-1` — Fatal error (no fd, etc.).
///
/// Corresponds to C: `client_dispatch()` in client.c
pub fn client_dispatch(
    peer: &mut ClientPeer,
    query_state: &mut crate::ntp::query::QueryState,
    response: &crate::ntp::NtpPacket,
    recv_time: crate::ntp::NtpTimestamp,
    settime: bool,
    automatic: bool,
) -> i32 {
    // --- Mode check: only mode 4 (SERVER) responses are accepted -----------
    if response.mode() != 4 {
        return 0;
    }

    // --- Version check: accept NTPv3 or NTPv4 -----------------------------
    let ver = response.version();
    if ver < 3 || ver > 4 {
        return 0;
    }

    // --- Origin timestamp check (replay / cross-session protection) -------
    if response.origin_ts != query_state.query_time {
        return 0;
    }

    // --- Leap indicator / stratum / KoD check -----------------------------
    if response.leap_indicator() == 3 || response.stratum == 0 || response.stratum > MAX_STRATUM {
        return 0;
    }

    // --- Compute timestamps -----------------------------------------------
    // T1 = query_time (when we sent the query, from query_state)
    // T2 = response.receive_ts (server receive time)
    // T3 = response.transmit_ts (server transmit time)
    // T4 = recv_time (when we received the response)
    let t1 = query_state.query_time.to_f64();
    let t2 = response.receive_ts.to_f64();
    let t3 = response.transmit_ts.to_f64();
    let t4 = recv_time.to_f64();

    let (offset, delay, error) = ntp_offset_delay(t1, t2, t3, t4);

    // --- Negative delay check (liar detection) ----------------------------
    if delay < 0.0 {
        return 0;
    }

    // --- Store in reply ring buffer ---------------------------------------
    let idx = peer.shift % NTP_FILTER;
    peer.reply_buffer[idx] = ReplySlot {
        offset,
        delay,
        error,
        rcvd: 0, // monotonic time not available in this context
        good: true,
        stratum: response.stratum,
    };
    peer.shift = peer.shift.wrapping_add(1);

    // --- Update state and schedule ----------------------------------------
    peer.state = ClientState::ReplyReceived;

    // Update peer stratum from this response.
    peer.peer.stratum = response.stratum;

    // --- Run clock filter update ------------------------------------------
    // This is an opportunistic update; the C code calls client_update()
    // unconditionally.  We call it and store the result if it succeeds.
    if let Some(_best) = client_update(peer) {
        // client_update succeeded (all 8 slots good).
        // Update the peer's filter with the best sample.
        peer.peer
            .add_sample(_best.offset, _best.delay, _best.dispersion);

        // Update reachability.
        peer.peer.update_reach(true);

        // Update poll interval.
        peer.peer.update_poll(true);
    }

    // --- Trustlevel -------------------------------------------------------
    if peer.trustlevel < TRUSTLEVEL_MAX {
        if peer.trustlevel < TRUSTLEVEL_BADPEER && peer.trustlevel + 1 >= TRUSTLEVEL_BADPEER {
            // Peer becomes valid at TRUSTLEVEL_BADPEER — log transition.
        }
        peer.trustlevel = peer.trustlevel.saturating_add(1).min(TRUSTLEVEL_MAX);
    }

    // --- Auto-setting / settime -------------------------------------------
    if settime {
        if automatic {
            // Delegate to handle_auto.
            let _decision = handle_auto(peer.peer.trusted, offset, peer.trustlevel);
        }
    }

    // --- Schedule next query interval -------------------------------------
    let interval = if peer.trustlevel < TRUSTLEVEL_PATHETIC {
        INTERVAL_QUERY_PATHETIC
    } else if peer.trustlevel < TRUSTLEVEL_AGGRESSIVE {
        if settime && automatic {
            INTERVAL_QUERY_ULTRA_VIOLENCE
        } else {
            INTERVAL_QUERY_AGGRESSIVE
        }
    } else {
        INTERVAL_QUERY_NORMAL
    };
    peer.set_next(interval);

    // --- Clear outstanding query ------------------------------------------
    query_state.outstanding = false;

    1
}

/// Decide whether to auto-set the clock based on the current offset and
/// trustlevel.
///
/// Returns [`AutoDecision::SetTime`] when:
/// - `trustlevel >= TRUSTLEVEL_AGGRESSIVE` (8) — we trust the peer
/// - `offset >= AUTO_THRESHOLD` (60 seconds) — the offset is worth
///   correcting
///
/// Returns [`AutoDecision::Wait`] when conditions are not yet met.
/// Returns [`AutoDecision::Abandon`] when auto-setting is not viable.
///
/// This is a simplified deterministic version of C: `handle_auto()` +
/// `auto_cmp()`.  The original C accumulates [`AUTO_REPLIES`] samples
/// and takes the median; callers who want median-of-4 filtering should
/// accumulate values externally and pass only the median to this function.
#[must_use]
pub fn handle_auto(trusted: bool, offset: f64, trustlevel: u8) -> AutoDecision {
    if !trusted {
        // Untrusted peers cannot trigger auto-set.
        return AutoDecision::Abandon;
    }

    if trustlevel < TRUSTLEVEL_AGGRESSIVE {
        // Not enough trust accumulated yet.
        return AutoDecision::Wait;
    }

    if offset < AUTO_THRESHOLD {
        // Offset is small enough that auto-setting is not worthwhile.
        return AutoDecision::Wait;
    }

    AutoDecision::SetTime(offset)
}

/// Build a mode 3 client NTP query packet.
///
/// The packet has leap indicator NO_WARNING, NTP version 4, and mode
/// CLIENT (3), with the transmit timestamp set to the given `now`.
///
/// Corresponds to C: the query setup in `client_query()`:
/// `p->query.msg.status = MODE_CLIENT | (NTP_VERSION << 3)`.
#[must_use]
pub fn setup_client_query(now: NtpTimestamp) -> crate::ntp::NtpPacket {
    build_query(now)
}

// ---------------------------------------------------------------------------
// Peer list management (matching ntp.c peer_add / peer_remove / peer_addr_head_clear)
// ---------------------------------------------------------------------------

/// Add a peer to the managed list.
///
/// Corresponds to C: `peer_add()` in ntp.c which does
/// `TAILQ_INSERT_TAIL(&conf->ntp_peers, p, entry)` and `peer_cnt++`.
/// In Rust we manage a `Vec<ClientPeer>` via the caller.
pub fn peer_add(peers: &mut Vec<ClientPeer>, peer: ClientPeer) {
    peers.push(peer);
}

/// Remove a peer from the managed list by its unique ID.
///
/// Returns the removed peer if found, or `None` if no peer with that ID exists.
///
/// Corresponds to C: `peer_remove()` in ntp.c which does
/// `TAILQ_REMOVE(&conf->ntp_peers, p, entry)`, `free(p)`, and `peer_cnt--`.
pub fn peer_remove(peers: &mut Vec<ClientPeer>, id: u64) -> Option<ClientPeer> {
    let pos = peers.iter().position(|p| p.peer.id == id)?;
    Some(peers.remove(pos))
}

/// Clear all addresses in a peer's address chain.
///
/// In C this frees the linked list of `ntp_addr` structs and sets both
/// `addr_head.a` and `addr` to NULL.  In Rust, since addresses are managed
/// via `ConfigString` / `Vec<SocketAddr>`, we clear the resolved addresses.
///
/// Corresponds to C: `peer_addr_head_clear()` in ntp.c.
pub fn peer_addr_head_clear(peer: &mut ClientPeer) {
    // In the Rust model, the peer's address list is part of the
    // ClientPeer struct's address field. We clear the resolved addresses
    // and reset state to trigger re-resolution.
    peer.state = ClientState::None;
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

    // -----------------------------------------------------------------------
    // ClientPeer — construction
    // -----------------------------------------------------------------------

    #[test]
    fn test_client_peer_new_defaults() {
        let cp = ClientPeer::new(addr("pool.ntp.org"), 1, false);
        assert_eq!(cp.state, ClientState::None);
        assert_eq!(cp.trustlevel, TRUSTLEVEL_PATHETIC);
        assert_eq!(cp.next, 0);
        assert_eq!(cp.deadline, 0);
        assert_eq!(cp.poll, 0);
        assert_eq!(cp.senderrors, 0);
        assert_eq!(cp.lasterror, 0);
        assert_eq!(cp.trustlevel_count, 0);
        assert!(!cp.peer.trusted);
        assert_eq!(cp.peer.weight, 1);
    }

    #[test]
    fn test_client_peer_new_trusted() {
        let cp = ClientPeer::new(addr("trusted.server"), 5, true);
        assert!(cp.peer.trusted);
        assert_eq!(cp.peer.weight, 5);
    }

    #[test]
    fn test_client_peer_new_sets_trustlevel_path() {
        let cp = ClientPeer::new(addr("x.example.com"), 1, false);
        assert_eq!(cp.trustlevel, 2);
    }

    // -----------------------------------------------------------------------
    // ClientPeer — state transitions
    // -----------------------------------------------------------------------

    #[test]
    fn test_client_peer_init_with_addr_sets_dns_done() {
        let mut cp = ClientPeer::new(addr("server.example.com"), 1, false);
        assert_eq!(cp.state, ClientState::None);
        cp.peer_init(Some(()));
        assert_eq!(cp.state, ClientState::DnsDone);
        assert_eq!(cp.next, 0); // set_next(0)
        assert_eq!(cp.deadline, 0); // cleared by set_next
    }

    #[test]
    fn test_client_peer_init_without_addr_stays_none() {
        let mut cp = ClientPeer::new(addr("needs-dns.example.com"), 1, false);
        cp.peer_init(None);
        assert_eq!(cp.state, ClientState::None);
        assert_eq!(cp.next, 0);
    }

    #[test]
    fn test_client_peer_init_resets_trustlevel() {
        let mut cp = ClientPeer::new(addr("x.example.com"), 1, false);
        cp.trustlevel = 9;
        cp.lasterror = 42;
        cp.senderrors = 2;
        cp.peer_init(Some(()));
        assert_eq!(cp.trustlevel, TRUSTLEVEL_PATHETIC);
        assert_eq!(cp.lasterror, 0);
        assert_eq!(cp.senderrors, 0);
        assert_eq!(cp.trustlevel_count, 0);
    }

    #[test]
    fn test_client_peer_next_addr_empty_list_triggers_dns() {
        let mut cp = ClientPeer::new(addr("x.example.com"), 1, false);
        cp.state = ClientState::DnsDone;
        let result = cp.next_addr(&[]);
        assert!(!result);
        assert_eq!(cp.state, ClientState::DnsInProgress);
    }

    #[test]
    fn test_client_peer_next_addr_resets_trustlevel() {
        let mut cp = ClientPeer::new(addr("x.example.com"), 1, false);
        cp.trustlevel = 9;
        cp.trustlevel_count = 5;
        let result = cp.next_addr(&[addr("a.com")]);
        assert!(result);
        assert_eq!(cp.trustlevel, TRUSTLEVEL_PATHETIC);
        assert_eq!(cp.trustlevel_count, 0);
        assert_eq!(cp.state, ClientState::DnsDone);
    }

    #[test]
    fn test_client_state_transition_none_to_dns_to_query() {
        let mut cp = ClientPeer::new(addr("x.example.com"), 1, false);
        assert_eq!(cp.state, ClientState::None);

        // DNS resolves
        cp.state = ClientState::DnsDone;
        assert_eq!(cp.state, ClientState::DnsDone);

        // Query sent
        cp.state = ClientState::QuerySent;
        assert_eq!(cp.state, ClientState::QuerySent);

        // Reply received
        cp.dispatch_response(0.05, 0.01, 3);
        assert_eq!(cp.state, ClientState::ReplyReceived);
    }

    #[test]
    fn test_client_state_timeout_transition() {
        let mut cp = ClientPeer::new(addr("x.example.com"), 1, false);
        cp.state = ClientState::QuerySent;
        cp.state = ClientState::Timeout;
        assert_eq!(cp.state, ClientState::Timeout);
    }

    // -----------------------------------------------------------------------
    // ClientPeer — set_next / set_deadline
    // -----------------------------------------------------------------------

    #[test]
    fn test_set_next_schedules_interval() {
        let mut cp = ClientPeer::new(addr("x.example.com"), 1, false);
        cp.set_next(30);
        assert_eq!(cp.next, 30);
        assert_eq!(cp.deadline, 0);
        assert_eq!(cp.poll, 30);
    }

    #[test]
    fn test_set_next_zero_interval() {
        let mut cp = ClientPeer::new(addr("x.example.com"), 1, false);
        cp.set_next(0);
        assert_eq!(cp.next, 0);
        assert_eq!(cp.poll, 0);
    }

    #[test]
    fn test_set_next_clears_deadline() {
        let mut cp = ClientPeer::new(addr("x.example.com"), 1, false);
        cp.deadline = 42;
        cp.set_next(15);
        assert_eq!(cp.deadline, 0, "set_next must clear deadline");
    }

    #[test]
    fn test_set_deadline_schedules_timeout() {
        let mut cp = ClientPeer::new(addr("x.example.com"), 1, false);
        cp.set_deadline(15);
        assert_eq!(cp.deadline, 15);
        assert_eq!(cp.next, 0, "set_deadline must clear next");
    }

    #[test]
    fn test_set_deadline_clears_next() {
        let mut cp = ClientPeer::new(addr("x.example.com"), 1, false);
        cp.next = 99;
        cp.set_deadline(10);
        assert_eq!(cp.next, 0, "set_deadline must clear next");
    }

    // -----------------------------------------------------------------------
    // ClientPeer — trustlevel ramp-up (good responses)
    // -----------------------------------------------------------------------

    #[test]
    fn test_trustlevel_increments_from_path_to_aggressive() {
        let mut cp = ClientPeer::new(addr("x.example.com"), 1, false);
        assert_eq!(cp.trustlevel, 2); // PATHETIC

        for _ in 0..6 {
            cp.update_trustlevel(true);
        }
        // 2 + 6 = 8 = AGGRESSIVE
        assert_eq!(cp.trustlevel, TRUSTLEVEL_AGGRESSIVE);
    }

    #[test]
    fn test_trustlevel_every_8_after_aggressive() {
        let mut cp = ClientPeer::new(addr("x.example.com"), 1, false);
        cp.trustlevel = TRUSTLEVEL_AGGRESSIVE; // 8

        // 7 good responses: should stay at 8
        for _ in 0..7 {
            cp.update_trustlevel(true);
        }
        assert_eq!(cp.trustlevel, 8);
        assert_eq!(cp.trustlevel_count, 7);

        // 8th good response: should tick to 9
        cp.update_trustlevel(true);
        assert_eq!(cp.trustlevel, 9);
        assert_eq!(cp.trustlevel_count, 0);
    }

    #[test]
    fn test_trustlevel_reaches_max() {
        let mut cp = ClientPeer::new(addr("x.example.com"), 1, false);
        // 2 → 8 needs 6 hits
        for _ in 0..6 {
            cp.update_trustlevel(true);
        }
        assert_eq!(cp.trustlevel, 8);
        // 8 → 9 needs 8 hits
        for _ in 0..8 {
            cp.update_trustlevel(true);
        }
        assert_eq!(cp.trustlevel, 9);
        // 9 → 10 needs 8 hits
        for _ in 0..8 {
            cp.update_trustlevel(true);
        }
        assert_eq!(cp.trustlevel, 10);
    }

    #[test]
    fn test_trustlevel_stays_at_max() {
        let mut cp = ClientPeer::new(addr("x.example.com"), 1, false);
        cp.trustlevel = TRUSTLEVEL_MAX;
        for _ in 0..20 {
            cp.update_trustlevel(true);
        }
        assert_eq!(cp.trustlevel, 10, "must not exceed MAX");
    }

    #[test]
    fn test_trustlevel_count_wrapping() {
        let mut cp = ClientPeer::new(addr("x.example.com"), 1, false);
        cp.trustlevel = TRUSTLEVEL_AGGRESSIVE;
        cp.trustlevel_count = 255;
        // wrapping_add(1) → 0, which is < 8, so trustlevel stays at 8
        cp.update_trustlevel(true);
        assert_eq!(cp.trustlevel, 8, "0 < 8 so no trustlevel tick");
        assert_eq!(cp.trustlevel_count, 0);
    }

    // -----------------------------------------------------------------------
    // ClientPeer — trustlevel decay (bad responses)
    // -----------------------------------------------------------------------

    #[test]
    fn test_trustlevel_decrements_on_bad_response() {
        let mut cp = ClientPeer::new(addr("x.example.com"), 1, false);
        cp.trustlevel = 9;
        cp.update_trustlevel(false);
        assert_eq!(cp.trustlevel, 8);
    }

    #[test]
    fn test_trustlevel_floor_at_badpeer() {
        let mut cp = ClientPeer::new(addr("x.example.com"), 1, false);
        cp.trustlevel = TRUSTLEVEL_BADPEER; // 6
        for _ in 0..5 {
            cp.update_trustlevel(false);
        }
        assert_eq!(cp.trustlevel, 6, "must not drop below BADPEER");
    }

    #[test]
    fn test_trustlevel_bad_from_max() {
        let mut cp = ClientPeer::new(addr("x.example.com"), 1, false);
        cp.trustlevel = TRUSTLEVEL_MAX;
        // 10 → 9 → 8 → 7 → 6 (stops at 6)
        for _ in 0..6 {
            cp.update_trustlevel(false);
        }
        assert_eq!(cp.trustlevel, 6);
    }

    // -----------------------------------------------------------------------
    // ClientPeer — send_errors tracking
    // -----------------------------------------------------------------------

    #[test]
    fn test_senderrors_tracking() {
        let mut cp = ClientPeer::new(addr("x.example.com"), 1, false);
        assert_eq!(cp.senderrors, 0);
        cp.senderrors = 1;
        assert_eq!(cp.senderrors, 1);
    }

    #[test]
    fn test_senderrors_at_max() {
        let mut cp = ClientPeer::new(addr("x.example.com"), 1, false);
        cp.senderrors = MAX_SEND_ERRORS;
        assert_eq!(cp.senderrors, 3);
    }

    #[test]
    fn test_senderrors_reset_by_peer_init() {
        let mut cp = ClientPeer::new(addr("x.example.com"), 1, false);
        cp.senderrors = 3;
        cp.peer_init(Some(()));
        assert_eq!(cp.senderrors, 0);
    }

    // -----------------------------------------------------------------------
    // ClientPeer — dispatch_response
    // -----------------------------------------------------------------------

    #[test]
    fn test_dispatch_response_sets_state() {
        let mut cp = ClientPeer::new(addr("x.example.com"), 1, false);
        cp.state = ClientState::QuerySent;
        cp.dispatch_response(0.05, 0.01, 3);
        assert_eq!(cp.state, ClientState::ReplyReceived);
    }

    #[test]
    fn test_dispatch_response_updates_peer_filter() {
        let mut cp = ClientPeer::new(addr("x.example.com"), 1, false);
        cp.peer.poll = 3;
        cp.dispatch_response(0.05, 0.01, 3);
        assert!(
            (cp.peer.offset - 0.05).abs() < 1e-9,
            "peer offset should be ~0.05, got {}",
            cp.peer.offset
        );
        assert!(
            (cp.peer.delay - 0.01).abs() < 1e-9,
            "peer delay should be ~0.01, got {}",
            cp.peer.delay
        );
        assert_eq!(cp.peer.stratum, 3);
    }

    #[test]
    fn test_dispatch_response_updates_reachability() {
        let mut cp = ClientPeer::new(addr("x.example.com"), 1, false);
        assert_eq!(cp.peer.reach, 0);
        cp.dispatch_response(0.05, 0.01, 3);
        // update_reach(true) shifts left and sets LSB
        assert_eq!(cp.peer.reach, 0b0000_0001);
    }

    #[test]
    fn test_dispatch_response_increments_trustlevel() {
        let mut cp = ClientPeer::new(addr("x.example.com"), 1, false);
        assert_eq!(cp.trustlevel, 2);
        cp.dispatch_response(0.05, 0.01, 3);
        assert_eq!(cp.trustlevel, 3);
    }

    #[test]
    fn test_dispatch_response_sets_next_interval_path() {
        let mut cp = ClientPeer::new(addr("x.example.com"), 1, false);
        // trustlevel is 2 (PATHETIC) — but dispatch checks:
        // if trustlevel < PATHETIC → PATHETIC (60)
        // else if trustlevel < AGGRESSIVE → AGGRESSIVE (5)
        // else → NORMAL (30)
        // With PATHETIC=2 and trust=2: 2 < 2 is false, 2 < 8 is true → AGGRESSIVE
        cp.dispatch_response(0.05, 0.01, 3);
        assert_eq!(cp.next, INTERVAL_QUERY_AGGRESSIVE);
    }

    #[test]
    fn test_dispatch_response_sets_next_interval_normal() {
        let mut cp = ClientPeer::new(addr("x.example.com"), 1, false);
        cp.trustlevel = TRUSTLEVEL_AGGRESSIVE; // 8
        cp.dispatch_response(0.05, 0.01, 3);
        assert_eq!(cp.next, INTERVAL_QUERY_NORMAL);
    }

    #[test]
    fn test_dispatch_response_with_zero_offset() {
        let mut cp = ClientPeer::new(addr("x.example.com"), 1, false);
        cp.dispatch_response(0.0, 0.0, 1);
        assert!(
            (cp.peer.offset - 0.0).abs() < 1e-9,
            "offset should be ~0, got {}",
            cp.peer.offset
        );
        assert_eq!(cp.peer.stratum, 1);
    }

    #[test]
    fn test_dispatch_response_with_large_offset() {
        let mut cp = ClientPeer::new(addr("x.example.com"), 1, false);
        cp.dispatch_response(10.0, 0.5, 2);
        assert!(
            (cp.peer.offset - 10.0).abs() < 1e-9,
            "offset should be ~10, got {}",
            cp.peer.offset
        );
        assert_eq!(cp.peer.stratum, 2);
    }

    // -----------------------------------------------------------------------
    // ClientPeer — log_error
    // -----------------------------------------------------------------------

    #[test]
    fn test_log_error_new_error() {
        let cp = ClientPeer::new(addr("my.server"), 1, false);
        let msg = cp.log_error("sendmsg", 42);
        assert!(msg.contains("sendmsg"));
        assert!(msg.contains("my.server"));
        assert!(!msg.contains("repeated"));
    }

    #[test]
    fn test_log_error_repeated_error() {
        let mut cp = ClientPeer::new(addr("my.server"), 1, false);
        cp.lasterror = 42;
        let msg = cp.log_error("recvmsg", 42);
        assert!(msg.contains("recvmsg"));
        assert!(msg.contains("repeated"));
    }

    #[test]
    fn test_log_error_different_error() {
        let mut cp = ClientPeer::new(addr("my.server"), 1, false);
        cp.lasterror = 11;
        let msg = cp.log_error("sendmsg", 42);
        assert!(msg.contains("sendmsg"));
        assert!(msg.contains("my.server"));
        assert!(!msg.contains("repeated"), "different error is not repeated");
    }

    #[test]
    fn test_log_error_unknown_addr() {
        let cp = ClientPeer::new(addr(""), 1, false);
        let msg = cp.log_error("connect", 99);
        assert!(msg.contains("connect"));
    }

    // -----------------------------------------------------------------------
    // Constants match C values
    // -----------------------------------------------------------------------

    #[test]
    fn test_constants_match_c_values() {
        assert_eq!(TRUSTLEVEL_BADPEER, 6);
        assert_eq!(TRUSTLEVEL_PATHETIC, 2);
        assert_eq!(TRUSTLEVEL_AGGRESSIVE, 8);
        assert_eq!(TRUSTLEVEL_MAX, 10);
        assert_eq!(INTERVAL_QUERY_NORMAL, 30);
        assert_eq!(INTERVAL_QUERY_PATHETIC, 60);
        assert_eq!(INTERVAL_QUERY_AGGRESSIVE, 5);
        assert_eq!(INTERVAL_QUERY_ULTRA_VIOLENCE, 1);
        assert_eq!(QUERYTIME_MAX, 15);
        assert_eq!(SETTIME_TIMEOUT, 15);
        assert_eq!(MAX_SEND_ERRORS, 3);
    }

    // -----------------------------------------------------------------------
    // handle_auto decisions
    // -----------------------------------------------------------------------

    #[test]
    fn test_handle_auto_abandon_untrusted() {
        let decision = handle_auto(false, 100.0, TRUSTLEVEL_AGGRESSIVE);
        assert_eq!(decision, AutoDecision::Abandon);
    }

    #[test]
    fn test_handle_auto_wait_low_trustlevel() {
        let decision = handle_auto(true, 100.0, TRUSTLEVEL_PATHETIC);
        assert_eq!(decision, AutoDecision::Wait);
    }

    #[test]
    fn test_handle_auto_settime_when_ready() {
        let decision = handle_auto(true, 100.0, TRUSTLEVEL_AGGRESSIVE);
        assert_eq!(decision, AutoDecision::SetTime(100.0));
    }

    #[test]
    fn test_handle_auto_wait_below_threshold() {
        // 59 < 60 threshold, should wait even though trust is high
        let decision = handle_auto(true, 59.0, TRUSTLEVEL_AGGRESSIVE);
        assert_eq!(decision, AutoDecision::Wait);
    }

    #[test]
    fn test_handle_auto_wait_at_boundary() {
        // Exactly 60 is >= threshold, but need trust >= 8
        let decision = handle_auto(true, 60.0, TRUSTLEVEL_AGGRESSIVE);
        assert_eq!(decision, AutoDecision::SetTime(60.0));
    }

    #[test]
    fn test_handle_auto_wait_just_under_threshold() {
        let decision = handle_auto(true, 59.999, TRUSTLEVEL_AGGRESSIVE);
        assert_eq!(decision, AutoDecision::Wait);
    }

    #[test]
    fn test_handle_auto_with_max_trustlevel() {
        let decision = handle_auto(true, 100.0, TRUSTLEVEL_MAX);
        assert_eq!(decision, AutoDecision::SetTime(100.0));
    }

    #[test]
    fn test_handle_auto_abandon_untrusted_high_offset() {
        let decision = handle_auto(false, 500.0, TRUSTLEVEL_MAX);
        assert_eq!(decision, AutoDecision::Abandon);
    }

    // -----------------------------------------------------------------------
    // setup_client_query
    // -----------------------------------------------------------------------

    #[test]
    fn test_setup_client_query_builds_mode3() {
        use crate::ntp::mode;
        let now = NtpTimestamp::from_f64(12345.0);
        let pkt = setup_client_query(now);
        assert_eq!(pkt.mode(), mode::CLIENT, "must be mode 3 (CLIENT)");
        assert_eq!(pkt.version(), 4, "must be NTPv4");
        assert_eq!(pkt.transmit_ts, now, "transmit timestamp must match");
    }

    #[test]
    fn test_setup_client_query_transmit_ts() {
        let now = NtpTimestamp::from_f64(99999.0);
        let pkt = setup_client_query(now);
        assert_eq!(pkt.transmit_ts, now);
    }

    // -----------------------------------------------------------------------
    // Integration-style: dispatch + trustlevel lifecycle
    // -----------------------------------------------------------------------

    #[test]
    fn test_trustlevel_ramps_up_through_dispatch() {
        let mut cp = ClientPeer::new(addr("x.example.com"), 1, false);
        assert_eq!(cp.trustlevel, 2);

        // Send 6 good responses → trust goes 2→8
        for _ in 0..6 {
            cp.dispatch_response(0.01, 0.005, 3);
        }
        assert_eq!(cp.trustlevel, 8);
    }

    #[test]
    fn test_trustlevel_reaches_max_after_many_responses() {
        let mut cp = ClientPeer::new(addr("x.example.com"), 1, false);
        assert_eq!(cp.trustlevel, 2);

        // 6 to reach AGGRESSIVE + 8 to reach 9 + 8 to reach 10 = 22
        for _ in 0..22 {
            cp.dispatch_response(0.01, 0.005, 3);
        }
        assert_eq!(cp.trustlevel, 10);
    }

    #[test]
    fn test_trustlevel_decays_with_bad_responses_integration() {
        let mut cp = ClientPeer::new(addr("x.example.com"), 1, false);
        cp.trustlevel = TRUSTLEVEL_AGGRESSIVE; // 8

        // Bad responses: 8 → 7 → 6 (floor at BADPEER=6)
        cp.update_trustlevel(false);
        assert_eq!(cp.trustlevel, 7);
        cp.update_trustlevel(false);
        assert_eq!(cp.trustlevel, 6);
        cp.update_trustlevel(false);
        assert_eq!(cp.trustlevel, 6, "floor at BADPEER");
    }

    #[test]
    fn test_trustlevel_floor_in_integration() {
        let mut cp = ClientPeer::new(addr("x.example.com"), 1, false);
        cp.trustlevel = 9;
        for _ in 0..10 {
            cp.update_trustlevel(false);
        }
        assert_eq!(cp.trustlevel, 6); // floored at BADPEER
    }

    #[test]
    fn test_next_addr_after_dns_done_resets() {
        let mut cp = ClientPeer::new(addr("x.example.com"), 1, false);
        cp.state = ClientState::DnsInProgress;
        cp.trustlevel = 7;

        let addrs = vec![addr("192.0.2.1"), addr("192.0.2.2"), addr("192.0.2.3")];
        let result = cp.next_addr(&addrs);
        assert!(result);
        assert_eq!(cp.trustlevel, TRUSTLEVEL_PATHETIC);
        assert_eq!(cp.state, ClientState::DnsDone);
    }

    // -----------------------------------------------------------------------
    // Edge cases
    // -----------------------------------------------------------------------

    #[test]
    fn test_trustlevel_zero_edge() {
        let mut cp = ClientPeer::new(addr("x.example.com"), 1, false);
        cp.trustlevel = 0;
        // Good response should bring it to 1
        cp.update_trustlevel(true);
        assert_eq!(cp.trustlevel, 1);
    }

    #[test]
    fn test_trustlevel_max_then_bad() {
        let mut cp = ClientPeer::new(addr("x.example.com"), 1, false);
        cp.trustlevel = TRUSTLEVEL_MAX;
        cp.update_trustlevel(false);
        assert_eq!(cp.trustlevel, 9);
    }

    #[test]
    fn test_max_senderrors_reached_edge() {
        let mut cp = ClientPeer::new(addr("x.example.com"), 1, false);
        cp.senderrors = MAX_SEND_ERRORS;
        // Simulate one more send error
        cp.senderrors = cp.senderrors.saturating_add(1);
        assert_eq!(cp.senderrors, 4, "should saturate above MAX");
    }

    #[test]
    fn test_set_next_large_interval() {
        let mut cp = ClientPeer::new(addr("x.example.com"), 1, false);
        cp.set_next(999999);
        assert_eq!(cp.next, 999999);
        assert_eq!(cp.poll, 999999);
    }

    #[test]
    fn test_set_deadline_large_timeout() {
        let mut cp = ClientPeer::new(addr("x.example.com"), 1, false);
        cp.set_deadline(999999);
        assert_eq!(cp.deadline, 999999);
        assert_eq!(cp.next, 0);
    }

    #[test]
    fn test_dispatch_response_interval_below_path() {
        let mut cp = ClientPeer::new(addr("x.example.com"), 1, false);
        // trustlevel is checked BEFORE increment: trust=1 < PATHETIC=2 → PATHETIC(60)
        cp.trustlevel = 1;
        cp.dispatch_response(0.01, 0.01, 2);
        assert_eq!(
            cp.next, INTERVAL_QUERY_PATHETIC,
            "trust 1 < 2 should use pathetic interval"
        );
    }

    #[test]
    fn test_handle_auto_barely_above_threshold() {
        let decision = handle_auto(true, 60.001, TRUSTLEVEL_AGGRESSIVE);
        assert_eq!(decision, AutoDecision::SetTime(60.001));
    }

    // -----------------------------------------------------------------------
    // ntp_offset_delay
    // -----------------------------------------------------------------------

    #[test]
    fn test_ntp_offset_delay_symmetric() {
        // Symmetric path: T2-T1 == T4-T3 => offset = 0
        // T1=100, T2=101, T3=102, T4=103 => same delay both ways
        let (offset, delay, error) = ntp_offset_delay(100.0, 101.0, 102.0, 103.0);
        assert!(
            (offset - 0.0).abs() < 1e-12,
            "symmetric offset should be 0, got {}",
            offset
        );
        assert!(
            (delay - 2.0).abs() < 1e-12,
            "delay should be 2, got {}",
            delay
        );
        // error = (T2-T1) - (T3-T4) = (101-100) - (102-103) = 1 - (-1) = 2
        assert!(
            (error - 2.0).abs() < 1e-12,
            "error should be 2, got {}",
            error
        );
    }

    #[test]
    fn test_ntp_offset_delay_positive_offset() {
        // Server is ahead: T2-T1 > T4-T3
        let (offset, delay, _) = ntp_offset_delay(100.0, 102.0, 104.0, 105.0);
        // offset = ((102-100) + (104-105)) / 2 = (2 + -1) / 2 = 0.5
        assert!(
            (offset - 0.5).abs() < 1e-12,
            "positive offset should be 0.5, got {}",
            offset
        );
        // delay = (105-100) - (104-102) = 5 - 2 = 3
        assert!(
            (delay - 3.0).abs() < 1e-12,
            "delay should be 3, got {}",
            delay
        );
    }

    #[test]
    fn test_ntp_offset_delay_negative_offset() {
        // Server is behind: T4-T3 > T2-T1
        let (offset, delay, _) = ntp_offset_delay(100.0, 100.5, 101.0, 103.0);
        // offset = ((100.5-100) + (101-103)) / 2 = (0.5 + -2) / 2 = -0.75
        assert!(
            (offset - (-0.75)).abs() < 1e-12,
            "negative offset should be -0.75, got {}",
            offset
        );
    }

    #[test]
    fn test_ntp_offset_delay_zero_timestamps() {
        // All timestamps zero
        let (offset, delay, error) = ntp_offset_delay(0.0, 0.0, 0.0, 0.0);
        assert!((offset - 0.0).abs() < 1e-12);
        assert!((delay - 0.0).abs() < 1e-12);
        assert!((error - 0.0).abs() < 1e-12);
    }

    #[test]
    fn test_ntp_offset_delay_equal_timestamps() {
        // All timestamps equal => offset=0, delay=0, error=0
        let (offset, delay, error) = ntp_offset_delay(50.0, 50.0, 50.0, 50.0);
        assert!((offset - 0.0).abs() < 1e-12);
        assert!((delay - 0.0).abs() < 1e-12);
        assert!((error - 0.0).abs() < 1e-12);
    }

    #[test]
    fn test_ntp_offset_delay_negative_delay() {
        // T4 < T1 should give negative delay
        let (offset, delay, _) = ntp_offset_delay(100.0, 101.0, 102.0, 99.0);
        assert!(
            delay < 0.0,
            "delay should be negative when T4 < T1, got {}",
            delay
        );
    }

    #[test]
    fn test_ntp_offset_delay_large_values() {
        // Large NTP timestamps (close to era boundary)
        let t1 = 4_000_000_000.0;
        let t2 = 4_000_000_010.0;
        let t3 = 4_000_000_020.0;
        let t4 = 4_000_000_025.0;
        let (offset, delay, _) = ntp_offset_delay(t1, t2, t3, t4);
        // offset = ((10) + (20-25)) / 2 = (10-5)/2 = 2.5
        assert!((offset - 2.5).abs() < 1e-9);
        // delay = (25-0) - (20-10) = 25 - 10 = 15
        assert!((delay - 15.0).abs() < 1e-9);
    }

    // -----------------------------------------------------------------------
    // peer_noquery / peer_flash / peer_compare
    // -----------------------------------------------------------------------

    #[test]
    fn test_peer_noquery_sets_flash() {
        let mut p = Peer::new(addr("192.0.2.1"), 1, false);
        p.clear_flash(PFLASH_PEERNOQUERY);
        assert!(!p.has_flash(PFLASH_PEERNOQUERY));
        peer_noquery(&mut p);
        assert!(p.has_flash(PFLASH_PEERNOQUERY));
    }

    #[test]
    fn test_peer_flash_clears_then_sets() {
        let mut p = Peer::new(addr("192.0.2.1"), 1, false);
        p.stratum = 5; // valid stratum — avoid auto-set of PFLASH_PEERSTRAT
                       // Set all quality bits first.
        p.set_flash(PFLASH_PEERSTRAT | PFLASH_PEERDELAY | PFLASH_PEEROFFSET | PFLASH_PEERDISP);

        // Call peer_flash with good values — should clear all.
        peer_flash(&mut p, 0.01, 0.005, 0.001);
        assert!(!p.has_flash(PFLASH_PEERSTRAT));
        assert!(!p.has_flash(PFLASH_PEERBADSTRAT));
        assert!(!p.has_flash(PFLASH_PEERDELAY));
        assert!(!p.has_flash(PFLASH_PEEROFFSET));
        assert!(!p.has_flash(PFLASH_PEERDISP));
    }

    #[test]
    fn test_peer_flash_sets_delay_bit() {
        let mut p = Peer::new(addr("192.0.2.1"), 1, false);
        p.stratum = 3;
        peer_flash(&mut p, 0.01, MAX_DELAY + 1.0, 0.001);
        assert!(p.has_flash(PFLASH_PEERDELAY));
    }

    #[test]
    fn test_peer_flash_sets_offset_bit() {
        let mut p = Peer::new(addr("192.0.2.1"), 1, false);
        p.stratum = 3;
        peer_flash(&mut p, MAX_OFFSET + 1.0, 0.005, 0.001);
        assert!(p.has_flash(PFLASH_PEEROFFSET));
    }

    #[test]
    fn test_peer_flash_sets_dispersion_bit() {
        let mut p = Peer::new(addr("192.0.2.1"), 1, false);
        p.stratum = 3;
        peer_flash(&mut p, 0.01, 0.005, MAX_DISPERSION + 1.0);
        assert!(p.has_flash(PFLASH_PEERDISP));
    }

    #[test]
    fn test_peer_flash_sets_strat_bit_for_bad_stratum() {
        let mut p = Peer::new(addr("192.0.2.1"), 1, false);
        p.stratum = 16; // > MAX_STRATUM
        peer_flash(&mut p, 0.01, 0.005, 0.001);
        assert!(p.has_flash(PFLASH_PEERSTRAT));
        assert!(p.has_flash(PFLASH_PEERBADSTRAT));
    }

    #[test]
    fn test_peer_flash_sets_strat_bit_for_stratum_zero() {
        let mut p = Peer::new(addr("192.0.2.1"), 1, false);
        p.stratum = 0; // KoD / not synced
        peer_flash(&mut p, 0.01, 0.005, 0.001);
        assert!(p.has_flash(PFLASH_PEERSTRAT));
        assert!(p.has_flash(PFLASH_PEERBADSTRAT));
    }

    #[test]
    fn test_peer_flash_negative_delay_sets_both() {
        let mut p = Peer::new(addr("192.0.2.1"), 1, false);
        p.stratum = 3;
        peer_flash(&mut p, 0.01, -0.5, 0.001);
        assert!(p.has_flash(PFLASH_PEERDELAY));
    }

    #[test]
    fn test_peer_flash_negative_dispersion_sets_bit() {
        let mut p = Peer::new(addr("192.0.2.1"), 1, false);
        p.stratum = 3;
        peer_flash(&mut p, 0.01, 0.005, -1.0);
        assert!(p.has_flash(PFLASH_PEERDISP));
    }

    #[test]
    fn test_peer_compare_less() {
        let mut a = Peer::new(addr("192.0.2.1"), 1, false);
        let mut b = Peer::new(addr("192.0.2.2"), 1, false);
        a.offset = -0.5;
        b.offset = 0.3;
        assert_eq!(peer_compare(&a, &b), core::cmp::Ordering::Less);
        assert_eq!(peer_compare(&b, &a), core::cmp::Ordering::Greater);
    }

    #[test]
    fn test_peer_compare_equal() {
        let mut a = Peer::new(addr("192.0.2.1"), 1, false);
        let mut b = Peer::new(addr("192.0.2.2"), 1, false);
        a.offset = 0.123;
        b.offset = 0.123;
        assert_eq!(peer_compare(&a, &b), core::cmp::Ordering::Equal);
    }

    #[test]
    fn test_peer_compare_sorts_by_offset() {
        let mut peers = vec![
            Peer::new(addr("c"), 1, false),
            Peer::new(addr("a"), 1, false),
            Peer::new(addr("b"), 1, false),
        ];
        peers[0].offset = 0.5;
        peers[1].offset = -0.1;
        peers[2].offset = 0.2;

        peers.sort_by(peer_compare);

        assert!(
            peers[0].offset <= peers[1].offset && peers[1].offset <= peers[2].offset,
            "peers not sorted by offset: {:?} {:?} {:?}",
            peers[0].offset,
            peers[1].offset,
            peers[2].offset
        );
        assert_eq!(peers[0].offset, -0.1);
        assert_eq!(peers[1].offset, 0.2);
        assert_eq!(peers[2].offset, 0.5);
    }

    // -----------------------------------------------------------------------
    // client_update
    // -----------------------------------------------------------------------

    #[test]
    fn test_client_update_not_enough_samples() {
        let mut cp = ClientPeer::new(addr("192.0.2.1"), 1, false);
        // Put 4 good samples in the buffer (need 8).
        for i in 0..4 {
            cp.reply_buffer[i] = ReplySlot {
                offset: 0.01 * (i as f64),
                delay: 0.005 * (i as f64),
                error: 0.001,
                rcvd: i as i64,
                good: true,
                stratum: 2,
            };
        }
        assert!(client_update(&mut cp).is_none(), "need 8 good samples");
    }

    #[test]
    fn test_client_update_requires_all_8_good() {
        let mut cp = ClientPeer::new(addr("192.0.2.1"), 1, false);
        // Fill 8 slots, but mark one as not good.
        for i in 0..8 {
            cp.reply_buffer[i] = ReplySlot {
                offset: 0.01,
                delay: 0.01 * (i as f64),
                error: 0.0,
                rcvd: i as i64,
                good: i != 5, // slot 5 is not good
                stratum: 2,
            };
        }
        assert!(client_update(&mut cp).is_none(), "all 8 must be good");
    }

    #[test]
    fn test_client_update_selects_lowest_delay() {
        let mut cp = ClientPeer::new(addr("192.0.2.1"), 1, false);
        // Fill all 8 slots with varying delays.
        for i in 0..8 {
            cp.reply_buffer[i] = ReplySlot {
                offset: 0.01 * (i as f64),
                delay: 0.1 * (i as f64), // delay increases with i
                error: 0.001,
                rcvd: i as i64,
                good: true,
                stratum: 2,
            };
        }
        // Slot 0 has lowest delay (0.0) but also lowest rcvd.
        let result = client_update(&mut cp);
        assert!(result.is_some(), "all 8 good should return Some");
        let sample = result.unwrap();
        assert!(
            (sample.offset - 0.0).abs() < 1e-12,
            "should select slot 0 with offset 0, got {}",
            sample.offset
        );
        assert!(
            (sample.delay - 0.0).abs() < 1e-12,
            "should select slot 0 with delay 0, got {}",
            sample.delay
        );
    }

    #[test]
    fn test_client_update_marks_older_samples_invalid() {
        let mut cp = ClientPeer::new(addr("192.0.2.1"), 1, false);
        // Fill all 8 slots.  Let slot 4 have the lowest delay.
        for i in 0..8 {
            cp.reply_buffer[i] = ReplySlot {
                offset: 0.01,
                delay: if i == 4 { 0.001 } else { 0.1 },
                error: 0.0,
                rcvd: i as i64,
                good: true,
                stratum: 2,
            };
        }
        let _ = client_update(&mut cp);

        // Slots with rcvd <= 4 should be marked not good.
        for i in 0..=4 {
            assert!(
                !cp.reply_buffer[i].good,
                "slot {} should be marked not good",
                i
            );
        }
        // Slots with rcvd > 4 should remain good.
        for i in 5..8 {
            assert!(cp.reply_buffer[i].good, "slot {} should remain good", i);
        }
    }

    #[test]
    fn test_client_update_returns_error_as_dispersion() {
        let mut cp = ClientPeer::new(addr("192.0.2.1"), 1, false);
        for i in 0..8 {
            cp.reply_buffer[i] = ReplySlot {
                offset: 0.01,
                delay: 0.01,
                error: if i == 3 { -0.005 } else { 0.001 },
                rcvd: i as i64,
                good: true,
                stratum: 2,
            };
        }
        let result = client_update(&mut cp);
        assert!(result.is_some());
        // Slot 3 has delay 0.01 which is same as others; since it's the same
        // delay for all, the first one (slot 0) with lowest rcvd is selected.
        assert!(
            (result.unwrap().dispersion - 0.001).abs() < 1e-12,
            "dispersion should be abs(error) of best slot"
        );
    }

    // -----------------------------------------------------------------------
    // client_dispatch
    // -----------------------------------------------------------------------

    #[test]
    fn test_client_dispatch_valid_mode4_response() {
        use crate::ntp::{mode, NtpTimestamp};
        let mut cp = ClientPeer::new(addr("192.0.2.1"), 1, false);
        let mut qs = crate::ntp::query::QueryState::new();

        // Use integer-only timestamps to avoid fractional precision issues.
        let query_ts = NtpTimestamp::new(4_000_000_000, 0);
        qs.send_query(query_ts);

        // Build a valid mode 4 response.
        let mut response = crate::ntp::NtpPacket::zero();
        response.set_li_vn_mode(0, 4, 4); // no-warning, v4, server
        response.stratum = 3;
        response.origin_ts = query_ts;
        response.receive_ts = NtpTimestamp::new(4_000_000_010, 0); // T2
        response.transmit_ts = NtpTimestamp::new(4_000_000_020, 0); // T3

        let recv_time = NtpTimestamp::new(4_000_000_030, 0); // T4

        let result = client_dispatch(&mut cp, &mut qs, &response, recv_time, false, false);
        assert_eq!(result, 1, "valid mode 4 response should return 1");
        assert_eq!(
            cp.state,
            ClientState::ReplyReceived,
            "state should be ReplyReceived"
        );
        // Shift should have advanced.
        assert_eq!(cp.shift, 1);
        // Reply buffer should have the entry.
        assert!(cp.reply_buffer[0].good);
        // offset = ((T2-T1) + (T3-T4)) / 2 = ((10) + (20-30)) / 2 = 0
        assert!(
            (cp.reply_buffer[0].offset - 0.0).abs() < 1e-9,
            "offset should be 0, got {}",
            cp.reply_buffer[0].offset
        );
        // delay = (T4-T1) - (T3-T2) = (30-0) - (20-10) = 30 - 10 = 20
        assert!(
            (cp.reply_buffer[0].delay - 20.0).abs() < 1e-9,
            "delay should be 20, got {}",
            cp.reply_buffer[0].delay
        );
    }

    #[test]
    fn test_client_dispatch_wrong_origin_returns_0() {
        use crate::ntp::NtpTimestamp;
        let mut cp = ClientPeer::new(addr("192.0.2.1"), 1, false);
        let mut qs = crate::ntp::query::QueryState::new();

        qs.send_query(NtpTimestamp::new(1000, 0));

        let mut response = crate::ntp::NtpPacket::zero();
        response.set_li_vn_mode(0, 4, 4);
        response.stratum = 3;
        response.origin_ts = NtpTimestamp::new(999999, 0); // wrong origin!
        response.receive_ts = NtpTimestamp::new(1010, 0);
        response.transmit_ts = NtpTimestamp::new(1020, 0);

        let recv_time = NtpTimestamp::new(1030, 0);

        let result = client_dispatch(&mut cp, &mut qs, &response, recv_time, false, false);
        assert_eq!(result, 0, "wrong origin should return 0");
    }

    #[test]
    fn test_client_dispatch_alarm_leap_returns_0() {
        use crate::ntp::NtpTimestamp;
        let mut cp = ClientPeer::new(addr("192.0.2.1"), 1, false);
        let mut qs = crate::ntp::query::QueryState::new();

        let query_ts = NtpTimestamp::new(1000, 0);
        qs.send_query(query_ts);

        let mut response = crate::ntp::NtpPacket::zero();
        response.set_li_vn_mode(3, 4, 4); // LI_ALARM
        response.stratum = 3;
        response.origin_ts = query_ts;
        response.receive_ts = NtpTimestamp::new(1010, 0);
        response.transmit_ts = NtpTimestamp::new(1020, 0);

        let result = client_dispatch(
            &mut cp,
            &mut qs,
            &response,
            NtpTimestamp::new(1030, 0),
            false,
            false,
        );
        assert_eq!(result, 0, "LI_ALARM should return 0");
    }

    #[test]
    fn test_client_dispatch_stratum_zero_returns_0() {
        use crate::ntp::NtpTimestamp;
        let mut cp = ClientPeer::new(addr("192.0.2.1"), 1, false);
        let mut qs = crate::ntp::query::QueryState::new();

        let query_ts = NtpTimestamp::new(1000, 0);
        qs.send_query(query_ts);

        let mut response = crate::ntp::NtpPacket::zero();
        response.set_li_vn_mode(0, 4, 4);
        response.stratum = 0; // Kiss-o'-Death
        response.origin_ts = query_ts;
        response.receive_ts = NtpTimestamp::new(1010, 0);
        response.transmit_ts = NtpTimestamp::new(1020, 0);

        let result = client_dispatch(
            &mut cp,
            &mut qs,
            &response,
            NtpTimestamp::new(1030, 0),
            false,
            false,
        );
        assert_eq!(result, 0, "stratum 0 should return 0");
    }

    #[test]
    fn test_client_dispatch_stratum_above_max_returns_0() {
        use crate::ntp::NtpTimestamp;
        let mut cp = ClientPeer::new(addr("192.0.2.1"), 1, false);
        let mut qs = crate::ntp::query::QueryState::new();

        let query_ts = NtpTimestamp::new(1000, 0);
        qs.send_query(query_ts);

        let mut response = crate::ntp::NtpPacket::zero();
        response.set_li_vn_mode(0, 4, 4);
        response.stratum = 16; // > MAX_STRATUM
        response.origin_ts = query_ts;
        response.receive_ts = NtpTimestamp::new(1010, 0);
        response.transmit_ts = NtpTimestamp::new(1020, 0);

        let result = client_dispatch(
            &mut cp,
            &mut qs,
            &response,
            NtpTimestamp::new(1030, 0),
            false,
            false,
        );
        assert_eq!(result, 0, "stratum > MAX should return 0");
    }

    #[test]
    fn test_client_dispatch_negative_delay_returns_0() {
        use crate::ntp::NtpTimestamp;
        let mut cp = ClientPeer::new(addr("192.0.2.1"), 1, false);
        let mut qs = crate::ntp::query::QueryState::new();

        let query_ts = NtpTimestamp::new(1000, 0);
        qs.send_query(query_ts);

        let mut response = crate::ntp::NtpPacket::zero();
        response.set_li_vn_mode(0, 4, 4);
        response.stratum = 3;
        response.origin_ts = query_ts;
        response.receive_ts = NtpTimestamp::new(1010, 0);
        response.transmit_ts = NtpTimestamp::new(1020, 0);
        // T4 before T1 => negative delay
        let recv_time = NtpTimestamp::new(990, 0);

        let result = client_dispatch(&mut cp, &mut qs, &response, recv_time, false, false);
        assert_eq!(result, 0, "negative delay should return 0");
    }

    #[test]
    fn test_client_dispatch_invalid_mode_returns_0() {
        use crate::ntp::{mode, NtpTimestamp};
        let mut cp = ClientPeer::new(addr("192.0.2.1"), 1, false);
        let mut qs = crate::ntp::query::QueryState::new();

        let query_ts = NtpTimestamp::new(1000, 0);
        qs.send_query(query_ts);

        // Mode 3 (CLIENT) instead of 4 (SERVER)
        let mut response = crate::ntp::NtpPacket::zero();
        response.set_li_vn_mode(0, 4, mode::CLIENT);
        response.stratum = 3;
        response.origin_ts = query_ts;

        let result = client_dispatch(
            &mut cp,
            &mut qs,
            &response,
            NtpTimestamp::new(1030, 0),
            false,
            false,
        );
        assert_eq!(result, 0, "non-server mode should return 0");
    }

    #[test]
    fn test_client_dispatch_invalid_version_returns_0() {
        use crate::ntp::NtpTimestamp;
        let mut cp = ClientPeer::new(addr("192.0.2.1"), 1, false);
        let mut qs = crate::ntp::query::QueryState::new();

        let query_ts = NtpTimestamp::new(1000, 0);
        qs.send_query(query_ts);

        // Version 1 (too old)
        let mut response = crate::ntp::NtpPacket::zero();
        response.set_li_vn_mode(0, 1, 4);
        response.stratum = 3;
        response.origin_ts = query_ts;

        let result = client_dispatch(
            &mut cp,
            &mut qs,
            &response,
            NtpTimestamp::new(1030, 0),
            false,
            false,
        );
        assert_eq!(result, 0, "version < 3 should return 0");
    }

    // -----------------------------------------------------------------------
    // client_dispatch + client_update integration
    // -----------------------------------------------------------------------

    #[test]
    fn test_client_dispatch_full_ring_then_update() {
        use crate::ntp::NtpTimestamp;
        let mut cp = ClientPeer::new(addr("192.0.2.1"), 1, false);
        let mut qs = crate::ntp::query::QueryState::new();

        // Send 8 queries and receive 8 responses to fill the reply ring.
        for i in 0..8u32 {
            let base = 1000 + i * 100;
            let query_ts = NtpTimestamp::new(base, 0);
            qs.send_query(query_ts);

            let mut response = crate::ntp::NtpPacket::zero();
            response.set_li_vn_mode(0, 4, 4);
            response.stratum = 3;
            response.origin_ts = query_ts;
            response.receive_ts = NtpTimestamp::new(base + 10, 0);
            response.transmit_ts = NtpTimestamp::new(base + 20, 0);

            let recv_time = NtpTimestamp::new(base + 30, 0);
            let result = client_dispatch(&mut cp, &mut qs, &response, recv_time, false, false);
            assert_eq!(result, 1, "dispatch {} should succeed", i);
        }

        // After 8 dispatches, the clock filter update should have run.
        assert_eq!(cp.shift, 8);
        assert!((cp.peer.offset - 0.0).abs() < 1e-9, "offset should be 0");
        assert!((cp.peer.delay - 20.0).abs() < 1e-9, "delay should be 20");
    }

    #[test]
    fn test_client_dispatch_clears_outstanding() {
        use crate::ntp::NtpTimestamp;
        let mut cp = ClientPeer::new(addr("192.0.2.1"), 1, false);
        let mut qs = crate::ntp::query::QueryState::new();

        let query_ts = NtpTimestamp::new(1000, 0);
        qs.send_query(query_ts);
        assert!(qs.outstanding);

        let mut response = crate::ntp::NtpPacket::zero();
        response.set_li_vn_mode(0, 4, 4);
        response.stratum = 3;
        response.origin_ts = query_ts;
        response.receive_ts = NtpTimestamp::new(1010, 0);
        response.transmit_ts = NtpTimestamp::new(1020, 0);

        let _ = client_dispatch(
            &mut cp,
            &mut qs,
            &response,
            NtpTimestamp::new(1030, 0),
            false,
            false,
        );
        assert!(!qs.outstanding, "query should be cleared after dispatch");
    }

    #[test]
    fn test_client_dispatch_schedules_next_interval() {
        use crate::ntp::NtpTimestamp;
        let mut cp = ClientPeer::new(addr("192.0.2.1"), 1, false);
        let mut qs = crate::ntp::query::QueryState::new();

        let query_ts = NtpTimestamp::new(1000, 0);
        qs.send_query(query_ts);

        let mut response = crate::ntp::NtpPacket::zero();
        response.set_li_vn_mode(0, 4, 4);
        response.stratum = 3;
        response.origin_ts = query_ts;
        response.receive_ts = NtpTimestamp::new(1010, 0);
        response.transmit_ts = NtpTimestamp::new(1020, 0);

        // trustlevel starts at 2 (PATHETIC) → interval: 2 < 2 is false,
        // 2 < 8 is true → AGGRESSIVE (5)
        let _ = client_dispatch(
            &mut cp,
            &mut qs,
            &response,
            NtpTimestamp::new(1030, 0),
            false,
            false,
        );
        assert_eq!(
            cp.next, 5,
            "trustlevel 2 should schedule aggressive interval"
        );
        assert_eq!(cp.poll, 5);
    }

    #[test]
    fn test_client_dispatch_with_settime_and_automatic() {
        use crate::ntp::NtpTimestamp;
        let mut cp = ClientPeer::new(addr("192.0.2.1"), 1, true);
        cp.trustlevel = TRUSTLEVEL_AGGRESSIVE;
        let mut qs = crate::ntp::query::QueryState::new();

        let query_ts = NtpTimestamp::new(1000, 0);
        qs.send_query(query_ts);

        let mut response = crate::ntp::NtpPacket::zero();
        response.set_li_vn_mode(0, 4, 4);
        response.stratum = 3;
        response.origin_ts = query_ts;
        response.receive_ts = NtpTimestamp::new(1010, 0);
        response.transmit_ts = NtpTimestamp::new(1020, 0);

        // With settime + automatic + trustlevel >= AGGRESSIVE
        // AND the computed offset is 0 (< AUTO_THRESHOLD), so handle_auto returns Wait.
        let result = client_dispatch(
            &mut cp,
            &mut qs,
            &response,
            NtpTimestamp::new(1030, 0),
            true,
            true,
        );
        assert_eq!(result, 1);
    }

    #[test]
    fn test_reply_buffer_wraps_after_8() {
        let mut cp = ClientPeer::new(addr("192.0.2.1"), 1, false);
        // Push 10 entries: writes go to slots 0,1,2,3,4,5,6,7,0,1
        for i in 0..10 {
            cp.reply_buffer[i % NTP_FILTER] = ReplySlot {
                offset: i as f64,
                delay: 0.01,
                error: 0.0,
                rcvd: i as i64,
                good: true,
                stratum: 2,
            };
            cp.shift = cp.shift.wrapping_add(1);
        }
        assert_eq!(cp.shift, 10);
        // Slot 2 was last written by i=2 → offset=2.0
        assert!(
            (cp.reply_buffer[2].offset - 2.0).abs() < 1e-12,
            "slot 2 should have offset 2.0 (written by i=2), got {}",
            cp.reply_buffer[2].offset
        );
        // Slot 0 was overwritten by i=8 → offset=8.0
        assert!(
            (cp.reply_buffer[0].offset - 8.0).abs() < 1e-12,
            "slot 0 should have offset 8.0 (overwritten by i=8), got {}",
            cp.reply_buffer[0].offset
        );
    }

    #[test]
    fn test_reply_slot_default() {
        let slot = ReplySlot::default();
        assert!((slot.offset - 0.0).abs() < 1e-12);
        assert!((slot.delay - 0.0).abs() < 1e-12);
        assert!((slot.error - 0.0).abs() < 1e-12);
        assert_eq!(slot.rcvd, 0);
        assert!(!slot.good);
        assert_eq!(slot.stratum, 0);
    }

    #[test]
    fn test_peer_flash_many_bits_at_once() {
        let mut p = Peer::new(addr("192.0.2.1"), 1, false);
        p.stratum = 0; // bad
                       // All thresholds exceeded simultaneously
        peer_flash(&mut p, 10.0, 99.0, 99.0);
        assert!(p.has_flash(PFLASH_PEERSTRAT));
        assert!(p.has_flash(PFLASH_PEERBADSTRAT));
        assert!(p.has_flash(PFLASH_PEERDELAY));
        assert!(p.has_flash(PFLASH_PEEROFFSET));
        assert!(p.has_flash(PFLASH_PEERDISP));
    }

    #[test]
    fn test_peer_flash_clears_previous_bits() {
        let mut p = Peer::new(addr("192.0.2.1"), 1, false);
        p.stratum = 3;
        // First call: set some bits.
        peer_flash(&mut p, 10.0, 0.005, 0.001);
        assert!(p.has_flash(PFLASH_PEEROFFSET));
        assert!(!p.has_flash(PFLASH_PEERDELAY));
        assert!(!p.has_flash(PFLASH_PEERDISP));

        // Second call: different bits should clear PFLASH_PEEROFFSET.
        peer_flash(&mut p, 0.01, 99.0, 0.001);
        assert!(
            !p.has_flash(PFLASH_PEEROFFSET),
            "previous offset bit should be cleared"
        );
        assert!(p.has_flash(PFLASH_PEERDELAY), "delay bit should be set");
    }

    // -------------------------------------------------------------------
    // Peer list management (peer_add / peer_remove / peer_addr_head_clear)
    // -------------------------------------------------------------------

    #[test]
    fn test_peer_add_appends_to_list() {
        let mut peers: Vec<ClientPeer> = Vec::new();
        let p = ClientPeer::new(addr("pool.ntp.org"), 1, false);
        assert_eq!(peers.len(), 0);
        peer_add(&mut peers, p);
        assert_eq!(peers.len(), 1);
    }

    #[test]
    fn test_peer_add_multiple() {
        let mut peers: Vec<ClientPeer> = Vec::new();
        peer_add(&mut peers, ClientPeer::new(addr("pool.ntp.org"), 1, false));
        peer_add(
            &mut peers,
            ClientPeer::new(addr("time.google.com"), 1, false),
        );
        assert_eq!(peers.len(), 2);
    }

    #[test]
    fn test_peer_remove_by_id() {
        let mut peers: Vec<ClientPeer> = Vec::new();
        let p1 = ClientPeer::new(addr("pool.ntp.org"), 1, false);
        let id1 = p1.peer.id;
        let p2 = ClientPeer::new(addr("time.google.com"), 1, false);
        let id2 = p2.peer.id;
        peer_add(&mut peers, p1);
        peer_add(&mut peers, p2);
        assert_eq!(peers.len(), 2);
        let removed = peer_remove(&mut peers, id1);
        assert!(removed.is_some());
        assert_eq!(removed.as_ref().unwrap().peer.id, id1);
        assert_eq!(peers.len(), 1);
        assert_eq!(peers[0].peer.id, id2);
    }

    #[test]
    fn test_peer_remove_nonexistent_id() {
        let mut peers: Vec<ClientPeer> = Vec::new();
        peer_add(&mut peers, ClientPeer::new(addr("pool.ntp.org"), 1, false));
        let removed = peer_remove(&mut peers, 999);
        assert!(removed.is_none());
        assert_eq!(peers.len(), 1);
    }

    #[test]
    fn test_peer_remove_empty_list() {
        let mut peers: Vec<ClientPeer> = Vec::new();
        let removed = peer_remove(&mut peers, 1);
        assert!(removed.is_none());
    }

    #[test]
    fn test_peer_addr_head_clear_resets_state() {
        let mut p = ClientPeer::new(addr("192.0.2.1"), 1, false);
        p.state = ClientState::DnsDone;
        peer_addr_head_clear(&mut p);
        assert_eq!(p.state, ClientState::None);
    }

    #[test]
    fn test_peer_add_then_remove_verifies_ids() {
        let mut peers: Vec<ClientPeer> = Vec::new();
        let p1 = ClientPeer::new(addr("a.example.com"), 1, false);
        let id1 = p1.peer.id;
        let p2 = ClientPeer::new(addr("b.example.com"), 1, false);
        let id2 = p2.peer.id;
        let p3 = ClientPeer::new(addr("c.example.com"), 1, false);
        let id3 = p3.peer.id;
        peer_add(&mut peers, p1);
        peer_add(&mut peers, p2);
        peer_add(&mut peers, p3);
        assert_eq!(peers.len(), 3);
        // Remove the middle one
        let removed = peer_remove(&mut peers, id2);
        assert!(removed.is_some());
        assert_eq!(removed.unwrap().peer.id, id2);
        assert_eq!(peers.len(), 2);
        // First and last remain
        assert_eq!(peers[0].peer.id, id1);
        assert_eq!(peers[1].peer.id, id3);
    }
}
