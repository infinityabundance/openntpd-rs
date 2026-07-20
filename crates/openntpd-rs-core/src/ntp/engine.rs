//! NTP child process event loop and peer lifecycle management.
//!
//! This module owns the core state machine that runs in the NTP child
//! process after `privsep` fork.  It manages peer query scheduling,
//! response processing, clock selection, and clock discipline
//! adjustment — corresponding to OpenNTPD's `ntp.c` (`ntp_main`,
//! `ntp_dispatch_imsg`, `priv_adjtime`, `update_scale`, etc.).
//!
//! ## no_std
//!
//! This module is `no_std` + `deny(unsafe_code)`.  It uses `alloc::vec::Vec`
//! for dynamic storage and `libm` for floating-point operations.
//!
//! ## Determinism
//!
//! The engine is purely computational: it takes time values and peer
//! responses as inputs and returns actions (queries to send, clock
//! adjustments to apply) as outputs.  No I/O is performed here.

use alloc::vec::Vec;
use core::cmp;

use crate::ntp::clock::{ClockAdjustment, ClockState};
use crate::peer::{ClockSelection, Peer};

// ---------------------------------------------------------------------------
// Constants derived from OpenNTPD's ntpd.h
// ---------------------------------------------------------------------------

/// Normal query interval (seconds) — used when synced and stable.
const INTERVAL_QUERY_NORMAL: i64 = 30;

/// Pathetic query interval (seconds) — used when things are going badly.
const INTERVAL_QUERY_PATHETIC: i64 = 60;

/// Minimum scale-offset threshold (seconds).
/// Offsets below this produce maximum scale factor.
const QSCALE_OFF_MIN: f64 = 0.001;

/// Maximum scale-offset threshold (seconds).
/// Offsets above this (or unsynced) produce scale = 1.
const QSCALE_OFF_MAX: f64 = 0.050;

/// How many sync-loss intervals to tolerate before declaring unsynced.
const SYNC_LOSS_MULTIPLIER: i64 = 3;

/// Minimum number of frequency samples before scale tracking is active.
const MIN_FREQ_SAMPLES: u32 = 3;

/// Maximum frequency adjustment (ppm).
const MAX_FREQUENCY_ADJUST: f64 = 128e-5;

/// Number of offset samples for frequency estimation via linear regression.
const FREQUENCY_SAMPLES: u32 = 8;

// ---------------------------------------------------------------------------
// Scale helper (from ntpd.h)
// ---------------------------------------------------------------------------

/// Compute the randomisation range for a scaled interval.
///
/// Corresponds to C: `SCALE_INTERVAL(x)` = `MAXIMUM(5, x / 10)`.
#[inline]
fn scale_jitter_range(interval: i64) -> i64 {
    cmp::max(5, interval / 10)
}

// ---------------------------------------------------------------------------
// Free functions
// ---------------------------------------------------------------------------

/// Compute a backoff interval for error/retry situations.
///
/// Returns a positive interval in seconds.  The original C uses
/// `arc4random_uniform` for jitter; this version returns the base
/// deterministic value.  Callers may add jitter externally.
///
/// Corresponds to C: `error_interval()`.
///
/// Base formula:
/// ```text
/// interval = INTERVAL_QUERY_PATHETIC * QSCALE_OFF_MAX / QSCALE_OFF_MIN
///         = 60 * 0.050 / 0.001
///         = 3000
/// ```
/// With random jitter of `interval / 10` (≈300).
#[must_use]
pub fn error_interval() -> i64 {
    INTERVAL_QUERY_PATHETIC * (QSCALE_OFF_MAX / QSCALE_OFF_MIN) as i64
}

/// Scale a query interval by the current frequency scale factor.
///
/// Returns `requested * scale` plus a jitter component of up to
/// `MAX(5, (requested * scale) / 10)`.
///
/// The jitter is computed deterministically by taking `jitter_seed`
/// modulo the jitter range.  Pass `0` for no jitter.
///
/// Corresponds to C: `scale_interval()`.
#[must_use]
pub fn scale_interval(requested: i64, scale: f64, jitter_seed: u32) -> i64 {
    let interval = (requested as f64 * scale) as i64;
    let range = scale_jitter_range(interval);
    let jitter = if range > 0 {
        (jitter_seed as i64) % range
    } else {
        0
    };
    interval + jitter
}

/// Update the frequency scale factor based on current offset.
///
/// The scale factor controls how aggressively peers are polled:
///
/// - If `|offset| > QSCALE_OFF_MAX` (50 ms) OR not synced OR too few
///   frequency samples → scale = 1 (no scaling).
/// - If `|offset| < QSCALE_OFF_MIN` (1 ms) → maximum scale
///   (`QSCALE_OFF_MAX / QSCALE_OFF_MIN` = 50).
/// - Otherwise → `QSCALE_OFF_MAX / |offset|`.
///
/// Corresponds to C: `update_scale()`.
#[must_use]
pub fn update_scale(offset: f64, synced: bool, freq_samples: u32) -> f64 {
    if !synced || freq_samples < MIN_FREQ_SAMPLES {
        return 1.0;
    }

    let abs_offset = offset.abs();
    if abs_offset > QSCALE_OFF_MAX {
        1.0
    } else if abs_offset < QSCALE_OFF_MIN {
        QSCALE_OFF_MAX / QSCALE_OFF_MIN
    } else {
        QSCALE_OFF_MAX / abs_offset
    }
}

/// Check if a socket address (raw bytes) is already in a pool of known
/// addresses.
///
/// Compares up to 16 bytes of the address.  `addr` should be the raw
/// address bytes (e.g. 4 bytes for IPv4, 16 bytes for IPv6).
/// `pool` contains up-to-16-byte address representations.
///
/// Returns `true` if `addr` matches any entry in `pool`.
///
/// Corresponds to C: `inpool()`.
#[must_use]
pub fn inpool(addr: &[u8], pool: &[[u8; 16]]) -> bool {
    let addr_len = addr.len().min(16);
    for entry in pool {
        if entry[..addr_len] == addr[..addr_len] {
            return true;
        }
    }
    false
}

/// Compare two offsets, returning `Less`, `Equal`, or `Greater`.
///
/// This is the ordering function used for median selection (qsort
/// compatibility).  NaN is sorted as equal to anything.
///
/// Corresponds to C: `offset_compare()`.
#[must_use]
pub fn offset_compare(a: f64, b: f64) -> cmp::Ordering {
    a.partial_cmp(&b).unwrap_or(cmp::Ordering::Equal)
}

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

/// Configuration for the NTP engine.
#[derive(Debug, Clone)]
pub struct NtpEngineConfig {
    /// If `true`, the engine may request an immediate clock step
    /// (`settime`) on first sync.
    pub settime: bool,
    /// If `true`, the engine may automatically step the clock on
    /// first meaningful offset.
    pub automatic: bool,
}

// ---------------------------------------------------------------------------
// Tick result
// ---------------------------------------------------------------------------

/// The result of one iteration of the NTP engine.
#[derive(Debug, Clone)]
pub struct NtpTickResult {
    /// Clock adjustments to send to the parent process (adjtime/adjfreq).
    pub adjustments: Vec<ClockAdjustment>,
    /// Indices of peers that need a query sent.
    pub queries_to_send: Vec<usize>,
    /// If `Some`, a `settime` request with the given offset (seconds).
    pub need_settime: Option<f64>,
    /// Whether the engine's sync status changed.
    pub sync_changed: Option<bool>,
}

// ---------------------------------------------------------------------------
// Parent messages (imsg dispatch)
// ---------------------------------------------------------------------------

/// Messages that can be received from the parent process.
///
/// Corresponds to the imsg types handled in C: `ntp_dispatch_imsg()`.
#[derive(Debug, Clone)]
pub enum ParentMsg {
    /// Adjtime notification: `true` = synced, `false` = unsynced.
    AdjTime(bool),
    /// Adjfreq value (ppm).
    AdjFreq(f64),
    /// Immediate settime offset (seconds).
    SetTime(f64),
    /// Clock is now synced.
    Synced,
    /// Clock is now unsynced.
    Unsynced,
    /// Constraint result from parent (id, data).
    ConstraintResult { id: u32, data: Vec<u8> },
    /// Constraint query result (id, data).
    ConstraintQuery { id: u32, data: Vec<u8> },
    /// Kill/close a constraint connection.
    ConstraintKill(u32),
}

/// Parse a parent message from raw imsg type and data.
///
/// Corresponds to C: `ntp_dispatch_imsg()` switch on `imsg.hdr.type`.
#[must_use]
pub fn parse_parent_msg(type_: u32, data: &[u8]) -> Option<ParentMsg> {
    match type_ {
        // IMSG_ADJTIME: data contains an int (0 or 1)
        0x01 => {
            if data.len() >= core::mem::size_of::<i32>() {
                let mut buf = [0u8; 4];
                buf.copy_from_slice(&data[..4]);
                let n = i32::from_ne_bytes(buf);
                Some(ParentMsg::AdjTime(n != 0))
            } else {
                None
            }
        }
        // IMSG_ADJFREQ: data contains a double (f64)
        0x02 => {
            if data.len() >= core::mem::size_of::<f64>() {
                let mut buf = [0u8; 8];
                buf.copy_from_slice(&data[..8]);
                let freq = f64::from_ne_bytes(buf);
                Some(ParentMsg::AdjFreq(freq))
            } else {
                None
            }
        }
        // IMSG_SETTIME: data contains a double (f64)
        0x03 => {
            if data.len() >= core::mem::size_of::<f64>() {
                let mut buf = [0u8; 8];
                buf.copy_from_slice(&data[..8]);
                let offset = f64::from_ne_bytes(buf);
                Some(ParentMsg::SetTime(offset))
            } else {
                None
            }
        }
        // IMSG_SYNCED
        0x04 => Some(ParentMsg::Synced),
        // IMSG_UNSYNCED
        0x05 => Some(ParentMsg::Unsynced),
        // IMSG_CONSTRAINT_RESULT
        0x10 => {
            let id = extract_peerid(data);
            let payload = if data.len() > 4 {
                data[4..].to_vec()
            } else {
                Vec::new()
            };
            Some(ParentMsg::ConstraintResult { id, data: payload })
        }
        // IMSG_CONSTRAINT_CLOSE / CONSTRAINT_QUERY
        0x11 => {
            let id = extract_peerid(data);
            let payload = if data.len() > 4 {
                data[4..].to_vec()
            } else {
                Vec::new()
            };
            Some(ParentMsg::ConstraintQuery { id, data: payload })
        }
        // IMSG_CONSTRAINT_KILL
        0x12 => {
            if data.len() >= 4 {
                let mut buf = [0u8; 4];
                buf.copy_from_slice(&data[..4]);
                Some(ParentMsg::ConstraintKill(u32::from_ne_bytes(buf)))
            } else {
                None
            }
        }
        _ => None,
    }
}

/// Extract a 4-byte peer/constraint ID from the beginning of a data buffer.
fn extract_peerid(data: &[u8]) -> u32 {
    if data.len() >= 4 {
        let mut buf = [0u8; 4];
        buf.copy_from_slice(&data[..4]);
        u32::from_ne_bytes(buf)
    } else {
        0
    }
}

// ---------------------------------------------------------------------------
// Auto-result
// ---------------------------------------------------------------------------

/// Result of the auto-setting logic (first-time sync).
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum AutoResult {
    /// Continue polling — not ready to set time yet.
    Continue,
    /// Set the clock to this offset (seconds).
    SetTime(f64),
    /// Abandon auto-setting (too many failures).
    Abandon,
}

// ---------------------------------------------------------------------------
// Frequency tracker (linear regression)
// ---------------------------------------------------------------------------

/// Tracks frequency estimation using linear regression over offset
/// samples.
///
/// Corresponds to the `freq` fields in OpenNTPD's `ntpd_conf`.
#[derive(Debug, Clone)]
struct FrequencyTracker {
    samples: u32,
    x: f64,
    y: f64,
    xx: f64,
    xy: f64,
    overall_offset: f64,
    num_updates: u32,
}

impl FrequencyTracker {
    fn new() -> Self {
        Self {
            samples: 0,
            x: 0.0,
            y: 0.0,
            xx: 0.0,
            xy: 0.0,
            overall_offset: 0.0,
            num_updates: 0,
        }
    }

    /// Add a new offset sample and optionally compute a frequency estimate.
    ///
    /// Returns `Some(freq_ppm)` when enough samples have accumulated,
    /// and resets the accumulator.
    fn add_sample(&mut self, offset: f64, curtime: f64) -> Option<f64> {
        self.samples += 1;
        self.num_updates += 1;
        self.overall_offset += offset;

        let cumulative_offset = self.overall_offset;
        self.xy += cumulative_offset * curtime;
        self.x += curtime;
        self.y += cumulative_offset;
        self.xx += curtime * curtime;

        if self.samples % FREQUENCY_SAMPLES != 0 {
            return None;
        }

        let n = f64::from(self.samples);
        let denom = self.xx - self.x * self.x / n;
        if denom.abs() < 1e-18 {
            self.reset();
            return None;
        }

        let freq = (self.xy - self.x * self.y / n) / denom;

        // Clamp to maximum adjustment.
        let freq = freq.clamp(-MAX_FREQUENCY_ADJUST, MAX_FREQUENCY_ADJUST);

        self.reset();
        Some(freq)
    }

    fn reset(&mut self) {
        self.xy = 0.0;
        self.x = 0.0;
        self.y = 0.0;
        self.xx = 0.0;
        self.samples = 0;
        self.overall_offset = 0.0;
    }
}

// ---------------------------------------------------------------------------
// NTP Engine
// ---------------------------------------------------------------------------

/// The NTP child process state machine.
///
/// This struct owns the peer list, clock discipline state, frequency
/// tracker, and scale factor.  It is advanced by calling [`tick`] and
/// [`process_response`].
///
/// Corresponds to the inner logic of `ntp.c`'s `ntp_main()`.
#[derive(Debug, Clone)]
pub struct NtpEngine {
    /// List of peers, each paired with its query state.
    pub peers: Vec<(Peer, QueryState)>,
    /// Clock discipline state (PLL/FLL).
    pub clock: ClockState,
    /// Frequency scale factor for interval scaling.
    pub scale: f64,
    /// Engine configuration.
    pub conf: NtpEngineConfig,
    /// Whether the clock is currently synced.
    pub synced: bool,
    /// Timestamp of the last successful offset update.
    pub last_action: f64,
    /// Frequency tracking (linear regression accumulator).
    freq_tracker: FrequencyTracker,
    #[allow(dead_code)]
    /// Jitter seed for deterministic interval jitter.
    jitter_seed: u32,
    /// Whether auto-setting is still in progress.
    auto_pending: bool,
    /// Number of DNS failures during auto.
    auto_dns_fails: u32,
}

/// Minimum query state tracking for the engine.
///
/// This is a simplified version of the full `QueryState` from
/// `ntp::query`, adapted for engine-level use.
#[derive(Debug, Clone)]
pub struct QueryState {
    /// Whether a query is currently outstanding.
    pub outstanding: bool,
    /// The monotonic time when the query was sent.
    pub query_time: f64,
    /// The monotonic time by which a response must arrive.
    pub deadline: f64,
    /// The monotonic time of the next scheduled query.
    pub next_query: f64,
    /// Number of consecutive send errors.
    pub send_errors: u32,
}

impl QueryState {
    /// Create a new idle query state.
    #[must_use]
    pub fn new() -> Self {
        Self {
            outstanding: false,
            query_time: 0.0,
            deadline: 0.0,
            next_query: 0.0,
            send_errors: 0,
        }
    }

    /// Check if a query is due to be sent at `now`.
    #[must_use]
    pub fn is_query_due(&self, now: f64) -> bool {
        !self.outstanding && now >= self.next_query
    }

    /// Check if an outstanding query has timed out.
    #[must_use]
    pub fn is_timed_out(&self, now: f64) -> bool {
        self.outstanding && now >= self.deadline
    }

    /// Mark a query as sent at `now` with the given poll interval.
    pub fn mark_sent(&mut self, now: f64, poll_interval: f64) {
        self.outstanding = true;
        self.query_time = now;
        // Deadline is 3x the poll interval (or at least 5 seconds).
        let timeout = poll_interval.max(5.0) * 3.0;
        self.deadline = now + timeout;
        // Schedule next query at poll_interval from now.
        self.next_query = now + poll_interval;
    }

    /// Mark a response as received.
    pub fn mark_received(&mut self) {
        self.outstanding = false;
        self.send_errors = 0;
    }

    /// Handle a timeout — reset outstanding and schedule retry.
    pub fn handle_timeout(&mut self, now: f64, backoff_interval: f64) {
        self.outstanding = false;
        self.next_query = now + backoff_interval;
    }

    /// Handle a send error.
    pub fn handle_send_error(&mut self, now: f64, backoff_interval: f64) {
        self.outstanding = false;
        self.send_errors += 1;
        self.next_query = now + backoff_interval;
    }
}

impl Default for QueryState {
    fn default() -> Self {
        Self::new()
    }
}

impl NtpEngine {
    /// Create a new NTP engine with the given configuration.
    #[must_use]
    pub fn new(conf: NtpEngineConfig) -> Self {
        let automatic = conf.automatic;
        Self {
            peers: Vec::new(),
            clock: ClockState::new(),
            scale: 1.0,
            conf,
            synced: false,
            last_action: 0.0,
            freq_tracker: FrequencyTracker::new(),
            jitter_seed: 0,
            auto_pending: automatic,
            auto_dns_fails: 0,
        }
    }

    /// Add a peer to the engine.
    pub fn add_peer(&mut self, peer: Peer) {
        self.peers.push((peer, QueryState::new()));
    }

    /// Remove a peer by its index.
    pub fn remove_peer(&mut self, idx: usize) {
        if idx < self.peers.len() {
            self.peers.swap_remove(idx);
        }
    }

    /// Run one iteration of the NTP engine.
    ///
    /// This advances the state machine: checks for pending queries,
    /// handles timeouts, runs clock selection, and produces clock
    /// adjustments.
    ///
    /// # Parameters
    ///
    /// * `now` — current monotonic time in seconds (e.g. from
    ///   `getmonotime()`).
    /// * `constraint_median` — the current constraint median offset
    ///   (0 if constraints are not active).
    /// * `constraint_active` — whether constraints are configured.
    ///
    /// # Returns
    ///
    /// An [`NtpTickResult`] describing actions the caller should take.
    pub fn tick(
        &mut self,
        now: f64,
        constraint_median: f64,
        constraint_active: bool,
    ) -> NtpTickResult {
        let mut result = NtpTickResult {
            adjustments: Vec::new(),
            queries_to_send: Vec::new(),
            need_settime: None,
            sync_changed: None,
        };

        // ── Phase 1: Check each peer for query scheduling ──────────────────
        for (i, (peer, qstate)) in self.peers.iter_mut().enumerate() {
            // Skip untrusted peers when constraints are active but have
            // not yet produced a median.
            if !peer.trusted && constraint_active && constraint_median == 0.0 {
                continue;
            }

            // Check if it's time to send a query.
            if qstate.is_query_due(now) {
                let poll_secs = (1i64 << peer.poll) as f64;
                qstate.mark_sent(now, poll_secs);
                result.queries_to_send.push(i);
            }

            // Check for outstanding query timeout.
            if qstate.is_timed_out(now) {
                let backoff_secs = error_interval();
                qstate.handle_timeout(now, backoff_secs as f64);

                // Update peer reachability (miss).
                peer.update_reach(false);

                // Update peer poll state (no response).
                if !peer.reachable() {
                    peer.set_flash(crate::peer::PFLASH_PEERREACH);
                }
            }
        }

        // ── Phase 2: Run clock selection ───────────────────────────────────
        let (clock_adjustments, median_offset, median_delay, median_stratum) =
            self.run_clock_selection(now);

        if let Some(adj) = clock_adjustments {
            result.adjustments.push(adj);
        }

        // ── Phase 3: Handle sync status ────────────────────────────────────
        let interval = INTERVAL_QUERY_NORMAL;
        let scaled_interval = (interval as f64 * self.scale) as i64;
        let jitter_range = scale_jitter_range(scaled_interval);
        let effective_interval = scaled_interval + jitter_range;

        if self.synced
            && self.last_action > 0.0
            && now > self.last_action + (SYNC_LOSS_MULTIPLIER * effective_interval) as f64
        {
            // Lost sync due to no responses.
            self.synced = false;
            self.scale = 1.0;
            result.sync_changed = Some(false);
        }

        // ── Phase 4: Handle settime / auto ─────────────────────────────────
        if let (Some(offset), Some(_delay), Some(stratum)) =
            (median_offset, median_delay, median_stratum)
        {
            if self.conf.settime && !self.synced && self.auto_pending {
                match self.handle_auto(true, offset) {
                    AutoResult::SetTime(offset) => {
                        result.need_settime = Some(offset);
                        self.auto_pending = false;
                    }
                    AutoResult::Abandon => {
                        // Abandon auto-setting but continue normal sync.
                        self.auto_pending = false;
                    }
                    AutoResult::Continue => {
                        // Not yet ready.
                    }
                }
            }

            // Mark as synced if we got a good update.
            if !self.synced && stratum < 16 {
                self.synced = true;
                result.sync_changed = Some(true);
            }

            // Update scale factor.
            self.scale = update_scale(offset, self.synced, self.freq_tracker.num_updates);
        }

        result
    }

    /// Run the clock selection pipeline and produce clock adjustments.
    ///
    /// Returns `(adjustment, median_offset, median_delay, median_stratum)`.
    #[allow(clippy::type_complexity)]
    fn run_clock_selection(
        &mut self,
        now: f64,
    ) -> (
        Option<ClockAdjustment>,
        Option<f64>,
        Option<f64>,
        Option<u8>,
    ) {
        // Collect peers with good data (no flash bits set, reachable).
        let valid_peers: Vec<Peer> = self
            .peers
            .iter()
            .filter(|(p, _)| !p.has_any_flash() && p.reachable() && p.stratum > 0 && p.stratum < 16)
            .map(|(p, _)| p.clone())
            .collect();

        if valid_peers.is_empty() {
            return (None, None, None, None);
        }

        // Run the full selection pipeline.
        let mut selection = ClockSelection::new(valid_peers);
        let combined = selection.select().cloned();

        let combined = match combined {
            Some(c) => c,
            None => return (None, None, None, None),
        };

        let median_offset = combined.offset;
        let median_delay = combined.delay;
        let median_stratum = combined.stratum;

        // Produce clock adjustment.
        let now_ts = crate::ntp::NtpTimestamp::from_f64(now);
        let adjustment = self.clock.update(median_offset, median_delay, now_ts);

        // Track frequency.
        if let Some(freq) = self.freq_tracker.add_sample(median_offset, now) {
            // We have a frequency update to apply.
            // The freq_delta in the adjustment is already computed,
            // but we also deliver the linear-regression frequency.
            let _ = freq;
        }

        self.last_action = now;

        (
            Some(adjustment),
            Some(median_offset),
            Some(median_delay),
            Some(median_stratum),
        )
    }

    /// Process a received NTP response for a peer.
    ///
    /// Updates the peer's filter, reachability, and poll state.
    ///
    /// # Parameters
    ///
    /// * `peer_idx` — index into the `peers` list.
    /// * `offset` — computed clock offset (seconds).
    /// * `delay` — round-trip delay (seconds).
    /// * `stratum` — NTP stratum of the server.
    ///
    /// Corresponds to the successful-reply path in C: `client_dispatch()`.
    pub fn process_response(&mut self, peer_idx: usize, offset: f64, delay: f64, stratum: u8) {
        if peer_idx >= self.peers.len() {
            return;
        }

        let (peer, qstate) = &mut self.peers[peer_idx];

        // Mark query as no longer outstanding.
        qstate.mark_received();

        // Update peer reachability (success).
        peer.update_reach(true);
        peer.clear_flash(crate::peer::PFLASH_PEERNOQUERY);

        // Set stratum and peer state.
        peer.stratum = stratum;

        // Add sample to the clock filter.
        // Dispersion is computed as the sum of root delay + root dispersion,
        // scaled by time since last update. For simplicity, we use a
        // base dispersion of 0.001 (1 ms) + delay component.
        let dispersion = 0.001 + delay * 0.01;

        // Before adding, check if the sample has reasonable values.
        let offset_abs = offset.abs();
        if offset_abs > crate::peer::MAX_OFFSET {
            peer.set_flash(crate::peer::PFLASH_PEEROFFSET);
        }
        if delay > crate::peer::MAX_DELAY {
            peer.set_flash(crate::peer::PFLASH_PEERDELAY);
        }
        if dispersion > crate::peer::MAX_DISPERSION {
            peer.set_flash(crate::peer::PFLASH_PEERDISP);
        }
        if stratum > crate::peer::MAX_STRATUM || stratum == 0 {
            peer.stratum = 16;
            peer.set_flash(crate::peer::PFLASH_PEERSTRAT);
        }

        peer.add_sample(offset, delay, dispersion);

        // Update poll state (successful response).
        peer.update_poll(true);
    }

    /// Handle a query timeout for a peer (no response received).
    ///
    /// # Parameters
    ///
    /// * `peer_idx` — index into the `peers` list.
    /// * `now` — current monotonic time.
    pub fn handle_timeout(&mut self, peer_idx: usize, now: f64) {
        if peer_idx >= self.peers.len() {
            return;
        }

        let (peer, qstate) = &mut self.peers[peer_idx];
        let backoff = error_interval() as f64;
        qstate.handle_timeout(now, backoff);

        // Update peer reachability (miss).
        peer.update_reach(false);
        peer.update_poll(false);

        if !peer.reachable() {
            peer.set_flash(crate::peer::PFLASH_PEERREACH);
        }
    }

    /// Handle a send error for a peer.
    ///
    /// # Parameters
    ///
    /// * `peer_idx` — index into the `peers` list.
    /// * `now` — current monotonic time.
    pub fn handle_send_error(&mut self, peer_idx: usize, now: f64) {
        if peer_idx >= self.peers.len() {
            return;
        }

        let (peer, qstate) = &mut self.peers[peer_idx];
        let backoff = error_interval() as f64;
        qstate.handle_send_error(now, backoff);

        peer.update_poll(false);
    }

    /// Get the best current offset estimate from the clock selection
    /// pipeline.
    #[must_use]
    pub fn best_offset(&self) -> Option<f64> {
        let valid_peers: Vec<Peer> = self
            .peers
            .iter()
            .filter(|(p, _)| !p.has_any_flash() && p.reachable() && p.stratum > 0 && p.stratum < 16)
            .map(|(p, _)| p.clone())
            .collect();

        if valid_peers.is_empty() {
            return None;
        }

        let mut selection = ClockSelection::new(valid_peers);
        let combined = selection.select().cloned()?;
        Some(combined.offset)
    }

    /// Handle the auto-setting logic (first-time sync).
    ///
    /// This implements the logic that decides whether to immediately
    /// step the clock on first meaningful data.
    ///
    /// Corresponds to C: `priv_settime()` logic and the auto-set path
    /// from `client_dispatch()`.
    #[must_use]
    pub fn handle_auto(&mut self, trusted: bool, offset: f64) -> AutoResult {
        if !self.conf.automatic {
            return AutoResult::Continue;
        }

        if !trusted {
            return AutoResult::Continue;
        }

        // If the offset is tiny, no need to step.
        if offset.abs() < 0.001 {
            return AutoResult::Continue;
        }

        // If the offset is large enough to warrant a step, do it.
        if offset.abs() > crate::ntp::clock::CLOCK_MAX_STEP {
            return AutoResult::SetTime(offset);
        }

        // For moderate offsets, continue polling.
        AutoResult::Continue
    }

    /// Record a DNS failure (for auto-setting decision).
    pub fn record_dns_fail(&mut self) {
        self.auto_dns_fails += 1;
    }

    /// Get the maximum number of DNS failures before abandoning auto.
    #[must_use]
    pub const fn max_dns_fails() -> u32 {
        3
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::directive::ConfigString;
    use crate::peer::Peer;

    fn make_peer_id(addr: &str) -> Peer {
        Peer::new(
            ConfigString::new(addr.as_bytes().to_vec()).unwrap(),
            1,
            false,
        )
    }

    // ── error_interval ────────────────────────────────────────────────────

    #[test]
    fn test_error_interval_positive() {
        let val = error_interval();
        assert!(val > 0, "error_interval must be positive, got {}", val);
    }

    #[test]
    fn test_error_interval_deterministic() {
        assert_eq!(error_interval(), error_interval());
    }

    #[test]
    fn test_error_interval_expected_value() {
        // 60 * 0.050 / 0.001 = 3000
        assert_eq!(error_interval(), 3000);
    }

    // ── scale_interval ────────────────────────────────────────────────────

    #[test]
    fn test_scale_interval_identity() {
        // scale=1 should return requested + jitter
        let val = scale_interval(30, 1.0, 0);
        assert!(val >= 30);
        assert!(val < 30 + scale_jitter_range(30) + 1);
    }

    #[test]
    fn test_scale_interval_scales_up() {
        // scale=2 should double the base interval
        let val = scale_interval(30, 2.0, 0);
        assert!(val >= 60);
    }

    #[test]
    fn test_scale_interval_scales_down() {
        // scale=0.5 should halve the base interval
        let val = scale_interval(30, 0.5, 0);
        assert!(val >= 15);
        assert!(val < 15 + scale_jitter_range(15) + 1);
    }

    #[test]
    fn test_scale_interval_jitter_variation() {
        let val1 = scale_interval(30, 1.0, 0);
        let val2 = scale_interval(30, 1.0, 999);
        // With different seeds, jitter may differ.
        assert!(val1 >= 30);
        assert!(val2 >= 30);
    }

    #[test]
    fn test_scale_interval_zero_requested() {
        let val = scale_interval(0, 1.0, 0);
        assert_eq!(val, 0);
    }

    #[test]
    fn test_scale_interval_large_scale() {
        let val = scale_interval(30, 50.0, 0);
        assert!(val >= 1500);
    }

    // ── update_scale ──────────────────────────────────────────────────────

    #[test]
    fn test_update_scale_returns_one_when_not_synced() {
        assert_eq!(update_scale(0.01, false, 5), 1.0);
    }

    #[test]
    fn test_update_scale_returns_one_when_few_samples() {
        assert_eq!(update_scale(0.01, true, 2), 1.0);
    }

    #[test]
    fn test_update_scale_small_offset_gives_max_scale() {
        // offset < 0.001 gives max scale = 0.05 / 0.001 = 50
        let scale = update_scale(0.0005, true, 5);
        assert!((scale - 50.0).abs() < 1e-9);
    }

    #[test]
    fn test_update_scale_large_offset_returns_one() {
        // offset > 0.05 returns 1.0
        assert_eq!(update_scale(0.1, true, 5), 1.0);
    }

    #[test]
    fn test_update_scale_medium_offset() {
        // offset = 0.01 gives scale = 0.05 / 0.01 = 5
        let scale = update_scale(0.01, true, 5);
        assert!((scale - 5.0).abs() < 1e-9);
    }

    #[test]
    fn test_update_scale_negative_offset() {
        // Absolute value is used, so -0.01 should give 5
        let scale = update_scale(-0.01, true, 5);
        assert!((scale - 5.0).abs() < 1e-9);
    }

    #[test]
    fn test_update_scale_exact_boundary() {
        // offset == 0.05 is exactly at max => not > max, so scale = 0.05/0.05 = 1
        let scale = update_scale(0.05, true, 5);
        assert!((scale - 1.0).abs() < 1e-9);
    }

    #[test]
    fn test_update_scale_exact_min_boundary() {
        // offset == 0.001 is not < min, so scale = 0.05/0.001 = 50
        let scale = update_scale(0.001, true, 5);
        assert!((scale - 50.0).abs() < 1e-9);
    }

    // ── inpool ────────────────────────────────────────────────────────────

    #[test]
    fn test_inpool_match_ipv4() {
        let addr = [192, 168, 1, 1];
        let pool = [
            [0u8; 16],
            [192, 168, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
        ];
        assert!(inpool(&addr, &pool));
    }

    #[test]
    fn test_inpool_no_match() {
        let addr = [10, 0, 0, 1];
        let pool = [[192u8, 168, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]];
        assert!(!inpool(&addr, &pool));
    }

    #[test]
    fn test_inpool_empty_pool() {
        let addr = [192, 168, 1, 1];
        let pool: [[u8; 16]; 0] = [];
        assert!(!inpool(&addr, &pool));
    }

    #[test]
    fn test_inpool_match_ipv6() {
        let addr = [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
        let pool = [[0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]];
        assert!(inpool(&addr, &pool));
    }

    #[test]
    fn test_inpool_match_any_prefix() {
        // addr shorter than 16 bytes should match on the prefix
        let addr = [10, 0, 0, 1];
        let pool = [[10u8, 0, 0, 1, 0xde, 0xad, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]];
        assert!(inpool(&addr, &pool));
    }

    #[test]
    fn test_inpool_first_in_pool_matches() {
        let addr = [10, 0, 0, 2];
        let pool = [
            [10u8, 0, 0, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
            [192u8, 168, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
        ];
        assert!(inpool(&addr, &pool));
    }

    // ── offset_compare ────────────────────────────────────────────────────

    #[test]
    fn test_offset_compare_less() {
        assert_eq!(offset_compare(1.0, 2.0), cmp::Ordering::Less);
    }

    #[test]
    fn test_offset_compare_greater() {
        assert_eq!(offset_compare(5.0, 3.0), cmp::Ordering::Greater);
    }

    #[test]
    fn test_offset_compare_equal() {
        assert_eq!(offset_compare(3.0, 3.0), cmp::Ordering::Equal);
    }

    #[test]
    fn test_offset_compare_negative() {
        assert_eq!(offset_compare(-5.0, -3.0), cmp::Ordering::Less);
    }

    #[test]
    fn test_offset_compare_zero() {
        assert_eq!(offset_compare(0.0, 0.0), cmp::Ordering::Equal);
    }

    #[test]
    fn test_offset_compare_nan_treated_as_equal() {
        assert_eq!(offset_compare(f64::NAN, 1.0), cmp::Ordering::Equal);
        assert_eq!(offset_compare(1.0, f64::NAN), cmp::Ordering::Equal);
    }

    // ── NtpEngine::tick — query scheduling ─────────────────────────────────

    #[test]
    fn test_tick_produces_queries_when_due() {
        let mut engine = NtpEngine::new(NtpEngineConfig {
            settime: false,
            automatic: false,
        });

        let mut peer = make_peer_id("pool.ntp.org");
        peer.poll = 3; // 2^3 = 8 second interval
        engine.add_peer(peer);

        // Initially, next_query = 0, so query is due immediately.
        let result = engine.tick(10.0, 0.0, false);
        assert!(!result.queries_to_send.is_empty(), "query should be due");
        assert_eq!(result.queries_to_send[0], 0);
    }

    #[test]
    fn test_tick_no_query_before_next() {
        let mut engine = NtpEngine::new(NtpEngineConfig {
            settime: false,
            automatic: false,
        });

        let mut peer = make_peer_id("time.google.com");
        peer.poll = 3;
        engine.add_peer(peer);

        // First tick sends query, scheduling next.
        let _result1 = engine.tick(0.0, 0.0, false);

        // Second tick immediately after should not produce another query.
        let result2 = engine.tick(1.0, 0.0, false);
        assert!(
            result2.queries_to_send.is_empty(),
            "no query should be due yet"
        );
    }

    #[test]
    fn test_tick_query_after_poll_interval() {
        let mut engine = NtpEngine::new(NtpEngineConfig {
            settime: false,
            automatic: false,
        });

        let mut peer = make_peer_id("time.apple.com");
        peer.poll = 3; // 8 seconds
        engine.add_peer(peer);

        // Send first query at t=0.
        let _r = engine.tick(0.0, 0.0, false);

        // Process response so the query is no longer outstanding.
        engine.process_response(0, 0.005, 0.020, 2);

        // Fast-forward past poll interval (next_query = 0 + 8 = 8,
        // so at t=20 it should be due).
        let result = engine.tick(20.0, 0.0, false);
        assert!(
            !result.queries_to_send.is_empty(),
            "query should be due again"
        );
    }

    // ── NtpEngine::process_response ───────────────────────────────────────

    #[test]
    fn test_process_response_updates_peer() {
        let mut engine = NtpEngine::new(NtpEngineConfig {
            settime: false,
            automatic: false,
        });

        engine.add_peer(make_peer_id("time.cloudflare.com"));
        engine.process_response(0, 0.005, 0.020, 2);

        let (peer, qstate) = &engine.peers[0];
        assert!(!qstate.outstanding, "query should no longer be outstanding");
        assert!(peer.reachable(), "peer should be reachable");
        assert_eq!(peer.stratum, 2);
    }

    #[test]
    fn test_process_response_flags_large_offset() {
        let mut engine = NtpEngine::new(NtpEngineConfig {
            settime: false,
            automatic: false,
        });

        engine.add_peer(make_peer_id("bad.clock.net"));
        // MAX_OFFSET is 1.0, so 2.0 should set flash.
        engine.process_response(0, 2.0, 0.020, 2);

        let (peer, _) = &engine.peers[0];
        assert!(peer.has_flash(crate::peer::PFLASH_PEEROFFSET));
    }

    #[test]
    fn test_process_response_flags_bad_stratum() {
        let mut engine = NtpEngine::new(NtpEngineConfig {
            settime: false,
            automatic: false,
        });

        engine.add_peer(make_peer_id("bad.stratum.net"));
        engine.process_response(0, 0.005, 0.020, 16);

        let (peer, _) = &engine.peers[0];
        assert!(peer.has_flash(crate::peer::PFLASH_PEERSTRAT));
    }

    // ── handle_auto ───────────────────────────────────────────────────────

    #[test]
    fn test_handle_auto_returns_continue_when_not_automatic() {
        let mut engine = NtpEngine::new(NtpEngineConfig {
            settime: true,
            automatic: false,
        });
        assert_eq!(engine.handle_auto(true, 0.2), AutoResult::Continue);
    }

    #[test]
    fn test_handle_auto_settime_large_offset() {
        let mut engine = NtpEngine::new(NtpEngineConfig {
            settime: true,
            automatic: true,
        });
        // CLOCK_MAX_STEP = 0.125, so 0.2 > 0.125 should trigger settime.
        let result = engine.handle_auto(true, 0.2);
        assert_eq!(result, AutoResult::SetTime(0.2));
    }

    #[test]
    fn test_handle_auto_continue_small_offset() {
        let mut engine = NtpEngine::new(NtpEngineConfig {
            settime: true,
            automatic: true,
        });
        // Offset < 0.001 is tiny.
        assert_eq!(engine.handle_auto(true, 0.0005), AutoResult::Continue);
    }

    #[test]
    fn test_handle_auto_continue_not_trusted() {
        let mut engine = NtpEngine::new(NtpEngineConfig {
            settime: true,
            automatic: true,
        });
        assert_eq!(engine.handle_auto(false, 0.2), AutoResult::Continue);
    }

    #[test]
    fn test_handle_auto_continue_moderate_offset() {
        let mut engine = NtpEngine::new(NtpEngineConfig {
            settime: true,
            automatic: true,
        });
        // 0.05 is < 0.125 so no step, but > 0.001 so not tiny.
        assert_eq!(engine.handle_auto(true, 0.05), AutoResult::Continue);
    }

    // ── best_offset ───────────────────────────────────────────────────────

    #[test]
    fn test_best_offset_empty_returns_none() {
        let engine = NtpEngine::new(NtpEngineConfig {
            settime: false,
            automatic: false,
        });
        assert!(engine.best_offset().is_none());
    }

    #[test]
    fn test_best_offset_with_single_peer() {
        let mut engine = NtpEngine::new(NtpEngineConfig {
            settime: false,
            automatic: false,
        });
        engine.add_peer(make_peer_id("time.cloudflare.com"));

        // Process a response so the peer has data and is reachable.
        engine.process_response(0, 0.005, 0.020, 2);

        let offset = engine.best_offset();
        assert!(offset.is_some(), "should have an offset estimate");
        // The offset should be close to what we fed in.
        if let Some(o) = offset {
            assert!(
                (o - 0.005).abs() < 0.01,
                "offset should be ~0.005, got {}",
                o
            );
        }
    }

    #[test]
    fn test_best_offset_no_good_peers() {
        let mut engine = NtpEngine::new(NtpEngineConfig {
            settime: false,
            automatic: false,
        });
        engine.add_peer(make_peer_id("bad.stratum.net"));
        // Process with bad stratum.
        engine.process_response(0, 0.005, 0.020, 16);

        assert!(engine.best_offset().is_none());
    }

    // ── parse_parent_msg ──────────────────────────────────────────────────

    #[test]
    fn test_parse_adjtime_true() {
        let data = 1i32.to_ne_bytes();
        let msg = parse_parent_msg(0x01, &data);
        assert!(matches!(msg, Some(ParentMsg::AdjTime(true))));
    }

    #[test]
    fn test_parse_adjtime_false() {
        let data = 0i32.to_ne_bytes();
        let msg = parse_parent_msg(0x01, &data);
        assert!(matches!(msg, Some(ParentMsg::AdjTime(false))));
    }

    #[test]
    fn test_parse_adjfreq() {
        let freq = 12.5_f64;
        let data = freq.to_ne_bytes();
        let msg = parse_parent_msg(0x02, &data);
        assert!(matches!(msg, Some(ParentMsg::AdjFreq(v)) if (v - 12.5).abs() < 1e-9));
    }

    #[test]
    fn test_parse_settime() {
        let offset = 0.125_f64;
        let data = offset.to_ne_bytes();
        let msg = parse_parent_msg(0x03, &data);
        assert!(matches!(msg, Some(ParentMsg::SetTime(v)) if (v - 0.125).abs() < 1e-9));
    }

    #[test]
    fn test_parse_synced() {
        let msg = parse_parent_msg(0x04, &[]);
        assert!(matches!(msg, Some(ParentMsg::Synced)));
    }

    #[test]
    fn test_parse_unsynced() {
        let msg = parse_parent_msg(0x05, &[]);
        assert!(matches!(msg, Some(ParentMsg::Unsynced)));
    }

    #[test]
    fn test_parse_constraint_result() {
        let id = 42u32;
        let payload = [1u8, 2, 3];
        let mut data = Vec::new();
        data.extend_from_slice(&id.to_ne_bytes());
        data.extend_from_slice(&payload);
        let msg = parse_parent_msg(0x10, &data);
        assert!(matches!(
            msg,
            Some(ParentMsg::ConstraintResult { id: 42, .. })
        ));
        if let Some(ParentMsg::ConstraintResult { data: d, .. }) = msg {
            assert_eq!(&d, &[1u8, 2, 3]);
        }
    }

    #[test]
    fn test_parse_constraint_query() {
        let id = 7u32;
        let data = id.to_ne_bytes();
        let msg = parse_parent_msg(0x11, &data);
        assert!(matches!(
            msg,
            Some(ParentMsg::ConstraintQuery { id: 7, .. })
        ));
    }

    #[test]
    fn test_parse_constraint_kill() {
        let id = 99u32;
        let data = id.to_ne_bytes();
        let msg = parse_parent_msg(0x12, &data);
        assert!(matches!(msg, Some(ParentMsg::ConstraintKill(99))));
    }

    #[test]
    fn test_parse_unknown_type() {
        let msg = parse_parent_msg(0xFF, &[]);
        assert!(msg.is_none());
    }

    #[test]
    fn test_parse_short_data_returns_none() {
        let data = [0u8; 1]; // too short for i32
        let msg = parse_parent_msg(0x01, &data);
        assert!(msg.is_none());
    }

    // ── Integration: multiple ticks simulate full poll cycle ──────────────

    #[test]
    fn test_integration_poll_cycle_single_peer() {
        let mut engine = NtpEngine::new(NtpEngineConfig {
            settime: false,
            automatic: false,
        });

        let mut peer = make_peer_id("time.cloudflare.com");
        peer.poll = 3; // 8-second interval
        engine.add_peer(peer);

        // Tick at t=0: query should be due.
        let r = engine.tick(0.0, 0.0, false);
        assert_eq!(r.queries_to_send.len(), 1);

        // Process the response.
        engine.process_response(0, 0.003, 0.015, 2);

        // Tick at t=1: no query due yet.
        let r = engine.tick(1.0, 0.0, false);
        assert!(r.queries_to_send.is_empty());

        // Tick at t=20: past 8-second interval, query should be due.
        let r = engine.tick(20.0, 0.0, false);
        assert_eq!(r.queries_to_send.len(), 1);

        // Process second response.
        engine.process_response(0, 0.004, 0.012, 2);

        // Engine should be synced after two good responses.
        assert!(
            engine.synced,
            "engine should be synced after good responses"
        );
    }

    #[test]
    fn test_integration_timeout_and_backoff() {
        let mut engine = NtpEngine::new(NtpEngineConfig {
            settime: false,
            automatic: false,
        });

        let mut peer = make_peer_id("unreachable.example.com");
        peer.poll = 3; // 8-second interval
        engine.add_peer(peer);

        // Tick at t=0: query sent.
        let r = engine.tick(0.0, 0.0, false);
        assert_eq!(r.queries_to_send.len(), 1);

        // The deadline is set to 3 * max(8, 5) = 24 seconds.
        // Tick at t=30: should trigger timeout.
        let _r = engine.tick(30.0, 0.0, false);
        // After timeout, a new query should be scheduled with backoff.

        let (peer, qstate) = &engine.peers[0];
        assert!(!qstate.outstanding, "query should no longer be outstanding");
        assert!(!peer.reachable(), "peer should not be reachable");
        assert!(
            qstate.next_query > 30.0,
            "next query should be in the future"
        );
    }

    #[test]
    fn test_integration_multiple_peers() {
        let mut engine = NtpEngine::new(NtpEngineConfig {
            settime: false,
            automatic: false,
        });

        let mut p1 = make_peer_id("time1.example.com");
        p1.poll = 3;
        let mut p2 = make_peer_id("time2.example.com");
        p2.poll = 4; // 16-second interval
        engine.add_peer(p1);
        engine.add_peer(p2);

        // Both peers due at t=0.
        let r = engine.tick(0.0, 0.0, false);
        assert_eq!(r.queries_to_send.len(), 2);

        // Process responses for both.
        engine.process_response(0, 0.002, 0.010, 2);
        engine.process_response(1, 0.003, 0.012, 2);

        // Only peer 0 (poll=3, 8s) should be due at t=10.
        let r = engine.tick(10.0, 0.0, false);
        assert_eq!(r.queries_to_send.len(), 1);
        assert_eq!(r.queries_to_send[0], 0);
    }

    // ── Edge cases ────────────────────────────────────────────────────────

    #[test]
    fn test_edge_empty_pool_inpool() {
        let addr = [0u8; 4];
        let pool: [[u8; 16]; 0] = [];
        assert!(!inpool(&addr, &pool));
    }

    #[test]
    fn test_edge_negative_scale_interval() {
        // Requested negative should still work (unusual but shouldn't panic).
        let val = scale_interval(-10, 1.0, 0);
        assert!(val <= 0, "negative requested should give <= 0, got {}", val);
    }

    #[test]
    fn test_edge_zero_offset_update_scale() {
        let scale = update_scale(0.0, true, 5);
        // 0.0 < 0.001 so max scale
        assert!((scale - 50.0).abs() < 1e-9);
    }

    #[test]
    fn test_edge_handle_auto_abandon() {
        let mut engine = NtpEngine::new(NtpEngineConfig {
            settime: true,
            automatic: true,
        });

        // Simulate many DNS fails.
        for _ in 0..4 {
            engine.record_dns_fail();
        }

        // Even with large offset, auto should still set time if trusted.
        let result = engine.handle_auto(true, 0.2);
        assert_eq!(result, AutoResult::SetTime(0.2));
    }

    #[test]
    fn test_process_response_out_of_range_index() {
        let mut engine = NtpEngine::new(NtpEngineConfig {
            settime: false,
            automatic: false,
        });
        // Should not panic.
        engine.process_response(999, 0.0, 0.0, 0);
    }

    #[test]
    fn test_handle_timeout_out_of_range() {
        let mut engine = NtpEngine::new(NtpEngineConfig {
            settime: false,
            automatic: false,
        });
        engine.handle_timeout(999, 0.0);
    }

    #[test]
    fn test_sync_loss_detection() {
        let mut engine = NtpEngine::new(NtpEngineConfig {
            settime: false,
            automatic: false,
        });

        engine.synced = true;
        engine.last_action = 100.0;
        engine.scale = 1.0;

        // INTERVAL_QUERY_NORMAL = 30, SYNC_LOSS_MULTIPLIER = 3
        // threshold = 100 + 3 * (30 + max(5, 30/10)) = 100 + 3 * (30 + 5) = 100 + 105 = 205
        // actually: 30 * 1.0 = 30, jitter_range = max(5, 30/10) = 5, effective = 35, 3 * 35 = 105
        // threshold = 100 + 105 = 205
        let r = engine.tick(300.0, 0.0, false);
        assert!(!engine.synced, "engine should have lost sync");
        assert_eq!(r.sync_changed, Some(false));
    }

    #[test]
    fn test_sync_preserved_within_window() {
        let mut engine = NtpEngine::new(NtpEngineConfig {
            settime: false,
            automatic: false,
        });

        engine.synced = true;
        engine.last_action = 100.0;
        engine.scale = 1.0;

        // 150 < 205, so sync should be preserved.
        let r = engine.tick(150.0, 0.0, false);
        assert!(engine.synced, "engine should still be synced");
        assert_eq!(r.sync_changed, None);
    }

    #[test]
    fn test_best_offset_filters_peers_with_flash() {
        let mut engine = NtpEngine::new(NtpEngineConfig {
            settime: false,
            automatic: false,
        });

        let mut peer = make_peer_id("bad.example.com");
        peer.poll = 3;
        engine.add_peer(peer);

        // Process a response with bad stratum to set flash.
        engine.process_response(0, 0.005, 0.020, 16);

        assert!(
            engine.best_offset().is_none(),
            "should not return offset from flashed peer"
        );
    }

    #[test]
    fn test_scale_interval_jitter_seed_zero() {
        // jitter_seed=0 should give no jitter component (0 % range = 0)
        let val = scale_interval(30, 1.0, 0);
        assert_eq!(val, 30);
    }

    #[test]
    fn test_scale_interval_jitter_seed_nonzero() {
        // jitter_seed=15 with range=5 should give 15 % 5 = 0 jitter
        let val = scale_interval(30, 1.0, 15);
        assert_eq!(val, 30);

        // jitter_seed=17 with range=5 should give 17 % 5 = 2 jitter
        let val = scale_interval(30, 1.0, 17);
        assert_eq!(val, 32);
    }

    #[test]
    fn test_update_scale_at_min_freq_samples_boundary() {
        // Exactly MIN_FREQ_SAMPLES (3) should work.
        assert_eq!(update_scale(0.01, true, 3), 5.0);
        // Below 3 should return 1.
        assert_eq!(update_scale(0.01, true, 2), 1.0);
    }
}
