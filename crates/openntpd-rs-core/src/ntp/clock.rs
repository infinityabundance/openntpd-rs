//! NTP clock discipline — PLL/FLL hybrid state machine.
//!
//! This module implements the hybrid phase-locked loop / frequency-locked
//! loop clock discipline from **RFC 5905 §10** (Clock Filter and
//! Discipline), corresponding to OpenNTPD's [`ntpd.c` clock_update](
//! https://github.com/openntpd-portable/openntpd-openbsd/blob/master/src/usr.sbin/ntpd/ntpd.c
//! ).
//!
//! ## Algorithm overview
//!
//! 1. **Step / slew decision** — if `|θ| > CLOCK_MAX_STEP` (125 ms) and
//!    this is not the very first update, the clock is **stepped**
//!    immediately and the frequency estimate is reset.
//! 2. **PLL mode** (poll ≤ `CLOCK_POLL_THRESHOLD` ≈ 128 s) — the
//!    frequency correction is updated with a phase-detector gain that
//!    depends on the poll interval: `Δφ = θ / (τ · 2π · 4)` rad/s,
//!    converted to ppm.
//! 3. **FLL mode** (poll > threshold) — the frequency is estimated
//!    directly from the offset and elapsed time: `φ = θ / τ`.
//! 4. **Jitter tracking** — an exponential moving average of `|θ|` with
//!    time constant `CLOCK_POLL_THRESHOLD`.
//!
//! ## References
//!
//! - RFC 5905 §10 — Clock discipline algorithm.
//! - OpenNTPD `ntpd.c` — `clock_update()`, `clock_step()`, `clock_slew()`.
//! - Mills, D.L. — *Computer Network Time Synchronization* (2nd ed.), Ch. 9.

use core::f64::consts::PI;

use crate::ntp::NtpTimestamp;
use crate::peer::{NtpFilterSample, Peer};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Maximum clock step: 125 ms.
///
/// Offsets larger than this trigger a **step** (immediate jump) rather
/// than a **slew** (gradual adjtime adjustment).  This matches OpenNTPD's
/// `CLOCK_MAX_STEP` and RFC 5905's recommended maximum phase adjustment.
pub const CLOCK_MAX_STEP: f64 = 0.125;

/// Maximum single adjtime slew: 0.5 s.
///
/// If the total adjustment exceeds this, the caller should consider
/// stepping or splitting across multiple adjtime calls.
pub const CLOCK_MAX_ADJ: f64 = 0.5;

/// Poll threshold for PLL/FLL mode switch: 2⁷ = 128 s.
///
/// When `poll ≤ CLOCK_POLL_THRESHOLD` the discipline runs in PLL mode
/// (phase detector).  At longer poll intervals the FLL takes over,
/// estimating frequency directly from the offset and elapsed time.
pub const CLOCK_POLL_THRESHOLD: i8 = 7;

/// FLL mode constant (matches OpenNTPD's `CLOCK_FLL`).
pub const CLOCK_FLL: u8 = 0;

/// PLL mode constant (matches OpenNTPD's `CLOCK_PLL`).
pub const CLOCK_PLL: u8 = 1;

// ---------------------------------------------------------------------------
// Clock mode
// ---------------------------------------------------------------------------

/// Clock discipline mode — PLL (phase-locked loop) or FLL (frequency-locked
/// loop).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClockMode {
    /// Phase-locked loop — used at short poll intervals (≤`CLOCK_POLL_THRESHOLD`).
    /// The frequency is adjusted incrementally per update based on the
    /// phase error.
    Pll,
    /// Frequency-locked loop — used at long poll intervals.
    /// The frequency is estimated directly from the offset divided by the
    /// elapsed interval.
    Fll,
}

// ---------------------------------------------------------------------------
// Clock discipline state
// ---------------------------------------------------------------------------

/// Clock discipline state machine.
///
/// Tracks the running offset, frequency error, jitter, and wander
/// estimates.  Drives the PLL/FLL hybrid algorithm described in
/// RFC 5905 §10.
///
/// # Stepping vs. slewing
///
/// - **Step**: immediate clock jump.  Used for large offsets (>125 ms).
///   Resets the frequency and jitter estimates.
/// - **Slew**: gradual correction via frequency adjustment.  Used for
///   small offsets.  Employs PLL or FLL depending on the poll interval.
#[derive(Debug, Clone)]
pub struct ClockState {
    /// Current clock offset (seconds). Positive means the local clock is
    /// **ahead** of the reference.
    pub offset: f64,
    /// Current frequency correction (parts per million, ppm).
    ///
    /// A positive value means the local clock is running **fast** and
    /// needs to be slowed down.
    pub frequency: f64,
    /// Clock jitter estimate (seconds) — RMS of the offset residuals.
    ///
    /// Updated as an exponential moving average of `|θ|` with time
    /// constant `CLOCK_POLL_THRESHOLD`.
    pub jitter: f64,
    /// Frequency wander estimate (ppm) — how much the frequency changes
    /// between updates.
    pub wander: f64,
    /// Current poll interval exponent: interval = 2^poll seconds.
    pub poll: i8,
    /// Current discipline mode (PLL or FLL).
    pub state: ClockMode,
    /// NTP timestamp of the last clock update.
    pub last_update: NtpTimestamp,
    /// Number of times `update()` has been called.
    pub update_count: u64,
    /// Number of times a step (rather than slew) has been performed.
    pub step_count: u64,
}

impl ClockState {
    /// Create a new `ClockState` with default initial values.
    ///
    /// - `offset`: 0.0
    /// - `frequency`: 0.0 (no correction)
    /// - `jitter`: 0.001 (1 ms initial uncertainty)
    /// - `wander`: 0.0
    /// - `poll`: 0 (1 s — caller should set to the peer's poll interval)
    /// - `state`: Pll
    /// - `last_update`: NTP epoch zero
    /// - `update_count`: 0
    /// - `step_count`: 0
    #[must_use]
    pub fn new() -> Self {
        Self {
            offset: 0.0,
            frequency: 0.0,
            jitter: 0.001,
            wander: 0.0,
            poll: 0,
            state: ClockMode::Pll,
            last_update: NtpTimestamp::zero(),
            update_count: 0,
            step_count: 0,
        }
    }

    /// Update the clock discipline with a new offset sample.
    ///
    /// This is the core of the PLL/FLL hybrid algorithm:
    ///
    /// 1. Store the offset and update timestamp.
    /// 2. If `|θ| > CLOCK_MAX_STEP` and not the first update → **step**
    ///    (reset frequency, return step adjustment).
    /// 3. Otherwise → **slew**:
    ///    - **PLL mode** (`poll ≤ CLOCK_POLL_THRESHOLD`): adjust frequency
    ///      by `θ / (τ · 2π · 4)`.
    ///    - **FLL mode** (`poll > CLOCK_POLL_THRESHOLD`): set frequency to
    ///      `θ / τ`.
    /// 4. Update jitter with an exponential moving average:
    ///    `ψ ← ψ + (|θ| − ψ) / CLOCK_POLL_THRESHOLD`.
    /// 5. Update wander with an exponential moving average of the
    ///    frequency change magnitude.
    ///
    /// # Parameters
    ///
    /// * `offset` — the combined clock offset in seconds (positive =
    ///   local clock is ahead of reference).
    /// * `_delay` — the round-trip delay in seconds (not directly used in
    ///   the discipline update, but accepted for API consistency with the
    ///   peer filter pipeline).
    /// * `now` — the current NTP timestamp.
    ///
    /// # Returns
    ///
    /// A [`ClockAdjustment`] describing whether to step or slew, and by
    /// how much.
    pub fn update(&mut self, offset: f64, _delay: f64, now: NtpTimestamp) -> ClockAdjustment {
        self.offset = offset;
        self.last_update = now;

        // ── Step decision ────────────────────────────────────────────────
        if Self::should_step(offset) && self.update_count > 0 {
            // Large offset: step the clock, reset frequency and jitter.
            self.frequency = 0.0;
            self.jitter = 0.001;
            self.step_count += 1;
            self.update_count += 1;
            return ClockAdjustment {
                offset,
                freq_delta: 0.0,
                step: true,
                interval: self.poll,
            };
        }

        // ── Slew — compute poll interval in seconds ──────────────────────
        let tau = if self.poll >= 0 {
            (1u64 << self.poll as u32) as f64
        } else {
            // Negative poll exponent (very rare): fractional seconds.
            1.0 / (1u64 << (-self.poll) as u32) as f64
        };

        // ── Frequency correction ─────────────────────────────────────────
        let freq_delta: f64;
        if self.poll <= CLOCK_POLL_THRESHOLD {
            // PLL mode: incremental frequency adjustment.
            //   Δφ = θ / (τ · 2π · 4)   [rad/s]
            //   Convert to ppm: × 1e6 / (2π)
            self.state = ClockMode::Pll;
            let rad_per_s = offset / (tau * 2.0 * PI * 4.0);
            freq_delta = rad_per_s * 1_000_000.0 / (2.0 * PI);
            self.frequency += freq_delta;
        } else {
            // FLL mode: direct frequency estimate.
            //   φ = θ / τ   [s/s]
            //   Convert to ppm: × 1e6
            self.state = ClockMode::Fll;
            let new_freq = offset * 1_000_000.0 / tau;
            freq_delta = new_freq - self.frequency;
            self.frequency = new_freq;
        }

        // ── Jitter update (exponential moving average) ───────────────────
        let jitter_residual = offset.abs() - self.jitter;
        self.jitter += jitter_residual / CLOCK_POLL_THRESHOLD as f64;

        // ── Wander update ────────────────────────────────────────────────
        let wander_residual = freq_delta.abs() - self.wander;
        self.wander += wander_residual / CLOCK_POLL_THRESHOLD as f64;

        self.update_count += 1;

        ClockAdjustment {
            offset,
            freq_delta,
            step: false,
            interval: self.poll,
        }
    }

    /// Directly set the frequency correction (in ppm).
    ///
    /// This is used to apply a frequency correction from the peer state
    /// or from an external calibration source.
    pub fn set_frequency(&mut self, freq: f64) {
        self.frequency = freq;
    }

    /// Determine whether an offset of this magnitude should trigger a
    /// clock step rather than a slew.
    ///
    /// Returns `true` when `|offset| > CLOCK_MAX_STEP` (0.125 s).
    #[must_use]
    pub fn should_step(offset: f64) -> bool {
        offset.abs() > CLOCK_MAX_STEP
    }
}

impl Default for ClockState {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Clock adjustment result
// ---------------------------------------------------------------------------

/// The result of a [`ClockState::update`] call, describing what
/// adjustment to apply to the system clock.
#[derive(Debug, Clone)]
pub struct ClockAdjustment {
    /// The clock offset adjustment (seconds).
    ///
    /// - For **step** adjustments: the value to pass to
    ///   `clock_settime()` — positive means the local clock is ahead
    ///   (needs to be moved backward / slowed).
    /// - For **slew** adjustments: the value to pass to `adjtime()` or
    ///   `adjtimex()`.
    pub offset: f64,
    /// Frequency correction delta (ppm).
    ///
    /// For slew adjustments, this is the change in frequency that the
    /// discipline algorithm computed.  The caller can accumulate this
    /// into the kernel's frequency correction via `adjtimex()` or
    /// `adjfreq()`.
    pub freq_delta: f64,
    /// Whether to **step** the clock (`true`) or **slew** (`false`).
    pub step: bool,
    /// Suggested poll interval (log2 seconds).
    ///
    /// Currently returns the current poll value.  Future extensions may
    /// adjust this based on jitter and wander.
    pub interval: i8,
}

// ---------------------------------------------------------------------------
// Clock filter jitter  (RFC 5905 §10 — filter jitter ψ)
// ---------------------------------------------------------------------------

/// Compute the clock filter jitter — the RMS of sample residuals around
/// the best offset estimate.
///
/// The jitter is the root-mean-square of `(sample.offset − best_offset)`
/// across all filled slots in the filter ring buffer:
///
/// ```text
/// ψ = sqrt(Σ(θ_i − θ_best)² / N)
/// ```
///
/// This matches RFC 5905 equation (17) and is used as the clock jitter
/// estimate for the clock selection and discipline algorithms.
///
/// # Returns
///
/// * The jitter in seconds.
/// * `0.0` if there are no samples in the filter.
#[must_use]
pub fn filter_jitter(samples: &[Option<NtpFilterSample>], best_offset: f64) -> f64 {
    let mut sum_sq = 0.0f64;
    let mut count = 0u32;

    for sample in samples.iter().flatten() {
        let residual = sample.offset - best_offset;
        sum_sq += residual * residual;
        count += 1;
    }

    if count == 0 {
        return 0.0;
    }

    libm::sqrt(sum_sq / f64::from(count))
}

// ---------------------------------------------------------------------------
// Peer dispersion  (RFC 5905 — root dispersion aggregate)
// ---------------------------------------------------------------------------

/// Compute the RMS of peer dispersions.
///
/// Takes a slice of selected peers and returns the root-mean-square of
/// their individual dispersion values.  This is used as a component of
/// the system's root dispersion estimate.
///
/// # Returns
///
/// * The RMS dispersion in seconds.
/// * `0.0` if the peer list is empty.
#[must_use]
pub fn filter_dispersion(peers: &[&Peer]) -> f64 {
    let count = peers.len();
    if count == 0 {
        return 0.0;
    }

    let mut sum_sq = 0.0f64;
    for peer in peers {
        sum_sq += peer.dispersion * peer.dispersion;
    }

    libm::sqrt(sum_sq / count as f64)
}

// ---------------------------------------------------------------------------
// RMS helper
// ---------------------------------------------------------------------------

/// Root-mean-square of a slice of `f64` values.
///
/// Returns `0.0` for an empty slice.
///
/// ```text
/// RMS = sqrt(Σ x_i² / N)
/// ```
#[must_use]
pub fn rms(values: &[f64]) -> f64 {
    let count = values.len();
    if count == 0 {
        return 0.0;
    }

    let mut sum_sq = 0.0f64;
    for &v in values {
        sum_sq += v * v;
    }

    libm::sqrt(sum_sq / count as f64)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::peer::NtpFilterSample;
    use alloc::format;

    // Helper to create an NtpTimestamp from f64 seconds.
    fn ntp_ts(secs: f64) -> NtpTimestamp {
        NtpTimestamp::from_f64(secs)
    }

    // Helper: a sample with just offset, no delay/dispersion.
    fn sample(offset: f64) -> Option<NtpFilterSample> {
        Some(NtpFilterSample {
            offset,
            delay: 0.0,
            dispersion: 0.0,
        })
    }

    // -----------------------------------------------------------------------
    // ClockState initialization
    // -----------------------------------------------------------------------

    #[test]
    fn test_clock_state_new_defaults() {
        let cs = ClockState::new();
        assert_eq!(cs.offset, 0.0);
        assert_eq!(cs.frequency, 0.0);
        assert_eq!(cs.jitter, 0.001);
        assert_eq!(cs.wander, 0.0);
        assert_eq!(cs.poll, 0);
        assert_eq!(cs.state, ClockMode::Pll);
        assert_eq!(cs.update_count, 0);
        assert_eq!(cs.step_count, 0);
        assert_eq!(cs.last_update, NtpTimestamp::zero());
    }

    #[test]
    fn test_clock_state_default_equals_new() {
        assert_eq!(
            format!("{:?}", ClockState::default()),
            format!("{:?}", ClockState::new())
        );
    }

    // -----------------------------------------------------------------------
    // Single update
    // -----------------------------------------------------------------------

    #[test]
    fn test_single_update_produces_adjustment() {
        let mut cs = ClockState::new();
        cs.poll = 3; // 8-second poll

        let adj = cs.update(0.010, 0.020, ntp_ts(1000.0));

        // First update always slews (update_count = 0, so even large offsets
        // pass through the slew path — this allows initial frequency
        // estimation).
        assert!(!adj.step);
        assert_eq!(cs.update_count, 1);
        assert_eq!(cs.offset, 0.010);
        assert_eq!(cs.state, ClockMode::Pll);
    }

    #[test]
    fn test_single_update_nonzero_freq_delta() {
        let mut cs = ClockState::new();
        cs.poll = 3;

        let adj = cs.update(0.010, 0.020, ntp_ts(1000.0));

        // With poll=3, tau=8s, θ=0.010:
        //   Δφ = θ / (τ·2π·4) · 1e6/(2π) ppm
        let tau = 8.0f64;
        let expected = 0.010 / (tau * 2.0 * PI * 4.0) * 1_000_000.0 / (2.0 * PI);
        assert!(
            (adj.freq_delta - expected).abs() < 1e-12,
            "freq_delta {} != expected {}",
            adj.freq_delta,
            expected
        );
        assert!(
            (cs.frequency - expected).abs() < 1e-12,
            "frequency {} != expected {}",
            cs.frequency,
            expected
        );
    }

    // -----------------------------------------------------------------------
    // Multiple updates converge frequency
    // -----------------------------------------------------------------------

    #[test]
    fn test_multiple_updates_converge_frequency() {
        let mut cs = ClockState::new();
        cs.poll = 3; // 8-second poll

        // Simulate a constant frequency error: each update sees the same
        // per-interval offset. The PLL should accumulate frequency.
        let drift_ppm = 400.0;
        let tau_secs = 8.0;
        let per_interval_offset = drift_ppm * 1e-6 * tau_secs;

        for i in 0..40 {
            cs.update(
                per_interval_offset,
                0.020,
                ntp_ts(1000.0 + tau_secs * (i as f64 + 1.0)),
            );
        }

        // The frequency should have built up significantly.
        assert!(
            cs.frequency > 50.0,
            "PLL frequency {} should be > 50 ppm after 40 updates",
            cs.frequency
        );
    }

    #[test]
    fn test_pure_fll_convergence() {
        let mut cs = ClockState::new();
        cs.poll = 8; // 256s — above CLOCK_POLL_THRESHOLD → FLL

        let drift_ppm = 50.0;
        let tau_secs = 256.0;

        // Each update sees the offset that accumulated over one poll
        // interval: θ = drift × τ.
        let per_interval_offset = drift_ppm * 1e-6 * tau_secs; // 0.0128 s

        for i in 0..10 {
            cs.update(
                per_interval_offset,
                0.020,
                ntp_ts(2000.0 + tau_secs * (i as f64 + 1.0)),
            );
        }

        // In FLL mode the frequency is computed directly as θ/τ,
        // so it should settle at the true drift rate immediately.
        assert!(
            (cs.frequency - drift_ppm).abs() < 1e-9,
            "FLL frequency {} should be exactly {} ppm",
            cs.frequency,
            drift_ppm
        );
        assert_eq!(cs.state, ClockMode::Fll);
    }

    // -----------------------------------------------------------------------
    // Step vs slew at boundary
    // -----------------------------------------------------------------------

    #[test]
    fn test_step_when_offset_exceeds_max_step() {
        let mut cs = ClockState::new();
        cs.poll = 4;
        cs.update_count = 1; // Not the first update

        let adj = cs.update(0.126, 0.020, ntp_ts(2000.0));

        assert!(adj.step, "should step for offset > CLOCK_MAX_STEP");
        assert_eq!(adj.offset, 0.126);
        assert_eq!(cs.frequency, 0.0, "frequency should reset on step");
        assert_eq!(cs.step_count, 1);
    }

    #[test]
    fn test_slew_when_offset_within_max_step() {
        let mut cs = ClockState::new();
        cs.poll = 4;
        cs.update_count = 1;

        let adj = cs.update(0.124, 0.020, ntp_ts(2000.0));

        assert!(!adj.step, "should slew for offset ≤ CLOCK_MAX_STEP");
        assert_ne!(cs.frequency, 0.0, "frequency should update on slew");
    }

    #[test]
    fn test_first_update_always_slews_even_large_offset() {
        let mut cs = ClockState::new();
        cs.poll = 4;
        // update_count = 0 → even large offsets go through slew path to
        // allow initial frequency estimation.

        let adj = cs.update(0.5, 0.020, ntp_ts(2000.0));

        assert!(!adj.step, "first update should always slew");
        assert_eq!(cs.update_count, 1);
        assert_eq!(cs.step_count, 0);
    }

    #[test]
    fn test_step_resets_jitter() {
        let mut cs = ClockState::new();
        cs.poll = 4;
        cs.update_count = 1;
        cs.jitter = 0.050; // some accumulated jitter

        cs.update(0.150, 0.020, ntp_ts(3000.0));

        assert_eq!(
            cs.jitter, 0.001,
            "jitter should reset to initial value after step"
        );
    }

    #[test]
    fn test_step_count_increments() {
        let mut cs = ClockState::new();
        cs.poll = 4;
        cs.update_count = 1;

        cs.update(0.130, 0.020, ntp_ts(1000.0));
        cs.update(0.140, 0.020, ntp_ts(2000.0));
        cs.update(0.150, 0.020, ntp_ts(3000.0));

        assert_eq!(cs.step_count, 3);
    }

    // -----------------------------------------------------------------------
    // PLL vs FLL mode switching at poll threshold
    // -----------------------------------------------------------------------

    #[test]
    fn test_pll_mode_at_or_below_threshold() {
        let mode_check = |poll: i8| {
            let mut cs = ClockState::new();
            cs.poll = poll;
            cs.update_count = 1;
            cs.update(0.010, 0.020, ntp_ts(1000.0));
            assert_eq!(
                cs.state,
                ClockMode::Pll,
                "poll={poll} should be in PLL mode"
            );
        };

        for poll in 0..=CLOCK_POLL_THRESHOLD {
            mode_check(poll);
        }
    }

    #[test]
    fn test_fll_mode_above_threshold() {
        let mut cs = ClockState::new();
        cs.poll = CLOCK_POLL_THRESHOLD + 1;
        cs.update_count = 1;
        cs.update(0.010, 0.020, ntp_ts(1000.0));

        assert_eq!(cs.state, ClockMode::Fll);
    }

    #[test]
    fn test_pll_to_fll_transition() {
        let mut cs = ClockState::new();
        cs.poll = 6; // PLL
        cs.update_count = 1;
        cs.update(0.010, 0.020, ntp_ts(1000.0));
        assert_eq!(cs.state, ClockMode::Pll);

        cs.poll = 8; // FLL
        cs.update(0.010, 0.020, ntp_ts(2000.0));
        assert_eq!(cs.state, ClockMode::Fll);
    }

    #[test]
    fn test_fll_to_pll_transition() {
        let mut cs = ClockState::new();
        cs.poll = 8; // FLL
        cs.update_count = 1;
        cs.update(0.010, 0.020, ntp_ts(1000.0));
        assert_eq!(cs.state, ClockMode::Fll);

        cs.poll = 6; // PLL
        cs.update(0.010, 0.020, ntp_ts(2000.0));
        assert_eq!(cs.state, ClockMode::Pll);
    }

    // -----------------------------------------------------------------------
    // Frequency set/get
    // -----------------------------------------------------------------------

    #[test]
    fn test_set_frequency() {
        let mut cs = ClockState::new();
        assert_eq!(cs.frequency, 0.0);

        cs.set_frequency(15.5);
        assert_eq!(cs.frequency, 15.5);

        cs.set_frequency(-3.2);
        assert_eq!(cs.frequency, -3.2);
    }

    #[test]
    fn test_update_does_not_clobber_external_frequency() {
        let mut cs = ClockState::new();
        cs.poll = 4;
        cs.set_frequency(10.0);

        cs.update_count = 1;
        cs.update(0.010, 0.020, ntp_ts(1000.0));

        // Frequency should have been adjusted, not reset to 0.
        assert!(
            (cs.frequency - 10.0).abs() > 1e-12,
            "frequency should change from set value"
        );
    }

    // -----------------------------------------------------------------------
    // should_step
    // -----------------------------------------------------------------------

    #[test]
    fn test_should_step_exactly_at_boundary() {
        assert!(!ClockState::should_step(CLOCK_MAX_STEP));
        assert!(!ClockState::should_step(-CLOCK_MAX_STEP));
    }

    #[test]
    fn test_should_step_just_beyond_boundary() {
        assert!(ClockState::should_step(CLOCK_MAX_STEP + 1e-9));
        assert!(ClockState::should_step(-CLOCK_MAX_STEP - 1e-9));
    }

    #[test]
    fn test_should_step_zero() {
        assert!(!ClockState::should_step(0.0));
    }

    #[test]
    fn test_should_step_small() {
        assert!(!ClockState::should_step(0.01));
        assert!(!ClockState::should_step(-0.01));
    }

    // -----------------------------------------------------------------------
    // Edge cases: zero, large, negative offset
    // -----------------------------------------------------------------------

    #[test]
    fn test_zero_offset_update() {
        let mut cs = ClockState::new();
        cs.poll = 4;
        cs.update_count = 1;

        let adj = cs.update(0.0, 0.020, ntp_ts(1000.0));

        assert!(!adj.step);
        assert_eq!(adj.offset, 0.0);
        // freq_delta should be near zero
        assert!(
            adj.freq_delta.abs() < 1e-15,
            "freq_delta {} should be ~0 for zero offset",
            adj.freq_delta
        );
    }

    #[test]
    fn test_negative_offset_update() {
        let mut cs = ClockState::new();
        cs.poll = 4;
        cs.update_count = 1;

        let adj = cs.update(-0.010, 0.020, ntp_ts(1000.0));

        assert!(!adj.step);
        assert_eq!(adj.offset, -0.010);
        assert!(
            adj.freq_delta < 0.0,
            "negative offset should produce negative freq_delta, got {}",
            adj.freq_delta
        );
    }

    #[test]
    fn test_very_large_offset_triggers_step() {
        let mut cs = ClockState::new();
        cs.poll = 4;
        cs.update_count = 5;

        let adj = cs.update(10.0, 0.020, ntp_ts(1000.0));

        assert!(adj.step);
        assert_eq!(cs.frequency, 0.0);
        assert_eq!(cs.step_count, 1);
    }

    #[test]
    fn test_negative_large_offset_triggers_step() {
        let mut cs = ClockState::new();
        cs.poll = 4;
        cs.update_count = 5;

        let adj = cs.update(-0.5, 0.020, ntp_ts(1000.0));

        assert!(adj.step);
        assert_eq!(adj.offset, -0.5);
        assert_eq!(cs.frequency, 0.0);
    }

    // -----------------------------------------------------------------------
    // Jitter and wander tracking
    // -----------------------------------------------------------------------

    #[test]
    fn test_jitter_increases_with_larger_offset() {
        let mut cs = ClockState::new();
        cs.poll = 4;
        cs.jitter = 0.001;

        cs.update_count = 1;
        cs.update(0.050, 0.020, ntp_ts(1000.0));

        // Jitter should have increased toward 0.050
        assert!(
            cs.jitter > 0.001,
            "jitter should increase, got {}",
            cs.jitter
        );
        assert!(
            cs.jitter < 0.050,
            "jitter should be less than offset, got {}",
            cs.jitter
        );
    }

    #[test]
    fn test_jitter_decreases_with_smaller_offset() {
        let mut cs = ClockState::new();
        cs.poll = 4;
        cs.jitter = 0.050;

        cs.update_count = 1;
        cs.update(0.001, 0.020, ntp_ts(1000.0));

        // Jitter should decrease toward 0.001
        assert!(
            cs.jitter < 0.050,
            "jitter should decrease, got {}",
            cs.jitter
        );
        assert!(cs.jitter > 0.001);
    }

    #[test]
    fn test_wander_tracks_frequency_changes() {
        let mut cs = ClockState::new();
        cs.poll = 4;
        cs.update_count = 1;

        // First update: some frequency change
        cs.update(0.010, 0.020, ntp_ts(1000.0));
        let wander1 = cs.wander;

        // Second update with larger offset: bigger frequency change
        cs.update(0.050, 0.020, ntp_ts(2000.0));
        let wander2 = cs.wander;

        assert!(
            wander2 >= wander1,
            "wander should increase with larger adjustments"
        );
    }

    // -----------------------------------------------------------------------
    // Filter jitter
    // -----------------------------------------------------------------------

    #[test]
    fn test_filter_jitter_all_same_offset() {
        let samples = [sample(0.010), sample(0.010), sample(0.010), sample(0.010)];
        let jitter = filter_jitter(&samples, 0.010);
        assert!(
            jitter.abs() < 1e-15,
            "jitter should be 0 when all samples match best_offset, got {}",
            jitter
        );
    }

    #[test]
    fn test_filter_jitter_with_spread() {
        let samples = [sample(0.010), sample(0.012), sample(0.008)];
        let best = 0.010;

        let jitter = filter_jitter(&samples, best);

        // Residuals: 0, 0.002, -0.002
        // Squares: 0, 4e-6, 4e-6
        // Mean: 8e-6 / 3 ≈ 2.6667e-6
        // RMS: sqrt(2.6667e-6) ≈ 0.001633
        let expected = libm::sqrt((0.0f64 + 0.000_004 + 0.000_004) / 3.0);
        assert!(
            (jitter - expected).abs() < 1e-12,
            "jitter {} != expected {}",
            jitter,
            expected
        );
    }

    #[test]
    fn test_filter_jitter_single_sample() {
        let samples = [sample(0.010)];
        let jitter = filter_jitter(&samples, 0.010);
        assert!(
            jitter.abs() < 1e-15,
            "single sample with matching offset should have 0 jitter"
        );
    }

    #[test]
    fn test_filter_jitter_empty_filter() {
        let samples = [None, None, None];
        let jitter = filter_jitter(&samples, 0.0);
        assert_eq!(jitter, 0.0, "empty filter should return 0 jitter");
    }

    #[test]
    fn test_filter_jitter_partial_filter() {
        let samples = [None, sample(0.010), None, sample(0.014), None];
        let jitter = filter_jitter(&samples, 0.012);

        // Residuals: -0.002, 0.002
        // Squares: 4e-6, 4e-6 → mean = 4e-6 → RMS = 0.002
        let expected = libm::sqrt(0.000_004);
        assert!(
            (jitter - expected).abs() < 1e-15,
            "jitter {} != expected {}",
            jitter,
            expected
        );
    }

    // -----------------------------------------------------------------------
    // Filter dispersion
    // -----------------------------------------------------------------------

    /// Create a minimal peer with just a dispersion value for testing.
    fn peer_with_dispersion(dispersion: f64) -> Peer {
        use crate::config::directive::ConfigString;
        Peer {
            id: 0,
            address: ConfigString::new(b"0.0.0.0".to_vec()).unwrap(),
            offset: 0.0,
            delay: 0.0,
            dispersion,
            filter: [None; 8],
            filter_next: 0,
            reach: 0,
            poll: 3,
            flash: 0,
            weight: 1,
            trusted: false,
            stratum: 2,
            precision: 0,
            root_delay: 0.0,
            root_dispersion: 0.0,
            reference_id: 0,
            poll_count: 0,
            rapid_polls: 0,
            consecutive_unreachable: 0,
        }
    }

    #[test]
    fn test_filter_dispersion_single_peer() {
        let p = peer_with_dispersion(0.010);
        let d = filter_dispersion(&[&p]);
        assert!((d - 0.010).abs() < 1e-15, "dispersion should match");
    }

    #[test]
    fn test_filter_dispersion_multiple_peers() {
        let peers = [peer_with_dispersion(0.010), peer_with_dispersion(0.020)];
        let d = filter_dispersion(&[&peers[0], &peers[1]]);
        let expected = libm::sqrt((0.0001 + 0.0004) / 2.0);
        assert!(
            (d - expected).abs() < 1e-12,
            "dispersion {} != expected {}",
            d,
            expected
        );
    }

    #[test]
    fn test_filter_dispersion_empty() {
        let d = filter_dispersion(&[]);
        assert_eq!(d, 0.0, "empty peer list should return 0 dispersion");
    }

    // -----------------------------------------------------------------------
    // RMS helper
    // -----------------------------------------------------------------------

    #[test]
    fn test_rms_all_positive() {
        let v = [3.0, 4.0];
        let r = rms(&v);
        // sqrt((9 + 16) / 2) = sqrt(12.5) ≈ 3.5355
        let expected = libm::sqrt(12.5);
        assert!((r - expected).abs() < 1e-12, "RMS {} != {}", r, expected);
    }

    #[test]
    fn test_rms_negative_values() {
        let v = [-3.0, -4.0];
        let r = rms(&v);
        let expected = libm::sqrt(12.5);
        assert!(
            (r - expected).abs() < 1e-12,
            "RMS with negatives {} != {}",
            r,
            expected
        );
    }

    #[test]
    fn test_rms_single_value() {
        let v = [5.0];
        let r = rms(&v);
        assert!((r - 5.0).abs() < 1e-15, "RMS of single value should match");
    }

    #[test]
    fn test_rms_all_zeros() {
        let v = [0.0, 0.0, 0.0];
        let r = rms(&v);
        assert_eq!(r, 0.0);
    }

    #[test]
    fn test_rms_empty() {
        let r = rms(&[]);
        assert_eq!(r, 0.0, "RMS of empty slice should be 0");
    }

    // -----------------------------------------------------------------------
    // Integration: update counts
    // -----------------------------------------------------------------------

    #[test]
    fn test_update_count_increments() {
        let mut cs = ClockState::new();
        cs.poll = 4;

        cs.update(0.010, 0.020, ntp_ts(1000.0));
        assert_eq!(cs.update_count, 1);

        cs.update(0.011, 0.020, ntp_ts(2000.0));
        assert_eq!(cs.update_count, 2);

        cs.update(0.009, 0.020, ntp_ts(3000.0));
        assert_eq!(cs.update_count, 3);
    }

    #[test]
    fn test_update_count_increments_through_step() {
        let mut cs = ClockState::new();
        cs.poll = 4;

        cs.update(0.010, 0.020, ntp_ts(1000.0));
        assert_eq!(cs.update_count, 1);

        // Step
        cs.update(0.200, 0.020, ntp_ts(2000.0));
        assert_eq!(cs.update_count, 2);
        assert_eq!(cs.step_count, 1);
    }

    // -----------------------------------------------------------------------
    // ClockAdjustment properties
    // -----------------------------------------------------------------------

    #[test]
    fn test_adjustment_offset_matches_input() {
        let mut cs = ClockState::new();
        cs.poll = 4;
        cs.update_count = 1;

        let adj = cs.update(0.025, 0.010, ntp_ts(1000.0));
        assert_eq!(adj.offset, 0.025);
        assert!(!adj.step);
        assert_eq!(adj.interval, 4);
    }

    #[test]
    fn test_adjustment_step_sets_freq_delta_zero() {
        let mut cs = ClockState::new();
        cs.poll = 4;
        cs.update_count = 5;

        let adj = cs.update(0.200, 0.020, ntp_ts(1000.0));
        assert!(adj.step);
        assert_eq!(adj.freq_delta, 0.0);
        assert_eq!(cs.frequency, 0.0);
    }

    // -----------------------------------------------------------------------
    // PLL vs FLL frequency delta computation
    // -----------------------------------------------------------------------

    #[test]
    fn test_pll_freq_delta_formula() {
        let mut cs = ClockState::new();
        cs.poll = 3; // tau = 8s, PLL mode
        cs.update_count = 1;

        let offset = 0.010;
        let adj = cs.update(offset, 0.020, ntp_ts(1000.0));

        // PLL: Δf = θ / (2^poll * 2π * 4) * 1e6 / (2π)  ppm
        let tau = 8.0f64;
        let expected = offset / (tau * 2.0 * PI * 4.0) * 1_000_000.0 / (2.0 * PI);
        assert!(
            (adj.freq_delta - expected).abs() < 1e-12,
            "PLL freq_delta {} != expected {}",
            adj.freq_delta,
            expected
        );
    }

    #[test]
    fn test_fll_freq_delta_formula() {
        let mut cs = ClockState::new();
        cs.poll = 8; // tau = 256s, FLL mode
        cs.update_count = 1;

        let offset = 0.010;
        let adj = cs.update(offset, 0.020, ntp_ts(1000.0));

        // FLL: f = θ / 2^poll * 1e6  ppm
        let tau = 256.0f64;
        let expected_freq = offset * 1_000_000.0 / tau;
        assert!(
            (cs.frequency - expected_freq).abs() < 1e-12,
            "FLL frequency {} != expected {}",
            cs.frequency,
            expected_freq
        );
        // freq_delta = new_freq - old_freq
        assert!(
            (adj.freq_delta - expected_freq).abs() < 1e-12,
            "FLL freq_delta {} != expected {}",
            adj.freq_delta,
            expected_freq
        );
    }

    // -----------------------------------------------------------------------
    // Negative poll edge case
    // -----------------------------------------------------------------------

    #[test]
    fn test_negative_poll_does_not_panic() {
        let mut cs = ClockState::new();
        cs.poll = -1; // sub-second poll interval

        // Should not panic, tau will be fractional
        let adj = cs.update(0.001, 0.020, ntp_ts(1000.0));
        assert!(!adj.step);
    }
}
