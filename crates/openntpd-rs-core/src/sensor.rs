//! Timedelta sensor device framework — PPS, NMEA, and other hardware
//! time sources.
//!
//! This module corresponds to OpenNTPD's
//! [`sensors.c`](https://github.com/openntpd-portable/openntpd-openbsd/blob/master/src/usr.sbin/ntpd/sensors.c).
//!
//! Sensors provide raw time readings from hardware devices (PPS, NMEA,
//! DCF77, etc.).  Each reading is a pair of a sensor-reported time and
//! the system monotonic timestamp at which it was captured.  The
//! difference yields the clock offset, to which a per-sensor correction
//! (configured in microseconds) is applied.
//!
//! ## Device discovery
//!
//! [`discover_pps_devices`] generates `/dev/ppsN` paths matching
//! OpenNTPD's `sensor *` wildcard.  No I/O is performed — the caller
//! probes each path separately.
//!
//! ## Sensor selection
//!
//! [`select_sensor_readings`] implements a weighted median over active
//! sensor offsets, matching OpenNTPD's combination strategy.

use alloc::string::String;
use alloc::vec::Vec;

// ---------------------------------------------------------------------------
// Constants (matching OpenNTPD's ntpd.h)
// ---------------------------------------------------------------------------

/// Maximum number of offset samples stored per sensor.
/// C: `#define SENSOR_OFFSETS 6`
pub const SENSOR_OFFSETS: usize = 6;

/// Default reference clock identifier for hardware sensors.
/// C: `#define SENSOR_DEFAULT_REFID "HARD"`
pub const SENSOR_DEFAULT_REFID: [u8; 4] = [b'H', b'A', b'R', b'D'];

// ---------------------------------------------------------------------------
// Sensor status
// ---------------------------------------------------------------------------

/// Operational status of a sensor device.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SensorStatus {
    /// No readings have been applied yet.
    Unknown,
    /// Last applied reading was valid.
    Ok,
    /// Sensor has been explicitly marked as failed.
    Failed,
    /// Last reading is older than the staleness threshold.
    Stale,
}

// ---------------------------------------------------------------------------
// Sensor reading
// ---------------------------------------------------------------------------

/// A single time sample from a hardware sensor.
///
/// # Fields
///
/// * `time_secs` — seconds component of the sensor-reported time.
/// * `time_nsecs` — nanoseconds component of the sensor-reported time
///   (may be negative or exceed 10⁹ — normalised by the caller if desired).
/// * `timestamp` — system monotonic clock (in seconds) when the reading
///   was captured.
#[derive(Debug, Clone, Copy)]
pub struct SensorReading {
    /// Seconds from sensor.
    pub time_secs: i64,
    /// Nanoseconds from sensor.
    pub time_nsecs: i64,
    /// When the reading was taken (monotonic seconds).
    pub timestamp: i64,
}

impl SensorReading {
    /// Create a new sensor reading.
    #[must_use]
    pub const fn new(time_secs: i64, time_nsecs: i64, timestamp: i64) -> Self {
        Self {
            time_secs,
            time_nsecs,
            timestamp,
        }
    }
}

// ---------------------------------------------------------------------------
// Sensor device
// ---------------------------------------------------------------------------

/// A hardware timedelta sensor device.
///
/// Each `Sensor` holds its configuration (correction, refid, stratum,
/// weight, trust) and runtime state (last reading, computed offset,
/// reading count).
#[derive(Debug, Clone)]
pub struct Sensor {
    /// Device path (e.g. `/dev/pps0`).
    pub device: String,
    /// Per-sensor correction in microseconds (added to offset).
    pub correction: i64,
    /// Reference ID (4-byte ASCII, e.g. `PPS\0`).
    pub refid: [u8; 4],
    /// NTP stratum (typically 0 for reference clocks).
    pub stratum: u8,
    /// Weight for sensor combination (0–255).
    pub weight: u8,
    /// Whether this sensor is trusted.
    pub trusted: bool,
    /// Current operational status.
    pub status: SensorStatus,
    /// The most recent reading (if any).
    pub last_reading: Option<SensorReading>,
    /// Computed clock offset from the last reading (seconds).
    pub offset: f64,
    /// Total number of readings applied.
    pub reading_count: u64,
}

impl Sensor {
    /// Create a new sensor with defaults.
    ///
    /// Defaults match OpenNTPD's `sensor_add`:
    /// - `correction`: 0
    /// - `refid`: `[0, 0, 0, 0]`
    /// - `stratum`: 0
    /// - `weight`: 1
    /// - `trusted`: `false`
    /// - `status`: `SensorStatus::Unknown`
    /// - `last_reading`: `None`
    /// - `offset`: 0.0
    /// - `reading_count`: 0
    #[must_use]
    pub fn new(device: String) -> Self {
        Self {
            device,
            correction: 0,
            refid: [0, 0, 0, 0],
            stratum: 0,
            weight: 1,
            trusted: false,
            status: SensorStatus::Unknown,
            last_reading: None,
            offset: 0.0,
            reading_count: 0,
        }
    }

    /// Apply a sensor reading, compute the corrected offset, and update
    /// runtime state.
    ///
    /// Returns the corrected offset in seconds.
    ///
    /// # Effects
    ///
    /// * `self.last_reading` is set to `Some(reading)`.
    /// * `self.offset` is updated to the computed offset.
    /// * `self.reading_count` is incremented.
    /// * `self.status` is set to [`SensorStatus::Ok`].
    pub fn apply_reading(&mut self, reading: SensorReading) -> f64 {
        let offset = sensor_offset(&reading, self.correction);
        self.last_reading = Some(reading);
        self.offset = offset;
        self.reading_count += 1;
        self.status = SensorStatus::Ok;
        offset
    }

    /// Mark this sensor as failed.
    ///
    /// Sets `status` to [`SensorStatus::Failed`].
    pub fn mark_failed(&mut self) {
        self.status = SensorStatus::Failed;
    }

    /// Check whether the sensor's last reading is stale.
    ///
    /// A reading is stale when `(now - reading.timestamp) > threshold_secs`.
    /// If there has never been a reading, returns `false` (the sensor has
    /// not had a chance to become fresh yet).
    #[must_use]
    pub fn is_stale(&self, now: i64, threshold_secs: i64) -> bool {
        match &self.last_reading {
            Some(reading) => now.saturating_sub(reading.timestamp) > threshold_secs,
            None => false,
        }
    }
}

// ---------------------------------------------------------------------------
// Device discovery
// ---------------------------------------------------------------------------

/// Discover PPS device paths matching OpenNTPD's `sensor *` wildcard.
///
/// Generates paths `/dev/pps0` through `/dev/ppsN-1` where `N` is
/// `max_devices`.  No I/O is performed; the caller should probe each
/// path with `stat` or `open`.
///
/// # Example
///
/// ```
/// use openntpd_rs_core::sensor::discover_pps_devices;
/// let devices = discover_pps_devices(4);
/// assert_eq!(devices, vec!["/dev/pps0", "/dev/pps1", "/dev/pps2", "/dev/pps3"]);
/// ```
#[must_use]
pub fn discover_pps_devices(max_devices: u8) -> Vec<String> {
    (0..max_devices)
        .map(|i| {
            let mut buf = String::with_capacity(12);
            // Pre-allocate: "/dev/pps" (8) + up to 2 decimal digits + null
            buf.push_str("/dev/pps");
            // Manual u8-to-decimal formatting (no_std, no core::Write).
            if i >= 100 {
                buf.push(char::from(b'0' + (i / 100)));
                buf.push(char::from(b'0' + ((i / 10) % 10)));
                buf.push(char::from(b'0' + (i % 10)));
            } else if i >= 10 {
                buf.push(char::from(b'0' + (i / 10)));
                buf.push(char::from(b'0' + (i % 10)));
            } else {
                buf.push(char::from(b'0' + i));
            }
            buf
        })
        .collect()
}

// ---------------------------------------------------------------------------
// Offset computation
// ---------------------------------------------------------------------------

/// Compute the corrected clock offset from a sensor reading.
///
/// The offset is:
///
/// ```text
/// offset = (time_secs + time_nsecs / 1e9) - timestamp + correction_us / 1e6
/// ```
///
/// where `correction_us` is the configured per-sensor correction in
/// microseconds.
#[must_use]
pub fn sensor_offset(reading: &SensorReading, correction_us: i64) -> f64 {
    let sensor_time = reading.time_secs as f64 + reading.time_nsecs as f64 / 1_000_000_000.0;
    let correction = correction_us as f64 / 1_000_000.0;
    sensor_time - reading.timestamp as f64 + correction
}

// ---------------------------------------------------------------------------
// Sensor selection (weighted median)
// ---------------------------------------------------------------------------

/// Select a combined clock offset from active sensors using a weighted
/// median.
///
/// Only sensors that have at least one reading and are not in `Failed`
/// status are considered.  The weighted median is:
///
/// 1. Collect `(offset, weight)` pairs from eligible sensors.
/// 2. Sort by offset.
/// 3. Accumulate weights until cumulative weight exceeds half the total.
///    The offset at that position is the weighted median.
///
/// If all eligible weights are zero, the simple median (middle element)
/// is returned instead.
///
/// Returns `None` when no sensors are eligible.
#[must_use]
pub fn select_sensor_readings(sensors: &[&Sensor]) -> Option<f64> {
    let mut values: Vec<(f64, u8)> = sensors
        .iter()
        .filter(|s| s.last_reading.is_some() && s.status != SensorStatus::Failed)
        .map(|s| (s.offset, s.weight))
        .collect();

    if values.is_empty() {
        return None;
    }

    // Sort by offset value.
    values.sort_by(|a, b| a.0.partial_cmp(&b.0).unwrap_or(core::cmp::Ordering::Equal));

    let total_weight: u64 = values.iter().map(|(_, w)| u64::from(*w)).sum();

    if total_weight == 0 {
        // All weights are zero: return the simple median.
        return Some(values[values.len() / 2].0);
    }

    let half = total_weight / 2;
    let mut cumulative: u64 = 0;

    for (offset, weight) in &values {
        cumulative += u64::from(*weight);
        if cumulative > half {
            return Some(*offset);
        }
    }

    // Fallback (shouldn't be reached if total_weight > 0).
    values.last().map(|(o, _)| *o)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // -----------------------------------------------------------------------
    // Sensor creation
    // -----------------------------------------------------------------------

    #[test]
    fn test_sensor_new_defaults() {
        let s = Sensor::new(String::from("/dev/pps0"));
        assert_eq!(s.device, "/dev/pps0");
        assert_eq!(s.correction, 0);
        assert_eq!(s.refid, [0, 0, 0, 0]);
        assert_eq!(s.stratum, 0);
        assert_eq!(s.weight, 1);
        assert!(!s.trusted);
        assert_eq!(s.status, SensorStatus::Unknown);
        assert!(s.last_reading.is_none());
        assert_eq!(s.offset, 0.0);
        assert_eq!(s.reading_count, 0);
    }

    // -----------------------------------------------------------------------
    // Apply reading
    // -----------------------------------------------------------------------

    #[test]
    fn test_apply_reading_zero_correction() {
        let mut s = Sensor::new(String::from("/dev/pps0"));
        // Sensor says time is 1000.5s, captured at monotonic 999.0s
        let reading = SensorReading::new(1000, 500_000_000, 999);
        let offset = s.apply_reading(reading);

        // offset = (1000 + 0.5) - 999 + 0 = 1.5
        assert!((offset - 1.5).abs() < 1e-9);
        assert_eq!(s.status, SensorStatus::Ok);
        assert_eq!(s.reading_count, 1);
        assert!(s.last_reading.is_some());
        assert!((s.offset - 1.5).abs() < 1e-9);
    }

    #[test]
    fn test_apply_reading_positive_correction() {
        let mut s = Sensor::new(String::from("/dev/pps0"));
        s.correction = 500_000; // +0.5s correction
        let reading = SensorReading::new(1000, 0, 1000);
        let offset = s.apply_reading(reading);

        // offset = (1000) - 1000 + 0.5 = 0.5
        assert!((offset - 0.5).abs() < 1e-9);
    }

    #[test]
    fn test_apply_reading_negative_correction() {
        let mut s = Sensor::new(String::from("/dev/pps0"));
        s.correction = -250_000; // -0.25s correction
        let reading = SensorReading::new(2000, 0, 2000);
        let offset = s.apply_reading(reading);

        // offset = (2000) - 2000 - 0.25 = -0.25
        assert!((offset - (-0.25)).abs() < 1e-9);
    }

    #[test]
    fn test_multiple_readings_update() {
        let mut s = Sensor::new(String::from("/dev/pps0"));
        let r1 = SensorReading::new(1000, 0, 999);
        let _ = s.apply_reading(r1);
        assert_eq!(s.reading_count, 1);
        assert!((s.offset - 1.0).abs() < 1e-9);

        let r2 = SensorReading::new(2000, 0, 1999);
        let _ = s.apply_reading(r2);
        assert_eq!(s.reading_count, 2);
        // offset = (2000) - 1999 = 1.0
        assert!((s.offset - 1.0).abs() < 1e-9);

        let r3 = SensorReading::new(3000, 0, 3001);
        let offset = s.apply_reading(r3);
        // offset = (3000) - 3001 = -1.0
        assert!((offset - (-1.0)).abs() < 1e-9);
        assert_eq!(s.reading_count, 3);
    }

    // -----------------------------------------------------------------------
    // Staleness
    // -----------------------------------------------------------------------

    #[test]
    fn test_stale_detection() {
        let mut s = Sensor::new(String::from("/dev/pps0"));
        // No reading yet → not stale
        assert!(!s.is_stale(100, 10));

        let reading = SensorReading::new(100, 0, 100);
        let _ = s.apply_reading(reading);

        // now=105, threshold=10: 105-100=5 ≤ 10 → not stale
        assert!(!s.is_stale(105, 10));

        // now=115, threshold=10: 115-100=15 > 10 → stale
        assert!(s.is_stale(115, 10));
    }

    #[test]
    fn test_stale_boundary() {
        let mut s = Sensor::new(String::from("/dev/pps0"));
        let reading = SensorReading::new(100, 0, 100);
        let _ = s.apply_reading(reading);

        // Exactly at boundary: 110 - 100 = 10, threshold=10 → NOT stale (> not >=)
        assert!(!s.is_stale(110, 10));

        // One past boundary: 111 - 100 = 11 > 10 → stale
        assert!(s.is_stale(111, 10));
    }

    #[test]
    fn test_stale_no_reading() {
        let s = Sensor::new(String::from("/dev/pps0"));
        // A sensor with no readings is not stale (it hasn't had a chance).
        assert!(!s.is_stale(999_999, 1));
    }

    // -----------------------------------------------------------------------
    // Status transitions
    // -----------------------------------------------------------------------

    #[test]
    fn test_sensor_status_transitions() {
        let mut s = Sensor::new(String::from("/dev/pps0"));
        assert_eq!(s.status, SensorStatus::Unknown);

        // Apply reading → Ok
        let reading = SensorReading::new(100, 0, 100);
        let _ = s.apply_reading(reading);
        assert_eq!(s.status, SensorStatus::Ok);

        // Mark failed
        s.mark_failed();
        assert_eq!(s.status, SensorStatus::Failed);

        // Apply reading after failure → back to Ok
        let reading = SensorReading::new(101, 0, 101);
        let _ = s.apply_reading(reading);
        assert_eq!(s.status, SensorStatus::Ok);
    }

    // -----------------------------------------------------------------------
    // Reading count
    // -----------------------------------------------------------------------

    #[test]
    fn test_reading_count_tracking() {
        let mut s = Sensor::new(String::from("/dev/pps0"));
        assert_eq!(s.reading_count, 0);

        for i in 0u64..100 {
            let reading = SensorReading::new(i as i64, 0, i as i64);
            let _ = s.apply_reading(reading);
            assert_eq!(s.reading_count, i + 1);
        }
    }

    // -----------------------------------------------------------------------
    // PPS device discovery
    // -----------------------------------------------------------------------

    #[test]
    fn test_discover_pps_devices_zero() {
        let devices = discover_pps_devices(0);
        assert!(devices.is_empty());
    }

    #[test]
    fn test_discover_pps_devices_small() {
        let devices = discover_pps_devices(4);
        assert_eq!(devices.len(), 4);
        assert_eq!(devices[0], "/dev/pps0");
        assert_eq!(devices[1], "/dev/pps1");
        assert_eq!(devices[2], "/dev/pps2");
        assert_eq!(devices[3], "/dev/pps3");
    }

    #[test]
    fn test_discover_pps_devices_max() {
        let devices = discover_pps_devices(32);
        assert_eq!(devices.len(), 32);
        assert_eq!(devices[0], "/dev/pps0");
        assert_eq!(devices[10], "/dev/pps10");
        assert_eq!(devices[31], "/dev/pps31");
    }

    // -----------------------------------------------------------------------
    // sensor_offset direct computation
    // -----------------------------------------------------------------------

    #[test]
    fn test_sensor_offset_zero_correction() {
        let reading = SensorReading::new(1000, 0, 999);
        let offset = sensor_offset(&reading, 0);
        assert!((offset - 1.0).abs() < 1e-9);
    }

    #[test]
    fn test_sensor_offset_with_nanoseconds() {
        // Sensor says 1000.5s, captured at 999.0s
        let reading = SensorReading::new(1000, 500_000_000, 999);
        let offset = sensor_offset(&reading, 0);
        assert!((offset - 1.5).abs() < 1e-9);
    }

    #[test]
    fn test_sensor_offset_negative_sensor_time() {
        // Sensor time before epoch
        let reading = SensorReading::new(-100, 0, 50);
        let offset = sensor_offset(&reading, 0);
        // offset = (-100) - 50 = -150
        assert!((offset - (-150.0)).abs() < 1e-9);
    }

    #[test]
    fn test_sensor_offset_negative_nanoseconds() {
        // Sensor reports negative nanoseconds
        let reading = SensorReading::new(100, -500_000_000, 99);
        let offset = sensor_offset(&reading, 0);
        // offset = (100 + (-0.5)) - 99 = 0.5
        assert!((offset - 0.5).abs() < 1e-9);
    }

    #[test]
    fn test_sensor_offset_large_correction() {
        let reading = SensorReading::new(1000, 0, 1000);
        // 10_000_000 µs = 10s correction
        let offset = sensor_offset(&reading, 10_000_000);
        // offset = 0 + 10 = 10
        assert!((offset - 10.0).abs() < 1e-9);
    }

    // -----------------------------------------------------------------------
    // Selection / weighted median
    // -----------------------------------------------------------------------

    #[test]
    fn test_select_sensor_readings_empty() {
        let sensors: Vec<&Sensor> = Vec::new();
        assert!(select_sensor_readings(&sensors).is_none());
    }

    #[test]
    fn test_select_sensor_readings_single() {
        let mut s = Sensor::new(String::from("/dev/pps0"));
        let _ = s.apply_reading(SensorReading::new(100, 0, 99));
        let sensors = [&s];
        let result = select_sensor_readings(&sensors);
        assert!(result.is_some());
        assert!((result.unwrap() - 1.0).abs() < 1e-9);
    }

    #[test]
    fn test_select_sensor_readings_without_reading() {
        // A sensor with no reading should be excluded.
        let s = Sensor::new(String::from("/dev/pps0"));
        let sensors = [&s];
        assert!(select_sensor_readings(&sensors).is_none());
    }

    #[test]
    fn test_select_sensor_readings_failed_excluded() {
        let mut s = Sensor::new(String::from("/dev/pps0"));
        let _ = s.apply_reading(SensorReading::new(100, 0, 99));
        s.mark_failed();
        let sensors = [&s];
        assert!(select_sensor_readings(&sensors).is_none());
    }

    #[test]
    fn test_select_sensor_readings_weighted_median() {
        // Three sensors at offsets -1, 0, +1 with weights 1, 3, 1
        // Total weight = 5, half = 2, median is the element where
        // cumulative > 2 → offset 0 (weight 3 pushes cum from 1 to 4 > 2)
        let mut s1 = Sensor::new(String::from("/dev/pps0"));
        s1.weight = 1;
        let mut s2 = Sensor::new(String::from("/dev/pps1"));
        s2.weight = 3;
        let mut s3 = Sensor::new(String::from("/dev/pps2"));
        s3.weight = 1;

        let _ = s1.apply_reading(SensorReading::new(99, 0, 100)); // offset = -1
        let _ = s2.apply_reading(SensorReading::new(100, 0, 100)); // offset = 0
        let _ = s3.apply_reading(SensorReading::new(101, 0, 100)); // offset = +1

        let sensors = [&s1, &s2, &s3];
        let result = select_sensor_readings(&sensors);
        assert!(result.is_some());
        assert!((result.unwrap() - 0.0).abs() < 1e-9);
    }

    #[test]
    fn test_select_sensor_readings_zero_weight() {
        // All weights zero → simple median (middle element).
        let mut s1 = Sensor::new(String::from("/dev/pps0"));
        s1.weight = 0;
        let mut s2 = Sensor::new(String::from("/dev/pps1"));
        s2.weight = 0;
        let mut s3 = Sensor::new(String::from("/dev/pps2"));
        s3.weight = 0;

        let _ = s1.apply_reading(SensorReading::new(99, 0, 100)); // offset = -1
        let _ = s2.apply_reading(SensorReading::new(100, 0, 100)); // offset = 0
        let _ = s3.apply_reading(SensorReading::new(101, 0, 100)); // offset = +1

        let sensors = [&s1, &s2, &s3];
        let result = select_sensor_readings(&sensors);
        assert!(result.is_some());
        assert!((result.unwrap() - 0.0).abs() < 1e-9);
    }

    #[test]
    fn test_select_sensor_readings_partial_eligible() {
        // One sensor has no reading → excluded.
        let mut s1 = Sensor::new(String::from("/dev/pps0"));
        let s2 = Sensor::new(String::from("/dev/pps1")); // no reading

        let _ = s1.apply_reading(SensorReading::new(100, 0, 99));
        let sensors = [&s1, &s2];
        let result = select_sensor_readings(&sensors);
        assert!(result.is_some());
        assert!((result.unwrap() - 1.0).abs() < 1e-9);
    }

    // -----------------------------------------------------------------------
    // Edge cases
    // -----------------------------------------------------------------------

    #[test]
    fn test_edge_future_reading_time() {
        // Sensor reports a time far in the future relative to capture
        // timestamp → large positive offset.
        let mut s = Sensor::new(String::from("/dev/pps0"));
        let reading = SensorReading::new(1_000_000, 0, 100);
        let offset = s.apply_reading(reading);
        assert!((offset - 999_900.0).abs() < 1e-9);
    }

    #[test]
    fn test_edge_correction_overflow_i64() {
        // Large correction value (near i64::MAX) should not panic.
        let mut s = Sensor::new(String::from("/dev/pps0"));
        s.correction = i64::MAX;
        let reading = SensorReading::new(100, 0, 100);
        let offset = s.apply_reading(reading);
        // correction = i64::MAX / 1e6 ≈ 9.22e12 seconds
        assert!(offset > 0.0);
        assert!(offset.is_finite());
    }

    #[test]
    fn test_edge_trusted_flag() {
        // The trusted flag is metadata; verify it's preserved.
        let mut s = Sensor::new(String::from("/dev/pps0"));
        assert!(!s.trusted);
        s.trusted = true;
        assert!(s.trusted);
        let reading = SensorReading::new(100, 0, 99);
        let _ = s.apply_reading(reading);
        // Trusted flag survives apply_reading.
        assert!(s.trusted);
    }

    #[test]
    fn test_edge_large_stratum() {
        let mut s = Sensor::new(String::from("/dev/pps0"));
        s.stratum = 255;
        assert_eq!(s.stratum, 255);
    }

    // -----------------------------------------------------------------------
    // Double-check that sensor_offset matches apply_reading
    // -----------------------------------------------------------------------

    #[test]
    fn test_offset_consistency() {
        let mut s = Sensor::new(String::from("/dev/pps0"));
        s.correction = 100_000; // 0.1s

        let reading = SensorReading::new(500, 750_000_000, 400);
        let from_apply = s.apply_reading(reading);
        let from_fn = sensor_offset(&reading, 100_000);

        assert!((from_apply - from_fn).abs() < 1e-12);
    }
}
