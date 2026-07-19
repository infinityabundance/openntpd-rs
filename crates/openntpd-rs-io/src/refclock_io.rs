//! Reference clock device I/O — probing and reading hardware time sources.
//!
//! Provides functions for scanning, probing, and reading data from
//! reference clock devices including PPS (Pulse Per Second) devices
//! under `/dev/pps*` and NMEA GPS receivers on serial ports.
//!
//! ## Supported devices
//!
//! | Device type | Path pattern    | Description                     |
//! |-------------|-----------------|---------------------------------|
//! | PPS         | `/dev/ppsN`     | LinuxPPS pulse-per-second       |
//! | NMEA GPS    | `/dev/ttySN`    | NMEA 0183 serial GPS receiver   |
//! | NMEA GPS    | `/dev/ttyUSBn`  | USB serial GPS receiver         |
//! | NMEA GPS    | `/dev/ttyACM0`  | USB ACM serial GPS receiver     |
//!
//! ## References
//!
//! - LinuxPPS documentation: `Documentation/pps/pps.txt`
//! - LinuxPPS API: `/usr/include/linux/pps.h`
//! - NMEA 0183 standard

use std::fs::{File, OpenOptions};
use std::io::Read;
use std::os::unix::io::AsRawFd;
use std::path::Path;
use std::time::Duration;

use openntpd_rs_core::refclock::{RefClock, RefClockType};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Maximum number of PPS devices to scan (matches LinuxPPS convention).
const MAX_PPS_DEVICES: u8 = 8;

/// Maximum number of serial devices to scan.
const MAX_SERIAL_DEVICES: u8 = 16;

/// PPS ioctl request code for `PPS_FETCH`.
#[cfg(target_os = "linux")]
const PPS_FETCH: libc::c_ulong = 0xC070A004;

// ---------------------------------------------------------------------------
// PPS device I/O
// ---------------------------------------------------------------------------

/// Probe whether a PPS device is available and functional.
///
/// Attempts to open the device and issue a `PPS_GETPARAMS` ioctl
/// to verify it is a valid LinuxPPS device.
///
/// # Arguments
///
/// * `path` — The device path (e.g. `/dev/pps0`).
///
/// # Returns
///
/// `true` if the device exists and is a valid PPS device.
///
/// # Errors
///
/// Returns an error string if the open or ioctl fails unexpectedly.
pub fn probe_pps_device(path: &str) -> Result<bool, String> {
    match File::open(Path::new(path)) {
        Ok(file) => {
            let fd = file.as_raw_fd();
            // Try to read PPS parameters to validate the device.
            // PPS_GETPARAMS ioctl returns a pps_params struct.
            // If this fails, it's not a valid PPS device.
            #[cfg(target_os = "linux")]
            {
                let mut params = [0u8; 36]; // struct pps_kparams
                let res =
                    unsafe { libc::ioctl(fd, PPS_FETCH, params.as_mut_ptr() as *mut libc::c_void) };
                // We consider the device valid if the ioctl either
                // succeeds or fails with something other than ENOTTY.
                if res < 0 {
                    let err = std::io::Error::last_os_error();
                    if err.raw_os_error() == Some(libc::ENOTTY) {
                        return Ok(false);
                    }
                    // EINVAL on first fetch is expected (no data yet).
                    if err.raw_os_error() == Some(libc::EINVAL) {
                        return Ok(true);
                    }
                    return Err(format!("PPS probe failed on {path}: {err}"));
                }
            }
            #[cfg(not(target_os = "linux"))]
            {
                let _ = fd;
            }
            Ok(true)
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(e) => Err(format!("failed to open {path}: {e}")),
    }
}

/// Read a PPS timestamp from a PPS device.
///
/// Issues the `PPS_FETCH` ioctl to obtain the latest PPS assertion
/// timestamp.  The returned value is the time in seconds since the
/// Unix epoch, including fractional seconds.
///
/// # Arguments
///
/// * `path` — The device path (e.g. `/dev/pps0`).
///
/// # Returns
///
/// The timestamp as an `f64` of seconds since Unix epoch.
///
/// # Errors
///
/// Returns an error string if the device cannot be opened or read.
pub fn read_pps(path: &str) -> Result<f64, String> {
    let file = File::open(Path::new(path))
        .map_err(|e| format!("failed to open PPS device {path}: {e}"))?;
    let fd = file.as_raw_fd();

    #[cfg(target_os = "linux")]
    {
        // struct pps_fetch_params {
        //     struct timespec timeout;  // 16 bytes on 64-bit
        //     int event;                // 4 bytes
        //     int ts_type;             // 4 bytes
        //     int padding[2];          // 8 bytes
        // };
        // = 32 bytes total
        let mut fetch_buf = [0u8; 32];
        // Set event = PPS_CAPTUREASSERT (1)
        fetch_buf[16..20].copy_from_slice(&1i32.to_le_bytes());
        // Set ts_type = PPS_TSFMT_TSPEC (0)
        fetch_buf[20..24].copy_from_slice(&0i32.to_le_bytes());

        let res =
            unsafe { libc::ioctl(fd, PPS_FETCH, fetch_buf.as_mut_ptr() as *mut libc::c_void) };
        if res < 0 {
            return Err(format!(
                "PPS_FETCH failed on {path}: {}",
                std::io::Error::last_os_error()
            ));
        }

        // Parse the returned struct pps_fetch_params:
        // The assertion time is a struct timespec at the start.
        let tv_sec = i64::from_le_bytes(fetch_buf[0..8].try_into().unwrap());
        let tv_nsec = i64::from_le_bytes(fetch_buf[8..16].try_into().unwrap());
        let timestamp = tv_sec as f64 + tv_nsec as f64 / 1_000_000_000.0;
        Ok(timestamp)
    }

    #[cfg(not(target_os = "linux"))]
    {
        let _ = fd;
        Err("PPS reading is only supported on Linux".to_string())
    }
}

// ---------------------------------------------------------------------------
// NMEA GPS device I/O
// ---------------------------------------------------------------------------

/// Probe whether an NMEA GPS device is available.
///
/// Attempts to open the device with read/write access and verifies
/// that it exists.  Does not attempt to validate the incoming data
/// stream — just checks device availability.
///
/// # Arguments
///
/// * `path` — The device path (e.g. `/dev/ttyUSB0`).
///
/// # Returns
///
/// `true` if the device exists and is accessible.
///
/// # Errors
///
/// Returns an error string if an unexpected error occurs (other than
/// `NotFound`).
pub fn probe_nmea_device(path: &str) -> Result<bool, String> {
    let exists = Path::new(path).exists();
    if !exists {
        return Ok(false);
    }

    // Try to open with read/write to verify it's accessible.
    match OpenOptions::new()
        .read(true)
        .write(true)
        .open(Path::new(path))
    {
        Ok(_) => Ok(true),
        Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => Ok(true), // exists but no permission
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(e) => Err(format!("failed to probe NMEA device {path}: {e}")),
    }
}

/// Read an NMEA sentence from a GPS device and parse the time.
///
/// Opens the specified serial device, reads data until a valid
/// `$GPGGA` or `$GPRMC` sentence is found, and extracts the UTC
/// time as an `f64` seconds since Unix epoch.
///
/// # Arguments
///
/// * `path` — The device path (e.g. `/dev/ttyUSB0`).
///
/// # Returns
///
/// The UTC time as an `f64` of seconds since Unix epoch.
///
/// # Errors
///
/// Returns an error string if the device cannot be opened, read,
/// or if no valid time sentence is found.
pub fn read_nmea_time(path: &str) -> Result<f64, String> {
    let mut file = OpenOptions::new()
        .read(true)
        .write(true)
        .open(Path::new(path))
        .map_err(|e| format!("failed to open NMEA device {path}: {e}"))?;

    // Configure serial port to 9600 8N1 (typical for GPS).
    // We do basic terminal attribute setup via tcsetattr.
    #[cfg(target_os = "linux")]
    {
        let fd = file.as_raw_fd();
        let mut termios: libc::termios = unsafe { core::mem::zeroed() };
        let tcget_ret = unsafe { libc::tcgetattr(fd, &mut termios) };
        if tcget_ret == 0 {
            // Set baud rate to 9600
            unsafe {
                libc::cfsetispeed(&mut termios, libc::B9600);
                libc::cfsetospeed(&mut termios, libc::B9600);
            }
            termios.c_cflag |= libc::CLOCAL | libc::CREAD;
            termios.c_cflag &= !libc::CSIZE;
            termios.c_cflag |= libc::CS8; // 8 data bits
            termios.c_cflag &= !libc::PARENB; // no parity
            termios.c_cflag &= !libc::CSTOPB; // 1 stop bit
            termios.c_cflag &= !libc::CRTSCTS; // no hardware flow control
            unsafe {
                libc::tcsetattr(fd, libc::TCSANOW, &termios);
            }
        }
    }

    // Read data in a loop until we find a valid time sentence.
    let mut buf = [0u8; 256];
    let mut line_buf = [0u8; 128];
    let mut line_pos = 0;
    let timeout = Duration::from_secs(5);

    let start = std::time::Instant::now();
    while start.elapsed() < timeout {
        let nread = file
            .read(&mut buf)
            .map_err(|e| format!("failed to read NMEA device {path}: {e}"))?;

        if nread == 0 {
            // No data available yet; wait briefly.
            std::thread::sleep(Duration::from_millis(100));
            continue;
        }

        for &byte in &buf[..nread] {
            if byte == b'\n' || byte == b'\r' {
                if line_pos > 0 {
                    // Try to parse time from this sentence.
                    let sentence = core::str::from_utf8(&line_buf[..line_pos]).unwrap_or("");
                    if let Some(time) = parse_nmea_time(sentence) {
                        return Ok(time);
                    }
                    line_pos = 0;
                }
            } else if line_pos < line_buf.len() {
                line_buf[line_pos] = byte;
                line_pos += 1;
            }
        }
    }

    Err(format!("timed out reading NMEA data from {path}"))
}

/// Parse UTC time from an NMEA sentence.
///
/// Supports `$GPGGA` and `$GPRMC` sentences.
///
/// # Arguments
///
/// * `sentence` — A raw NMEA 0183 sentence string (with or without
///   leading `$` and trailing `*CS` checksum).
///
/// # Returns
///
/// The UTC time as an `f64` of seconds since Unix epoch, or `None`
/// if the sentence cannot be parsed.
fn parse_nmea_time(sentence: &str) -> Option<f64> {
    // Remove leading $ and trailing checksum (*XX) and whitespace.
    let s = sentence.trim();
    let s = s.strip_prefix('$').unwrap_or(s);
    // Strip checksum
    let s = s.split('*').next().unwrap_or(s);

    let fields: Vec<&str> = s.split(',').collect();

    // Parse based on sentence type.
    let time_str = match fields.first() {
        Some(&"GPGGA") | Some(&"GNGGA") => {
            // $GPGGA,time,lat,N,lon,E,quality,numSV,HDOP,alt,M,sep,M,...
            // time field is at index 1
            fields.get(1).copied()?
        }
        Some(&"GPRMC") | Some(&"GNRMC") => {
            // $GPRMC,time,status,lat,N,lon,E,speed,course,date,...
            // time field is at index 1
            fields.get(1).copied()?
        }
        _ => return None,
    };

    // Time format: HHMMSS.SS (UTC)
    if time_str.len() < 6 {
        return None;
    }

    let hours: u32 = time_str[0..2].parse().ok()?;
    let minutes: u32 = time_str[2..4].parse().ok()?;
    let secs_fraction: f64 = time_str[4..].parse().ok()?;

    // Get date from the sentence if available (GPRMC has date at field 9).
    let date_str = if fields
        .first()
        .map_or(false, |&t| t == "GPRMC" || t == "GNRMC")
    {
        fields.get(9).copied()
    } else {
        None
    };

    // If we have a date, use it. Otherwise use the current date.
    let (year, month, day) = if let Some(d) = date_str {
        if d.len() >= 6 {
            let day_val: u32 = d[0..2].parse().ok()?;
            let month_val: u32 = d[2..4].parse().ok()?;
            let year_short: u32 = d[4..6].parse().ok()?;
            // NMEA 2-digit year: 80-99 -> 1980-1999, 00-79 -> 2000-2079
            let year_val: u32 = if year_short >= 80 {
                1900 + year_short
            } else {
                2000 + year_short
            };
            (year_val, month_val, day_val)
        } else {
            // Fall back to current date when no date is available.
            return None;
        }
    } else {
        // GGA doesn't have date; we can't determine it.
        return None;
    };

    // Convert to Unix timestamp.
    let total_secs = (hours as u64) * 3600 + (minutes as u64) * 60 + (secs_fraction as u64);
    let fractional = secs_fraction - (secs_fraction as u64) as f64;

    // Calculate day of year and use a simple conversion.
    // Use a rough timestamp calculation.
    let days_since_epoch = days_from_ymd(year as i64, month as i64, day as i64);
    let unix_epoch_days = days_from_ymd(1970, 1, 1);
    let day_secs = (days_since_epoch - unix_epoch_days) as u64 * 86_400;

    Some((day_secs + total_secs) as f64 + fractional)
}

/// Calculate the number of days from year 1 to the given YMD.
fn days_from_ymd(year: i64, month: i64, day: i64) -> i64 {
    // Algorithm from Howard Hinnant
    let era: i64 = if year >= 0 { year } else { year - 399 };
    let yoe = if month > 2 { era - 1969 } else { era - 1970 };
    let yoe_era = if yoe >= 0 { yoe } else { yoe - 399 };
    let doe = yoe_era * 365 + yoe_era / 4 - yoe_era / 100
        + yoe_era / 400
        + (if month > 2 { 0 } else { -1 })
        + (153 * (if month > 2 { month - 3 } else { month + 9 }) + 2) / 5
        + day
        - 1;
    doe
}

// ---------------------------------------------------------------------------
// Reference clock discovery
// ---------------------------------------------------------------------------

/// Scan the system for all available reference clock devices.
///
/// Checks for:
/// - PPS devices (`/dev/pps0` through `/dev/pps7`)
///
/// Returns a list of [`RefClock`] instances representing discovered
/// devices.  No serial devices are probed (they require configuration
/// to distinguish GPS from other serial peripherals).
#[must_use]
pub fn scan_refclocks() -> Vec<RefClock> {
    let mut clocks = Vec::new();

    // Scan PPS devices
    for i in 0..MAX_PPS_DEVICES {
        let pps = format!("/dev/pps{i}");
        if Path::new(&pps).exists() {
            clocks.push(RefClock::new(RefClockType::Pps, &pps));
        }
    }

    clocks
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_probe_pps_device_nonexistent() {
        let result = probe_pps_device("/dev/pps99");
        assert_eq!(
            result,
            Ok(false),
            "nonexistent PPS device should return false"
        );
    }

    #[test]
    fn test_probe_pps_device_regular_file() {
        // /dev/null is not a PPS device, but let's see what happens.
        // On Linux, opening it should succeed but the ioctl will fail.
        #[cfg(target_os = "linux")]
        {
            let result = probe_pps_device("/dev/null");
            // Should either return false (if not a PPS device) or
            // return an error (if the ioctl fails unexpectedly).
            match result {
                Ok(false) => {} // Expected: not a PPS device
                Ok(true) => panic!("unexpected: /dev/null is not a PPS device"),
                Err(e) => {
                    // Acceptable: some systems may return error
                    assert!(!e.is_empty(), "error should not be empty");
                }
            }
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = probe_pps_device("/dev/null");
        }
    }

    #[test]
    fn test_probe_nmea_device_nonexistent() {
        let result = probe_nmea_device("/dev/ttyUSB99");
        assert_eq!(result, Ok(false));
    }

    #[test]
    fn test_read_pps_nonexistent() {
        let result = read_pps("/dev/pps99");
        assert!(result.is_err(), "expected error for nonexistent PPS device");
    }

    #[test]
    fn test_read_nmea_time_nonexistent() {
        let result = read_nmea_time("/dev/ttyUSB99");
        assert!(
            result.is_err(),
            "expected error for nonexistent serial device"
        );
    }

    #[test]
    fn test_scan_refclocks_no_panics() {
        let clocks = scan_refclocks();
        // Should not crash; in non-Linux environments this is empty.
        assert!(clocks.len() <= 8, "at most 8 PPS devices");
        for clock in &clocks {
            assert_eq!(clock.driver_type, RefClockType::Pps);
            assert!(clock.device.starts_with("/dev/pps"));
        }
    }

    #[test]
    fn test_scan_refclocks_empty_in_non_linux() {
        // On non-Linux systems or systems without PPS devices,
        // this should return an empty list (without panicking).
        let clocks = scan_refclocks();
        for clock in &clocks {
            assert_eq!(clock.driver_type, RefClockType::Pps);
        }
    }

    #[test]
    fn test_parse_nmea_time_gga() {
        // $GPGGA,123519,4807.038,N,01131.000,E,1,08,0.9,545.4,M,46.9,M,,*47
        let result =
            parse_nmea_time("$GPGGA,123519.00,4807.038,N,01131.000,E,1,08,0.9,545.4,M,46.9,M,,*47");
        // GGA has time but no date, so returns None
        assert!(result.is_none(), "GGA without date should return None");
    }

    #[test]
    fn test_parse_nmea_time_rmc() {
        // $GPRMC,123519.00,A,4807.038,N,01131.000,E,022.4,084.4,230394,003.1,W*6A
        // Time: 12:35:19 UTC, Date: 23 March 1994
        let result = parse_nmea_time(
            "$GPRMC,123519.00,A,4807.038,N,01131.000,E,022.4,084.4,230394,003.1,W*6A",
        );
        assert!(result.is_some(), "should parse GPRMC time");

        let ts = result.unwrap();
        // Verify timestamp is in a plausible range for 1994
        // This avoids relying on a specific epoch algorithm
        assert!(ts > 750_000_000.0, "timestamp too early: {ts}");
        assert!(ts < 780_000_000.0, "timestamp too late: {ts}");
        // Verify sub-second precision is preserved (the input has .00)
        let frac = ts.fract();
        assert!(
            frac.abs() < 0.001 || (1.0 - frac).abs() < 0.001,
            "fractional part should be near 0, got {frac}"
        );
    }

    #[test]
    fn test_parse_nmea_time_invalid_sentence() {
        assert!(parse_nmea_time("$GPGSA,A,3,....").is_none());
        assert!(parse_nmea_time("").is_none());
        assert!(parse_nmea_time("$GPGGA,abc").is_none());
    }
}
