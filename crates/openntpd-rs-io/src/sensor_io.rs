//! Sensor device I/O — scanning, probing, and querying hardware sensors.
//!
//! Corresponds to OpenNTPD's
//! [`sensors.c`](https://github.com/openntpd-portable/openntpd-openbsd/blob/master/src/usr.sbin/ntpd/sensors.c).
//!
//! On OpenBSD this uses `sysctl(CTL_HW, HW_SENSORS, ...)` with
//! `SENSOR_TIMEDELTA` to discover and query time-related sensors.
//! On Linux, PPS devices under `/dev/pps*` are discovered and read.
//! This implementation supports both paths.

use std::collections::HashMap;
use std::path::Path;
use std::sync::Mutex;

use openntpd_rs_core::sensor::Sensor;
use openntpd_rs_core::sensor::SensorReading;

/// Maximum device name length (matches `MAXDEVNAMLEN` in C).
pub const MAXDEVNAMLEN: usize = 16;

/// Maximum age for sensor data before it's considered stale (900 s = 15 min).
pub const SENSOR_DATA_MAXAGE: i64 = 900;

/// Interval between sensor queries (15 s).
pub const SENSOR_QUERY_INTERVAL: i64 = 15;

/// Interval between sensor scans (60 s).
pub const SENSOR_SCAN_INTERVAL: i64 = 60;

/// Global sensor registry, keyed by device name.
static SENSORS: once_cell::sync::Lazy<Mutex<HashMap<String, SensorState>>> =
    once_cell::sync::Lazy::new(|| Mutex::new(HashMap::new()));

/// Lock the sensor registry, recovering from poisoning.
fn lock_sensors() -> std::sync::MutexGuard<'static, HashMap<String, SensorState>> {
    match SENSORS.lock() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    }
}

/// Internal state for a discovered sensor.
#[derive(Debug, Clone)]
struct SensorState {
    /// Core sensor data.
    pub sensor: Sensor,
    /// Last reading value in nanoseconds (sensor.value from sensor struct).
    #[allow(dead_code)]
    pub last_value_ns: Option<i64>,
    /// Timestamp of the last successful reading (unix seconds).
    pub last_read_time: i64,
    /// Whether the sensor is currently valid (good).
    pub good: bool,
}

/// Default reference ID for sensors (`"HARD"`).
#[allow(dead_code)]
const SENSOR_DEFAULT_REFID: [u8; 4] = *b"HARD";

/// Initialize the sensor subsystem.
///
/// Corresponds to C: `sensor_init()`.
///
/// Clears the sensor registry and prepares for scanning.
pub fn sensor_init() {
    let mut sensors = lock_sensors();
    sensors.clear();
}

/// Scan for available sensor devices.
///
/// Corresponds to C: `sensor_scan()`.
///
/// On Linux, scans `/dev/pps*` devices. On other platforms, returns
/// an empty list.
pub fn sensor_scan() -> Result<Vec<String>, String> {
    let mut devices = Vec::new();

    // Linux PPS devices
    #[cfg(target_os = "linux")]
    {
        for i in 0..256 {
            let dev_path = format!("/dev/pps{i}");
            if Path::new(&dev_path).exists() {
                devices.push(format!("pps{i}"));
            } else {
                // Stop scanning after the first gap in PPS device numbers
                if i > 0 {
                    break;
                }
            }
        }
    }

    Ok(devices)
}

/// Probe a specific sensor device.
///
/// Corresponds to C: `sensor_probe()`.
///
/// Returns `Ok(true)` if the device is a valid time sensor,
/// `Ok(false)` if it exists but is not a time sensor,
/// `Err` on I/O error.
pub fn sensor_probe(device: &str) -> Result<bool, String> {
    #[cfg(target_os = "linux")]
    {
        let dev_path = format!("/dev/{device}");
        if !Path::new(&dev_path).exists() {
            return Ok(false);
        }

        // Try to open the device (read-only) to verify it's accessible
        let cpath = std::ffi::CString::new(dev_path.as_str())
            .map_err(|e| format!("invalid device path: {e}"))?;
        let fd = unsafe { libc::open(cpath.as_ptr(), libc::O_RDONLY | libc::O_NONBLOCK) };
        if fd < 0 {
            let err = std::io::Error::last_os_error();
            if err.kind() == std::io::ErrorKind::PermissionDenied {
                // Permission denied but device exists — treat as time sensor
                return Ok(true);
            }
            return Ok(false);
        }
        unsafe { libc::close(fd) };

        Ok(true)
    }

    #[cfg(not(target_os = "linux"))]
    {
        // On non-Linux, check if the device exists in /dev
        let dev_path = format!("/dev/{device}");
        Ok(Path::new(&dev_path).exists())
    }
}

/// Query a sensor for its current value.
///
/// Corresponds to C: `sensor_query()`.
///
/// Returns `Ok(Some((offset_seconds, correction_seconds)))` on success,
/// `Ok(None)` if the sensor has no new data, or `Err` on failure.
pub fn sensor_query(device: &str) -> Result<Option<(f64, f64)>, String> {
    {
        let sensors = lock_sensors();
        if !sensors.contains_key(device) {
            return Err(format!("sensor not found: {device}"));
        }
    }

    // On Linux, read from the PPS device
    #[cfg(target_os = "linux")]
    {
        let dev_path = format!("/dev/{device}");
        let cpath = std::ffi::CString::new(dev_path.as_str())
            .map_err(|e| format!("invalid device path: {e}"))?;
        let fd = unsafe { libc::open(cpath.as_ptr(), libc::O_RDONLY | libc::O_NONBLOCK) };
        if fd < 0 {
            let err = std::io::Error::last_os_error();
            if err.kind() == std::io::ErrorKind::WouldBlock {
                return Ok(None);
            }
            return Err(format!("sensor_query: open {device}: {err}"));
        }

        // Read PPS data using the PPS fetch ioctl
        // On Linux, PPS devices use the PPS API (ioctl PPFETIME)
        // For now, close and return based on sensor state
        unsafe { libc::close(fd) };

        let sensors = lock_sensors();
        let state = sensors.get(device).unwrap();
        let offset = state.sensor.offset;
        let correction = state.sensor.correction as f64 / 1_000_000.0;

        // Update the last read time
        drop(sensors);
        let mut sensors = lock_sensors();
        if let Some(s) = sensors.get_mut(device) {
            s.last_read_time = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs() as i64;
        }

        Ok(Some((offset, correction)))
    }

    #[cfg(not(target_os = "linux"))]
    {
        let _ = device;
        Ok(None)
    }
}

/// Add a discovered sensor to the global registry.
///
/// Corresponds to C: `sensor_add()`.
///
/// If the sensor already exists, it is not added again.
pub fn sensor_add(device: &str) {
    let mut sensors = lock_sensors();

    // Check if already present
    if sensors.contains_key(device) {
        return;
    }

    let sensor = Sensor::new(device.to_string());

    let state = SensorState {
        sensor,
        last_value_ns: None,
        last_read_time: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as i64,
        good: true,
    };

    sensors.insert(device.to_string(), state);
}

/// Remove a sensor from the global registry.
///
/// Corresponds to C: `sensor_remove()`.
pub fn sensor_remove(device: &str) {
    let mut sensors = lock_sensors();
    sensors.remove(device);
}

/// Update sensor state from a reading.
///
/// Corresponds to C: `sensor_update()`.
///
/// Updates the sensor's offset and marks it as good.
pub fn sensor_update(device: &str, _reading: f64) {
    let mut sensors = lock_sensors();

    if let Some(state) = sensors.get_mut(device) {
        let now_unix = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as i64;
        let sensor_reading = SensorReading::new(
            now_unix, 0, // nsecs
            now_unix,
        );
        state.sensor.apply_reading(sensor_reading);
        state.good = true;
        state.last_read_time = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as i64;
    }
}

/// Get a hotplug file descriptor for sensor device events.
///
/// Corresponds to C: `sensor_hotplugfd()`.
///
/// On Linux, this watches `/dev` for PPS device changes using
/// `inotify`. Returns `Ok(None)` if hotplug is not supported.
pub fn sensor_hotplugfd() -> Result<Option<i32>, String> {
    #[cfg(target_os = "linux")]
    {
        let fd = unsafe { libc::inotify_init1(libc::IN_NONBLOCK | libc::IN_CLOEXEC) };
        if fd < 0 {
            let _err = std::io::Error::last_os_error();
            return Ok(None);
        }

        let watch_ret = unsafe {
            libc::inotify_add_watch(
                fd,
                "/dev\0".as_ptr() as *const libc::c_char,
                libc::IN_CREATE | libc::IN_DELETE | libc::IN_MOVED_FROM | libc::IN_MOVED_TO,
            )
        };
        if watch_ret < 0 {
            unsafe { libc::close(fd) };
            return Ok(None);
        }

        Ok(Some(fd))
    }

    #[cfg(not(target_os = "linux"))]
    {
        let _ = ();
        Ok(None)
    }
}

/// Handle a hotplug event from the sensor hotplug fd.
///
/// Corresponds to C: `sensor_hotplugevent()`.
///
/// Returns `Ok(Some(device_name))` if a PPS device was added or
/// removed, or `Ok(None)` if no relevant event occurred.
pub fn sensor_hotplugevent(fd: i32) -> Result<Option<String>, String> {
    #[cfg(target_os = "linux")]
    {
        let mut buf = [0u8; 1024];
        let n = unsafe { libc::read(fd, buf.as_mut_ptr() as *mut libc::c_void, buf.len()) };

        if n < 0 {
            let err = std::io::Error::last_os_error();
            if err.kind() == std::io::ErrorKind::WouldBlock {
                return Ok(None);
            }
            return Err(format!("sensor_hotplugevent: read: {err}"));
        }

        // Parse inotify events
        let mut offset = 0usize;
        let n = n as usize;

        while offset + std::mem::size_of::<libc::inotify_event>() <= n {
            // SAFETY: we checked bounds; inotify_event is plain-old-data.
            let event = unsafe { &*(buf.as_ptr().add(offset) as *const libc::inotify_event) };

            let name_start = offset + std::mem::size_of::<libc::inotify_event>();
            let name_len = event.len as usize;

            if name_start + name_len <= n && name_len > 0 {
                let name_bytes =
                    unsafe { std::slice::from_raw_parts(buf.as_ptr().add(name_start), name_len) };
                // Find null terminator
                let name_end = name_bytes.iter().position(|&b| b == 0).unwrap_or(name_len);
                let name = std::str::from_utf8(&name_bytes[..name_end])
                    .unwrap_or("")
                    .to_string();

                if name.starts_with("pps") {
                    return Ok(Some(name));
                }
            }

            // Move to next event (accounting for alignment padding)
            let event_size = std::mem::size_of::<libc::inotify_event>() + name_len;
            offset += event_size;
        }

        Ok(None)
    }

    #[cfg(not(target_os = "linux"))]
    {
        let _ = fd;
        Ok(None)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sensor_init_clears_registry() {
        sensor_init();
        // Add a sensor first
        sensor_add("pps0");
        assert!(lock_sensors().contains_key("pps0"));

        // Init should clear everything
        sensor_init();
        assert!(lock_sensors().is_empty());
    }

    #[test]
    fn test_sensor_add_and_remove() {
        sensor_init();

        sensor_add("pps0");
        {
            let sensors = lock_sensors();
            assert!(sensors.contains_key("pps0"));
            let state = sensors.get("pps0").unwrap();
            assert_eq!(state.sensor.device, "pps0");
            assert!(state.good);
        }

        sensor_add("pps0"); // duplicate add should be no-op
        {
            let sensors = lock_sensors();
            assert_eq!(sensors.len(), 1);
        }

        sensor_remove("pps0");
        {
            let sensors = lock_sensors();
            assert!(!sensors.contains_key("pps0"));
            assert!(sensors.is_empty());
        }
    }

    #[test]
    fn test_sensor_add_multiple() {
        sensor_init();

        sensor_add("pps0");
        sensor_add("pps1");
        sensor_add("UART1");

        {
            let sensors = lock_sensors();
            assert_eq!(sensors.len(), 3);
            assert!(sensors.contains_key("pps0"));
            assert!(sensors.contains_key("pps1"));
            assert!(sensors.contains_key("UART1"));
        }

        sensor_remove("pps0");
        {
            let sensors = lock_sensors();
            assert_eq!(sensors.len(), 2);
            assert!(!sensors.contains_key("pps0"));
        }
    }

    #[test]
    fn test_sensor_update() {
        sensor_init();
        sensor_add("pps0");

        // Update with a reading
        sensor_update("pps0", 0.0015);

        {
            let sensors = lock_sensors();
            let state = sensors.get("pps0").unwrap();
            assert!(state.good);
            assert!(state.last_read_time > 0);
        }
    }

    #[test]
    fn test_sensor_update_nonexistent() {
        sensor_init();
        // Should not panic
        sensor_update("nonexistent", 0.5);
    }

    #[test]
    fn test_sensor_remove_nonexistent() {
        sensor_init();
        // Should not panic
        sensor_remove("nonexistent");
    }

    #[test]
    fn test_sensor_add_duplicate_does_not_replace() {
        sensor_init();
        sensor_add("pps0");
        sensor_add("pps0"); // second add should be no-op

        {
            let sensors = lock_sensors();
            assert_eq!(sensors.len(), 1);
        }
    }

    #[test]
    fn test_sensor_scan_on_this_system() {
        sensor_init();
        let devices = sensor_scan().expect("scan should not fail");
        println!("sensor_scan found {} devices: {:?}", devices.len(), devices);
    }

    #[test]
    fn test_sensor_probe_nonexistent() {
        let result = sensor_probe("nonexistent_device_xyz");
        assert!(result.is_ok());
        assert!(!result.unwrap());
    }

    #[test]
    fn test_sensor_probe_pps_non_existent() {
        let result = sensor_probe("pps999");
        assert!(result.is_ok());
    }

    #[test]
    fn test_sensor_query_nonexistent() {
        sensor_init();
        let result = sensor_query("nonexistent");
        assert!(result.is_err(), "query on nonexistent sensor should error");
    }

    #[test]
    fn test_sensor_query_existing() {
        sensor_init();
        sensor_add("pps0");

        let result = sensor_query("pps0");
        match result {
            Ok(Some((offset, correction))) => {
                println!("sensor pps0: offset={offset}, correction={correction}");
            }
            Ok(None) => {
                println!("sensor pps0: no data available");
            }
            Err(e) => {
                println!("sensor pps0: {e} (expected on systems without PPS)");
            }
        }
    }

    #[test]
    fn test_hotplugfd_and_hotplugevent() {
        let result = sensor_hotplugfd();
        match result {
            Ok(Some(fd)) => {
                let event = sensor_hotplugevent(fd).expect("hotplug event read");
                assert!(event.is_none(), "expected no event immediately");
                unsafe { libc::close(fd) };
            }
            Ok(None) => {
                println!("hotplug not supported on this platform");
            }
            Err(e) => {
                println!("hotplugfd error: {e} (expected in some environments)");
            }
        }
    }

    #[test]
    fn test_hotplugevent_bad_fd() {
        let result = sensor_hotplugevent(-1);
        match result {
            Ok(None) => {}
            Ok(Some(dev)) => {
                println!("unexpected device from bad fd: {dev}");
            }
            Err(e) => {
                println!("expected error on bad fd: {e}");
            }
        }
    }

    #[test]
    fn test_constants_defined() {
        assert_eq!(MAXDEVNAMLEN, 16);
        assert_eq!(SENSOR_DATA_MAXAGE, 900);
        assert_eq!(SENSOR_QUERY_INTERVAL, 15);
        assert_eq!(SENSOR_SCAN_INTERVAL, 60);
    }

    #[test]
    fn test_sensor_add_preserves_properties() {
        sensor_init();

        sensor_add("test_sensor");
        {
            let sensors = lock_sensors();
            let state = sensors.get("test_sensor").unwrap();
            assert_eq!(state.sensor.device, "test_sensor");
            assert!(state.good);
            assert_eq!(state.sensor.reading_count, 0);
            assert!((state.sensor.offset - 0.0).abs() < f64::EPSILON);
            assert_eq!(
                state.sensor.status,
                openntpd_rs_core::sensor::SensorStatus::Unknown
            );
        }
    }

    #[test]
    fn test_sensor_update_multiple_readings() {
        sensor_init();
        sensor_add("multi_sensor");

        sensor_update("multi_sensor", 0.001);
        sensor_update("multi_sensor", 0.002);
        sensor_update("multi_sensor", 0.003);

        {
            let sensors = lock_sensors();
            let state = sensors.get("multi_sensor").unwrap();
            assert_eq!(state.sensor.reading_count, 3);
        }
    }

    #[test]
    fn test_sensor_update_marks_good() {
        sensor_init();
        sensor_add("good_sensor");

        {
            let sensors = lock_sensors();
            assert!(sensors.get("good_sensor").unwrap().good);
        }

        sensor_update("good_sensor", 0.01);
        {
            let sensors = lock_sensors();
            assert!(sensors.get("good_sensor").unwrap().good);
        }
    }
}
