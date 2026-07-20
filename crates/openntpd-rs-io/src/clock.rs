//! OS clock operations — [`adjtime(2)`], [`adjtimex(2)`],
//! [`clock_gettime(2)`].
//!
//! ## Platform boundary
//!
//! The `adjfreq` / `adjtimex` frequency unit differs between OpenBSD
//! and Linux.  This module owns the conversion:
//!
//! | Platform | Unit | Conversion from OpenBSD freq |
//! |----------|------|------------------------------|
//! | Linux    | scaled ppm (2¹⁶ per ppm) | `linux_freq = openbsd_freq / (1000 × 2¹⁶)` |
//! | OpenBSD  | ns/s × 2³² (internal)   | identity |
//!
//! See `compat/adjfreq_linux.c` in the openntpd-portable source.

/// Error type for clock operations.
#[derive(Debug)]
pub enum ClockError {
    /// Not supported on this platform.
    Unsupported,
    /// The underlying syscall returned an error.
    Syscall(std::io::Error),
    /// Invalid arguments (NaN, infinity, out of range).
    InvalidArgs(&'static str),
    /// Frequency value overflows the platform's accepted range.
    Overflow(&'static str),
}

impl std::fmt::Display for ClockError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Unsupported => write!(f, "not supported on this platform"),
            Self::Syscall(e) => write!(f, "syscall error: {e}"),
            Self::InvalidArgs(msg) => write!(f, "invalid argument: {msg}"),
            Self::Overflow(msg) => write!(f, "overflow: {msg}"),
        }
    }
}

impl std::error::Error for ClockError {}

/// Result type for clock operations.
pub type ClockResult<T> = Result<T, ClockError>;

/// Read the monotonic clock.
///
/// Corresponds to `clock_gettime(CLOCK_MONOTONIC)` in OpenNTPD's
/// `getmonotime()`.
pub fn get_monotonic_time() -> ClockResult<std::time::Instant> {
    Ok(std::time::Instant::now())
}

/// Read the realtime (wall) clock.
///
/// Corresponds to `clock_gettime(CLOCK_REALTIME)` in OpenNTPD's
/// `gettime()`.
#[cfg(any(target_os = "linux", target_os = "freebsd"))]
pub fn get_realtime_time() -> ClockResult<libc::timespec> {
    let mut ts = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    // SAFETY: `clock_gettime` is safe to call with a valid pointer.
    let ret = unsafe { libc::clock_gettime(libc::CLOCK_REALTIME, &mut ts) };
    if ret != 0 {
        return Err(ClockError::Syscall(std::io::Error::last_os_error()));
    }
    Ok(ts)
}

/// Convert OpenBSD internal frequency to FreeBSD `adjfreq(2)` units.
///
/// FreeBSD's `adjfreq(2)` uses the same unit as OpenBSD
/// (ns/s × 2³²), so the conversion is identity.  This function
/// exists for API consistency.
#[cfg(target_os = "freebsd")]
pub fn openbsd_freq_to_os(freq: openntpd_rs_core::util::Frequency) -> ClockResult<i64> {
    Ok(freq.raw())
}

/// Convert FreeBSD `adjfreq(2)` frequency to OpenBSD internal frequency.
#[cfg(target_os = "freebsd")]
pub fn os_freq_to_openbsd(os_freq: i64) -> ClockResult<openntpd_rs_core::util::Frequency> {
    Ok(openntpd_rs_core::util::Frequency::from_raw(os_freq))
}

/// Convert OpenBSD internal frequency to Linux `adjtimex.freq` scaled-ppm.
///
/// This implements the formula from `compat/adjfreq_linux.c`:
///
/// ```c
/// tx.freq = openbsd_freq / 1000 / 65536;
/// ```
///
/// Returns `Overflow` if the divided value exceeds i32 range.
#[cfg(target_os = "linux")]
pub fn openbsd_freq_to_linux(freq: openntpd_rs_core::util::Frequency) -> ClockResult<i64> {
    freq.try_to_linux().ok_or(ClockError::Overflow(
        "frequency out of Linux adjtimex range",
    ))
}

/// Convert Linux `adjtimex.freq` scaled-ppm to OpenBSD internal frequency.
///
/// Returns `Overflow` if the multiplication would overflow `i64`.
#[cfg(target_os = "linux")]
pub fn linux_freq_to_openbsd(linux_freq: i64) -> ClockResult<openntpd_rs_core::util::Frequency> {
    openntpd_rs_core::util::Frequency::from_linux_checked(linux_freq).ok_or(ClockError::Overflow(
        "linux_freq_to_openbsd: multiplication overflow",
    ))
}

/// Read current kernel timex status.
///
/// Returns the raw `timex` struct from `adjtimex(2)`.
#[cfg(target_os = "linux")]
pub fn read_timex_status() -> ClockResult<libc::timex> {
    let mut tx: libc::timex = unsafe { std::mem::zeroed() };
    tx.modes = 0; // read-only
                  // SAFETY: adjtimex with modes=0 is a read operation.
    let ret = unsafe { libc::adjtimex(&mut tx) };
    if ret == -1 {
        return Err(ClockError::Syscall(std::io::Error::last_os_error()));
    }
    Ok(tx)
}

/// Adjust the system clock frequency via `adjfreq(2)`.
///
/// Available on FreeBSD and OpenBSD.  The frequency unit is
/// ns/s × 2³² (same as OpenBSD internal).
#[cfg(target_os = "freebsd")]
pub fn adjfreq(freq: openntpd_rs_core::util::Frequency) -> ClockResult<()> {
    // SAFETY: adjfreq syscall with pointers to properly sized i64 values.
    let mut oldfreq: i64 = 0;
    let newfreq = openbsd_freq_to_os(freq)?;
    let ret = unsafe { libc::adjfreq(&newfreq as *const i64, &mut oldfreq as *mut i64) };
    if ret != 0 {
        return Err(ClockError::Syscall(std::io::Error::last_os_error()));
    }
    Ok(())
}

/// `adjfreq(2)` is not available on macOS.
///
/// Returns `ClockError::Unsupported`.
#[cfg(target_os = "macos")]
pub fn adjfreq(_freq: openntpd_rs_core::util::Frequency) -> ClockResult<()> {
    Err(ClockError::Unsupported)
}

/// Adjust the system clock frequency (adjfreq equivalent).
///
/// On Linux this is `adjtimex(2)` with `ADJ_FREQUENCY`.
/// `freq` is the **OpenBSD internal** frequency (ns/s × 2³²);
/// this function converts to Linux scaled-ppm internally.
#[cfg(target_os = "linux")]
pub fn adjfreq(freq: openntpd_rs_core::util::Frequency) -> ClockResult<()> {
    let linux_freq = openbsd_freq_to_linux(freq)?;
    let mut tx: libc::timex = unsafe { std::mem::zeroed() };
    tx.modes = libc::ADJ_FREQUENCY;
    tx.freq = linux_freq;
    // SAFETY: adjtimex is safe; timex is fully initialized.
    let ret = unsafe { libc::adjtimex(&mut tx) };
    if ret == -1 {
        return Err(ClockError::Syscall(std::io::Error::last_os_error()));
    }
    Ok(())
}

/// Step the clock (settimeofday equivalent).
///
/// `tv` is the new wall-clock time.
#[cfg(any(target_os = "linux", target_os = "freebsd", target_os = "macos"))]
pub fn set_clock_time(tv: &libc::timeval) -> ClockResult<()> {
    // SAFETY: settimeofday with valid timeval pointer.
    let ret = unsafe { libc::settimeofday(tv as *const _, std::ptr::null()) };
    if ret != 0 {
        return Err(ClockError::Syscall(std::io::Error::last_os_error()));
    }
    Ok(())
}

/// Slew the clock via adjtime.
///
/// Corresponds to OpenNTPD's `adjtime` call (or `adjtimex` with
/// `ADJ_OFFSET_SINGLESHOT` on Linux via `compat/adjtime_adjtimex.c`).
///
/// Available on Linux, FreeBSD, and macOS.
#[cfg(any(target_os = "linux", target_os = "freebsd", target_os = "macos"))]
pub fn adjtime_oss(delta: &libc::timeval) -> ClockResult<()> {
    // SAFETY: adjtime with valid timeval and null old delta pointer.
    let ret = unsafe { libc::adjtime(delta as *const _, std::ptr::null_mut()) };
    if ret != 0 {
        return Err(ClockError::Syscall(std::io::Error::last_os_error()));
    }
    Ok(())
}

/// macOS clock support via mach_timebase.
///
/// macOS does not have `adjfreq(2)` or `adjtimex(2)`. Clock
/// adjustment is done via `adjtime(2)` only, and monotonic time
/// is read via `mach_absolute_time()`.
#[cfg(target_os = "macos")]
pub mod mach {
    /// Get monotonic time in nanoseconds using `mach_absolute_time()`.
    ///
    /// Returns nanoseconds since system boot.
    #[must_use]
    pub fn get_monotonic_nanos() -> u64 {
        // SAFETY: mach_timebase_info and mach_absolute_time are
        // safe FFI calls that return values without side effects.
        unsafe {
            let mut info = std::mem::zeroed::<libc::mach_timebase_info_data_t>();
            libc::mach_timebase_info(&mut info);
            let absolute = libc::mach_absolute_time();
            // Convert to nanoseconds using timebase numerator/denominator.
            absolute * info.numer as u64 / info.denom as u64
        }
    }

    /// Get wall-clock time as (seconds, nanoseconds).
    ///
    /// Uses `gettimeofday(2)` which is available on macOS.
    #[must_use]
    pub fn get_wall_time() -> (i64, u32) {
        // SAFETY: gettimeofday with valid timeval pointer.
        let mut tv: libc::timeval = unsafe { std::mem::zeroed() };
        let ret = unsafe { libc::gettimeofday(&mut tv, std::ptr::null_mut()) };
        if ret == 0 {
            (tv.tv_sec, tv.tv_usec as u32 * 1000)
        } else {
            // Fallback: this should never happen on macOS.
            (0, 0)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_openbsd_to_linux_known() {
        // 1 ppm OpenBSD freq = 1000 * 2^32
        let freq = openntpd_rs_core::util::Frequency::from_ppm(1.0);
        #[cfg(target_os = "linux")]
        {
            let linux = openbsd_freq_to_linux(freq).unwrap();
            // Linux expects 2^16 for 1 ppm
            assert_eq!(linux, 1i64 << 16);
        }
    }

    #[test]
    fn test_linux_roundtrip() {
        #[cfg(target_os = "linux")]
        {
            let linux_freq: i64 = 1i64 << 17; // 2 ppm
            let openbsd = linux_freq_to_openbsd(linux_freq).unwrap();
            let back = openbsd_freq_to_linux(openbsd).unwrap();
            assert_eq!(back, linux_freq);
        }
    }

    #[test]
    fn test_openbsd_to_linux_overflow_rejected() {
        #[cfg(target_os = "linux")]
        {
            // Use a freq that would exceed i32 max after division
            let huge = openntpd_rs_core::util::Frequency::from_raw(i64::MAX);
            assert!(openbsd_freq_to_linux(huge).is_err());
        }
    }

    #[test]
    fn test_get_monotonic_time_basic() {
        let t1 = get_monotonic_time().unwrap();
        let t2 = get_monotonic_time().unwrap();
        assert!(t2 >= t1);
    }

    #[test]
    fn test_adjfreq_returns_result() {
        // adjfreq may not be available (e.g., running in a container),
        // but the call should at least return a Result, not panic.
        let freq = openntpd_rs_core::util::Frequency::from_ppm(0.0);
        let _result = adjfreq(freq);
    }

    #[test]
    #[cfg(target_os = "macos")]
    fn test_mach_monotonic_nanos() {
        let nanos = mach::get_monotonic_nanos();
        // Must be positive (system has been running)
        assert!(nanos > 0);
    }

    #[test]
    #[cfg(target_os = "macos")]
    fn test_mach_wall_time() {
        let (secs, nsec) = mach::get_wall_time();
        // POSIX epoch: must be > 2020 (1609459200)
        assert!(secs > 1_609_459_200);
        assert!(nsec < 1_000_000_000);
    }

    #[cfg(target_os = "freebsd")]
    #[test]
    fn test_freebsd_adjfreq_identity() {
        let freq = openntpd_rs_core::util::Frequency::from_ppm(1.0);
        let os_freq = openbsd_freq_to_os(freq).unwrap();
        let back = os_freq_to_openbsd(os_freq).unwrap();
        assert_eq!(freq.raw(), back.raw());
    }
}
