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
#[cfg(target_os = "linux")]
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
    freq.try_to_linux()
        .ok_or_else(|| ClockError::Overflow("frequency out of Linux adjtimex range"))
}

/// Convert Linux `adjtimex.freq` scaled-ppm to OpenBSD internal frequency.
///
/// Returns `Overflow` if the multiplication would overflow `i64`.
#[cfg(target_os = "linux")]
pub fn linux_freq_to_openbsd(linux_freq: i64) -> ClockResult<openntpd_rs_core::util::Frequency> {
    openntpd_rs_core::util::Frequency::from_linux_checked(linux_freq)
        .ok_or_else(|| ClockError::Overflow("linux_freq_to_openbsd: multiplication overflow"))
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
#[cfg(target_os = "linux")]
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
#[cfg(target_os = "linux")]
pub fn adjtime_oss(delta: &libc::timeval) -> ClockResult<()> {
    // SAFETY: adjtime with valid timeval and null old delta pointer.
    let ret = unsafe { libc::adjtime(delta as *const _, std::ptr::null_mut()) };
    if ret != 0 {
        return Err(ClockError::Syscall(std::io::Error::last_os_error()));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_openbsd_to_linux_known() {
        // 1 ppm OpenBSD freq = 1000 * 2^32
        let freq = openntpd_rs_core::util::Frequency::from_ppm(1.0);
        let linux = openbsd_freq_to_linux(freq).unwrap();
        // Linux expects 2^16 for 1 ppm
        assert_eq!(linux, 1i64 << 16);
    }

    #[test]
    fn test_linux_roundtrip() {
        let linux_freq: i64 = 1i64 << 17; // 2 ppm
        let openbsd = linux_freq_to_openbsd(linux_freq).unwrap();
        let back = openbsd_freq_to_linux(openbsd).unwrap();
        assert_eq!(back, linux_freq);
    }

    #[test]
    fn test_openbsd_to_linux_overflow_rejected() {
        // Use a freq that would exceed i32 max after division
        let huge = openntpd_rs_core::util::Frequency::from_raw(i64::MAX);
        assert!(openbsd_freq_to_linux(huge).is_err());
    }
}
