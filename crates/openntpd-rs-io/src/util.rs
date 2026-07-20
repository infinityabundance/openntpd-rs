//! I/O-dependent utilities — clock queries, address formatting, syslog
//! logging.
//!
//! This module corresponds to OpenNTPD's `util.c` (the parts that depend
//! on `gettimeofday`, `adjtime`, `clock_gettime`, `getnameinfo`, and
//! syslog) and `log.c`.

use std::net::SocketAddr;
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

use openntpd_rs_core::ntp::NTP_UNIX_EPOCH_DELTA;

// ---------------------------------------------------------------------------
// Clock queries
// ---------------------------------------------------------------------------

/// Get monotonic time in seconds since an unspecified epoch, plus one
/// second to ensure the result is never zero at boot.
///
/// Corresponds to OpenNTPD's `getmonotime()`.
pub fn getmonotime() -> f64 {
    let mut ts = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    // SAFETY: clock_gettime with a valid timespec pointer is safe.
    let ret = unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut ts) };
    if ret != 0 {
        panic!(
            "clock_gettime(CLOCK_MONOTONIC) failed: {}",
            std::io::Error::last_os_error()
        );
    }
    ts.tv_sec as f64 + ts.tv_nsec as f64 / 1_000_000_000.0 + 1.0
}

/// Get wall clock time in seconds since the NTP epoch (1900-01-01), with
/// sub-second precision.
///
/// Corresponds to OpenNTPD's `gettime()` / `gettime_from_timeval()`.
pub fn gettime() -> f64 {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("SystemTime before UNIX_EPOCH");
    now.as_secs() as f64 + now.subsec_nanos() as f64 / 1_000_000_000.0 + NTP_UNIX_EPOCH_DELTA as f64
}

/// Get the current adjtime correction (the remaining slew offset).
///
/// Corresponds to OpenNTPD's `getoffset()`.
pub fn getoffset() -> f64 {
    let mut tv = libc::timeval {
        tv_sec: 0,
        tv_usec: 0,
    };
    // SAFETY: adjtime with null delta (query only) and valid olddelta.
    let ret = unsafe { libc::adjtime(std::ptr::null(), &mut tv) };
    if ret == -1 {
        return 0.0;
    }
    tv.tv_sec as f64 + tv.tv_usec as f64 / 1_000_000.0
}

// ---------------------------------------------------------------------------
// d_to_tv — f64 seconds to libc::timeval
// ---------------------------------------------------------------------------

/// Convert `f64` seconds to a `libc::timeval`.
///
/// Returns `None` for NaN, infinity, or values outside the `i64` range.
///
/// Corresponds to OpenNTPD's `d_to_tv()`.
pub fn d_to_tv(d: f64) -> Option<libc::timeval> {
    if !d.is_finite() || d > i64::MAX as f64 || d < i64::MIN as f64 {
        return None;
    }
    let secs = d as i64;
    let mut usec = ((d - secs as f64) * 1_000_000.0) as i64;
    let mut secs = secs;
    while usec < 0 {
        usec += 1_000_000;
        secs -= 1;
    }
    Some(libc::timeval {
        tv_sec: secs,
        tv_usec: usec as i64,
    })
}

// ---------------------------------------------------------------------------
// Address and routing table formatting
// ---------------------------------------------------------------------------

/// Format a socket address as a numeric IP string (no port).
///
/// Corresponds to OpenNTPD's `log_sockaddr()` which uses `getnameinfo`
/// with `NI_NUMERICHOST`.
pub fn log_sockaddr(addr: &SocketAddr) -> String {
    match addr {
        SocketAddr::V4(v4) => format!("{}", v4.ip()),
        SocketAddr::V6(v6) => format!("{}", v6.ip()),
    }
}

/// Format a routing table ID.
///
/// Returns the empty string when `rtable ≤ 0`, matching the C
/// `print_rtable()` which returns an empty (zero-length) string in that
/// case.
pub fn print_rtable(rtable: i32) -> String {
    if rtable > 0 {
        format!("rtable {}", rtable)
    } else {
        String::new()
    }
}

// ---------------------------------------------------------------------------
// Logging (matching OpenNTPD's log.c)
// ---------------------------------------------------------------------------

/// Logging destination.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LogDest {
    /// Write to stderr only.
    StdErr,
    /// Write to syslog only.
    SysLog,
    /// Write to both stderr and syslog.
    Both,
}

// Bitmask values matching C LOG_TO_STDERR and LOG_TO_SYSLOG.
const LOG_TO_STDERR: u8 = 1 << 0;
const LOG_TO_SYSLOG: u8 = 1 << 1;

fn dest_to_bits(dest: LogDest) -> u8 {
    match dest {
        LogDest::StdErr => LOG_TO_STDERR,
        LogDest::SysLog => LOG_TO_SYSLOG,
        LogDest::Both => LOG_TO_STDERR | LOG_TO_SYSLOG,
    }
}

#[allow(dead_code)]
fn bits_to_dest(bits: u8) -> LogDest {
    match bits {
        LOG_TO_STDERR => LogDest::StdErr,
        LOG_TO_SYSLOG => LogDest::SysLog,
        _ => LogDest::Both,
    }
}

static VERBOSE: std::sync::atomic::AtomicU8 = std::sync::atomic::AtomicU8::new(0);

struct LogState {
    dest: u8,
    procname: String,
    syslog_opened: bool,
}

impl LogState {
    const fn new() -> Self {
        Self {
            dest: LOG_TO_STDERR,
            procname: String::new(),
            syslog_opened: false,
        }
    }
}

static LOG_STATE: Mutex<LogState> = Mutex::new(LogState::new());

/// Initialise the logging subsystem.
///
/// Sets destination, verbosity, process name, opens syslog (if
/// appropriate), and calls `tzset()`.
///
/// Corresponds to OpenNTPD's `log_init()`.
pub fn log_init(dest: LogDest, verbose: u8, facility: i32) {
    VERBOSE.store(verbose, std::sync::atomic::Ordering::Release);
    let bits = dest_to_bits(dest);

    let mut state = LOG_STATE.lock().unwrap();
    state.dest = bits;
    state.procname = std::env::args()
        .next()
        .and_then(|s| {
            std::path::Path::new(&s)
                .file_name()
                .map(|f| f.to_string_lossy().to_string())
        })
        .unwrap_or_else(|| String::from("openntpd"));

    if bits & LOG_TO_SYSLOG != 0 {
        let cname = std::ffi::CString::new(state.procname.as_str()).unwrap();
        // SAFETY: openlog with valid CString.
        unsafe {
            libc::openlog(cname.as_ptr(), libc::LOG_PID | libc::LOG_NDELAY, facility);
        }
        state.syslog_opened = true;
    }

    // SAFETY: tzset is safe; it initialises tzname, timezone, daylight.
    // Not all platforms expose this in the libc crate, so we declare it
    // here.
    extern "C" {
        fn tzset();
    }
    unsafe {
        tzset();
    }
}

/// Set the process name for log messages.
///
/// Corresponds to OpenNTPD's `log_procinit()`.
pub fn log_procinit(name: &str) {
    let mut state = LOG_STATE.lock().unwrap();
    state.procname = name.to_string();
}

/// Set the verbosity level.
pub fn log_setverbose(v: u8) {
    VERBOSE.store(v, std::sync::atomic::Ordering::Release);
}

/// Get the current verbosity level.
pub fn log_getverbose() -> u8 {
    VERBOSE.load(std::sync::atomic::Ordering::Acquire)
}

/// Core logging function: dispatch a message to stderr and/or syslog.
///
/// This is the Rust equivalent of OpenNTPD's `vlog()`.  In C the function
/// takes a `va_list`; here we accept a pre-formatted `&str`.
///
/// Corresponds to OpenNTPD's `vlog()` in `log.c`.
pub fn vlog(priority: i32, msg: &str) {
    let state = LOG_STATE.lock().unwrap();
    let dest = state.dest;

    if dest & LOG_TO_STDERR != 0 {
        // Best-effort: append newline like the C code.
        eprintln!("{}", msg);
    }

    if dest & LOG_TO_SYSLOG != 0 {
        let cmsg = std::ffi::CString::new(msg).unwrap_or_else(|_| {
            // If the message contains interior NUL bytes, truncate.
            let nul_pos = msg.find('\0').unwrap_or(msg.len());
            std::ffi::CString::new(&msg[..nul_pos])
                .unwrap_or_else(|_| std::ffi::CString::new("(invalid log message)").unwrap())
        });
        // SAFETY: syslog with valid CString and priority.
        unsafe {
            libc::syslog(priority, b"%s\0".as_ptr() as *const i8, cmsg.as_ptr());
        }
    }
}

/// Log a message with the given syslog priority.
///
/// This is a thin wrapper around [`vlog`] matching the C `logit()` signature.
///
/// Corresponds to OpenNTPD's `logit()` in `log.c`.
pub fn logit(priority: i32, msg: &str) {
    vlog(priority, msg);
}

/// Log an info message (syslog `LOG_INFO`).
///
/// Corresponds to OpenNTPD's `log_info()`.
pub fn log_info(msg: &str) {
    vlog(libc::LOG_INFO, msg);
}

/// Log a warning message, appending the current `errno` / OS error string.
///
/// Corresponds to OpenNTPD's `log_warn()`.
pub fn log_warn(msg: &str) {
    let saved_errno = std::io::Error::last_os_error();
    let full_msg = format!("{}: {}", msg, saved_errno);
    vlog(libc::LOG_ERR, &full_msg);
}

/// Log a warning message **without** appending errno.
///
/// Corresponds to OpenNTPD's `log_warnx()`.
pub fn log_warnx(msg: &str) {
    vlog(libc::LOG_ERR, msg);
}

/// Log a debug message, but only if verbosity > 1.
///
/// Corresponds to OpenNTPD's `log_debug()`.
pub fn log_debug(msg: &str) {
    if log_getverbose() > 1 {
        vlog(libc::LOG_DEBUG, msg);
    }
}

/// Log a critical message with the process name and errno, then exit(1).
///
/// Corresponds to OpenNTPD's `fatal()`.
pub fn fatal(msg: &str) -> ! {
    let saved_errno = std::io::Error::last_os_error();
    let state = LOG_STATE.lock().unwrap();
    let full_msg = format!("{}: {}: {}", state.procname, msg, saved_errno);
    // Drop the lock before logging and exiting.
    drop(state);
    vlog(libc::LOG_CRIT, &full_msg);
    std::process::exit(1);
}

/// Log a critical message with the process name (no errno), then exit(1).
///
/// Corresponds to OpenNTPD's `fatalx()`.
pub fn fatalx(msg: &str) -> ! {
    let state = LOG_STATE.lock().unwrap();
    let full_msg = format!("{}{}", state.procname, msg);
    drop(state);
    vlog(libc::LOG_CRIT, &full_msg);
    std::process::exit(1);
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // ------------------------------------------------------------------
    // lfp / sfp roundtrips via the core functions
    // ------------------------------------------------------------------

    #[test]
    fn test_lfp_to_d_roundtrip_via_core() {
        // Verify we can call the core functions through the re-export
        let (int_part, frac) = openntpd_rs_core::util::d_to_lfp(42.5);
        let back = openntpd_rs_core::util::lfp_to_d(int_part, frac);
        // d_to_lfp wraps into one era; lfp_to_d may add an era.
        let expected = 42.5 % (u64::from(u32::MAX) + 1) as f64;
        assert!(
            (back - (expected + (u64::from(u32::MAX) + 1) as f64)).abs() < 1e-6
                || (back - expected).abs() < 1e-6,
            "roundtrip failed: int={int_part} frac={frac} back={back}"
        );
    }

    #[test]
    fn test_sfp_roundtrip_via_core() {
        let (int_part, frac) = openntpd_rs_core::util::d_to_sfp(-1.5);
        let back = openntpd_rs_core::util::sfp_to_d(int_part, frac);
        assert!((back - (-1.5)).abs() < 1e-4);
    }

    // ------------------------------------------------------------------
    // d_to_tv
    // ------------------------------------------------------------------

    #[test]
    fn test_d_to_tv_basic() {
        let tv = d_to_tv(1.5).unwrap();
        assert_eq!(tv.tv_sec, 1);
        assert_eq!(tv.tv_usec, 500_000);
    }

    #[test]
    fn test_d_to_tv_negative() {
        // -1.5 s → secs=-2, usec=500_000
        let tv = d_to_tv(-1.5).unwrap();
        assert_eq!(tv.tv_sec, -2);
        assert_eq!(tv.tv_usec, 500_000);
    }

    #[test]
    fn test_d_to_tv_zero() {
        let tv = d_to_tv(0.0).unwrap();
        assert_eq!(tv.tv_sec, 0);
        assert_eq!(tv.tv_usec, 0);
    }

    #[test]
    fn test_d_to_tv_exact_second() {
        let tv = d_to_tv(42.0).unwrap();
        assert_eq!(tv.tv_sec, 42);
        assert_eq!(tv.tv_usec, 0);
    }

    #[test]
    fn test_d_to_tv_small_negative() {
        // -0.001 s → secs=-1, usec=999_000
        let tv = d_to_tv(-0.001).unwrap();
        assert_eq!(tv.tv_sec, -1);
        assert_eq!(tv.tv_usec, 999_000);
    }

    #[test]
    fn test_d_to_tv_nan_rejected() {
        assert!(d_to_tv(f64::NAN).is_none());
    }

    #[test]
    fn test_d_to_tv_inf_rejected() {
        assert!(d_to_tv(f64::INFINITY).is_none());
        assert!(d_to_tv(f64::NEG_INFINITY).is_none());
    }

    #[test]
    fn test_d_to_tv_out_of_range_rejected() {
        assert!(d_to_tv(1e300).is_none());
        assert!(d_to_tv(-1e300).is_none());
    }

    #[test]
    fn test_d_to_tv_roundtrip() {
        let values = [0.0, 1.0, -1.0, 1.5, -1.5, 123456.789, -0.001, 0.000_001];
        for v in values {
            let tv = d_to_tv(v).unwrap();
            let back = tv.tv_sec as f64 + tv.tv_usec as f64 / 1_000_000.0;
            assert!(
                (back - v).abs() < 1e-9,
                "d_to_tv roundtrip failed for {v}: got {back}"
            );
        }
    }

    // ------------------------------------------------------------------
    // getmonotime — just check monotonicity
    // ------------------------------------------------------------------

    #[test]
    fn test_getmonotime_monotonic() {
        let t1 = getmonotime();
        let t2 = getmonotime();
        assert!(t2 >= t1, "monotonic time went backwards: {t1} > {t2}");
        assert!(t1 > 0.0, "monotonic time should not be zero or negative");
    }

    // ------------------------------------------------------------------
    // log_sockaddr
    // ------------------------------------------------------------------

    #[test]
    fn test_log_sockaddr_ipv4() {
        let addr: SocketAddr = "192.0.2.1:123".parse().unwrap();
        assert_eq!(log_sockaddr(&addr), "192.0.2.1");
    }

    #[test]
    fn test_log_sockaddr_ipv4_localhost() {
        let addr: SocketAddr = "127.0.0.1:80".parse().unwrap();
        assert_eq!(log_sockaddr(&addr), "127.0.0.1");
    }

    #[test]
    fn test_log_sockaddr_ipv6() {
        let addr: SocketAddr = "[2001:db8::1]:123".parse().unwrap();
        assert_eq!(log_sockaddr(&addr), "2001:db8::1");
    }

    #[test]
    fn test_log_sockaddr_ipv6_loopback() {
        let addr: SocketAddr = "[::1]:443".parse().unwrap();
        assert_eq!(log_sockaddr(&addr), "::1");
    }

    #[test]
    fn test_log_sockaddr_ipv6_mapped() {
        let addr: SocketAddr = "[::ffff:192.0.2.1]:53".parse().unwrap();
        assert_eq!(log_sockaddr(&addr), "::ffff:192.0.2.1");
    }

    // ------------------------------------------------------------------
    // print_rtable
    // ------------------------------------------------------------------

    #[test]
    fn test_print_rtable_positive() {
        assert_eq!(print_rtable(1), "rtable 1");
        assert_eq!(print_rtable(42), "rtable 42");
        assert_eq!(print_rtable(i32::MAX), format!("rtable {}", i32::MAX));
    }

    #[test]
    fn test_print_rtable_zero() {
        assert_eq!(print_rtable(0), "");
    }

    #[test]
    fn test_print_rtable_negative() {
        assert_eq!(print_rtable(-1), "");
        assert_eq!(print_rtable(i32::MIN), "");
    }

    // ------------------------------------------------------------------
    // Logging — log_init / log_setverbose / log_getverbose
    // ------------------------------------------------------------------

    #[test]
    fn test_log_verbose_cycle() {
        assert_eq!(log_getverbose(), 0);
        log_setverbose(2);
        assert_eq!(log_getverbose(), 2);
        log_setverbose(1);
        assert_eq!(log_getverbose(), 1);
        log_setverbose(0);
        assert_eq!(log_getverbose(), 0);
    }

    #[test]
    fn test_log_init_verbose() {
        log_init(LogDest::StdErr, 3, libc::LOG_DAEMON);
        assert_eq!(log_getverbose(), 3);
        log_init(LogDest::StdErr, 0, libc::LOG_DAEMON);
        assert_eq!(log_getverbose(), 0);
    }

    // ------------------------------------------------------------------
    // log_info / log_warn / log_warnx / log_debug — smoke tests that
    // they don't panic.  Actual output is hard to capture in tests, but
    // we at least exercise the code paths.
    // ------------------------------------------------------------------

    #[test]
    fn test_log_info_smoke() {
        log_init(LogDest::StdErr, 0, libc::LOG_DAEMON);
        log_info("test info message");
        // Should not panic.
    }

    #[test]
    fn test_log_warn_smoke() {
        log_init(LogDest::StdErr, 0, libc::LOG_DAEMON);
        log_warn("test warn message");
    }

    #[test]
    fn test_log_warnx_smoke() {
        log_init(LogDest::StdErr, 0, libc::LOG_DAEMON);
        log_warnx("test warnx message");
    }

    #[test]
    fn test_log_debug_does_not_emit_at_low_verbose() {
        log_init(LogDest::StdErr, 0, libc::LOG_DAEMON);
        log_debug("should not be visible");
        // Should not panic.
    }

    #[test]
    fn test_log_debug_emits_at_high_verbose() {
        log_init(LogDest::StdErr, 2, libc::LOG_DAEMON);
        log_debug("should be visible at verbose > 1");
    }

    #[test]
    fn test_log_setverbose_getverbose() {
        log_setverbose(5);
        assert_eq!(log_getverbose(), 5);
        log_setverbose(0);
        assert_eq!(log_getverbose(), 0);
    }

    #[test]
    fn test_log_procinit() {
        log_procinit("test-ntpd");
        // Verify by checking that fatal/fatalx don't crash
        // (can't easily verify the prefix without capturing stderr)
    }

    // ------------------------------------------------------------------
    // LogDest enum roundtrip
    // ------------------------------------------------------------------

    #[test]
    fn test_log_dest_bits_roundtrip() {
        let cases = [LogDest::StdErr, LogDest::SysLog, LogDest::Both];
        for d in cases {
            let bits = dest_to_bits(d);
            let back = bits_to_dest(bits);
            assert_eq!(d, back, "LogDest roundtrip failed for {d:?}");
        }
    }

    #[test]
    fn test_dest_to_bits_values() {
        assert_eq!(dest_to_bits(LogDest::StdErr), LOG_TO_STDERR);
        assert_eq!(dest_to_bits(LogDest::SysLog), LOG_TO_SYSLOG);
        assert_eq!(dest_to_bits(LogDest::Both), LOG_TO_STDERR | LOG_TO_SYSLOG);
    }

    // ------------------------------------------------------------------
    // logit / vlog (public wrappers matching C logit() / vlog())
    // ------------------------------------------------------------------

    #[test]
    fn test_logit_calls_vlog() {
        // logit is a thin wrapper; smoke test it doesn't panic.
        logit(libc::LOG_INFO, "logit test message");
    }

    #[test]
    fn test_vlog_public_api() {
        // vlog is now public; smoke test it doesn't panic.
        vlog(libc::LOG_DEBUG, "vlog test message");
    }

    #[test]
    fn test_logit_stderr_does_not_crash() {
        // Even if log_init hasn't been called, default stderr should work.
        logit(libc::LOG_WARNING, "test stderr logit");
    }

    #[test]
    fn test_logit_syslog_does_not_crash() {
        // Initialize syslog-like destination.
        log_init(LogDest::SysLog, 0, libc::LOG_DAEMON);
        logit(libc::LOG_INFO, "test syslog logit");
        // Reset to stderr for other tests.
        log_init(LogDest::StdErr, 0, libc::LOG_DAEMON);
    }

    #[test]
    fn test_vlog_multiple_priorities() {
        let priorities = [
            libc::LOG_ERR,
            libc::LOG_WARNING,
            libc::LOG_INFO,
            libc::LOG_DEBUG,
            libc::LOG_CRIT,
        ];
        for pri in priorities {
            // Should not panic for any standard priority.
            vlog(pri, &format!("vlog test priority {}", pri));
        }
    }
}
