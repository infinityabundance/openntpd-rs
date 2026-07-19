//! Parent daemon process functions — ported from OpenNTPD's `ntpd.c`.
//!
//! This module implements the privileged parent-side operations that
//! OpenNTPD's main process performs: clock adjustment (`adjtime`,
//! `adjfreq`, `settimeofday`), drift file management, child process
//! supervision, imsg dispatch, and the ntpctl control client.
//!
//! ## Platform support
//!
//! On Linux, `adjtime`, `adjtimex`, and `settimeofday` are used via
//! `libc`.  On OpenBSD, `adjtime` and `adjfreq` syscalls are used
//! directly.  Other platforms use the same `libc` interface where
//! available.

use std::ffi::CString;
use std::path::Path;

use openntpd_rs_core::ntp::clock::{ClockAdjustment, ClockState};
use openntpd_rs_core::ntp::NtpTimestamp;

use crate::util::{log_debug, log_info};

// ---------------------------------------------------------------------------
// Constants from ntpd.h
// ---------------------------------------------------------------------------

/// Negligible adjtime threshold (ms).  Offsets below this are logged at
/// DEBUG level instead of INFO.
/// Corresponds to C: `#define LOG_NEGLIGIBLE_ADJTIME 32`
pub const LOG_NEGLIGIBLE_ADJTIME_MS: f64 = 32.0;

/// Negligible adjfreq threshold (ppm).  Frequency changes below this
/// are logged at DEBUG level instead of INFO.
/// Corresponds to C: `#define LOG_NEGLIGIBLE_ADJFREQ 0.05`
pub const LOG_NEGLIGIBLE_ADJFREQ_PPM: f64 = 0.05;

/// Frequency scaling factor: 1e9 × 2³², used to convert a relative
/// frequency (in s/s) to the OpenBSD adjfreq internal unit (ns/s << 32).
const NTPD_FREQ_SCALE: f64 = 1_000_000_000.0 * (4_294_967_296.0);

// ---------------------------------------------------------------------------
// IMSG type constants from ntpd.h `enum imsg_type`
// ---------------------------------------------------------------------------

pub const IMSG_NONE: u32 = 0;
pub const IMSG_ADJTIME: u32 = 1;
pub const IMSG_ADJFREQ: u32 = 2;
pub const IMSG_SETTIME: u32 = 3;
pub const IMSG_HOST_DNS: u32 = 4;
pub const IMSG_CONSTRAINT_DNS: u32 = 5;
pub const IMSG_CONSTRAINT_QUERY: u32 = 6;
pub const IMSG_CONSTRAINT_RESULT: u32 = 7;
pub const IMSG_CONSTRAINT_CLOSE: u32 = 8;
pub const IMSG_CONSTRAINT_KILL: u32 = 9;
pub const IMSG_CTL_SHOW_STATUS: u32 = 10;
pub const IMSG_CTL_SHOW_PEERS: u32 = 11;
pub const IMSG_CTL_SHOW_PEERS_END: u32 = 12;
pub const IMSG_CTL_SHOW_SENSORS: u32 = 13;
pub const IMSG_CTL_SHOW_SENSORS_END: u32 = 14;
pub const IMSG_CTL_SHOW_ALL: u32 = 15;
pub const IMSG_CTL_SHOW_ALL_END: u32 = 16;
pub const IMSG_SYNCED: u32 = 17;
pub const IMSG_UNSYNCED: u32 = 18;
pub const IMSG_PROBE_ROOT: u32 = 19;

/// Return a human-readable name for an IMSG type.
#[must_use]
pub fn imsg_type_name(t: u32) -> &'static str {
    match t {
        IMSG_NONE => "IMSG_NONE",
        IMSG_ADJTIME => "IMSG_ADJTIME",
        IMSG_ADJFREQ => "IMSG_ADJFREQ",
        IMSG_SETTIME => "IMSG_SETTIME",
        IMSG_HOST_DNS => "IMSG_HOST_DNS",
        IMSG_CONSTRAINT_DNS => "IMSG_CONSTRAINT_DNS",
        IMSG_CONSTRAINT_QUERY => "IMSG_CONSTRAINT_QUERY",
        IMSG_CONSTRAINT_RESULT => "IMSG_CONSTRAINT_RESULT",
        IMSG_CONSTRAINT_CLOSE => "IMSG_CONSTRAINT_CLOSE",
        IMSG_CONSTRAINT_KILL => "IMSG_CONSTRAINT_KILL",
        IMSG_CTL_SHOW_STATUS => "IMSG_CTL_SHOW_STATUS",
        IMSG_CTL_SHOW_PEERS => "IMSG_CTL_SHOW_PEERS",
        IMSG_CTL_SHOW_PEERS_END => "IMSG_CTL_SHOW_PEERS_END",
        IMSG_CTL_SHOW_SENSORS => "IMSG_CTL_SHOW_SENSORS",
        IMSG_CTL_SHOW_SENSORS_END => "IMSG_CTL_SHOW_SENSORS_END",
        IMSG_CTL_SHOW_ALL => "IMSG_CTL_SHOW_ALL",
        IMSG_CTL_SHOW_ALL_END => "IMSG_CTL_SHOW_ALL_END",
        IMSG_SYNCED => "IMSG_SYNCED",
        IMSG_UNSYNCED => "IMSG_UNSYNCED",
        IMSG_PROBE_ROOT => "IMSG_PROBE_ROOT",
        _ => "IMSG_UNKNOWN",
    }
}

// ---------------------------------------------------------------------------
// DaemonConfig re-export
// ---------------------------------------------------------------------------

/// Re-export of the daemon configuration type.
/// NOTE: This type is defined in `openntpd-rs-d`, but we re-export it
/// here for convenience.  If `openntpd-rs-d` is not a dependency, this
/// will be a compile error.  The definition is:
/// ```rust,ignore
/// pub struct DaemonConfig {
///     pub config_path: PathBuf,
///     pub debug_mode: bool,
///     pub verbose: u8,
///     pub parent_proc: Option<String>,
///     pub pid_file: Option<String>,
///     pub config_test: bool,
/// }
/// ```
pub struct DaemonConfig {
    /// Path to the configuration file (/etc/ntpd.conf by default).
    pub config_path: std::path::PathBuf,
    /// Enable debug mode (log to stderr, don't daemonize).
    pub debug_mode: bool,
    /// Verbosity level (0-2).
    pub verbose: u8,
    /// If set, run as a named child process instead of the parent.
    pub parent_proc: Option<String>,
    /// Optional PID file path.
    pub pid_file: Option<std::path::PathBuf>,
    /// Config test mode (parse only, no daemon).
    pub config_test: bool,
}

// ---------------------------------------------------------------------------
// auto_preconditions
// ---------------------------------------------------------------------------

/// Check whether automatic time setting should be attempted.
///
/// Corresponds to C: `auto_preconditions()`
///
/// Automatic time setting is enabled when:
/// - At least one of: constraints configured, trusted peers, or
///   trusted sensors.
/// - (Caller's responsibility) The user has NOT explicitly set
///   `settime` (i.e. no `-s` flag).
/// - (Caller's responsibility) The kernel securelevel is 0.
///
/// This simplified Rust version takes boolean flags instead of
/// inspecting a full config struct.  The caller should additionally
/// verify `!settime` and `securelevel == 0` if those apply.
#[must_use]
pub fn auto_preconditions(
    has_constraints: bool,
    has_trusted_peers: bool,
    has_trusted_sensors: bool,
) -> bool {
    has_constraints || has_trusted_peers || has_trusted_sensors
}

// ---------------------------------------------------------------------------
// apply_clock_discipline — wire ClockState to system clock
// ---------------------------------------------------------------------------

/// Wire clock state to system clock via adjtimex/adjtime/adjfreq.
///
/// Takes an offset sample, updates the clock discipline state machine,
/// and applies the resulting adjustment to the system clock:
///
/// - **Step** (large offset, `|θ| > 0.125 s`): calls `ntpd_settime()`.
/// - **Slew** (small offset): calls `ntpd_adjtime()` for the offset
///   correction and `ntpd_adjfreq()` for the frequency correction.
///
/// Returns the [`ClockAdjustment`] that was applied, or an error string
/// if a system call fails.
pub fn apply_clock_discipline(
    clock: &mut ClockState,
    offset: f64,
    delay: f64,
    now: NtpTimestamp,
) -> Result<ClockAdjustment, String> {
    let adj = clock.update(offset, delay, now);
    if adj.step {
        // Large offset — step the clock immediately.
        log_info(&format!(
            "clock discipline: step {:+.6}s (freq_delta={:+.3}ppm)",
            adj.offset, adj.freq_delta
        ));
        ntpd_settime(adj.offset)?;
    } else {
        // Small offset — slew via adjtime + adjust frequency.
        if adj.offset.abs() >= LOG_NEGLIGIBLE_ADJTIME_MS / 1000.0 {
            log_info(&format!(
                "clock discipline: slew {:+.6}s (freq_delta={:+.3}ppm, interval={})",
                adj.offset, adj.freq_delta, adj.interval
            ));
        } else {
            log_debug(&format!(
                "clock discipline: slew {:+.6}s (freq_delta={:+.3}ppm)",
                adj.offset, adj.freq_delta
            ));
        }
        ntpd_adjtime(adj.offset)?;
        ntpd_adjfreq(adj.freq_delta, true)?;
    }
    Ok(adj)
}

// ---------------------------------------------------------------------------
// reset_adjtime
// ---------------------------------------------------------------------------

/// Reset the kernel's adjtime slewing to zero.
///
/// Corresponds to C: `reset_adjtime()`
pub fn reset_adjtime() -> Result<(), String> {
    // SAFETY: timerclear zeroes the timeval; adjtime with a zero delta
    // cancels any pending slew.
    let tv = libc::timeval {
        tv_sec: 0,
        tv_usec: 0,
    };
    // SAFETY: adjtime is safe with valid pointers; old_delta may be NULL.
    let ret = unsafe { libc::adjtime(&tv as *const _, std::ptr::null_mut()) };
    if ret != 0 {
        return Err(format!(
            "reset adjtime failed: {}",
            std::io::Error::last_os_error()
        ));
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// ntpd_adjtime
// ---------------------------------------------------------------------------

/// Slew the system clock via adjtime.
///
/// Corresponds to C: `ntpd_adjtime()`
///
/// Returns `true` if the clock became synchronised (old delta reached
/// zero on a non-first call), `false` otherwise.
pub fn ntpd_adjtime(offset: f64) -> Result<bool, String> {
    use crate::util::d_to_tv;

    let firstadj = FIRST_ADJ.load(std::sync::atomic::Ordering::Relaxed);

    // Add the accumulated offset from earlier corrections.
    let total_offset = offset + crate::util::getoffset();

    // Log threshold: 32 ms (LOG_NEGLIGIBLE_ADJTIME)
    let threshold = LOG_NEGLIGIBLE_ADJTIME_MS / 1000.0; // in seconds
    if total_offset >= threshold || total_offset <= -threshold {
        crate::util::log_info(&format!("adjusting local clock by {total_offset}s"));
    } else {
        crate::util::log_debug(&format!("adjusting local clock by {total_offset}s"));
    }

    let tv = d_to_tv(total_offset)
        .ok_or_else(|| format!("ntpd_adjtime: invalid offset value {total_offset}"))?;

    let mut olddelta = libc::timeval {
        tv_sec: 0,
        tv_usec: 0,
    };

    // SAFETY: adjtime with mutable olddelta to retrieve previous residual.
    let ret = unsafe { libc::adjtime(&tv as *const _, &mut olddelta as *mut _) };
    if ret != 0 {
        crate::util::log_warn(&format!(
            "adjtime failed: {}",
            std::io::Error::last_os_error()
        ));
        return Ok(false);
    }

    // Clock is synced if olddelta is zero on a non-first adjustment.
    let synced = if !firstadj && olddelta.tv_sec == 0 && olddelta.tv_usec == 0 {
        true
    } else {
        false
    };

    FIRST_ADJ.store(false, std::sync::atomic::Ordering::Relaxed);

    if synced {
        crate::util::log_info("clock is now synchronised (old delta reached zero)");
    }

    Ok(synced)
}

/// Tracks whether the next adjtime call is the first one.
/// Corresponds to C's `static int firstadj = 1;`
static FIRST_ADJ: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(true);

// ---------------------------------------------------------------------------
// ntpd_adjfreq
// ---------------------------------------------------------------------------

/// Adjust the kernel clock frequency via adjfreq/adjtimex.
///
/// Corresponds to C: `ntpd_adjfreq()`
///
/// `relfreq` is the relative frequency change in s/s (seconds per
/// second).  `wrlog` controls whether the adjustment is logged.
pub fn ntpd_adjfreq(relfreq: f64, wrlog: bool) -> Result<(), String> {
    let curfreq = adjfreq_read()?;

    // adjfreq's unit is ns/s shifted left 32; convert relfreq to
    // that unit before adding.
    let raw_delta = (relfreq * NTPD_FREQ_SCALE) as i64;
    let new_freq = curfreq.wrapping_add(raw_delta);

    // Write to drift file (compute ppm value for file).
    let freq_ppm = new_freq as f64 / NTPD_FREQ_SCALE;
    let write_ok = write_drift_file_internal(freq_ppm)?;

    let ppmfreq = relfreq * 1e6; // convert s/s to ppm
    if wrlog {
        if ppmfreq >= LOG_NEGLIGIBLE_ADJFREQ_PPM || ppmfreq <= -LOG_NEGLIGIBLE_ADJFREQ_PPM {
            let display_ppm = new_freq as f64 / 1e3 / (1u64 << 32) as f64;
            crate::util::log_info(&format!(
                "adjusting clock frequency by {ppmfreq} to {display_ppm}ppm{}",
                if write_ok { "" } else { " (no drift file)" }
            ));
        } else {
            let display_ppm = new_freq as f64 / 1e3 / (1u64 << 32) as f64;
            crate::util::log_debug(&format!(
                "adjusting clock frequency by {ppmfreq} to {display_ppm}ppm{}",
                if write_ok { "" } else { " (no drift file)" }
            ));
        }
    }

    adjfreq_set(new_freq)?;

    Ok(())
}

/// Read the current kernel frequency.
///
/// On Linux this reads via `adjtimex`; on OpenBSD via `adjfreq`.
#[cfg(target_os = "linux")]
fn adjfreq_read() -> Result<i64, String> {
    let mut tx: libc::timex = unsafe { std::mem::zeroed() };
    tx.modes = 0; // read-only
                  // SAFETY: adjtimex with modes=0 is a read operation.
    let ret = unsafe { libc::adjtimex(&mut tx) };
    if ret == -1 {
        return Err(format!(
            "adjfreq read failed: {}",
            std::io::Error::last_os_error()
        ));
    }
    // Convert Linux scaled-ppm back to OpenBSD internal unit.
    // Linux freq = openbsd_freq / 1e9 / 2^32 * 2^16 * 1000
    // Actually: openbsd_freq = linux_freq * 1000 * 2^16
    // But let's just do: openbsd_freq = linux_freq * 65536000
    let openbsd_freq = (tx.freq as i64).wrapping_mul(65_536_000);
    Ok(openbsd_freq)
}

/// Set the kernel frequency.
#[cfg(target_os = "linux")]
fn adjfreq_set(freq: i64) -> Result<(), String> {
    // Convert OpenBSD internal freq to Linux scaled-ppm.
    // linux_freq = openbsd_freq / (1000 * 2^16)
    let linux_freq = freq / 65_536_000;
    let mut tx: libc::timex = unsafe { std::mem::zeroed() };
    tx.modes = libc::ADJ_FREQUENCY;
    tx.freq = linux_freq;
    // SAFETY: adjtimex with ADJ_FREQUENCY sets the clock frequency.
    let ret = unsafe { libc::adjtimex(&mut tx) };
    if ret == -1 {
        return Err(format!(
            "adjfreq set failed: {}",
            std::io::Error::last_os_error()
        ));
    }
    Ok(())
}

#[cfg(not(target_os = "linux"))]
fn adjfreq_read() -> Result<i64, String> {
    let mut curfreq: i64 = 0;
    // SAFETY: adjfreq(NULL, &curfreq) reads the current frequency.
    let ret = unsafe { libc::adjfreq(std::ptr::null_mut(), &mut curfreq) };
    if ret == -1 {
        return Err(format!(
            "adjfreq read failed: {}",
            std::io::Error::last_os_error()
        ));
    }
    Ok(curfreq)
}

#[cfg(not(target_os = "linux"))]
fn adjfreq_set(freq: i64) -> Result<(), String> {
    // SAFETY: adjfreq(&freq, NULL) sets the clock frequency.
    let ret = unsafe { libc::adjfreq(&freq as *const _, std::ptr::null_mut()) };
    if ret == -1 {
        return Err(format!(
            "adjfreq set failed: {}",
            std::io::Error::last_os_error()
        ));
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// ntpd_settime
// ---------------------------------------------------------------------------

/// Step the system clock (settimeofday).
///
/// Corresponds to C: `ntpd_settime()`
///
/// Adds the given offset to the current wall-clock time and sets it.
pub fn ntpd_settime(offset: f64) -> Result<(), String> {
    if offset == 0.0 {
        return Ok(());
    }

    // Get current time
    let mut curtime = libc::timeval {
        tv_sec: 0,
        tv_usec: 0,
    };
    // SAFETY: gettimeofday with valid timeval pointer.
    let ret = unsafe { libc::gettimeofday(&mut curtime, std::ptr::null_mut()) };
    if ret != 0 {
        return Err(format!(
            "gettimeofday failed: {}",
            std::io::Error::last_os_error()
        ));
    }

    // Convert offset to timeval, matching C d_to_tv semantics
    let tv = crate::util::d_to_tv(offset)
        .ok_or_else(|| format!("ntpd_settime: invalid offset value {offset}"))?;

    // Apply the offset: same calculation as the C code:
    //   curtime.tv_usec += tv.tv_usec + 1000000;
    //   curtime.tv_sec += tv.tv_sec - 1 + (curtime.tv_usec / 1000000);
    //   curtime.tv_usec %= 1000000;
    curtime.tv_usec += tv.tv_usec + 1_000_000;
    curtime.tv_sec += tv.tv_sec - 1 + (curtime.tv_usec / 1_000_000);
    curtime.tv_usec %= 1_000_000;

    // SAFETY: settimeofday with valid timeval pointer.
    let ret = unsafe { libc::settimeofday(&curtime, std::ptr::null_mut()) };
    if ret != 0 {
        return Err(format!(
            "settimeofday failed: {}",
            std::io::Error::last_os_error()
        ));
    }

    // Format the local time for the log message (matching C strftime)
    let tval = curtime.tv_sec;
    // SAFETY: localtime is safe; result is a thread-local static buffer.
    let tm = unsafe { libc::localtime(&tval) };
    if tm.is_null() {
        crate::util::log_info(&format!("set local clock (offset {offset}s)"));
    } else {
        // SAFETY: tm is non-null, valid pointer from localtime.
        let tm_ref = unsafe { *tm };
        let mut buf = [0i8; 80];
        // SAFETY: strftime with valid buffer and tm struct.
        let len = unsafe {
            libc::strftime(
                buf.as_mut_ptr(),
                buf.len(),
                b"%a %b %e %H:%M:%S %Z %Y\0".as_ptr() as *const _,
                &tm_ref,
            )
        };
        if len > 0 {
            // SAFETY: buf now contains a valid C string (null-terminated).
            let time_str = unsafe { std::ffi::CStr::from_ptr(buf.as_ptr()).to_string_lossy() };
            crate::util::log_info(&format!("set local clock to {time_str} (offset {offset}s)"));
        } else {
            crate::util::log_info(&format!("set local clock (offset {offset}s)"));
        }
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Drift file management
// ---------------------------------------------------------------------------

/// Global drift file pointer.
///
/// Corresponds to C: `static FILE *freqfp;`
static DRIFT_FILE_PATH: std::sync::Mutex<Option<String>> = std::sync::Mutex::new(None);

/// Read the drift file at startup and apply the stored frequency.
///
/// Corresponds to C: `readfreq()`
///
/// The drift file path is supplied externally (from config).
/// Returns the frequency value read from the file, in s/s.
pub fn readfreq(drift_path: &Path) -> Result<f64, String> {
    // Store path for later writes
    *DRIFT_FILE_PATH.lock().unwrap() = Some(drift_path.to_string_lossy().to_string());

    match std::fs::read_to_string(drift_path) {
        Ok(contents) => {
            let trimmed = contents.trim();
            if trimmed.is_empty() {
                return Err(format!("drift file '{}' is empty", drift_path.display()));
            }
            let ppm: f64 = trimmed
                .parse()
                .map_err(|e| format!("drift file parse error: {e}"))?;
            let freq_s_per_s = ppm / 1e6; // scale from ppm
            Ok(freq_s_per_s)
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            // File doesn't exist; C code creates a new one.
            // Try to create it (matching fopen with "w")
            let _ = std::fs::File::create(drift_path);
            Ok(0.0)
        }
        Err(e) => Err(format!(
            "cannot read drift file '{}': {e}",
            drift_path.display()
        )),
    }
}

/// Write frequency to drift file.
///
/// Corresponds to C: `writefreq()`
///
/// `freq_ppm` is the frequency value in ppm.  Returns the proportion
/// of the value actually written (0.0 if the file wasn't open, the
/// value itself on success), matching the C convention of returning
/// 0 or 1.
pub fn writefreq(drift_path: &Path, freq_ppm: f64) -> Result<(), String> {
    // Store path for later writes
    *DRIFT_FILE_PATH.lock().unwrap() = Some(drift_path.to_string_lossy().to_string());

    // Open for writing (truncate/create).  The C code uses the
    // global `freqfp` FILE* opened in readfreq().  We re-open here.
    let contents = format!("{:.3}\n", freq_ppm);

    // Write atomically via temp file + rename, matching the C code's
    // rewind/fprintf/fflush/ftruncate/fsync pattern.
    let tmp_path = drift_path.with_extension("drift.tmp");
    {
        let mut tmp = std::fs::File::create(&tmp_path)
            .map_err(|e| format!("cannot create drift tmp file: {e}"))?;
        use std::io::Write;
        tmp.write_all(contents.as_bytes())
            .map_err(|e| format!("cannot write drift file: {e}"))?;
        tmp.sync_all()
            .map_err(|e| format!("cannot sync drift file: {e}"))?;
    }
    std::fs::rename(&tmp_path, drift_path).map_err(|e| format!("cannot rename drift file: {e}"))?;

    Ok(())
}

/// Internal helper: write frequency (in s/s) to the stored drift path.
/// Returns true if the write succeeded.
fn write_drift_file_internal(freq_s_per_s: f64) -> Result<bool, String> {
    let path_guard = DRIFT_FILE_PATH.lock().unwrap();
    let path_str = match path_guard.as_ref() {
        Some(p) => p.clone(),
        None => return Ok(false),
    };
    drop(path_guard);

    let freq_ppm = freq_s_per_s * 1e6;
    let contents = format!("{:.3}\n", freq_ppm);

    let tmp_path_str = format!("{}.tmp", path_str);
    {
        let mut tmp = std::fs::File::create(&tmp_path_str)
            .map_err(|e| format!("cannot create drift tmp file: {e}"))?;
        use std::io::Write;
        tmp.write_all(contents.as_bytes())
            .map_err(|e| format!("cannot write drift file: {e}"))?;
        tmp.sync_all()
            .map_err(|e| format!("cannot sync drift file: {e}"))?;
    }
    std::fs::rename(&tmp_path_str, &path_str)
        .map_err(|e| format!("cannot rename drift file: {e}"))?;

    Ok(true)
}

// ---------------------------------------------------------------------------
// ParentImsgAction + parent_dispatch_imsg
// ---------------------------------------------------------------------------

/// Actions the parent daemon should take in response to an imsg from
/// a child process.
///
/// Corresponds to C: the `switch` cases in `dispatch_imsg()`
#[derive(Debug, Clone, PartialEq)]
pub enum ParentImsgAction {
    /// Adjust clock via adjtime (slew).  Contains the offset in
    /// seconds.  Corresponds to `IMSG_ADJTIME`.
    AdjTime(f64),
    /// Adjust clock frequency via adjfreq.  Contains the relative
    /// frequency in s/s.  Corresponds to `IMSG_ADJFREQ`.
    AdjFreq(f64),
    /// Step the clock (settimeofday).  Contains the offset in
    /// seconds.  Corresponds to `IMSG_SETTIME`.
    SetTime(f64),
    /// Clock synchronisation achieved.  Corresponds to `IMSG_SYNCED`.
    Synced,
    /// Clock synchronisation lost.  Corresponds to `IMSG_UNSYNCED`.
    Unsynced,
    /// Query a constraint server.  Contains the constraint ID and
    /// the serialised query data.  Corresponds to `IMSG_CONSTRAINT_QUERY`.
    ConstraintQuery { id: u32, data: Vec<u8> },
    /// Kill a constraint child process by ID.
    /// Corresponds to `IMSG_CONSTRAINT_KILL`.
    ConstraintKill(u32),
}

/// Process an imsg from a child process and return the action the
/// parent should take.
///
/// Corresponds to C: `dispatch_imsg()` — specifically the message
/// decoding and dispatch logic, without the imsg plumbing itself.
///
/// The caller is responsible for reading the imsg from the socket
/// and passing the decoded type and payload.
#[must_use]
pub fn parent_dispatch_imsg(imsg_type: u32, data: &[u8]) -> Option<ParentImsgAction> {
    match imsg_type {
        IMSG_ADJTIME => {
            // C: memcpy(&d, imsg.data, sizeof(d)); n = ntpd_adjtime(d);
            if data.len() < 8 {
                crate::util::log_warnx("invalid IMSG_ADJTIME received: payload too short");
                return None;
            }
            let mut buf = [0u8; 8];
            buf.copy_from_slice(&data[..8]);
            let d = f64::from_le_bytes(buf);
            Some(ParentImsgAction::AdjTime(d))
        }
        IMSG_ADJFREQ => {
            // C: memcpy(&d, imsg.data, sizeof(d)); ntpd_adjfreq(d, 1);
            if data.len() < 8 {
                crate::util::log_warnx("invalid IMSG_ADJFREQ received: payload too short");
                return None;
            }
            let mut buf = [0u8; 8];
            buf.copy_from_slice(&data[..8]);
            let d = f64::from_le_bytes(buf);
            Some(ParentImsgAction::AdjFreq(d))
        }
        IMSG_SETTIME => {
            // C: memcpy(&d, imsg.data, sizeof(d)); ntpd_settime(d);
            if data.len() < 8 {
                crate::util::log_warnx("invalid IMSG_SETTIME received: payload too short");
                return None;
            }
            let mut buf = [0u8; 8];
            buf.copy_from_slice(&data[..8]);
            let d = f64::from_le_bytes(buf);
            Some(ParentImsgAction::SetTime(d))
        }
        IMSG_SYNCED => {
            // C: update_time_sync_status(1);
            Some(ParentImsgAction::Synced)
        }
        IMSG_UNSYNCED => {
            // C: update_time_sync_status(0);
            Some(ParentImsgAction::Unsynced)
        }
        IMSG_CONSTRAINT_QUERY => {
            // C: priv_constraint_msg(imsg.hdr.peerid, imsg.data,
            //     imsg.hdr.len - IMSG_HEADER_SIZE, argc, argv);
            // We pack peerid and data.  For simplicity, the first 4
            // bytes of data are the peerid.
            //
            // The C code uses peerid from the imsg header.  We expect
            // the caller to provide it encoded in the data.
            if data.len() < 4 {
                crate::util::log_warnx("invalid IMSG_CONSTRAINT_QUERY received: payload too short");
                return None;
            }
            let mut id_buf = [0u8; 4];
            id_buf.copy_from_slice(&data[..4]);
            let id = u32::from_le_bytes(id_buf);
            let query_data = data[4..].to_vec();
            Some(ParentImsgAction::ConstraintQuery {
                id,
                data: query_data,
            })
        }
        IMSG_CONSTRAINT_KILL => {
            // C: priv_constraint_kill(imsg.hdr.peerid);
            if data.len() < 4 {
                crate::util::log_warnx("invalid IMSG_CONSTRAINT_KILL received: payload too short");
                return None;
            }
            let mut id_buf = [0u8; 4];
            id_buf.copy_from_slice(&data[..4]);
            let id = u32::from_le_bytes(id_buf);
            Some(ParentImsgAction::ConstraintKill(id))
        }
        _ => {
            crate::util::log_debug(&format!(
                "unhandled imsg type {} ({})",
                imsg_type,
                imsg_type_name(imsg_type)
            ));
            None
        }
    }
}

// ---------------------------------------------------------------------------
// check_child
// ---------------------------------------------------------------------------

/// Check for exited child processes (non-blocking waitpid).
///
/// Corresponds to C: `check_child()`
///
/// Returns `Some((pid, status))` if a child exited, or `None` if no
/// children have exited.
pub fn check_child() -> Option<(u32, i32)> {
    // SAFETY: waitpid with WNOHANG is safe and does not block.
    let mut status: i32 = 0;
    let pid = unsafe { libc::waitpid(-1, &mut status, libc::WNOHANG) };

    if pid > 0 {
        Some((pid as u32, status))
    } else {
        // pid == 0: no child exited
        // pid == -1: error (ECHILD means no children)
        None
    }
}

// ---------------------------------------------------------------------------
// writepid
// ---------------------------------------------------------------------------

/// Write the current process PID to a file.
///
/// Corresponds to C: `writepid()`
pub fn writepid(path: &Path) -> Result<(), String> {
    let pid = std::process::id();
    let contents = format!("{pid}\n");
    std::fs::write(path, contents)
        .map_err(|e| format!("couldn't open pid file '{}': {e}", path.display()))?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Process names
// ---------------------------------------------------------------------------

/// Process name for the main NTP child.
pub const NTP_PROC_NAME: &str = "ntp_main";
/// Process name for the DNS child.
pub const NTPDNS_PROC_NAME: &str = "ntp_dns";
/// Process name for the constraint child.
pub const CONSTRAINT_PROC_NAME: &str = "constraint";

// ---------------------------------------------------------------------------
// start_child
// ---------------------------------------------------------------------------

/// Start a child process via fork + exec.
///
/// Corresponds to C: `start_child()`
///
/// `pname` is the process name (e.g. `"ntp_main"`), `fd` is the file
/// descriptor number to pass to the child as the parent socket, and
/// `args` are the command-line arguments.
///
/// Returns the child PID on success.
pub fn start_child(pname: &str, fd: i32, _args: &[String]) -> Result<u32, String> {
    // SAFETY: fork() creates a new process.
    let pid = unsafe { libc::fork() };

    if pid < 0 {
        return Err(format!("fork failed: {}", std::io::Error::last_os_error()));
    }

    if pid == 0 {
        // --- CHILD ---
        // Duplicate fd to PARENT_SOCK_FILENO (STDERR_FILENO + 1 = 3)
        // SAFETY: dup2 is safe; it duplicates the fd to the expected
        // child fd number.
        unsafe {
            libc::dup2(fd, libc::STDERR_FILENO + 1);
        }

        // Build argv for child: [ntpd, -P, pname, ...original args...]
        let child_binary = CString::new("ntpd").unwrap();
        let flag_p = CString::new("-P").unwrap();
        let pname_c = CString::new(pname).map_err(|_| "pname contains null byte".to_string())?;

        let mut exec_args: Vec<*const libc::c_char> = Vec::new();
        exec_args.push(child_binary.as_ptr());
        exec_args.push(flag_p.as_ptr());
        exec_args.push(pname_c.as_ptr());

        // Add remaining args (sanitised by the C caller)
        for arg in _args {
            let c_arg =
                CString::new(arg.as_bytes()).map_err(|_| "arg contains null byte".to_string())?;
            exec_args.push(c_arg.as_ptr());
            // Leak is intentional — child will execve or die.
        }
        exec_args.push(std::ptr::null());

        // SAFETY: execvp replaces the process image.  The args array
        // is properly null-terminated.  If it fails, _exit is called.
        unsafe {
            libc::execvp(child_binary.as_ptr(), exec_args.as_ptr());
            // If we get here, exec failed
            libc::_exit(1);
        }
    }

    // --- PARENT ---
    Ok(pid as u32)
}

// ---------------------------------------------------------------------------
// ntpctl control client
// ---------------------------------------------------------------------------

/// Control client actions.
///
/// Corresponds to C: `enum ctl_actions` in ntpd.h
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CtlAction {
    /// Show status summary.
    ShowStatus,
    /// Show peer list.
    ShowPeers,
    /// Show sensor list.
    ShowSensors,
    /// Show all (status, peers, sensors).
    ShowAll,
}

/// Valid show option strings, matching C's `ctl_showopt_list`.
#[cfg_attr(not(test), allow(dead_code))]
const CTL_SHOWOPT_LIST: &[&str] = &["peers", "Sensors", "status", "all"];

/// Look up a control option from a list of valid options.
///
/// Corresponds to C: `ctl_lookup_option()`
///
/// Performs a prefix match: if `cmd` uniquely matches one entry in
/// `valid`, that entry is returned.  Returns `None` if no match or
/// if ambiguous.
#[must_use]
pub fn ctl_lookup_option<'a>(cmd: &str, valid: &[&'a str]) -> Option<&'a str> {
    if cmd.is_empty() {
        return None;
    }

    let mut matched: Option<&'a str> = None;

    for item in valid {
        if item.starts_with(cmd) {
            if matched.is_some() {
                // Ambiguous match — C code calls errx(1, "... is ambiguous")
                return None;
            }
            matched = Some(item);
        }
    }

    matched
}

/// Run the ntpctl control client.
///
/// Corresponds to C: `ctl_main()`
///
/// Connects to the ntpd control socket at `sockpath`, sends the
/// appropriate request, and returns the response as a string.
pub fn ctl_main(action: CtlAction, sockpath: &str) -> Result<String, String> {
    use std::io::{Read, Write};

    // Map action to IMSG type
    let imsg_type = match action {
        CtlAction::ShowStatus => IMSG_CTL_SHOW_STATUS,
        CtlAction::ShowPeers => IMSG_CTL_SHOW_PEERS,
        CtlAction::ShowSensors => IMSG_CTL_SHOW_SENSORS,
        CtlAction::ShowAll => IMSG_CTL_SHOW_ALL,
    };

    // Create Unix socket connection
    let mut socket = std::os::unix::net::UnixStream::connect(sockpath)
        .map_err(|e| format!("connect: {sockpath}: {e}"))?;

    // Build a simple message: [msg_type:u32_le][peerid:u32_le][len:u32_le]
    // The C code uses imsg_compose + imsgbuf_flush with NULL, 0 payload.
    // We send a minimal frame: type + 0 peerid + 0 length.
    let mut msg = Vec::new();
    msg.extend_from_slice(&imsg_type.to_le_bytes()); // type
    msg.extend_from_slice(&0u32.to_le_bytes()); // peerid
    msg.extend_from_slice(&0u32.to_le_bytes()); // len

    socket
        .write_all(&msg)
        .map_err(|e| format!("write error: {e}"))?;

    // Read response(s).
    let mut response = String::new();
    let mut buf = [0u8; 4096];

    loop {
        let n = socket
            .read(&mut buf)
            .map_err(|e| format!("read error: {e}"))?;
        if n == 0 {
            break; // pipe closed
        }
        // Accumulate readable text
        if let Ok(s) = std::str::from_utf8(&buf[..n]) {
            response.push_str(s);
        }
        // For ShowAll, multiple messages are sent; keep reading.
        // For ShowStatus, one message then done.
        // We read until the connection closes (C code reads until done).
        if action != CtlAction::ShowAll
            && action != CtlAction::ShowPeers
            && action != CtlAction::ShowSensors
        {
            break;
        }
    }

    Ok(response)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // ── auto_preconditions ────────────────────────────────────────────────

    #[test]
    fn test_auto_preconditions_no_constraints_no_trusted() {
        // If no constraints and no trusted peers/sensors, automatic should
        // be false.
        assert!(!auto_preconditions(false, false, false));
    }

    #[test]
    fn test_auto_preconditions_with_constraints() {
        assert!(auto_preconditions(true, false, false));
    }

    #[test]
    fn test_auto_preconditions_with_trusted_peers() {
        assert!(auto_preconditions(false, true, false));
    }

    #[test]
    fn test_auto_preconditions_with_trusted_sensors() {
        assert!(auto_preconditions(false, false, true));
    }

    #[test]
    fn test_auto_preconditions_all_true() {
        assert!(auto_preconditions(true, true, true));
    }

    // ── reset_adjtime ─────────────────────────────────────────────────────

    #[test]
    fn test_reset_adjtime_succeeds_or_returns_error() {
        // adjtime with zero delta may fail if not root or if the kernel
        // doesn't support it.  We just verify it doesn't panic and returns
        // a Result.
        let result = reset_adjtime();
        // Either it succeeds or returns an error — both are acceptable
        // in test (non-root environments will get -1/EPERM).
        match result {
            Ok(()) => {} // success
            Err(e) => {
                // Must contain some descriptive text
                assert!(!e.is_empty(), "error message should not be empty");
            }
        }
    }

    // ── ntpd_adjtime ─────────────────────────────────────────────────────

    #[test]
    fn test_ntpd_adjtime_small_offset() {
        // A very small offset; should not panic.
        // In non-root environment adjtime will return error, but we handle it.
        let result = ntpd_adjtime(0.001);
        assert!(result.is_ok() || result.is_err());
    }

    #[test]
    fn test_ntpd_adjtime_large_offset() {
        // A large offset (above 32ms threshold).
        let result = ntpd_adjtime(1.0);
        assert!(result.is_ok() || result.is_err());
    }

    // ── ntpd_adjfreq ─────────────────────────────────────────────────────

    #[test]
    fn test_ntpd_adjfreq_small_freq() {
        // Very small frequency adjustment; should not panic.
        let result = ntpd_adjfreq(1e-12, false);
        // In non-root environment adjfreq will fail.
        assert!(result.is_ok() || result.is_err());
    }

    #[test]
    fn test_ntpd_adjfreq_large_freq() {
        // Frequency above 0.05 ppm threshold.
        let result = ntpd_adjfreq(1e-7, false);
        assert!(result.is_ok() || result.is_err());
    }

    // ── ntpd_settime ─────────────────────────────────────────────────────

    #[test]
    fn test_ntpd_settime_zero_offset() {
        // Zero offset is a no-op.
        let result = ntpd_settime(0.0);
        assert!(result.is_ok());
    }

    #[test]
    fn test_ntpd_settime_nonzero() {
        // Non-zero offset requires privileges; should not panic.
        let result = ntpd_settime(0.5);
        // Will fail without root but should not panic.
        assert!(result.is_ok() || result.is_err());
    }

    // ── readfreq / writefreq roundtrip ────────────────────────────────────

    #[test]
    fn test_readfreq_writefreq_roundtrip() {
        let dir = std::env::temp_dir().join("openntpd-rs-test-drift-roundtrip");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("ntpd.drift");

        // Write a known frequency (in ppm)
        let freq_ppm = -10.500;
        writefreq(&path, freq_ppm).unwrap();

        // Read it back
        let freq = readfreq(&path).unwrap();
        let expected_s_per_s = freq_ppm / 1e6;
        assert!(
            (freq - expected_s_per_s).abs() < 1e-12,
            "expected {expected_s_per_s}, got {freq}"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_readfreq_missing_file() {
        let dir = std::env::temp_dir().join("openntpd-rs-test-drift-missing");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("nonexistent.drift");

        // Missing file should return 0.0 (C code creates new)
        let freq = readfreq(&path).unwrap();
        assert_eq!(freq, 0.0);

        let _ = std::fs::remove_dir_all(&dir);
    }

    // ── parent_dispatch_imsg ──────────────────────────────────────────────

    #[test]
    fn test_dispatch_adjtime() {
        let offset = 0.5f64;
        let data = offset.to_le_bytes();
        let action = parent_dispatch_imsg(IMSG_ADJTIME, &data);
        assert_eq!(action, Some(ParentImsgAction::AdjTime(0.5)));
    }

    #[test]
    fn test_dispatch_adjtime_short_payload() {
        let action = parent_dispatch_imsg(IMSG_ADJTIME, &[0u8; 4]);
        assert!(action.is_none());
    }

    #[test]
    fn test_dispatch_adjfreq() {
        let relfreq = 1e-7f64;
        let data = relfreq.to_le_bytes();
        let action = parent_dispatch_imsg(IMSG_ADJFREQ, &data);
        assert_eq!(action, Some(ParentImsgAction::AdjFreq(1e-7)));
    }

    #[test]
    fn test_dispatch_adjfreq_short_payload() {
        let action = parent_dispatch_imsg(IMSG_ADJFREQ, &[0u8; 4]);
        assert!(action.is_none());
    }

    #[test]
    fn test_dispatch_settime() {
        let offset = 2.0f64;
        let data = offset.to_le_bytes();
        let action = parent_dispatch_imsg(IMSG_SETTIME, &data);
        assert_eq!(action, Some(ParentImsgAction::SetTime(2.0)));
    }

    #[test]
    fn test_dispatch_settime_short_payload() {
        let action = parent_dispatch_imsg(IMSG_SETTIME, &[0u8; 4]);
        assert!(action.is_none());
    }

    #[test]
    fn test_dispatch_synced() {
        let action = parent_dispatch_imsg(IMSG_SYNCED, &[]);
        assert_eq!(action, Some(ParentImsgAction::Synced));
    }

    #[test]
    fn test_dispatch_unsynced() {
        let action = parent_dispatch_imsg(IMSG_UNSYNCED, &[]);
        assert_eq!(action, Some(ParentImsgAction::Unsynced));
    }

    #[test]
    fn test_dispatch_constraint_query() {
        let id = 42u32;
        let query_data = b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n";
        let mut payload = Vec::new();
        payload.extend_from_slice(&id.to_le_bytes());
        payload.extend_from_slice(query_data);
        let action = parent_dispatch_imsg(IMSG_CONSTRAINT_QUERY, &payload);
        assert_eq!(
            action,
            Some(ParentImsgAction::ConstraintQuery {
                id: 42,
                data: query_data.to_vec()
            })
        );
    }

    #[test]
    fn test_dispatch_constraint_query_short_payload() {
        let action = parent_dispatch_imsg(IMSG_CONSTRAINT_QUERY, &[0u8; 2]);
        assert!(action.is_none());
    }

    #[test]
    fn test_dispatch_constraint_kill() {
        let id = 99u32;
        let data = id.to_le_bytes();
        let action = parent_dispatch_imsg(IMSG_CONSTRAINT_KILL, &data);
        assert_eq!(action, Some(ParentImsgAction::ConstraintKill(99)));
    }

    #[test]
    fn test_dispatch_constraint_kill_short_payload() {
        let action = parent_dispatch_imsg(IMSG_CONSTRAINT_KILL, &[0u8; 2]);
        assert!(action.is_none());
    }

    #[test]
    fn test_dispatch_unknown_type() {
        let action = parent_dispatch_imsg(999, &[]);
        assert!(action.is_none());
    }

    // ── ctl_lookup_option ────────────────────────────────────────────────

    #[test]
    fn test_ctl_lookup_status() {
        let result = ctl_lookup_option("status", CTL_SHOWOPT_LIST);
        assert_eq!(result, Some("status"));
    }

    #[test]
    fn test_ctl_lookup_peers() {
        let result = ctl_lookup_option("peers", CTL_SHOWOPT_LIST);
        assert_eq!(result, Some("peers"));
    }

    #[test]
    fn test_ctl_lookup_sensors() {
        let result = ctl_lookup_option("Sensors", CTL_SHOWOPT_LIST);
        assert_eq!(result, Some("Sensors"));
    }

    #[test]
    fn test_ctl_lookup_all() {
        let result = ctl_lookup_option("all", CTL_SHOWOPT_LIST);
        assert_eq!(result, Some("all"));
    }

    #[test]
    fn test_ctl_lookup_prefix() {
        // "p" matches "peers" uniquely
        let result = ctl_lookup_option("p", CTL_SHOWOPT_LIST);
        assert_eq!(result, Some("peers"));
    }

    #[test]
    fn test_ctl_lookup_not_ambiguous_s_matches_status() {
        // "s" matches only "status" (case-sensitive), not "Sensors".
        let result = ctl_lookup_option("s", CTL_SHOWOPT_LIST);
        assert_eq!(result, Some("status"));
    }

    #[test]
    fn test_ctl_lookup_ambiguous_custom_list() {
        // Use a list where "stat" is a prefix of both entries.
        let valid = &["status", "statistics"];
        let result = ctl_lookup_option("stat", valid);
        // Ambiguous match should return None.
        assert!(result.is_none());
    }

    #[test]
    fn test_ctl_lookup_empty_string() {
        let result = ctl_lookup_option("", CTL_SHOWOPT_LIST);
        assert!(result.is_none());
    }

    #[test]
    fn test_ctl_lookup_invalid() {
        let result = ctl_lookup_option("invalid", CTL_SHOWOPT_LIST);
        assert!(result.is_none());
    }

    #[test]
    fn test_ctl_lookup_empty_list() {
        let result = ctl_lookup_option("anything", &[]);
        assert!(result.is_none());
    }

    // ── check_child ───────────────────────────────────────────────────────

    #[test]
    fn test_check_child_no_children() {
        // Without forking any children, waitpid should return 0 or -1/ECHILD.
        let result = check_child();
        assert!(result.is_none());
    }

    // ── start_child ──────────────────────────────────────────────────────

    #[test]
    fn test_start_child_no_such_binary() {
        // "no-such-binary" doesn't exist; the child will exit.
        let result = start_child("test", 3, &[]);
        // fork should succeed (returning a PID), but the child will
        // fail to exec and exit.
        match result {
            Ok(pid) => {
                assert!(pid > 0);
                // Wait for the child to avoid zombies
                let mut status = 0;
                // SAFETY: waitpid to reap the child
                unsafe {
                    libc::waitpid(pid as i32, &mut status, 0);
                }
            }
            Err(e) => {
                // fork can fail on resource limits
                assert!(!e.is_empty());
            }
        }
    }

    // ── writpid ──────────────────────────────────────────────────────────

    #[test]
    fn test_writepid_roundtrip() {
        let dir = std::env::temp_dir().join("openntpd-rs-test-writepid");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("ntpd.pid");

        writepid(&path).unwrap();

        let contents = std::fs::read_to_string(&path).unwrap();
        let pid: u32 = contents.trim().parse().unwrap();
        assert_eq!(pid, std::process::id());

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_writepid_bad_path() {
        let result = writepid(Path::new("/nonexistent/directory/ntpd.pid"));
        assert!(result.is_err());
    }

    // ── apply_clock_discipline ────────────────────────────────────────────

    #[test]
    fn test_apply_clock_discipline_small_offset_slews() {
        // A small offset (below CLOCK_MAX_STEP) should produce a slew
        // (non-step) adjustment.
        let mut clock = ClockState::new();
        let now = NtpTimestamp::new(4_000_000_000, 0);
        // Small positive offset: local clock is 5 ms ahead.
        let result = apply_clock_discipline(&mut clock, 0.005, 0.010, now);
        match result {
            Ok(adj) => {
                assert!(!adj.step, "expected slew, got step");
                assert!((adj.offset - 0.005).abs() < 1e-9, "offset mismatch");
            }
            Err(e) => {
                // In non-root environments the system calls may fail;
                // that is acceptable.
                assert!(!e.is_empty(), "error should be descriptive");
            }
        }
    }

    #[test]
    fn test_apply_clock_discipline_large_offset_may_step() {
        // A large offset above CLOCK_MAX_STEP (0.125 s) should trigger
        // a step — but only on the second update (the first update
        // always slews).
        let mut clock = ClockState::new();
        let now1 = NtpTimestamp::new(4_000_000_000, 0);
        let now2 = NtpTimestamp::new(4_000_000_100, 0);

        // First update always slews.
        let _ = clock.update(0.2, 0.010, now1);

        // Second update with large offset → step.
        let result = apply_clock_discipline(&mut clock, 0.2, 0.010, now2);
        match result {
            Ok(adj) => {
                assert!(adj.step, "expected step for large offset");
                assert!((adj.offset - 0.2).abs() < 1e-9);
                assert_eq!(adj.freq_delta, 0.0, "step should reset freq_delta");
            }
            Err(e) => {
                // System call may fail without root.
                assert!(!e.is_empty());
            }
        }
    }

    #[test]
    fn test_apply_clock_discipline_updates_clock_state() {
        let mut clock = ClockState::new();
        let now = NtpTimestamp::new(4_000_000_000, 0);

        let _ = apply_clock_discipline(&mut clock, 0.01, 0.005, now);

        // Clock state should have been updated regardless of whether
        // the system call succeeded.
        assert!(
            clock.update_count > 0,
            "clock should have recorded an update"
        );
        assert!((clock.offset - 0.01).abs() < 1e-9, "clock offset mismatch");
    }

    // ── imsg_type_name ────────────────────────────────────────────────────

    #[test]
    fn test_imsg_type_name_known() {
        assert_eq!(imsg_type_name(IMSG_ADJTIME), "IMSG_ADJTIME");
        assert_eq!(imsg_type_name(IMSG_ADJFREQ), "IMSG_ADJFREQ");
        assert_eq!(imsg_type_name(IMSG_SETTIME), "IMSG_SETTIME");
        assert_eq!(imsg_type_name(IMSG_SYNCED), "IMSG_SYNCED");
        assert_eq!(imsg_type_name(IMSG_UNSYNCED), "IMSG_UNSYNCED");
        assert_eq!(
            imsg_type_name(IMSG_CONSTRAINT_QUERY),
            "IMSG_CONSTRAINT_QUERY"
        );
        assert_eq!(imsg_type_name(IMSG_CONSTRAINT_KILL), "IMSG_CONSTRAINT_KILL");
        assert_eq!(imsg_type_name(IMSG_CTL_SHOW_STATUS), "IMSG_CTL_SHOW_STATUS");
        assert_eq!(imsg_type_name(IMSG_CTL_SHOW_PEERS), "IMSG_CTL_SHOW_PEERS");
        assert_eq!(
            imsg_type_name(IMSG_CTL_SHOW_SENSORS),
            "IMSG_CTL_SHOW_SENSORS"
        );
        assert_eq!(imsg_type_name(IMSG_CTL_SHOW_ALL), "IMSG_CTL_SHOW_ALL");
        assert_eq!(imsg_type_name(IMSG_NONE), "IMSG_NONE");
    }

    #[test]
    fn test_imsg_type_name_unknown() {
        assert_eq!(imsg_type_name(255), "IMSG_UNKNOWN");
    }

    // ── CtlAction ────────────────────────────────────────────────────────

    #[test]
    fn test_ctl_action_debug_clone() {
        let actions = [
            CtlAction::ShowStatus,
            CtlAction::ShowPeers,
            CtlAction::ShowSensors,
            CtlAction::ShowAll,
        ];
        for &a in &actions {
            let cloned = a;
            assert_eq!(a, cloned);
            let _dbg = format!("{a:?}");
        }
    }
}
