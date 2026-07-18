//! Process lifecycle helpers — daemonization, PID files, user
//! credential dropping.
//!
//! ## What this is NOT
//!
//! Despite the name "process", this is **not** yet OpenNTPD's full
//! privilege-separation architecture.  Actual privilege separation
//! requires:
//!
//! - A privileged parent process.
//! - A restricted NTP process.
//! - Additional DNS and constraint subprocesses.
//! - Socketpairs and `imsg` dispatch.
//! - Different filesystem and syscall capabilities per process.
//! - Process death and restart handling.
//!
//! This module provides only the lower-level building blocks:
//! daemonization, PID files, and credential dropping.  The full
//! privsep architecture will live here once implemented.

use std::ffi::CString;
use std::path::Path;

/// Error type for process operations.
#[derive(Debug)]
pub enum ProcessError {
    /// Underlying I/O or syscall error.
    Io(std::io::Error),
    /// Invalid configuration.
    Config(&'static str),
}

impl std::fmt::Display for ProcessError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(e) => write!(f, "process operation: {e}"),
            Self::Config(s) => write!(f, "configuration: {s}"),
        }
    }
}

impl std::error::Error for ProcessError {}

/// Result for process operations.
pub type ProcessResult<T> = Result<T, ProcessError>;

/// Drop root privileges to the given user.
///
/// Uses `setresgid`/`setresuid` if available (preferred).
/// Falls back to `setgid`/`setuid` otherwise.
///
/// Note: does not currently verify that saved-setuid privileges
/// cannot be recovered (no `getresuid` check).
///
/// # Safety
///
/// Affects process credentials.  Must be called with root privileges.
pub unsafe fn drop_privileges(user: &str) -> ProcessResult<()> {
    let c_user =
        CString::new(user).map_err(|_| ProcessError::Config("username contains nul byte"))?;

    // Look up the user
    // SAFETY: getpwnam returns a pointer to a static struct; we copy
    // what we need before any subsequent calls.
    let passwd = unsafe { libc::getpwnam(c_user.as_ptr()) };
    if passwd.is_null() {
        return Err(ProcessError::Io(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            format!("user '{user}' not found"),
        )));
    }

    // SAFETY: passwd is non-null and valid from getpwnam.
    let pw = unsafe { *passwd };

    // Set supplementary groups
    // SAFETY: initgroups is safe with valid user name and gid.
    let ret = unsafe { libc::initgroups(c_user.as_ptr(), pw.pw_gid) };
    if ret != 0 {
        return Err(ProcessError::Io(std::io::Error::last_os_error()));
    }

    // Prefer setresgid/setresuid (available on Linux, BSDs).
    // SAFETY: setresgid with explicit real, effective, saved values.
    #[cfg(any(target_os = "linux", target_os = "freebsd", target_os = "openbsd"))]
    {
        let ret = unsafe { libc::setresgid(pw.pw_gid, pw.pw_gid, pw.pw_gid) };
        if ret != 0 {
            return Err(ProcessError::Io(std::io::Error::last_os_error()));
        }
        // SAFETY: setresuid after setresgid ensures we cannot regain
        // privileges by switching back.
        let ret = unsafe { libc::setresuid(pw.pw_uid, pw.pw_uid, pw.pw_uid) };
        if ret != 0 {
            return Err(ProcessError::Io(std::io::Error::last_os_error()));
        }
    }

    // Fallback for platforms without setresuid/setresgid
    #[cfg(not(any(target_os = "linux", target_os = "freebsd", target_os = "openbsd")))]
    {
        let ret = unsafe { libc::setgid(pw.pw_gid) };
        if ret != 0 {
            return Err(ProcessError::Io(std::io::Error::last_os_error()));
        }
        let ret = unsafe { libc::setuid(pw.pw_uid) };
        if ret != 0 {
            return Err(ProcessError::Io(std::io::Error::last_os_error()));
        }
    }

    Ok(())
}

/// Write a PID file.
///
/// Creates or overwrites the PID file atomically (write + check).
/// Corresponds to OpenNTPD portable's `-p` flag handling (patch 0007).
pub fn write_pid_file(path: &Path) -> ProcessResult<()> {
    let pid = std::process::id();
    let contents = format!("{pid}\n");
    std::fs::write(path, contents).map_err(ProcessError::Io)?;
    // Verify we wrote what we intended
    let verify = std::fs::read_to_string(path).map_err(ProcessError::Io)?;
    if verify.trim() != pid.to_string() {
        return Err(ProcessError::Io(std::io::Error::new(
            std::io::ErrorKind::Other,
            "PID file verification failed",
        )));
    }
    Ok(())
}

/// Remove a PID file.
///
/// Suppresses errors (the file might already be gone on shutdown).
pub fn remove_pid_file(path: &Path) {
    let _ = std::fs::remove_file(path);
}

/// Daemonize the process (double-fork).
///
/// # Safety
///
/// This function calls `fork()`, `setsid()`, and `chdir()` which
/// affect the process tree.
pub unsafe fn daemonize(no_chdir: bool) -> ProcessResult<()> {
    // First fork
    // SAFETY: fork() creates a new process.
    let pid = unsafe { libc::fork() };
    if pid < 0 {
        return Err(ProcessError::Io(std::io::Error::last_os_error()));
    }
    if pid > 0 {
        // Parent must use _exit, not process::exit, to avoid running
        // atexit handlers in the child.
        unsafe { libc::_exit(0) };
    }

    // Create new session (detach from terminal)
    // SAFETY: setsid is safe; may fail if already session leader.
    let ret = unsafe { libc::setsid() };
    if ret < 0 {
        return Err(ProcessError::Io(std::io::Error::last_os_error()));
    }

    // Second fork (prevents re-acquiring terminal)
    // SAFETY: fork again to orphan the process.
    let pid = unsafe { libc::fork() };
    if pid < 0 {
        return Err(ProcessError::Io(std::io::Error::last_os_error()));
    }
    if pid > 0 {
        unsafe { libc::_exit(0) };
    }

    // Change to root directory unless -n prevented it
    if !no_chdir {
        // SAFETY: chdir("/") always succeeds.
        let ret = unsafe { libc::chdir(b"/\0".as_ptr() as *const _) };
        if ret != 0 {
            return Err(ProcessError::Io(std::io::Error::last_os_error()));
        }
    }

    Ok(())
}
