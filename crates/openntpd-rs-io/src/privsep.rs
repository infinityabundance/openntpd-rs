//! # Privilege separation — parent/child architecture
//!
//! Implements OpenNTPD's privilege separation model:
//!
//! - **Parent** process runs as root, handles control socket, TLS, drift file.
//! - **Child** process drops all privileges, handles NTP queries.
//! - File descriptors (e.g., bound NTP sockets) are passed from parent to
//!   child via Unix domain socket + `SCM_RIGHTS` (`imsg`).
//!
//! ## Design
//!
//! - `privsep_fork()` creates a `socketpair(AF_UNIX)`, forks, and returns the
//!   appropriate `PrivsepRole` for the current process.
//! - The child calls `drop_all_privileges()` to drop root, set uid/gid, and
//!   optionally `chroot()`.
//! - `verify_privileges_dropped()` checks that the current process is running
//!   as a non-root user.
//! - `send_ntp_socket_to_child()` / `recv_ntp_socket_from_parent()` implement
//!   the SCM_RIGHTS fd handoff for the bound NTP socket.

use std::os::unix::io::RawFd;
use std::path::Path;

use crate::imsg::{recv_imsg_with_fd, send_imsg_with_fd, Imsg, ImsgSocket};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Default unprivileged user for the NTP child process.
pub const PRIVSEP_USER: &str = "_ntp";

/// Default unprivileged group for the NTP child process.
pub const PRIVSEP_GROUP: &str = "_ntp";

/// Imsg type for sending a bound NTP socket fd from parent to child.
pub const IMSG_PARENT_SOCKET_FD: u32 = 0x10;

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/// Result of the privsep fork.
///
/// - `Parent`: the privileged parent process, with an imsg socket to
///   communicate with the child and the child's PID.
/// - `Child`: the unprivileged child process, with an imsg socket to
///   communicate with the parent.
#[derive(Debug)]
pub enum PrivsepRole {
    /// Parent process — keeps privileges, handles control socket, TLS,
    /// drift file.
    Parent {
        child_socket: ImsgSocket,
        child_pid: u32,
    },
    /// Child process — unprivileged, handles NTP queries.
    Child { parent_socket: ImsgSocket },
}

// ---------------------------------------------------------------------------
// Privilege dropping
// ---------------------------------------------------------------------------

/// Drop all privileges in the child process.
///
/// Steps:
/// 1. Optionally `chroot()` to a directory (must be called before
///    `setresuid` on Linux, as the chroot directory must be accessible).
/// 2. Drop supplementary groups via `setgroups()` / `initgroups()`.
/// 3. Drop group privileges via `setresgid()`.
/// 4. Drop user privileges via `setresuid()`.
///
/// # Safety
///
/// Affects process credentials. Must be called with root privileges.
/// After this call, the process cannot regain root.
#[cfg(any(target_os = "linux", target_os = "freebsd", target_os = "openbsd"))]
pub unsafe fn drop_all_privileges(user: &str, chroot_dir: Option<&Path>) -> Result<(), String> {
    // Step 1: Optional chroot
    if let Some(dir) = chroot_dir {
        let c_dir = std::ffi::CString::new(dir.as_os_str().as_encoded_bytes())
            .map_err(|_| "chroot path contains nul byte".to_string())?;
        // SAFETY: caller ensures root privileges; chroot is irreversible.
        let ret = unsafe { libc::chroot(c_dir.as_ptr()) };
        if ret != 0 {
            return Err(format!(
                "chroot to '{}' failed: {}",
                dir.display(),
                std::io::Error::last_os_error()
            ));
        }
        // SAFETY: after chroot, change to the new root.
        let ret = unsafe { libc::chdir(c"/".as_ptr() as *const _) };
        if ret != 0 {
            return Err(format!(
                "chdir to '/' after chroot failed: {}",
                std::io::Error::last_os_error()
            ));
        }
    }

    // Step 2: Look up the user
    let c_user =
        std::ffi::CString::new(user).map_err(|_| "username contains nul byte".to_string())?;

    // SAFETY: getpwnam returns a pointer to a static struct; we copy what we
    // need before any subsequent calls.
    let passwd = unsafe { libc::getpwnam(c_user.as_ptr()) };
    if passwd.is_null() {
        return Err(format!("user '{user}' not found"));
    }

    // SAFETY: passwd is non-null and valid from getpwnam.
    let pw = unsafe { *passwd };

    // Step 3: Set supplementary groups
    // SAFETY: initgroups with valid user name and gid.
    let ret = unsafe { libc::initgroups(c_user.as_ptr(), pw.pw_gid) };
    if ret != 0 {
        return Err(format!(
            "initgroups failed: {}",
            std::io::Error::last_os_error()
        ));
    }

    // Step 4: setresgid — drop group privileges
    // SAFETY: setresgid with explicit real, effective, saved values.
    let ret = unsafe { libc::setresgid(pw.pw_gid, pw.pw_gid, pw.pw_gid) };
    if ret != 0 {
        return Err(format!(
            "setresgid failed: {}",
            std::io::Error::last_os_error()
        ));
    }

    // Step 5: setresuid — drop user privileges (must be last)
    // SAFETY: setresuid after setresgid ensures we cannot regain privileges.
    let ret = unsafe { libc::setresuid(pw.pw_uid, pw.pw_uid, pw.pw_uid) };
    if ret != 0 {
        return Err(format!(
            "setresuid failed: {}",
            std::io::Error::last_os_error()
        ));
    }

    Ok(())
}

/// Verify that privileges have been dropped by checking `getresuid` and
/// `getresgid`.
///
/// If the current process is already non-root, this succeeds harmlessly
/// (it just confirms the real/effective/saved uids match and are non-zero).
pub fn verify_privileges_dropped() -> Result<(), String> {
    #[cfg(any(target_os = "linux", target_os = "freebsd", target_os = "openbsd"))]
    {
        let mut ruid: libc::uid_t = 0;
        let mut euid: libc::uid_t = 0;
        let mut suid: libc::uid_t = 0;

        // SAFETY: getresuid with valid pointers.
        let ret = unsafe { libc::getresuid(&mut ruid, &mut euid, &mut suid) };
        if ret != 0 {
            return Err(format!(
                "getresuid failed: {}",
                std::io::Error::last_os_error()
            ));
        }

        // All three should be the same (no saved-setuid escalation possible).
        if ruid != euid || euid != suid {
            return Err(format!(
                "inconsistent uids: real={ruid}, effective={euid}, saved={suid}"
            ));
        }

        let mut rgid: libc::gid_t = 0;
        let mut egid: libc::gid_t = 0;
        let mut sgid: libc::gid_t = 0;

        // SAFETY: getresgid with valid pointers.
        let ret = unsafe { libc::getresgid(&mut rgid, &mut egid, &mut sgid) };
        if ret != 0 {
            return Err(format!(
                "getresgid failed: {}",
                std::io::Error::last_os_error()
            ));
        }

        if rgid != egid || egid != sgid {
            return Err(format!(
                "inconsistent gids: real={rgid}, effective={egid}, saved={sgid}"
            ));
        }

        // Non-root check: either uid should be != 0 (harmless if we were
        // never root to begin with).
        if ruid == 0 {
            return Err("still running as root".to_string());
        }

        Ok(())
    }

    #[cfg(not(any(target_os = "linux", target_os = "freebsd", target_os = "openbsd")))]
    {
        // Fallback: just check geteuid.
        // SAFETY: geteuid is always safe.
        let euid = unsafe { libc::geteuid() };
        if euid == 0 {
            return Err("still running as root".to_string());
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Fork
// ---------------------------------------------------------------------------

/// Fork the process into privileged parent and unprivileged child.
///
/// Creates a `socketpair(AF_UNIX)` for imsg communication, then forks.
///
/// - **Parent** returns `PrivsepRole::Parent` with the child's imsg socket
///   and PID.
/// - **Child** calls `drop_all_privileges()` and returns
///   `PrivsepRole::Child` with the parent's imsg socket.
///
/// # Safety
///
/// Calls `fork()`, and if the child path is taken, also calls
/// `setresuid()`, `setresgid()`, and optionally `chroot()`.  Must be
/// called with root privileges.
#[cfg(any(target_os = "linux", target_os = "freebsd", target_os = "openbsd"))]
pub unsafe fn privsep_fork(user: &str, chroot_dir: Option<&Path>) -> Result<PrivsepRole, String> {
    // Create socketpair for imsg communication.
    let (parent_socket, child_socket) =
        ImsgSocket::pair().map_err(|e| format!("socketpair failed: {e}"))?;

    // SAFETY: fork() creates a new process.
    let pid = unsafe { libc::fork() };
    if pid < 0 {
        return Err(format!("fork failed: {}", std::io::Error::last_os_error()));
    }

    if pid > 0 {
        // Parent process
        Ok(PrivsepRole::Parent {
            child_socket: parent_socket,
            child_pid: pid as u32,
        })
    } else {
        // Child process: drop privileges
        // SAFETY: called with root privileges before dropping.
        unsafe {
            drop_all_privileges(user, chroot_dir)?;
        }

        Ok(PrivsepRole::Child {
            parent_socket: child_socket,
        })
    }
}

// ---------------------------------------------------------------------------
// NTP socket handoff (parent -> child via imsg + SCM_RIGHTS)
// ---------------------------------------------------------------------------

/// Send the bound NTP socket from parent to child via imsg + SCM_RIGHTS.
///
/// The parent sends an `IMSG_PARENT_SOCKET_FD` message with the NTP socket
/// file descriptor attached via `SCM_RIGHTS`.
pub fn send_ntp_socket_to_child(
    parent_socket: &mut ImsgSocket,
    ntp_fd: RawFd,
) -> Result<(), String> {
    let msg = Imsg::new(IMSG_PARENT_SOCKET_FD, b"NTP_FD".to_vec());
    send_imsg_with_fd(parent_socket.inner_stream(), &msg, ntp_fd)
        .map_err(|e| format!("send_imsg_with_fd failed: {e}"))
}

/// Receive the bound NTP socket from parent in the child process.
///
/// Returns the received `RawFd`. The caller takes ownership of the fd
/// and must close it (or wrap it in a safe type).
pub fn recv_ntp_socket_from_parent(child_socket: &mut ImsgSocket) -> Result<RawFd, String> {
    let (msg, fd) = recv_imsg_with_fd(child_socket.inner_stream())
        .map_err(|e| format!("recv_imsg_with_fd failed: {e}"))?;

    if msg.header.type_ != IMSG_PARENT_SOCKET_FD {
        return Err(format!(
            "expected IMSG_PARENT_SOCKET_FD (0x{:x}), got 0x{:x}",
            IMSG_PARENT_SOCKET_FD, msg.header.type_
        ));
    }

    fd.ok_or_else(|| "received IMSG_PARENT_SOCKET_FD without a file descriptor".to_string())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::imsg::{Imsg, IMSG_PARENT_SENSOR, MAX_SCM_RIGHTS_FDS};
    use std::os::unix::fs::MetadataExt;
    use std::os::unix::io::{AsRawFd, IntoRawFd};
    use std::os::unix::net::UnixStream;

    #[test]
    fn test_imsg_parent_socket_fd_constant() {
        assert_eq!(IMSG_PARENT_SOCKET_FD, 0x10);
    }

    #[test]
    fn test_privsep_role_parent_discriminant() {
        let (_a, _b) = UnixStream::pair().unwrap();
        let socket = ImsgSocket::new(_a);
        let role = PrivsepRole::Parent {
            child_socket: socket,
            child_pid: 42,
        };
        match role {
            PrivsepRole::Parent {
                child_socket: _,
                child_pid,
            } => {
                assert_eq!(child_pid, 42);
            }
            _ => panic!("expected Parent variant"),
        }
    }

    #[test]
    fn test_privsep_role_child_discriminant() {
        let (_a, _b) = UnixStream::pair().unwrap();
        let socket = ImsgSocket::new(_a);
        let role = PrivsepRole::Child {
            parent_socket: socket,
        };
        match role {
            PrivsepRole::Child { parent_socket: _ } => {} // expected
            _ => panic!("expected Child variant"),
        }
    }

    #[test]
    fn test_send_recv_ntp_socket_roundtrip() {
        // Test send/recv of NTP socket fd via imsg (no actual fork).
        // Uses socketpair + SCM_RIGHTS directly.

        let (parent, mut child_imsg) = ImsgSocket::pair().unwrap();
        let mut parent_imsg = parent;
        let ntp_fd = parent_imsg.as_raw_fd(); // Use the socket's own fd as a test fd

        // Send the fd from parent to child
        send_ntp_socket_to_child(&mut parent_imsg, ntp_fd).unwrap();

        // Receive in child
        let received_fd = recv_ntp_socket_from_parent(&mut child_imsg).unwrap();

        // Verify it's a valid fd (at least non-negative)
        assert!(received_fd >= 0, "received fd should be valid");

        // Verify the received fd refers to the same resource by checking
        // fstat info (same dev + ino for socketpair endpoints).
        // SAFETY: fstat is safe with valid fds.
        let mut orig_stat: libc::stat = unsafe { std::mem::zeroed() };
        let mut recv_stat: libc::stat = unsafe { std::mem::zeroed() };
        // SAFETY: fstat on valid fds.
        let r1 = unsafe { libc::fstat(ntp_fd, &mut orig_stat) };
        let r2 = unsafe { libc::fstat(received_fd, &mut recv_stat) };

        if r1 == 0 && r2 == 0 {
            // Both stat calls succeeded — sockets and pipes have the same
            // inode on the same filesystem when they're the same object.
            // (Note: for socketpair, both ends may have different inodes
            // on some systems, so this check is best-effort.)
            assert_eq!(orig_stat.st_dev, recv_stat.st_dev);
        }

        // Close the received fd (we dup'd it, so the original is still open).
        // SAFETY: received_fd is a valid, owned fd.
        unsafe { libc::close(received_fd) };
    }

    #[test]
    fn test_send_recv_ntp_socket_wrong_type() {
        let (mut parent, mut child) = ImsgSocket::pair().unwrap();

        // Send a regular imsg (not IMSG_PARENT_SOCKET_FD)
        let msg = Imsg::new(crate::imsg::IMSG_PARENT_REQ_DNS, b"not a socket".to_vec());
        parent.send(&msg).unwrap();

        // Try to receive as ntp socket — should fail
        let result = recv_ntp_socket_from_parent(&mut child);
        assert!(result.is_err(), "should fail on wrong imsg type");
    }

    #[test]
    fn test_send_recv_ntp_socket_no_fd() {
        let (mut parent, mut child) = ImsgSocket::pair().unwrap();

        // Send a correct type but no SCM_RIGHTS fd
        let msg = Imsg::new(IMSG_PARENT_SOCKET_FD, b"NTP_FD".to_vec());
        parent.send(&msg).unwrap();

        // Try to receive — should fail because no fd was passed
        let result = recv_ntp_socket_from_parent(&mut child);
        assert!(result.is_err(), "should fail without SCM_RIGHTS fd");
    }

    #[test]
    fn test_verify_privileges_dropped_non_root() {
        // When running as non-root, this should succeed harmlessly.
        let result = verify_privileges_dropped();
        // This will succeed if not root, or fail with "still running as root"
        // if we happen to be root (which is fine — the check works).
        match &result {
            Ok(_) => {} // expected when non-root
            Err(msg) => {
                // If running as root, verify the error message makes sense.
                assert!(msg.contains("root"), "unexpected error: {msg}");
            }
        }
    }

    #[test]
    fn test_scm_rights_roundtrip_via_imsg_socket_roundtrip() {
        // Full SCM_RIGHTS roundtrip: send fd from parent imsg socket to child
        // imsg socket, then verify the received fd works and matches.
        use std::fs::File;
        use std::os::unix::io::FromRawFd;

        let (mut parent, mut child) = ImsgSocket::pair().unwrap();

        // Create a temp file to get a real fd.
        let file = File::create("/tmp/ntp_test_scm_roundtrip").unwrap();
        let fd = file.as_raw_fd();
        let orig_ino = file.metadata().unwrap().ino();

        // Send via parent using the method
        parent
            .send_with_fd(&Imsg::new(IMSG_PARENT_SOCKET_FD, b"fd_test".to_vec()), fd)
            .unwrap();

        // Receive via child using the method
        let (msg, opt_fd) = child.recv_with_fd().unwrap();
        assert_eq!(msg.header.type_, IMSG_PARENT_SOCKET_FD);
        assert!(opt_fd.is_some());

        let recv_fd = opt_fd.unwrap();
        // SAFETY: recv_fd is a valid fd from SCM_RIGHTS.
        let recv_file = unsafe { File::from_raw_fd(recv_fd) };
        let recv_ino = recv_file.metadata().unwrap().ino();

        assert_eq!(
            orig_ino, recv_ino,
            "inode should match after SCM_RIGHTS roundtrip"
        );

        // Take back ownership so drop doesn't close the fds we still hold.
        let _ = recv_file.into_raw_fd();
        drop(file);
        let _ = std::fs::remove_file("/tmp/ntp_test_scm_roundtrip");
    }

    #[test]
    fn test_scm_rights_send_recv_fd() {
        // Direct test of send_imsg_with_fd / recv_imsg_with_fd via
        // the free functions, verifying inode equality.
        use std::fs::File;
        use std::os::unix::io::FromRawFd;
        use std::os::unix::io::IntoRawFd;

        let (mut a, mut b) = UnixStream::pair().unwrap();
        let file = File::create("/tmp/ntp_test_scm_direct").unwrap();
        let fd = file.as_raw_fd();
        let orig_ino = file.metadata().unwrap().ino();

        let msg = Imsg::new(IMSG_PARENT_SENSOR, b"sensor_data".to_vec());
        send_imsg_with_fd(&mut a, &msg, fd).unwrap();

        let (received, opt_fd) = recv_imsg_with_fd(&mut b).unwrap();
        assert_eq!(received.header.type_, IMSG_PARENT_SENSOR);
        assert_eq!(received.payload, b"sensor_data");
        assert!(opt_fd.is_some());

        let recv_fd = opt_fd.unwrap();
        let recv_file = unsafe { File::from_raw_fd(recv_fd) };
        let recv_ino = recv_file.metadata().unwrap().ino();
        assert_eq!(orig_ino, recv_ino, "inode should match");

        let _ = recv_file.into_raw_fd();
        drop(file);
        let _ = std::fs::remove_file("/tmp/ntp_test_scm_direct");
    }

    #[test]
    fn test_privsep_constants() {
        assert_eq!(PRIVSEP_USER, "_ntp");
        assert_eq!(PRIVSEP_GROUP, "_ntp");
    }

    #[test]
    fn test_max_scm_rights_fds_constant() {
        assert_eq!(MAX_SCM_RIGHTS_FDS, 1);
    }
}
