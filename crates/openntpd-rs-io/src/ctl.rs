//! Control socket — Unix domain socket for `ntpctl`-style administration.
//!
//! Corresponds to OpenNTPD's
//! [`control.c`](https://github.com/openntpd-portable/openntpd-openbsd/blob/master/src/usr.sbin/ntpd/control.c).
//!
//! Provides the full lifecycle for a `AF_UNIX SOCK_STREAM` control
//! socket: check availability, create, bind, listen, accept, dispatch
//! messages, close connections, and shut down.

use openntpd_rs_core::control::{
    ControlRequest, ControlResponse, CTL_REQ_ALL, CTL_REQ_PEERS, CTL_REQ_SENSORS, CTL_REQ_STATUS,
};

use crate::imsg::{Imsg, ImsgHeader, IMSG_CTL_REQ, IMSG_CTL_RESP};

/// Backlog for `listen()` on the control socket.
pub const CONTROL_BACKLOG: i32 = 5;

/// Check whether a control socket path is available (not already in use).
///
/// Corresponds to C: `control_check()`.
///
/// Returns `Ok(())` if the path is usable (either nonexistent or not
/// currently bound).  Returns `Err` if the socket is already active
/// or an I/O error occurs.
pub fn control_check(path: &str) -> Result<(), String> {
    let path_c = std::ffi::CString::new(path).map_err(|e| format!("invalid path: {e}"))?;

    // SAFETY: sockaddr_un initialization and connect are safe with a
    // valid path that fits in sun_path.
    let fd = unsafe { libc::socket(libc::AF_UNIX, libc::SOCK_STREAM, 0) };
    if fd == -1 {
        return Err(format!(
            "control_check: socket: {}",
            std::io::Error::last_os_error()
        ));
    }

    let mut sa: libc::sockaddr_un = unsafe { std::mem::zeroed() };
    sa.sun_family = libc::AF_UNIX as libc::sa_family_t;

    // Copy path into sun_path (i8 array). Cast to i8 slice.
    let path_bytes = path_c.as_bytes();
    let sun_path_len = path_bytes.len().min(
        (std::mem::size_of::<libc::sockaddr_un>() - std::mem::size_of::<libc::sa_family_t>()) - 1,
    );
    let sa_slice: &mut [i8] = &mut sa.sun_path;
    for (i, &b) in path_bytes[..sun_path_len].iter().enumerate() {
        sa_slice[i] = b as i8;
    }

    // SAFETY: we're connecting to check if the socket is already bound.
    let ret = unsafe {
        libc::connect(
            fd,
            &sa as *const _ as *const libc::sockaddr,
            std::mem::size_of::<libc::sockaddr_un>() as libc::socklen_t,
        )
    };

    // Close fd in all cases.
    unsafe { libc::close(fd) };

    if ret == 0 {
        Err(format!("control_check: socket in use: {path}"))
    } else {
        let err = std::io::Error::last_os_error();
        if err.kind() == std::io::ErrorKind::ConnectionRefused
            || err.kind() == std::io::ErrorKind::NotFound
        {
            Ok(())
        } else {
            Err(format!("control_check: connect: {err}"))
        }
    }
}

/// Initialize and bind the control socket.
///
/// Corresponds to C: `control_init()`.
///
/// Creates an `AF_UNIX SOCK_STREAM` socket, removes any existing file
/// at `path`, binds with restrictive permissions (`S_IRUSR|S_IWUSR|
/// S_IRGRP|S_IWGRP`), and sets `SOCK_CLOEXEC` / non-blocking mode.
///
/// Returns the raw file descriptor on success.
pub fn control_init(path: &str) -> Result<i32, String> {
    // SAFETY: socket() with SOCK_CLOEXEC | SOCK_STREAM.
    let fd = unsafe { libc::socket(libc::AF_UNIX, libc::SOCK_STREAM | libc::SOCK_CLOEXEC, 0) };
    if fd == -1 {
        return Err(format!(
            "control_init: socket: {}",
            std::io::Error::last_os_error()
        ));
    }

    // Check path length
    let path_c =
        std::ffi::CString::new(path).map_err(|e| format!("control_init: path too long: {e}"))?;
    let max_path =
        std::mem::size_of::<libc::sockaddr_un>() - std::mem::size_of::<libc::sa_family_t>() - 1;
    if path_c.as_bytes().len() >= max_path {
        unsafe { libc::close(fd) };
        return Err(format!("control_init: socket name too long: {path}"));
    }

    // Remove existing socket file (ignore ENOENT)
    let ret = unsafe { libc::unlink(path_c.as_ptr()) };
    if ret == -1 {
        let err = std::io::Error::last_os_error();
        if err.kind() != std::io::ErrorKind::NotFound {
            unsafe { libc::close(fd) };
            return Err(format!("control_init: unlink {path}: {err}"));
        }
    }

    // Bind with restrictive umask
    let mut sa: libc::sockaddr_un = unsafe { std::mem::zeroed() };
    sa.sun_family = libc::AF_UNIX as libc::sa_family_t;
    let bytes = path_c.as_bytes();
    let sa_slice: &mut [i8] = &mut sa.sun_path;
    for (i, &b) in bytes.iter().enumerate() {
        sa_slice[i] = b as i8;
    }

    let old_umask = unsafe {
        libc::umask(libc::S_IXUSR | libc::S_IXGRP | libc::S_IWOTH | libc::S_IROTH | libc::S_IXOTH)
    };
    let bind_ret = unsafe {
        libc::bind(
            fd,
            &sa as *const _ as *const libc::sockaddr,
            std::mem::size_of::<libc::sockaddr_un>() as libc::socklen_t,
        )
    };
    unsafe { libc::umask(old_umask) };

    if bind_ret == -1 {
        let err = std::io::Error::last_os_error();
        unsafe { libc::close(fd) };
        return Err(format!("control_init: bind {path}: {err}"));
    }

    // chmod to owner/group read-write only
    let mode = (libc::S_IRUSR | libc::S_IWUSR | libc::S_IRGRP | libc::S_IWGRP) as libc::mode_t;
    let chmod_ret = unsafe { libc::chmod(path_c.as_ptr(), mode) };
    if chmod_ret == -1 {
        let err = std::io::Error::last_os_error();
        unsafe { libc::close(fd) };
        let _ = unsafe { libc::unlink(path_c.as_ptr()) };
        return Err(format!("control_init: chmod {path}: {err}"));
    }

    // Set non-blocking mode
    set_nonblock(fd)?;

    Ok(fd)
}

/// Listen on the control socket.
///
/// Corresponds to C: `control_listen()`.
pub fn control_listen(fd: i32) -> Result<(), String> {
    if fd == -1 {
        return Ok(());
    }
    let ret = unsafe { libc::listen(fd, CONTROL_BACKLOG) };
    if ret == -1 {
        return Err(format!(
            "control_listen: listen: {}",
            std::io::Error::last_os_error()
        ));
    }
    Ok(())
}

/// Accept a control connection.
///
/// Corresponds to C: `control_accept()`.
///
/// Returns the connected client fd on success, `Err` on failure.
pub fn control_accept(fd: i32) -> Result<i32, String> {
    let mut sa: libc::sockaddr_un = unsafe { std::mem::zeroed() };
    let mut len = std::mem::size_of::<libc::sockaddr_un>() as libc::socklen_t;

    let connfd = unsafe {
        libc::accept4(
            fd,
            &mut sa as *mut _ as *mut libc::sockaddr,
            &mut len,
            libc::SOCK_CLOEXEC,
        )
    };

    if connfd == -1 {
        let err = std::io::Error::last_os_error();
        if err.kind() == std::io::ErrorKind::WouldBlock
            || err.kind() == std::io::ErrorKind::Interrupted
        {
            return Err(format!("control_accept: {err}"));
        }
        return Err(format!("control_accept: accept: {err}"));
    }

    // Set non-blocking mode on the connection fd
    set_nonblock(connfd)?;

    Ok(connfd)
}

/// Close a control connection.
///
/// Corresponds to C: `control_close()`.
///
/// Closes the given file descriptor. Returns `Ok(())` on success.
pub fn control_close(fd: i32) {
    if fd >= 0 {
        unsafe { libc::close(fd) };
    }
}

/// Shut down the control socket.
///
/// Corresponds to C: `control_shutdown()`.
pub fn control_shutdown(fd: i32) {
    control_close(fd);
}

/// Category of control request received from a client.
///
/// Corresponds to the `enum ctl_actions` (`CTL_SHOW_STATUS`,
/// `CTL_SHOW_PEERS`, etc.) and is decoded from the imsg message type.
#[derive(Debug, Clone, PartialEq)]
pub enum CtlRequest {
    ShowStatus,
    ShowPeers,
    ShowSensors,
    ShowAll,
    /// Unknown or unsupported request type.
    Unknown(u32),
}

/// Dispatch a control message from a connected client.
///
/// Corresponds to C: `control_dispatch_msg()`.
///
/// Reads one message from the imsg buffer on `fd` and decodes it into
/// a [`CtlRequest`].
pub fn control_dispatch_msg(fd: i32) -> Result<Option<CtlRequest>, String> {
    // Read available data from the socket.
    let mut buf = [0u8; 256];
    let n = match unsafe { libc::read(fd, buf.as_mut_ptr() as *mut libc::c_void, buf.len()) } {
        -1 => {
            let err = std::io::Error::last_os_error();
            if err.kind() == std::io::ErrorKind::WouldBlock {
                return Ok(None);
            }
            return Err(format!("control_dispatch_msg: read: {err}"));
        }
        0 => return Ok(None), // EOF
        n => n as usize,
    };

    // Decode the first byte as a control action type
    if n == 0 {
        return Ok(None);
    }

    let action = buf[0] as u32;
    let request = match action {
        a if a == CTL_REQ_STATUS => CtlRequest::ShowStatus,
        a if a == CTL_REQ_PEERS => CtlRequest::ShowPeers,
        a if a == CTL_REQ_SENSORS => CtlRequest::ShowSensors,
        a if a == CTL_REQ_ALL => CtlRequest::ShowAll,
        other => CtlRequest::Unknown(other),
    };

    Ok(Some(request))
}

/// Set a socket to non-blocking mode.
///
/// Corresponds to C: `session_socket_nonblockmode()`.
pub fn set_nonblock(fd: i32) -> Result<(), String> {
    set_session_nonblock(fd)
}

/// Alias for [`set_nonblock`] matching the C function name exactly.
///
/// Corresponds to C: `session_socket_nonblockmode()`.
pub fn session_socket_nonblockmode(fd: i32) -> Result<(), String> {
    set_nonblock(fd)
}

/// Internal implementation of socket non-block mode.
pub fn set_session_nonblock(fd: i32) -> Result<(), String> {
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
    if flags == -1 {
        return Err(format!(
            "fcntl F_GETFL: {}",
            std::io::Error::last_os_error()
        ));
    }

    let ret = unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) };
    if ret == -1 {
        return Err(format!(
            "fcntl F_SETFL: {}",
            std::io::Error::last_os_error()
        ));
    }

    Ok(())
}

/// Build a status report string for `ntpctl -s`.
///
/// Aggregates peer count, valid peer count, sensor count, valid sensor count,
/// sync status, stratum, clock offset, constraint info.
///
/// Corresponds to C: `build_show_status()` in control.c which populates a
/// `struct ctl_show_status`.  This Rust version returns a formatted string.
pub fn build_show_status() -> String {
    // In the simplified Rust model, we report a stub status.
    // A full implementation would iterate over the peer/sensor lists.
    format!("status: synced={} stratum={}", 0, 0)
}

/// Receive an imsg from a raw file descriptor (non-blocking).
///
/// Returns `Ok(None)` on EWOULDBLOCK/EAGAIN or EOF.
pub fn control_recv_imsg(fd: i32) -> Result<Option<Imsg>, String> {
    // Read the 12-byte imsg header.
    let mut hdr_buf = [0u8; 12];
    let mut offset = 0usize;
    while offset < 12 {
        let n = unsafe {
            libc::read(
                fd,
                hdr_buf.as_mut_ptr().add(offset) as *mut libc::c_void,
                12 - offset,
            )
        };
        if n < 0 {
            let err = std::io::Error::last_os_error();
            if err.kind() == std::io::ErrorKind::WouldBlock {
                return if offset == 0 {
                    Ok(None)
                } else {
                    Err("partial imsg header read".into())
                };
            }
            return Err(format!("control_recv_imsg: read: {err}"));
        }
        if n == 0 {
            return if offset == 0 {
                Ok(None)
            } else {
                Err("control_recv_imsg: unexpected EOF".into())
            };
        }
        offset += n as usize;
    }

    let header = ImsgHeader::from_bytes(&hdr_buf);
    if let Err(e) = header.validate() {
        return Err(format!("control_recv_imsg: invalid header: {e}"));
    }

    let payload_len = header.length as usize;
    let mut payload = vec![0u8; payload_len];
    offset = 0;
    while offset < payload_len {
        let n = unsafe {
            libc::read(
                fd,
                payload.as_mut_ptr().add(offset) as *mut libc::c_void,
                payload_len - offset,
            )
        };
        if n < 0 {
            return Err(format!(
                "control_recv_imsg: payload read: {}",
                std::io::Error::last_os_error()
            ));
        }
        if n == 0 {
            return Err("control_recv_imsg: unexpected EOF (payload)".into());
        }
        offset += n as usize;
    }

    Ok(Some(Imsg { header, payload }))
}

/// Send an imsg over a raw file descriptor.
pub fn control_send_imsg(fd: i32, msg: &Imsg) -> Result<(), String> {
    let bytes = msg.to_bytes();
    let mut offset = 0usize;
    while offset < bytes.len() {
        let n = unsafe {
            libc::write(
                fd,
                bytes.as_ptr().add(offset) as *const libc::c_void,
                bytes.len() - offset,
            )
        };
        if n < 0 {
            return Err(format!(
                "control_send_imsg: write: {}",
                std::io::Error::last_os_error()
            ));
        }
        offset += n as usize;
    }
    Ok(())
}

/// Handle a single control connection: read imsg request, send response.
///
/// Returns `Ok(true)` if a message was handled, `Ok(false)` if no data
/// (WouldBlock / EOF), and `Err` on protocol errors.
pub fn handle_control_conn(fd: i32, synced: bool, stratum: u8) -> Result<bool, String> {
    let imsg = match control_recv_imsg(fd)? {
        Some(m) => m,
        None => return Ok(false),
    };

    if imsg.header.type_ != IMSG_CTL_REQ {
        return Err(format!(
            "handle_control_conn: expected IMSG_CTL_REQ, got {}",
            imsg.header.type_
        ));
    }

    let req_type = ControlRequest::decode(&imsg.payload).unwrap_or(0);

    let resp = match req_type {
        CTL_REQ_STATUS | CTL_REQ_ALL => build_control_response(req_type, synced, stratum),
        CTL_REQ_PEERS => {
            // Build empty peers response
            let info = ControlResponse::new_peers(&[]);
            info
        }
        CTL_REQ_SENSORS => {
            // Build empty sensors response
            let info = ControlResponse::new_sensors(&[]);
            info
        }
        _ => {
            return Err(format!(
                "handle_control_conn: unknown request type {req_type}"
            ));
        }
    };

    let encoded = resp.encode();
    let resp_imsg = Imsg::new(IMSG_CTL_RESP, encoded);
    control_send_imsg(fd, &resp_imsg)?;

    Ok(true)
}

/// Build a [`ControlResponse`] for the given request type.
fn build_control_response(type_: u32, synced: bool, stratum: u8) -> ControlResponse {
    use openntpd_rs_core::control::{NtpdStatus, SyncState};

    let sync_state = if synced {
        SyncState::Synced
    } else {
        SyncState::Unsynchronized
    };
    let status = NtpdStatus {
        sync_state,
        stratum,
        offset: 0.0,
        frequency: 0.0,
        uptime: 0,
    };
    match type_ {
        CTL_REQ_ALL => ControlResponse::new_all(&status, &[], &[]),
        _ => ControlResponse::new_status(&status),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Get a unique temporary socket path.
    fn temp_socket_path() -> String {
        let dir = std::env::temp_dir();
        let pid = std::process::id();
        let tid = std::thread::current().id();
        dir.join(format!("ntpd-rs-ctl-test-{pid:?}-{tid:?}.sock"))
            .to_string_lossy()
            .to_string()
    }

    #[test]
    fn test_control_check_nonexistent_path() {
        let path = temp_socket_path();
        // Path doesn't exist yet, so check should succeed
        let result = control_check(&path);
        assert!(
            result.is_ok(),
            "check on nonexistent path should pass: {result:?}"
        );
        // Clean up
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn test_control_lifecycle() {
        let path = temp_socket_path();

        // 1. init (bind the socket)
        let fd = control_init(&path).expect("control_init should succeed");
        assert!(fd >= 0, "valid fd");

        // 2. listen on it so connect() can succeed
        control_listen(fd).expect("control_listen should succeed");

        // 3. check should fail (socket is active)
        let check_result = control_check(&path);
        assert!(check_result.is_err(), "check on active socket should fail");

        // 4. shutdown (cleanup)
        control_shutdown(fd);
        let _ = std::fs::remove_file(&path);

        // 5. check should succeed again after shutdown
        let check_again = control_check(&path);
        assert!(check_again.is_ok(), "check after shutdown should pass");
    }

    #[test]
    fn test_control_accept_and_close() {
        let path = temp_socket_path();

        let listen_fd = control_init(&path).expect("init");
        control_listen(listen_fd).expect("listen");

        // Connect a client
        let client_fd = unsafe { libc::socket(libc::AF_UNIX, libc::SOCK_STREAM, 0) };
        assert!(client_fd >= 0, "client socket created");

        let mut sa: libc::sockaddr_un = unsafe { std::mem::zeroed() };
        sa.sun_family = libc::AF_UNIX as libc::sa_family_t;
        let path_c = std::ffi::CString::new(path.as_str()).unwrap();
        let bytes = path_c.as_bytes();
        let sa_slice: &mut [i8] = &mut sa.sun_path;
        for (i, &b) in bytes.iter().enumerate() {
            sa_slice[i] = b as i8;
        }

        let connect_ret = unsafe {
            libc::connect(
                client_fd,
                &sa as *const _ as *const libc::sockaddr,
                std::mem::size_of::<libc::sockaddr_un>() as libc::socklen_t,
            )
        };
        assert_eq!(connect_ret, 0, "client connect");

        // Accept the connection on the server side
        let conn_fd = control_accept(listen_fd).expect("accept should succeed");
        assert!(conn_fd >= 0, "connection fd valid");

        // Close the connection
        control_close(conn_fd);
        control_close(client_fd);

        // Cleanup
        control_shutdown(listen_fd);
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn test_control_accept_without_connection() {
        let path = temp_socket_path();
        let listen_fd = control_init(&path).expect("init");
        control_listen(listen_fd).expect("listen");

        // accept on a non-blocking socket with no pending connection
        // should return WouldBlock error
        let result = control_accept(listen_fd);
        assert!(result.is_err(), "accept without connection should error");

        let err_msg = result.unwrap_err();
        assert!(
            err_msg.contains("WouldBlock") || err_msg.contains("Resource temporarily unavailable"),
            "error should mention WouldBlock: {err_msg}"
        );

        control_shutdown(listen_fd);
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn test_control_check_invalid_path_behavior() {
        let result = control_check("/nonexistent/ntpd.sock");
        assert!(result.is_ok());
    }

    #[test]
    fn test_set_nonblock() {
        let path = temp_socket_path();
        let fd = control_init(&path).expect("init");

        // Already in non-blocking mode from init; verify by calling
        // accept which should return WouldBlock
        let accept_result = control_accept(fd);
        assert!(accept_result.is_err());

        control_shutdown(fd);
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn test_control_dispatch_unknown_action() {
        let path = temp_socket_path();

        let listen_fd = control_init(&path).expect("init");
        control_listen(listen_fd).expect("listen");

        // Connect client
        let client_fd = unsafe { libc::socket(libc::AF_UNIX, libc::SOCK_STREAM, 0) };
        let mut sa: libc::sockaddr_un = unsafe { std::mem::zeroed() };
        sa.sun_family = libc::AF_UNIX as libc::sa_family_t;
        let path_c = std::ffi::CString::new(path.as_str()).unwrap();
        let bytes = path_c.as_bytes();
        let sa_slice: &mut [i8] = &mut sa.sun_path;
        for (i, &b) in bytes.iter().enumerate() {
            sa_slice[i] = b as i8;
        }
        unsafe {
            libc::connect(
                client_fd,
                &sa as *const _ as *const libc::sockaddr,
                std::mem::size_of::<libc::sockaddr_un>() as libc::socklen_t,
            )
        };

        let conn_fd = control_accept(listen_fd).expect("accept");

        // Write an unknown action byte
        let unknown_byte = [0xFFu8];
        let written =
            unsafe { libc::write(client_fd, unknown_byte.as_ptr() as *const libc::c_void, 1) };
        assert_eq!(written, 1, "should write 1 byte");

        // Give server time to receive
        std::thread::sleep(std::time::Duration::from_millis(50));

        // Dispatch should return Unknown
        let result = control_dispatch_msg(conn_fd).expect("dispatch should succeed");
        match result {
            Some(CtlRequest::Unknown(v)) => assert_eq!(v, 0xFF),
            other => panic!("expected Unknown(255), got {other:?}"),
        }

        control_close(conn_fd);
        control_close(client_fd);
        control_shutdown(listen_fd);
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn test_control_close_invalid_fd() {
        // Should not panic
        control_close(-1);
        control_close(-999);
    }

    #[test]
    fn test_control_shutdown_invalid_fd() {
        // Should not panic
        control_shutdown(-1);
    }

    #[test]
    fn test_control_dispatch_msg_no_data() {
        let path = temp_socket_path();
        let listen_fd = control_init(&path).expect("init");
        control_listen(listen_fd).expect("listen");

        let client_fd = unsafe { libc::socket(libc::AF_UNIX, libc::SOCK_STREAM, 0) };
        let mut sa: libc::sockaddr_un = unsafe { std::mem::zeroed() };
        sa.sun_family = libc::AF_UNIX as libc::sa_family_t;
        let path_c = std::ffi::CString::new(path.as_str()).unwrap();
        let bytes = path_c.as_bytes();
        let sa_slice: &mut [i8] = &mut sa.sun_path;
        for (i, &b) in bytes.iter().enumerate() {
            sa_slice[i] = b as i8;
        }
        unsafe {
            libc::connect(
                client_fd,
                &sa as *const _ as *const libc::sockaddr,
                std::mem::size_of::<libc::sockaddr_un>() as libc::socklen_t,
            )
        };

        let conn_fd = control_accept(listen_fd).expect("accept");

        // No data written -- dispatch should return Ok(None) on WouldBlock
        let result = control_dispatch_msg(conn_fd);
        assert!(result.is_ok(), "dispatch with no data should not error");

        control_close(conn_fd);
        control_close(client_fd);
        control_shutdown(listen_fd);
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn test_control_dispatch_show_status() {
        let path = temp_socket_path();
        let listen_fd = control_init(&path).expect("init");
        control_listen(listen_fd).expect("listen");

        let client_fd = unsafe { libc::socket(libc::AF_UNIX, libc::SOCK_STREAM, 0) };
        let mut sa: libc::sockaddr_un = unsafe { std::mem::zeroed() };
        sa.sun_family = libc::AF_UNIX as libc::sa_family_t;
        let path_c = std::ffi::CString::new(path.as_str()).unwrap();
        let bytes = path_c.as_bytes();
        let sa_slice: &mut [i8] = &mut sa.sun_path;
        for (i, &b) in bytes.iter().enumerate() {
            sa_slice[i] = b as i8;
        }
        unsafe {
            libc::connect(
                client_fd,
                &sa as *const _ as *const libc::sockaddr,
                std::mem::size_of::<libc::sockaddr_un>() as libc::socklen_t,
            )
        };

        let conn_fd = control_accept(listen_fd).expect("accept");

        // Write CTL_REQ_STATUS byte
        let data = [CTL_REQ_STATUS as u8];
        unsafe {
            libc::write(client_fd, data.as_ptr() as *const libc::c_void, 1);
        }

        std::thread::sleep(std::time::Duration::from_millis(50));

        let result = control_dispatch_msg(conn_fd).expect("dispatch");
        assert_eq!(result, Some(CtlRequest::ShowStatus));

        control_close(conn_fd);
        control_close(client_fd);
        control_shutdown(listen_fd);
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn test_control_dispatch_all_actions() {
        let actions = [
            (CTL_REQ_STATUS as u8, CtlRequest::ShowStatus),
            (CTL_REQ_PEERS as u8, CtlRequest::ShowPeers),
            (CTL_REQ_SENSORS as u8, CtlRequest::ShowSensors),
            (CTL_REQ_ALL as u8, CtlRequest::ShowAll),
        ];

        for &(action_byte, ref expected) in &actions {
            let path = format!("{}-{}.sock", temp_socket_path(), action_byte);
            let listen_fd = control_init(&path).expect("init");
            control_listen(listen_fd).expect("listen");

            let client_fd = unsafe { libc::socket(libc::AF_UNIX, libc::SOCK_STREAM, 0) };
            let mut sa: libc::sockaddr_un = unsafe { std::mem::zeroed() };
            sa.sun_family = libc::AF_UNIX as libc::sa_family_t;
            let path_c = std::ffi::CString::new(path.as_str()).unwrap();
            let bytes = path_c.as_bytes();
            let sa_slice: &mut [i8] = &mut sa.sun_path;
            for (i, &b) in bytes.iter().enumerate() {
                sa_slice[i] = b as i8;
            }
            unsafe {
                libc::connect(
                    client_fd,
                    &sa as *const _ as *const libc::sockaddr,
                    std::mem::size_of::<libc::sockaddr_un>() as libc::socklen_t,
                )
            };

            let conn_fd = control_accept(listen_fd).expect("accept");

            let data = [action_byte];
            unsafe {
                libc::write(client_fd, data.as_ptr() as *const libc::c_void, 1);
            }

            std::thread::sleep(std::time::Duration::from_millis(30));

            let result = control_dispatch_msg(conn_fd).expect("dispatch");
            assert_eq!(
                result,
                Some(expected.clone()),
                "action byte {action_byte:#04x}"
            );

            control_close(conn_fd);
            control_close(client_fd);
            control_shutdown(listen_fd);
            let _ = std::fs::remove_file(&path);
        }
    }

    #[test]
    fn test_control_init_path_too_long() {
        // Create a path longer than sun_path (usually 108 bytes on Linux)
        let long_path = "x".repeat(200);
        let result = control_init(&long_path);
        assert!(result.is_err(), "overly long path should fail");
        assert!(
            result.unwrap_err().contains("too long"),
            "error should mention path length"
        );
    }

    #[test]
    fn test_control_listen_bad_fd() {
        let result = control_listen(-1);
        assert!(result.is_ok(), "listen with fd=-1 should be no-op");
    }

    #[test]
    fn test_build_show_status_returns_string() {
        let status = build_show_status();
        assert!(!status.is_empty(), "status string should not be empty");
        assert!(
            status.contains("synced"),
            "status should mention synced state"
        );
        assert!(status.contains("stratum"), "status should mention stratum");
    }
}
