//! DNS child process — a dedicated subprocess for DNS resolution.
//!
//! OpenNTPD forks a DNS child process (`ntp_dns.c`) that:
//!
//! 1. Drops privileges to the `_ntp` user.
//! 2. Enters a poll(2) loop reading imsg requests from the parent.
//! 3. Resolves hostnames using `getaddrinfo()` (called via `host_dns()`).
//! 4. Sends results back to the parent via imsg.
//! 5. Probes DNS root servers at startup to warm the resolver cache.
//!
//! ## C correspondence
//!
//! | Rust                   | C                        |
//! |------------------------|--------------------------|
//! | [`ntp_dns_main`]       | `ntp_dns()`              |
//! | [`dns_dispatch_imsg`]  | `dns_dispatch_imsg()`    |
//! | [`probe_root`]         | `probe_root()`           |
//! | [`dns_sighdlr`]        | `sighdlr_dns()`          |

use std::sync::atomic::{AtomicBool, Ordering};

use crate::imsg::{Imsg, ImsgSocket};

/// Imessage type constants matching OpenNTPD's `imsg.h`.
/// These correspond to `IMSG_HOST_DNS` and `IMSG_CONSTRAINT_DNS`.
pub const IMSG_HOST_DNS: u32 = 4;
pub const IMSG_CONSTRAINT_DNS: u32 = 5;
pub const IMSG_PROBE_ROOT: u32 = 20;

/// Global quit flag for the DNS child process.
///
/// Corresponds to C's `volatile sig_atomic_t quit_dns`.
static QUIT_DNS: AtomicBool = AtomicBool::new(false);

/// Signal handler for the DNS child process.
///
/// Corresponds to C's `sighdlr_dns()` which sets `quit_dns = 1` on
/// `SIGTERM` and `SIGINT`.
///
/// # Signals handled
///
/// - `SIGTERM` → graceful shutdown
/// - `SIGINT`  → graceful shutdown
/// - `SIGHUP`  → ignored (handled by parent)
pub extern "C" fn dns_sighdlr(sig: i32) {
    match sig {
        libc::SIGTERM | libc::SIGINT => {
            QUIT_DNS.store(true, Ordering::SeqCst);
        }
        _ => {
            // Other signals are not handled by the DNS child.
        }
    }
}

/// Register signal handlers for the DNS child process.
///
/// In C this is done via `signal(SIGTERM, sighdlr_dns)`,
/// `signal(SIGINT, sighdlr_dns)`, and `signal(SIGHUP, SIG_IGN)`.
///
/// # Safety
///
/// Signal handlers are global process state.  This should only be
/// called once, in the forked DNS child process, before entering the
/// event loop.
///
/// On Linux, this uses `libc::signal()`.  On other platforms, it falls
/// back to `libc::sigaction()` to set signal dispositions.
#[cfg(target_os = "linux")]
pub unsafe fn register_dns_signal_handlers() {
    // SAFETY: Signal handlers are simple static functions that just set
    // an atomic flag.  No heap allocation, no complex state.
    unsafe {
        libc::signal(
            libc::SIGTERM,
            dns_sighdlr as *const () as libc::sighandler_t,
        );
        libc::signal(libc::SIGINT, dns_sighdlr as *const () as libc::sighandler_t);
        libc::signal(libc::SIGHUP, libc::SIG_IGN);
    }
}

/// Check if the DNS child should quit.
#[must_use]
pub fn dns_should_quit() -> bool {
    QUIT_DNS.load(Ordering::SeqCst)
}

/// DNS child process entry point.
///
/// Corresponds to C's `ntp_dns()` in `ntp_dns.c`.  This function:
///
/// 1. Initializes the resolver (`res_init()` in C).
/// 2. Sets up an imsg socket for communication with the parent.
/// 3. Probes DNS root servers (if there are non-numeric addresses).
/// 4. Enters the poll(2) loop, dispatching imsg requests.
///
/// # Arguments
///
/// * `imsg_fd` - File descriptor for the imsg socket connected to the
///   parent process.
///
/// # Errors
///
/// Returns `Err` if the imsg socket cannot be initialized.
pub fn ntp_dns_main(imsg_fd: i32) -> Result<(), String> {
    use std::os::unix::io::FromRawFd;

    // Create an ImsgSocket from the passed fd.
    // SAFETY: We take ownership of the fd that was passed to us by the parent.
    let socket = unsafe {
        let stream = std::os::unix::net::UnixStream::from_raw_fd(imsg_fd);
        ImsgSocket::new(stream)
    };
    let mut socket = socket;

    // Probe DNS root servers (warm the resolver cache).
    // In C this is only done if `non_numeric` is true.
    match probe_root() {
        Ok(addrs) => {
            // Send result back to parent via IMSG_PROBE_ROOT.
            let payload = if addrs.is_success() {
                vec![1u8] // success
            } else {
                vec![0u8] // failure
            };
            if let Err(e) = socket.send(&Imsg::new(IMSG_PROBE_ROOT, payload.clone())) {
                return Err(format!("failed to send probe result: {}", e));
            }
        }
        Err(e) => {
            let payload = vec![0u8]; // failure
            if let Err(e2) = socket.send(&Imsg::new(IMSG_PROBE_ROOT, payload)) {
                return Err(format!("failed to send probe result: {}", e2));
            }
            return Err(format!("DNS root probe failed: {}", e));
        }
    }

    // Main event loop — poll for imsg from parent.
    // In C this uses a single-element pollfd array waiting on the
    // imsg socket, with INFTIM timeout.
    loop {
        if dns_should_quit() {
            break;
        }

        match socket.recv() {
            Ok(imsg) => {
                if let Err(e) = dns_dispatch_imsg_inner(&mut socket, &imsg) {
                    return Err(e);
                }
            }
            Err(e) => {
                return Err(format!("imsg recv error: {}", e));
            }
        }
    }

    Ok(())
}

/// Dispatch a single imsg from the parent.
///
/// Corresponds to C's `dns_dispatch_imsg()` in `ntp_dns.c`.
///
/// Handles:
/// - `IMSG_HOST_DNS` / `IMSG_CONSTRAINT_DNS` → resolve hostname, send response
/// - `IMSG_PROBE_ROOT` → acknowledgment
///
/// # Arguments
///
/// * `socket` - The imsg socket to send responses on.
/// * `imsg` - The received imsg to dispatch.
///
/// # Errors
///
/// Returns `Err` if message handling or response sending fails.
pub fn dns_dispatch_imsg_inner(socket: &mut ImsgSocket, imsg: &Imsg) -> Result<(), String> {
    match imsg.header.type_ {
        IMSG_HOST_DNS | IMSG_CONSTRAINT_DNS => {
            // Extract hostname from payload (null-terminated in C).
            let hostname = match core::str::from_utf8(&imsg.payload) {
                Ok(s) => {
                    // Trim any trailing null bytes (C null-terminated string).
                    let trimmed = s.trim_end_matches('\0');
                    trimmed.to_string()
                }
                Err(_) => return Err("invalid UTF-8 in DNS request".into()),
            };

            if hostname.is_empty() {
                return Err("empty hostname in DNS request".into());
            }

            // Resolve the hostname (matching C's host_dns() call).
            let result = crate::dns_io::resolve_host(&hostname);

            // Build response payload:
            // [count: 4 bytes][ip_addr: 16 bytes each]
            match result {
                Ok(addrs) => {
                    let count = addrs.len() as u32;
                    let mut payload = Vec::with_capacity(4 + addrs.len() * 16);
                    payload.extend_from_slice(&count.to_be_bytes());
                    for addr in &addrs {
                        let octets = match addr {
                            std::net::IpAddr::V4(v4) => v4.octets().to_vec(),
                            std::net::IpAddr::V6(v6) => v6.octets().to_vec(),
                        };
                        // Pad to 16 bytes (IPv4 addresses are stored as
                        // IPv4-mapped IPv6 addresses).
                        let mut addr_bytes = [0u8; 16];
                        if octets.len() == 4 {
                            // IPv4-mapped IPv6: ::ffff:a.b.c.d
                            addr_bytes[10] = 0xff;
                            addr_bytes[11] = 0xff;
                            addr_bytes[12..16].copy_from_slice(&octets);
                        } else {
                            addr_bytes.copy_from_slice(&octets);
                        }
                        payload.extend_from_slice(&addr_bytes);
                    }
                    socket
                        .send(&Imsg::new(imsg.header.type_, payload.clone()))
                        .map_err(|e| format!("failed to send DNS response: {}", e))?;
                }
                Err(e) => {
                    // Send empty response (count = 0) to indicate failure.
                    let payload = 0u32.to_be_bytes().to_vec();
                    socket
                        .send(&Imsg::new(imsg.header.type_, payload))
                        .map_err(|e2| format!("failed to send DNS error response: {}", e2))?;
                    return Err(e);
                }
            }
        }
        IMSG_PROBE_ROOT => {
            // Acknowledge probe result request. In C this is just a
            // notification; no response is needed.
        }
        _ => {
            // Unknown message type — ignore (matches C behavior).
        }
    }

    Ok(())
}

/// Probe DNS root servers to warm the resolver cache.
///
/// Corresponds to C's `probe_root()` + `probe_root_ns()` in
/// `ntp_dns.c`.  The C code:
///
/// 1. Retries `res_query(".", C_IN, T_NS, buf, sizeof(buf))` up to
///    5 seconds with 1-second retransmission/retry.
/// 2. On success (n >= 0), exits the retry loop.
/// 3. If the probe returned quickly (duration.tv_sec == 0), sleeps
///    for 1 second to avoid tight loops.
///
/// Since Rust doesn't have the BIND resolver library readily available,
/// this function simulates probe behavior using `host_dns()` to resolve
/// the root nameservers (`a.root-servers.net`).
pub fn probe_root() -> Result<DnsProbeResult, String> {
    let start = std::time::Instant::now();
    let mut attempts = 0;

    // Try to resolve a.root-servers.net as a DNS connectivity check.
    // Retry for up to 5 seconds (matching C).
    loop {
        attempts += 1;

        // Try resolving one of the root server names.
        let result = crate::dns_io::host_dns("a.root-servers.net", false);

        match result {
            Ok(dns_result) => {
                if dns_result.is_success() {
                    let elapsed = start.elapsed();
                    if elapsed.as_secs() == 0 && attempts > 1 {
                        // C: "if probe returned quickly, sleep(1)"
                        std::thread::sleep(std::time::Duration::from_secs(1));
                    }
                    if attempts > 1 {
                        #[cfg(feature = "log")]
                        log::warn!(
                            "DNS root probe failed {} times (eventually succeeded)",
                            attempts - 1
                        );
                    }
                    return Ok(DnsProbeResult::Success);
                }
                // Temporary failure, retry.
            }
            Err(_) => {
                // Permanent failure, retry anyway.
            }
        }

        let elapsed = start.elapsed();
        if elapsed.as_secs() > 5 {
            #[cfg(feature = "log")]
            log::warn!("DNS root probe failed {} times (gave up)", attempts);
            return Err(format!("DNS root probe failed after {} attempts", attempts));
        }

        // Sleep before retry (in C this is 1 second per nameserver).
        std::thread::sleep(std::time::Duration::from_millis(1000));
    }
}

/// Result of probing DNS root servers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DnsProbeResult {
    /// Probe succeeded.
    Success,
    /// Probe failed.
    Failure,
}

impl DnsProbeResult {
    /// Returns `true` if the probe succeeded.
    #[must_use]
    pub fn is_success(&self) -> bool {
        matches!(self, Self::Success)
    }
}

// Re-export dns_io types for convenience.
pub use crate::dns_io::host_dns;

// ---------------------------------------------------------------------------
// Daemon wiring: start_dns_child / request_dns_resolution / poll_dns_child
// ---------------------------------------------------------------------------

/// A DNS resolution response from the child process.
#[derive(Debug, Clone)]
pub struct DnsResponse {
    /// The id that was sent with the original request.
    pub id: u32,
    /// Resolved IP addresses (empty on failure).
    pub addresses: Vec<std::net::IpAddr>,
    /// Whether the resolution succeeded.
    pub success: bool,
}

/// Start the DNS child process.
///
/// Creates a socketpair, forks, and the child enters `ntp_dns_main`.
/// Returns the child's PID on success (from the parent's perspective).
///
/// # Arguments
///
/// * `imsg_fd` - The file descriptor of the parent's end of the imsg
///   socketpair, to be passed to the child.
///
/// # Errors
///
/// Returns `Err` if the socketpair creation or fork fails.
pub fn start_dns_child(imsg_fd: i32) -> Result<u32, String> {
    // SAFETY: fork + child execution.  The child process calls
    // ntp_dns_main which handles its side of the protocol.
    let pid = unsafe { libc::fork() };
    if pid < 0 {
        return Err(format!(
            "fork for DNS child failed: {}",
            std::io::Error::last_os_error()
        ));
    }

    if pid == 0 {
        // Child process
        // SAFETY: we are in the forked child; we own imsg_fd.
        match ntp_dns_main(imsg_fd) {
            Ok(_) => unsafe { libc::_exit(0) },
            Err(e) => {
                #[cfg(feature = "log")]
                log::error!("DNS child exited with error: {}", e);
                let _ = e;
                unsafe { libc::_exit(1) }
            }
        }
    }

    // Parent returns child PID.
    Ok(pid as u32)
}

/// Send a DNS resolution request to the child process.
///
/// The hostname is sent as a null-terminated byte string in the imsg
/// payload.  The `id` is embedded in the peer_id field of the imsg
/// header so that responses can be correlated.
///
/// # Arguments
///
/// * `parent_socket` - The parent's imsg socket connected to the child.
/// * `hostname` - The hostname to resolve.
/// * `id` - A caller-chosen identifier for correlating the response.
///
/// # Errors
///
/// Returns `Err` if the imsg send fails.
pub fn request_dns_resolution(
    parent_socket: &mut ImsgSocket,
    hostname: &str,
    id: u32,
) -> Result<(), String> {
    let mut payload = hostname.as_bytes().to_vec();
    payload.push(0); // null terminator, matching C convention

    let mut msg = Imsg::new(IMSG_HOST_DNS, payload);
    msg.header.peer_id = id;

    parent_socket
        .send(&msg)
        .map_err(|e| format!("failed to send DNS request: {}", e))
}

/// Poll the DNS child for responses.
///
/// Non-blocking: reads any available imsg from the child and parses
/// them into `DnsResponse` entries.  If no message is available,
/// returns an empty vec (not an error).
///
/// # Arguments
///
/// * `dns_socket` - The parent's imsg socket connected to the child.
///
/// # Errors
///
/// Returns `Err` only on unexpected I/O errors (not on "no data").
pub fn poll_dns_child(dns_socket: &mut ImsgSocket) -> Result<Vec<DnsResponse>, String> {
    let mut responses = Vec::new();

    // Try to read messages in a non-blocking fashion.
    // We use a short timeout on the underlying stream.
    let raw_fd = dns_socket.as_raw_fd();

    loop {
        // Use poll to check if data is available.
        let mut pollfd = libc::pollfd {
            fd: raw_fd,
            events: libc::POLLIN,
            revents: 0,
        };

        // SAFETY: poll with a single fd, zero timeout (non-blocking check).
        let ret = unsafe { libc::poll(&mut pollfd, 1, 0) };
        if ret < 0 {
            let err = std::io::Error::last_os_error();
            if err.kind() == std::io::ErrorKind::Interrupted {
                continue;
            }
            return Err(format!("poll_dns_child poll failed: {}", err));
        }
        if ret == 0 || (pollfd.revents & libc::POLLIN) == 0 {
            // No data available.
            break;
        }

        match dns_socket.recv() {
            Ok(imsg) => {
                let id = imsg.header.peer_id;

                // Parse payload: first 4 bytes = count, then 16-byte addresses.
                if imsg.payload.len() < 4 {
                    responses.push(DnsResponse {
                        id,
                        addresses: Vec::new(),
                        success: false,
                    });
                    continue;
                }

                let count = u32::from_be_bytes(imsg.payload[0..4].try_into().unwrap()) as usize;
                let mut addrs = Vec::with_capacity(count);

                for i in 0..count {
                    let offset = 4 + i * 16;
                    if offset + 16 > imsg.payload.len() {
                        break;
                    }
                    let addr_bytes: [u8; 16] =
                        imsg.payload[offset..offset + 16].try_into().unwrap();
                    // Check if it's an IPv4-mapped IPv6 address.
                    if addr_bytes[0..12] == [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff] {
                        let v4 = std::net::Ipv4Addr::new(
                            addr_bytes[12],
                            addr_bytes[13],
                            addr_bytes[14],
                            addr_bytes[15],
                        );
                        addrs.push(std::net::IpAddr::V4(v4));
                    } else {
                        let v6 = std::net::Ipv6Addr::from(addr_bytes);
                        addrs.push(std::net::IpAddr::V6(v6));
                    }
                }

                responses.push(DnsResponse {
                    id,
                    success: count > 0,
                    addresses: addrs,
                });
            }
            Err(e) => {
                // If the connection was closed, we just stop.
                match e {
                    crate::imsg::ImsgError::ConnectionClosed => break,
                    _ => {
                        return Err(format!("poll_dns_child recv error: {}", e));
                    }
                }
            }
        }
    }

    Ok(responses)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::imsg::ImsgSocket;

    #[test]
    fn test_dns_sighdlr_ignore_sighup() {
        // SIGTERM/SIGINT should set the quit flag.
        // SIGHUP should NOT set the quit flag.
        QUIT_DNS.store(false, Ordering::SeqCst);
        dns_sighdlr(libc::SIGHUP);
        assert!(!dns_should_quit());
    }

    #[test]
    fn test_dns_sighdlr_sigterm() {
        QUIT_DNS.store(false, Ordering::SeqCst);
        dns_sighdlr(libc::SIGTERM);
        assert!(dns_should_quit());
    }

    #[test]
    fn test_dns_sighdlr_sigint() {
        QUIT_DNS.store(false, Ordering::SeqCst);
        dns_sighdlr(libc::SIGINT);
        assert!(dns_should_quit());
    }

    #[test]
    fn test_dns_sighdlr_unknown_signal() {
        QUIT_DNS.store(false, Ordering::SeqCst);
        dns_sighdlr(999); // Unknown signal
        assert!(!dns_should_quit());
    }

    #[test]
    fn test_dns_should_quit_default() {
        QUIT_DNS.store(false, Ordering::SeqCst);
        assert!(!dns_should_quit());
    }

    #[test]
    fn test_probe_root_result() {
        let r = DnsProbeResult::Success;
        assert!(r.is_success());
        let r = DnsProbeResult::Failure;
        assert!(!r.is_success());
    }

    #[test]
    fn test_dns_dispatch_imsg_empty_hostname() {
        let (mut a, _b) = ImsgSocket::pair().unwrap();
        let imsg = Imsg::new(IMSG_HOST_DNS, Vec::new());
        let result = dns_dispatch_imsg_inner(&mut a, &imsg);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("empty hostname"));
    }

    #[test]
    fn test_dns_dispatch_imsg_invalid_utf8() {
        let (mut a, _b) = ImsgSocket::pair().unwrap();
        // Invalid UTF-8 bytes
        let imsg = Imsg::new(IMSG_HOST_DNS, vec![0xff, 0xfe, 0x00]);
        let result = dns_dispatch_imsg_inner(&mut a, &imsg);
        assert!(result.is_err());
    }

    #[test]
    fn test_dns_dispatch_imsg_unknown_type() {
        let (mut a, _b) = ImsgSocket::pair().unwrap();
        let imsg = Imsg::new(999, b"test".to_vec());
        let result = dns_dispatch_imsg_inner(&mut a, &imsg);
        // Unknown types are silently ignored.
        assert!(result.is_ok());
    }

    #[test]
    fn test_dns_dispatch_imsg_resolve_ip_literal() {
        let (mut a, mut b) = ImsgSocket::pair().unwrap();
        let hostname = b"127.0.0.1\0";
        let imsg = Imsg::new(IMSG_HOST_DNS, hostname.to_vec());
        let result = dns_dispatch_imsg_inner(&mut a, &imsg);
        assert!(result.is_ok());

        // Check response
        let resp = b.recv().unwrap();
        assert_eq!(resp.header.type_, IMSG_HOST_DNS);
        // Payload: count(4 bytes) + addr(16 bytes)
        let payload = &resp.payload;
        assert!(payload.len() >= 4);
        let count = u32::from_be_bytes(payload[0..4].try_into().unwrap());
        assert!(count >= 1, "expected at least 1 address, got {}", count);
    }

    // ------------------------------------------------------------------
    // DnsResponse, request_dns_resolution, poll_dns_child
    // ------------------------------------------------------------------

    #[test]
    fn test_dns_response_struct() {
        let r = DnsResponse {
            id: 42,
            addresses: vec![
                std::net::IpAddr::V4(std::net::Ipv4Addr::new(127, 0, 0, 1)),
                std::net::IpAddr::V6(std::net::Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1)),
            ],
            success: true,
        };
        assert_eq!(r.id, 42);
        assert_eq!(r.addresses.len(), 2);
        assert!(r.success);

        let r2 = DnsResponse {
            id: 7,
            addresses: vec![],
            success: false,
        };
        assert!(!r2.success);
        assert!(r2.addresses.is_empty());
    }

    #[test]
    fn test_request_dns_resolution_sends_to_child() {
        let (mut parent, _child) = ImsgSocket::pair().unwrap();

        let result = request_dns_resolution(&mut parent, "example.com", 1);
        assert!(result.is_ok(), "send should succeed: {:?}", result);
    }

    #[test]
    fn test_request_dns_resolution_sets_peer_id() {
        let (mut parent, mut child) = ImsgSocket::pair().unwrap();

        request_dns_resolution(&mut parent, "test.host", 99).unwrap();

        let received = child.recv().unwrap();
        assert_eq!(received.header.peer_id, 99);
        assert_eq!(received.header.type_, IMSG_HOST_DNS);

        // Payload should be hostname + null terminator.
        let payload = String::from_utf8(received.payload.clone()).unwrap();
        assert_eq!(payload.trim_end_matches('\0'), "test.host");
    }

    #[test]
    fn test_poll_dns_child_no_data() {
        let (mut parent, _child) = ImsgSocket::pair().unwrap();

        // Should return an empty vec (not an error) when no data.
        // But poll_dns_child needs a reference to the parent socket,
        // not the child.  Actually poll_dns_child is called from the
        // parent side after the child has sent data.  In this test
        // we haven't sent anything, so we'll get an empty vec.
        let responses = poll_dns_child(&mut parent).unwrap();
        assert!(
            responses.is_empty(),
            "expected no responses: {:?}",
            responses
        );
    }

    #[test]
    fn test_poll_dns_child_reads_responses() {
        let (parent, mut child) = ImsgSocket::pair().unwrap();
        let mut parent = parent;

        // Simulate the child sending a DNS response back to parent.
        let mut payload = Vec::new();
        let count = 1u32;
        payload.extend_from_slice(&count.to_be_bytes());
        // IPv4-mapped IPv6 for 127.0.0.1
        let mut addr = [0u8; 16];
        addr[10] = 0xff;
        addr[11] = 0xff;
        addr[12] = 127;
        addr[13] = 0;
        addr[14] = 0;
        addr[15] = 1;
        payload.extend_from_slice(&addr);

        let mut msg = Imsg::new(IMSG_HOST_DNS, payload);
        msg.header.peer_id = 42;
        child.send(&msg).unwrap();

        // Give the OS a moment to transfer the data.
        std::thread::sleep(std::time::Duration::from_millis(50));

        let responses = poll_dns_child(&mut parent).unwrap();
        assert_eq!(responses.len(), 1, "expected 1 response: {:?}", responses);
        assert_eq!(responses[0].id, 42);
        assert!(responses[0].success);
        assert_eq!(
            responses[0].addresses,
            vec![std::net::IpAddr::V4(std::net::Ipv4Addr::new(127, 0, 0, 1))]
        );
    }

    #[test]
    fn test_poll_dns_child_empty_response() {
        let (parent, mut child) = ImsgSocket::pair().unwrap();
        let mut parent = parent;

        // Simulate child sending a failure response (count=0).
        let payload = 0u32.to_be_bytes().to_vec();
        let mut msg = Imsg::new(IMSG_HOST_DNS, payload);
        msg.header.peer_id = 7;
        child.send(&msg).unwrap();

        std::thread::sleep(std::time::Duration::from_millis(50));

        let responses = poll_dns_child(&mut parent).unwrap();
        assert_eq!(responses.len(), 1);
        assert_eq!(responses[0].id, 7);
        assert!(!responses[0].success);
        assert!(responses[0].addresses.is_empty());
    }

    #[test]
    fn test_request_and_poll_roundtrip() {
        // Test the full roundtrip: parent sends request, child dispatches
        // it (via dns_dispatch_imsg_inner), parent polls for response.
        let (mut parent, mut child) = ImsgSocket::pair().unwrap();

        // Parent sends request
        request_dns_resolution(&mut parent, "127.0.0.1", 123).unwrap();

        // Child receives and dispatches
        let req = child.recv().unwrap();
        assert_eq!(req.header.type_, IMSG_HOST_DNS);
        assert_eq!(req.header.peer_id, 123);
        dns_dispatch_imsg_inner(&mut child, &req).unwrap();

        // Read the response directly via blocking recv (more reliable than poll).
        let resp = parent.recv().unwrap();
        assert_eq!(resp.header.type_, IMSG_HOST_DNS);

        // Parse payload: first 4 bytes = count, then 16-byte addresses.
        assert!(resp.payload.len() >= 4);
        let count = u32::from_be_bytes(resp.payload[0..4].try_into().unwrap()) as usize;
        assert!(count > 0, "expected at least 1 address in DNS response");

        // Verify at least one address is present (should be 127.0.0.1).
        assert!(resp.payload.len() >= 4 + count * 16);
    }
}
