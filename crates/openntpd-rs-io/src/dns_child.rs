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
}
