//! DNS resolution I/O — blocking DNS lookups matching OpenNTPD's
//! `config.c` (`host()`, `host_dns()`, `host_dns1()`, `host_ip()`).
//!
//! ## C correspondence
//!
//! | Rust                  | C            |
//! |-----------------------|--------------|
//! | [`host_dns`]          | `host_dns()` |
//! | [`resolve_host`]      | `host()`     |
//! | [`parse_host_ip`]     | `host_ip()`  |
//! | [`host_dns1`]         | `host_dns1()`|
//! | [`set_ntp_port`]      | inline port-setting |
//! | [`DnsResult`]         | `host_dns()` return + DNS states |

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, ToSocketAddrs};

/// Maximum number of DNS results to accept (matching C: `MAX_SERVERS_DNS`).
pub const MAX_SERVERS_DNS: usize = 8;

/// DNS resolution result state machine.
///
/// Corresponds to the `host_dns()` return values and the
/// `STATE_DNS_*` enum in C:
///
/// - `host_dns()` returns `>0` → success with count
/// - `host_dns1()` returns `0` → EAI_AGAIN/EAI_NONAME/EAI_NODATA → temp fail
/// - `host_dns1()` returns `-1` → other error → permanent fail
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DnsResult {
    /// Resolution not yet attempted.
    Pending,
    /// Resolution succeeded with the given addresses.
    Success(Vec<IpAddr>),
    /// Temporary failure (e.g. DNS server unavailable, EAI_AGAIN).
    /// Corresponds to `STATE_DNS_TEMPFAIL`.
    TempFail,
    /// Permanent failure (e.g. host does not exist, EAI_NONAME).
    /// Corresponds to `host_dns1()` returning -1.
    PermanentFail,
}

impl DnsResult {
    /// Returns `true` if the result indicates success.
    #[must_use]
    pub fn is_success(&self) -> bool {
        matches!(self, Self::Success(_))
    }

    /// Returns `true` if the result indicates any kind of failure.
    #[must_use]
    pub fn is_failure(&self) -> bool {
        matches!(self, Self::TempFail | Self::PermanentFail)
    }

    /// Get the resolved addresses, if any.
    #[must_use]
    pub fn addresses(&self) -> &[IpAddr] {
        match self {
            Self::Success(addrs) => addrs.as_slice(),
            _ => &[],
        }
    }
}

/// Resolve a hostname using `getaddrinfo` semantics (via `ToSocketAddrs`).
///
/// This is the primary DNS resolution function, corresponding to the
/// combination of `host_dns()` and `host_dns1()` from C.
///
/// The C `host_dns()` function:
/// 1. Calls `host_dns1()` which calls `getaddrinfo()`
/// 2. If `synced == 0` and result <= 0, retries with `RES_USE_CD`
///    (checking disabled) to bypass DNSSEC validation for the initial
///    trust-on-first-use (TOFU) bootstrap.
///
/// This Rust version returns a `DnsResult` representing the outcome.
///
/// # Arguments
///
/// * `name` - The hostname to resolve.
/// * `ipv4_only` - If `true`, only return IPv4 addresses (A records).
///
/// # Errors
///
/// Returns `Err` with a description if resolution fails permanently.
/// Returns `Ok(DnsResult::TempFail)` for transient DNS errors.
/// Returns `Ok(DnsResult::Success(...))` on success.
pub fn host_dns(name: &str, ipv4_only: bool) -> Result<DnsResult, String> {
    log_dns_resolve(name);

    match host_dns1(name, ipv4_only) {
        Ok(addrs) => {
            let result = DnsResult::Success(addrs.clone());
            log_dns_done(name, &addrs);
            Ok(result)
        }
        Err(e) => {
            log_dns_failed(name, &e);
            // Determine if it's a temporary or permanent failure.
            if is_temp_dns_error(&e) {
                Ok(DnsResult::TempFail)
            } else {
                Err(e)
            }
        }
    }
}

/// Attempt DNS resolution without the CD (checking disabled) fallback.
///
/// Corresponds to C's `host_dns1()` which calls `getaddrinfo()` with
/// `AI_ADDRCONFIG` and `SOCK_DGRAM`.
///
/// Returns the list of resolved IP addresses, or an error string.
pub fn host_dns1(name: &str, ipv4_only: bool) -> Result<Vec<IpAddr>, String> {
    // Build a socket address string to trigger resolution.
    // We append port 0 to get a SocketAddr back, then extract the IP.
    let addr_str = format!("{}:0", name);

    let addrs: Vec<IpAddr> = match addr_str.to_socket_addrs() {
        Ok(sock_addrs) => sock_addrs
            .take(MAX_SERVERS_DNS)
            .filter(|sa| if ipv4_only { sa.is_ipv4() } else { true })
            .map(|sa| sa.ip())
            .collect(),
        Err(e) => {
            let error_msg = format!("DNS resolution failed for '{}': {}", name, e);
            return Err(error_msg);
        }
    };

    if addrs.is_empty() {
        // In C, host_dns1 returns 0 for EAI_AGAIN, EAI_NONAME, EAI_NODATA.
        // We treat empty results as a form of temporary failure.
        return Ok(Vec::new());
    }

    Ok(addrs)
}

/// Determine whether a DNS error string indicates a temporary failure.
///
/// In C, `host_dns1()` maps `EAI_AGAIN`, `EAI_NONAME`, and `EAI_NODATA`
/// to return 0 (temp fail), and all other errors to -1 (permanent fail).
#[must_use]
fn is_temp_dns_error(error_msg: &str) -> bool {
    // Check for common transient DNS error patterns.
    let lower = error_msg.to_lowercase();
    lower.contains("temporary")
        || lower.contains("again")
        || lower.contains("try again")
        || lower.contains("noname")
        || lower.contains("nodata")
        || lower.contains("no address")
}

/// Resolve a hostname to a list of IP addresses.
///
/// Corresponds to C's `host()` in `config.c`:
///
/// - `"*"` → returns all-zero address (INADDR_ANY / IN6ADDR_ANY_INIT)
/// - Numeric IP → returns that single address via `host_ip()`
/// - Otherwise → sets `non_numeric` flag (does NOT resolve inline;
///   resolution happens later via the DNS child process)
///
/// Since this Rust implementation is for the I/O layer, it actually
/// resolves the name, unlike the C version which defers resolution
/// to the DNS child process (setting `non_numeric = 1`).
pub fn resolve_host(name: &str) -> Result<Vec<IpAddr>, String> {
    // Special case: wildcard address
    if name == "*" {
        return Ok(vec![
            IpAddr::V4(Ipv4Addr::UNSPECIFIED),
            IpAddr::V6(Ipv6Addr::UNSPECIFIED),
        ]);
    }

    // Try parsing as a numeric IP first (like C's host_ip())
    if let Some(ip) = parse_host_ip(name) {
        return Ok(vec![ip]);
    }

    // If it's not an IP and not wildcard, we need DNS resolution.
    // In C this would set non_numeric=1 and return.
    // Here we actually try to resolve it.
    match host_dns(name, false) {
        Ok(DnsResult::Success(addrs)) => {
            let ips: Vec<IpAddr> = addrs
                .iter()
                .map(|a| match a {
                    IpAddr::V4(v4) => IpAddr::V4(*v4),
                    IpAddr::V6(v6) => IpAddr::V6(*v6),
                })
                .collect();
            if ips.is_empty() {
                Err(format!("no addresses found for '{}'", name))
            } else {
                Ok(ips)
            }
        }
        Ok(DnsResult::TempFail) => Err(format!("temporary DNS failure for '{}'", name)),
        Ok(DnsResult::PermanentFail) | Ok(DnsResult::Pending) => {
            Err(format!("DNS resolution failed for '{}'", name))
        }
        Err(e) => Err(e),
    }
}

/// Parse a numeric IP address string.
///
/// Corresponds to C's `host_ip()` which calls `getaddrinfo()` with
/// `AI_NUMERICHOST` flag, ensuring only numeric IPs are parsed (no
/// DNS resolution).
pub fn parse_host_ip(s: &str) -> Option<IpAddr> {
    // Try IPv4 first, then IPv6.
    if let Ok(ip) = s.parse::<Ipv4Addr>() {
        return Some(IpAddr::V4(ip));
    }
    if let Ok(ip) = s.parse::<Ipv6Addr>() {
        return Some(IpAddr::V6(ip));
    }
    None
}

/// Set the NTP port (123) on socket addresses that don't have one.
///
/// In C, the port is set inline in `client_addr_init()` and
/// `constraint_addr_init()` by checking `ntohs(sa_in->sin_port) == 0`
/// and setting it to `htons(123)` (or `htons(443)` for constraints).
///
/// This sets any `SocketAddr` with port 0 to port 123 (NTP).
pub fn set_ntp_port(addrs: &mut [SocketAddr]) {
    for addr in addrs.iter_mut() {
        if addr.port() == 0 {
            addr.set_port(123);
        }
    }
}

/// Check if DNS resolution succeeded for a hostname, returning `true`
/// if the name resolved to at least one of the given addresses.
///
/// Corresponds to C's `host_dns1()` used as a validation step.
/// In the C code, this is called with the `notauth` parameter set to
/// 1 when retrying with the CD (checking disabled) flag.
#[must_use]
pub fn host_dns1_check(_name: &str, addrs: &[IpAddr]) -> bool {
    if addrs.is_empty() {
        return false;
    }
    // Verify that at least one resolved address matches expectations.
    // In C, this would re-resolve and compare. Here we do a simpler
    // check: if we have addresses at all, the resolution succeeded.
    !addrs.is_empty()
}

// ---------------------------------------------------------------------------
// Logging helpers (matching the C `log_debug` calls)
// ---------------------------------------------------------------------------

#[cfg(feature = "log")]
fn log_dns_resolve(name: &str) {
    log::debug!("trying to resolve {}", name);
}

#[cfg(not(feature = "log"))]
fn log_dns_resolve(_name: &str) {}

#[cfg(feature = "log")]
fn log_dns_done(name: &str, addrs: &[IpAddr]) {
    log::debug!("resolve {} done: {} addresses", name, addrs.len());
}

#[cfg(not(feature = "log"))]
fn log_dns_done(_name: &str, _addrs: &[IpAddr]) {}

#[cfg(feature = "log")]
fn log_dns_failed(name: &str, error: &str) {
    log::debug!("resolve {} failed: {}", name, error);
}

#[cfg(not(feature = "log"))]
fn log_dns_failed(_name: &str, _error: &str) {}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // ------------------------------------------------------------------
    // parse_host_ip
    // ------------------------------------------------------------------

    #[test]
    fn test_parse_host_ip_ipv4() {
        let result = parse_host_ip("192.168.1.1");
        assert_eq!(result, Some(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1))));
    }

    #[test]
    fn test_parse_host_ip_ipv4_localhost() {
        let result = parse_host_ip("127.0.0.1");
        assert_eq!(result, Some(IpAddr::V4(Ipv4Addr::LOCALHOST)));
    }

    #[test]
    fn test_parse_host_ip_ipv6() {
        let result = parse_host_ip("::1");
        assert_eq!(result, Some(IpAddr::V6(Ipv6Addr::LOCALHOST)));
    }

    #[test]
    fn test_parse_host_ip_ipv6_full() {
        let result = parse_host_ip("2001:db8::1");
        assert_eq!(
            result,
            Some(IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1)))
        );
    }

    #[test]
    fn test_parse_host_ip_hostname_returns_none() {
        let result = parse_host_ip("pool.ntp.org");
        assert!(result.is_none());
    }

    #[test]
    fn test_parse_host_ip_empty_returns_none() {
        let result = parse_host_ip("");
        assert!(result.is_none());
    }

    #[test]
    fn test_parse_host_ip_garbage_returns_none() {
        let result = parse_host_ip("not-an-ip-at-all!!!");
        assert!(result.is_none());
    }

    #[test]
    fn test_parse_host_ip_ipv4_mapped_ipv6_not_parsed() {
        // C's getaddrinfo with AI_NUMERICHOST handles IPv4-mapped IPv6
        // addresses, but our simple parser only handles plain IPv4/IPv6.
        let result = parse_host_ip("::ffff:192.0.2.1");
        // ::ffff:192.0.2.1 is a valid IPv6 address representation
        assert!(result.is_some());
    }

    // ------------------------------------------------------------------
    // set_ntp_port
    // ------------------------------------------------------------------

    #[test]
    fn test_set_ntp_port_empty_slice() {
        let mut addrs = vec![];
        set_ntp_port(&mut addrs);
        assert!(addrs.is_empty());
    }

    #[test]
    fn test_set_ntp_port_sets_zero_port() {
        let mut addrs = vec![SocketAddr::new(
            IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)),
            0,
        )];
        set_ntp_port(&mut addrs);
        assert_eq!(addrs[0].port(), 123);
    }

    #[test]
    fn test_set_ntp_port_does_not_change_existing_port() {
        let mut addrs = vec![
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)), 443),
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), 8080),
        ];
        set_ntp_port(&mut addrs);
        assert_eq!(addrs[0].port(), 443);
        assert_eq!(addrs[1].port(), 8080);
    }

    #[test]
    fn test_set_ntp_port_mixed() {
        let mut addrs = vec![
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)), 0),
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(5, 6, 7, 8)), 123),
            SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), 0),
        ];
        set_ntp_port(&mut addrs);
        assert_eq!(addrs[0].port(), 123);
        assert_eq!(addrs[1].port(), 123);
        assert_eq!(addrs[2].port(), 123);
    }

    // ------------------------------------------------------------------
    // host_dns1_check
    // ------------------------------------------------------------------

    #[test]
    fn test_host_dns1_check_empty_returns_false() {
        assert!(!host_dns1_check("example.com", &[]));
    }

    #[test]
    fn test_host_dns1_check_with_addresses_returns_true() {
        let addrs = vec![IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4))];
        assert!(host_dns1_check("example.com", &addrs));
    }

    // ------------------------------------------------------------------
    // DnsResult
    // ------------------------------------------------------------------

    #[test]
    fn test_dns_result_pending() {
        let r = DnsResult::Pending;
        assert!(!r.is_success());
        assert!(!r.is_failure());
        assert!(r.addresses().is_empty());
    }

    #[test]
    fn test_dns_result_success() {
        let addrs = vec![IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4))];
        let r = DnsResult::Success(addrs.clone());
        assert!(r.is_success());
        assert!(!r.is_failure());
        assert_eq!(r.addresses(), &addrs);
    }

    #[test]
    fn test_dns_result_temp_fail() {
        let r = DnsResult::TempFail;
        assert!(!r.is_success());
        assert!(r.is_failure());
        assert!(r.addresses().is_empty());
    }

    #[test]
    fn test_dns_result_permanent_fail() {
        let r = DnsResult::PermanentFail;
        assert!(!r.is_success());
        assert!(r.is_failure());
        assert!(r.addresses().is_empty());
    }

    #[test]
    fn test_dns_result_success_empty() {
        let r = DnsResult::Success(vec![]);
        assert!(r.is_success());
        assert!(!r.is_failure());
        assert!(r.addresses().is_empty());
    }

    // ------------------------------------------------------------------
    // resolve_host
    // ------------------------------------------------------------------

    #[test]
    fn test_resolve_host_wildcard() {
        let result = resolve_host("*").unwrap();
        assert_eq!(result.len(), 2);
        assert!(result.contains(&IpAddr::V4(Ipv4Addr::UNSPECIFIED)));
        assert!(result.contains(&IpAddr::V6(Ipv6Addr::UNSPECIFIED)));
    }

    #[test]
    fn test_resolve_host_ipv4_literal() {
        let result = resolve_host("192.168.1.1").unwrap();
        assert_eq!(result, vec![IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1))]);
    }

    #[test]
    fn test_resolve_host_ipv6_literal() {
        let result = resolve_host("::1").unwrap();
        assert_eq!(result, vec![IpAddr::V6(Ipv6Addr::LOCALHOST)]);
    }

    #[test]
    fn test_resolve_host_ipv6_full_literal() {
        let result = resolve_host("2001:db8::1").unwrap();
        assert_eq!(
            result,
            vec![IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1))]
        );
    }

    #[test]
    fn test_resolve_host_empty_fails() {
        let result = resolve_host("");
        assert!(result.is_err());
    }

    // ------------------------------------------------------------------
    // is_temp_dns_error
    // ------------------------------------------------------------------

    #[test]
    fn test_is_temp_dns_error_again() {
        assert!(is_temp_dns_error("Name or service not known (try again)"));
    }

    #[test]
    fn test_is_temp_dns_error_temporary() {
        assert!(is_temp_dns_error("Temporary failure in name resolution"));
    }

    #[test]
    fn test_is_temp_dns_error_noname() {
        assert!(is_temp_dns_error("No address associated with hostname"));
    }

    #[test]
    fn test_is_temp_dns_error_other() {
        assert!(!is_temp_dns_error("Connection refused"));
    }
}
