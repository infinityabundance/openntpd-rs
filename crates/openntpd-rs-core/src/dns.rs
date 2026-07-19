use alloc::string::String;
use alloc::vec::Vec;
use core::net::IpAddr;

/// A DNS resolution request to be dispatched to the DNS child process.
#[derive(Debug, Clone)]
pub struct DnsRequest {
    pub id: u64,
    pub hostname: String,
    pub address_family: AddressFamily,
}

/// Desired address family for DNS resolution.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AddressFamily {
    /// Resolve only IPv4 addresses (A records).
    Ipv4Only,
    /// Resolve only IPv6 addresses (AAAA records).
    Ipv6Only,
    /// Resolve both A and AAAA records, preferring the first available.
    Any,
}

/// The result of a DNS resolution, delivered back from the child process.
#[derive(Debug, Clone)]
pub struct DnsResponse {
    pub id: u64,
    pub hostname: String,
    pub addresses: Vec<IpAddr>,
    pub success: bool,
}

impl DnsResponse {
    /// Construct a successful DNS response.
    pub fn new(id: u64, hostname: String, addresses: Vec<IpAddr>) -> Self {
        let success = !addresses.is_empty();
        Self {
            id,
            hostname,
            addresses,
            success,
        }
    }

    /// Construct a failed DNS response (resolution error, timeout, etc.).
    pub fn failed(id: u64, hostname: String) -> Self {
        Self {
            id,
            hostname,
            addresses: Vec::new(),
            success: false,
        }
    }
}

/// Split a constraint URL into a (host, path) pair.
///
/// Strips the `https://` prefix if present, then splits at the first `/` or `\`
/// to separate the hostname from the request path. If no delimiter is found the
/// path defaults to `"/"`.
///
/// # Examples
///
/// ```
/// assert_eq!(
///     openntpd_rs_core::dns::split_constraint_url("https://example.com/foo"),
///     ("example.com".into(), "/foo".into())
/// );
/// ```
pub fn split_constraint_url(url: &str) -> (String, String) {
    let url = url.strip_prefix("https://").unwrap_or(url);
    if let Some(pos) = url.find(|c: char| c == '/' || c == '\\') {
        (url[..pos].into(), url[pos..].into())
    } else {
        (url.into(), "/".into())
    }
}

/// Validate a config string as a potential hostname (basic sanity).
///
/// Checks that the hostname:
/// - Is non-empty
/// - Is at most 255 bytes
/// - Contains only allowed characters (`a-z`, `A-Z`, `0-9`, `-`, `.`)
/// - Does not start or end with a hyphen or dot
///
/// Note: this is a basic sanity check, not a full DNS validation.
pub fn validate_hostname(hostname: &str) -> Result<(), &'static str> {
    if hostname.is_empty() {
        return Err("hostname is empty");
    }

    if hostname.len() > 255 {
        return Err("hostname exceeds maximum length of 255 bytes");
    }

    if hostname.starts_with('.')
        || hostname.ends_with('.')
        || hostname.starts_with('-')
        || hostname.ends_with('-')
    {
        return Err("hostname must not start or end with a hyphen or dot");
    }

    for ch in hostname.chars() {
        match ch {
            'a'..='z' | 'A'..='Z' | '0'..='9' | '-' | '.' => {}
            _ => {
                return Err("hostname contains invalid characters");
            }
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    // ------------------------------------------------------------------
    // split_constraint_url
    // ------------------------------------------------------------------

    #[test]
    fn test_split_url_full_https_with_path() {
        assert_eq!(
            split_constraint_url("https://pool.ntp.org/zone/europe"),
            ("pool.ntp.org".into(), "/zone/europe".into())
        );
    }

    #[test]
    fn test_split_url_full_https_root_path() {
        assert_eq!(
            split_constraint_url("https://example.com/"),
            ("example.com".into(), "/".into())
        );
    }

    #[test]
    fn test_split_url_no_scheme_with_path() {
        assert_eq!(
            split_constraint_url("example.com/constraint"),
            ("example.com".into(), "/constraint".into())
        );
    }

    #[test]
    fn test_split_url_no_scheme_no_path() {
        assert_eq!(
            split_constraint_url("example.com"),
            ("example.com".into(), "/".into())
        );
    }

    #[test]
    fn test_split_url_backslash_delimiter() {
        assert_eq!(
            split_constraint_url("https://host\\path"),
            ("host".into(), "\\path".into())
        );
    }

    #[test]
    fn test_split_url_empty_string() {
        assert_eq!(split_constraint_url(""), ("".into(), "/".into()));
    }

    #[test]
    fn test_split_url_just_scheme_no_host() {
        // "https://" stripped → empty host, no delimiter → path defaults to "/"
        assert_eq!(split_constraint_url("https://"), ("".into(), "/".into()));
    }

    #[test]
    fn test_split_url_ipv4_host() {
        assert_eq!(
            split_constraint_url("https://192.168.1.1/ntp"),
            ("192.168.1.1".into(), "/ntp".into())
        );
    }

    #[test]
    fn test_split_url_ipv6_host() {
        assert_eq!(
            split_constraint_url("https://[::1]/constraint"),
            ("[::1]".into(), "/constraint".into())
        );
    }

    // ------------------------------------------------------------------
    // validate_hostname
    // ------------------------------------------------------------------

    #[test]
    fn test_validate_hostname_valid_simple() {
        assert!(validate_hostname("pool.ntp.org").is_ok());
    }

    #[test]
    fn test_validate_hostname_valid_single_label() {
        assert!(validate_hostname("localhost").is_ok());
    }

    #[test]
    fn test_validate_hostname_valid_with_numbers() {
        assert!(validate_hostname("ntp-1.example42.com").is_ok());
    }

    #[test]
    fn test_validate_hostname_valid_trailing_dot_allowed() {
        // a trailing dot is technically valid in DNS (absolute FQDN)
        // but our simple validator rejects it at the ends-with check.
        assert!(validate_hostname("example.com.").is_err());
    }

    #[test]
    fn test_validate_hostname_empty() {
        assert_eq!(validate_hostname(""), Err("hostname is empty"));
    }

    #[test]
    fn test_validate_hostname_too_long() {
        let long = "a".repeat(256);
        assert_eq!(
            validate_hostname(&long),
            Err("hostname exceeds maximum length of 255 bytes")
        );
    }

    #[test]
    fn test_validate_hostname_starts_with_hyphen() {
        assert_eq!(
            validate_hostname("-example.com"),
            Err("hostname must not start or end with a hyphen or dot")
        );
    }

    #[test]
    fn test_validate_hostname_ends_with_hyphen() {
        assert_eq!(
            validate_hostname("example.com-"),
            Err("hostname must not start or end with a hyphen or dot")
        );
    }

    #[test]
    fn test_validate_hostname_starts_with_dot() {
        assert_eq!(
            validate_hostname(".example.com"),
            Err("hostname must not start or end with a hyphen or dot")
        );
    }

    #[test]
    fn test_validate_hostname_invalid_characters() {
        assert_eq!(
            validate_hostname("example!.com"),
            Err("hostname contains invalid characters")
        );
    }

    #[test]
    fn test_validate_hostname_underscore() {
        // underscores are not allowed in hostnames per RFC 952/1123
        assert_eq!(
            validate_hostname("my_host.local"),
            Err("hostname contains invalid characters")
        );
    }

    #[test]
    fn test_validate_hostname_space() {
        assert_eq!(
            validate_hostname("ex ample.com"),
            Err("hostname contains invalid characters")
        );
    }

    #[test]
    fn test_validate_hostname_unicode() {
        assert_eq!(
            validate_hostname("exämple.com"),
            Err("hostname contains invalid characters")
        );
    }

    #[test]
    fn test_validate_hostname_max_length_valid() {
        // 255 bytes, all alphanumeric and dots/hyphens at valid positions
        let mut s = String::with_capacity(255);
        // start with a letter, then fill, ensure we don't hit invalid edge
        s.push('a');
        for _ in 0..125 {
            s.push_str("bc.");
        }
        s.truncate(254);
        s.push('z');
        // Verify it's exactly 255
        assert_eq!(s.len(), 255);
        assert!(validate_hostname(&s).is_ok());
    }

    // ------------------------------------------------------------------
    // DnsResponse::new / DnsResponse::failed
    // ------------------------------------------------------------------

    #[test]
    fn test_dns_response_new_with_addresses() {
        let resp = DnsResponse::new(
            42,
            "pool.ntp.org".into(),
            vec!["192.0.2.1".parse().unwrap()],
        );
        assert!(resp.success);
        assert_eq!(resp.id, 42);
        assert_eq!(resp.addresses.len(), 1);
    }

    #[test]
    fn test_dns_response_new_empty_addresses() {
        let resp = DnsResponse::new(1, "nowhere.example".into(), vec![]);
        assert!(!resp.success);
    }

    #[test]
    fn test_dns_response_failed() {
        let resp = DnsResponse::failed(7, "bad.host".into());
        assert!(!resp.success);
        assert!(resp.addresses.is_empty());
    }
}
