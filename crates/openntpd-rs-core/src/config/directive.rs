//! Configuration directives — OpenNTPD 7.9p1 `ntpd.conf` AST.
//!
//! ## Directive-to-option mapping (from parse.y)
//!
//! | Directive       | Options                                         |
//! |-----------------|-------------------------------------------------|
//! | `listen on`     | `rtable <num>`                                  |
//! | `query from`    | numeric IPv4 or IPv6 only                       |
//! | `server`        | `weight <1-10>`, `trusted`                      |
//! | `servers`       | `weight <1-10>`, `trusted`                      |
//! | `constraint`    | HTTPS host/path + optional pinned numeric addrs |
//! | `constraints`   | HTTPS host/path                                 |
//! | `sensor`        | `correction <µs>`, `refid <str>`, `stratum`, `weight`, `trusted` |

use alloc::{string::String, vec::Vec};
use core::fmt;
use core::net::IpAddr;

// ---------------------------------------------------------------------------
// ConfigString — byte-string preserving exact parser input
// ---------------------------------------------------------------------------

/// A non-NUL byte string from configuration input.
///
/// OpenNTPD's lexer stores configuration strings in a raw `char` buffer
/// and rejects NUL but does not validate UTF-8.  Quoted strings can
/// contain arbitrary bytes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ConfigString(Vec<u8>);

impl ConfigString {
    /// Create from bytes.  Returns `None` if the input contains NUL.
    pub fn new(bytes: Vec<u8>) -> Option<Self> {
        if bytes.contains(&0) {
            None
        } else {
            Some(Self(bytes))
        }
    }

    /// The underlying bytes.
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// Try to interpret as UTF-8.
    pub fn as_utf8(&self) -> Option<&str> {
        core::str::from_utf8(&self.0).ok()
    }

    /// Convert to a Rust String if valid UTF-8.
    pub fn to_utf8_string(&self) -> Option<String> {
        core::str::from_utf8(&self.0).ok().map(|s| s.into())
    }
}

impl fmt::Display for ConfigString {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if let Ok(s) = core::str::from_utf8(&self.0) {
            write!(f, "{s}")
        } else {
            write!(f, "{:02x?}", self.0)
        }
    }
}

// ---------------------------------------------------------------------------
// Source spans
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SourceSpan {
    pub start: usize,
    pub end: usize,
}
impl SourceSpan {
    pub fn new(start: usize, end: usize) -> Self {
        Self { start, end }
    }
    pub fn union(self, other: Self) -> Self {
        Self {
            start: self.start.min(other.start),
            end: self.end.max(other.end),
        }
    }
}

// ---------------------------------------------------------------------------
// Spanned wrapper
// ---------------------------------------------------------------------------

#[derive(Clone, Debug, PartialEq)]
pub struct Spanned<T> {
    pub value: T,
    pub span: SourceSpan,
}
impl<T> Spanned<T> {
    pub fn new(value: T, span: SourceSpan) -> Self {
        Self { value, span }
    }
}

// ---------------------------------------------------------------------------
// Top-level config
// ---------------------------------------------------------------------------

#[derive(Clone, Debug, PartialEq)]
pub struct Config {
    pub directives: Vec<Spanned<Directive>>,
}
impl Config {
    pub fn new() -> Self {
        Self {
            directives: Vec::new(),
        }
    }
}
impl Default for Config {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Directive enum — contextual address types
// ---------------------------------------------------------------------------

#[derive(Clone, Debug, PartialEq)]
pub enum Directive {
    Listen(ListenDirective),
    /// Numeric IP address only (parse.y calls inet_pton, rejects hostnames).
    QueryFrom(IpAddr),
    Server(ServerDirective),
    Constraint(ConstraintDirective),
    Sensor(SensorDirective),
}

// ---------------------------------------------------------------------------
// Listen
// ---------------------------------------------------------------------------

#[derive(Clone, Debug, PartialEq)]
pub enum ListenAddress {
    Wildcard,
    Numeric(IpAddr),
    /// Hostname preserving the original bytes (resolved by runtime lowering
    /// via `host_dns()`, matching OpenNTPD's config.c behavior).
    Name(ConfigString),
}

#[derive(Clone, Debug, PartialEq)]
pub struct ListenDirective {
    pub address: ListenAddress,
    pub rtable: RoutingTable,
}

// ---------------------------------------------------------------------------
// Server / pool
// ---------------------------------------------------------------------------

/// A server address: hostname or numeric IP.
#[derive(Clone, Debug, PartialEq)]
pub enum ServerAddress {
    Numeric(IpAddr),
    Name(ConfigString),
}

#[derive(Clone, Debug, PartialEq)]
pub enum ServerDirective {
    Single {
        address: ServerAddress,
        options: ServerOptions,
    },
    Pool {
        address: ServerAddress,
        options: ServerOptions,
    },
}

/// OpenNTPD `server`/`servers` options: only `weight` and `trusted`.
#[derive(Clone, Debug, PartialEq)]
pub struct ServerOptions {
    pub weight: Weight,
    pub trusted: bool,
}
impl Default for ServerOptions {
    fn default() -> Self {
        Self {
            weight: Weight::ONE,
            trusted: false,
        }
    }
}

// ---------------------------------------------------------------------------
// Constraint
// ---------------------------------------------------------------------------

#[derive(Clone, Debug, PartialEq)]
pub enum ConstraintDirective {
    Single {
        endpoint: ConstraintEndpoint,
        pinned_addresses: Vec<IpAddr>,
    },
    Pool {
        endpoint: ConstraintEndpoint,
    },
}

#[derive(Clone, Debug, PartialEq)]
pub struct ConstraintEndpoint {
    pub host: HostNameOrIp,
    pub path: ConfigString,
}

/// A hostname or numeric IP (no wildcard — not valid for constraints).
#[derive(Clone, Debug, PartialEq)]
pub enum HostNameOrIp {
    Numeric(IpAddr),
    Name(ConfigString),
}

// ---------------------------------------------------------------------------
// Sensor
// ---------------------------------------------------------------------------

#[derive(Clone, Debug, PartialEq)]
pub struct SensorDirective {
    pub device: ConfigString,
    pub options: SensorOptions,
}

/// OpenNTPD sensor options: `correction`, `refid`, `stratum`, `weight`, `trusted`.
#[derive(Clone, Debug, PartialEq)]
pub struct SensorOptions {
    pub correction: CorrectionMicros,
    pub refid: Option<RefId>,
    pub stratum: Stratum,
    pub weight: Weight,
    pub trusted: bool,
}
impl Default for SensorOptions {
    fn default() -> Self {
        Self {
            correction: CorrectionMicros::ZERO,
            refid: None,
            stratum: Stratum::ONE,
            weight: Weight::ONE,
            trusted: false,
        }
    }
}

// ---------------------------------------------------------------------------
// Validated newtypes
// ---------------------------------------------------------------------------

/// Selection weight (1–10).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Weight(u8);
impl Weight {
    pub const ONE: Self = Self(1);
    pub const MIN: u8 = 1;
    pub const MAX: u8 = 10;
    pub fn new(w: u8) -> Option<Self> {
        if (Self::MIN..=Self::MAX).contains(&w) {
            Some(Self(w))
        } else {
            None
        }
    }
    pub fn get(self) -> u8 {
        self.0
    }
}

/// Advertised stratum (1–15).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Stratum(u8);
impl Stratum {
    pub const ONE: Self = Self(1);
    pub const MIN: u8 = 1;
    pub const MAX: u8 = 15;
    pub fn new(s: u8) -> Option<Self> {
        if (Self::MIN..=Self::MAX).contains(&s) {
            Some(Self(s))
        } else {
            None
        }
    }
    pub fn get(self) -> u8 {
        self.0
    }
}

/// Clock correction in microseconds (±127_000_000).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CorrectionMicros(i32);
impl CorrectionMicros {
    pub const ZERO: Self = Self(0);
    pub const MIN: i32 = -127_000_000;
    pub const MAX: i32 = 127_000_000;
    pub fn new(c: i32) -> Option<Self> {
        if (Self::MIN..=Self::MAX).contains(&c) {
            Some(Self(c))
        } else {
            None
        }
    }
    pub fn get(self) -> i32 {
        self.0
    }
}

/// Reference identifier — 1 to 4 bytes (OpenNTPD accepts 1–4 chars).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RefId {
    bytes: [u8; 4],
    /// Valid length: 1..=4.
    len: u8,
}
impl RefId {
    /// Create from a byte slice of length 1–4.  Returns `None` for empty,
    /// more than 4 byte inputs, or inputs containing embedded NUL (the lexer rejects
    /// NUL and OpenNTPD measures with `strlen()`).
    pub fn from_bytes(src: &[u8]) -> Option<Self> {
        let len = src.len();
        if !(1..=4).contains(&len) || src.contains(&0) {
            return None;
        }
        let mut bytes = [0u8; 4];
        bytes[..len].copy_from_slice(src);
        Some(Self {
            bytes,
            len: len as u8,
        })
    }
    /// The raw 4-byte array (unused trailing bytes are zero).
    pub fn bytes(self) -> [u8; 4] {
        self.bytes
    }
    /// The number of meaningful bytes (1..=4).
    #[must_use]
    pub fn len(self) -> u8 {
        self.len
    }

    /// Returns `true` if the refid is empty (no bytes).
    #[must_use]
    pub fn is_empty(self) -> bool {
        self.len == 0
    }
}
impl fmt::Display for RefId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let slice = &self.bytes[..self.len as usize];
        if slice.iter().all(|b| b.is_ascii_graphic() || *b == b' ') {
            let s = core::str::from_utf8(slice).unwrap_or("????");
            write!(f, "\"{s}\"")
        } else {
            for &b in slice {
                write!(f, "{b:02x}")?;
            }
            Ok(())
        }
    }
}

/// Routing table ID.  The grammar accepts values up to RT_TABLEID_MAX
/// (platform-dependent).  This stores the raw parsed u32; target-specific
/// upper-bound checking is deferred to semantic lowering.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct RoutingTable(i64);
impl RoutingTable {
    pub fn new(rt: i64) -> Self {
        Self(rt)
    }
    pub fn get(self) -> i64 {
        self.0
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::string::ToString;
    use alloc::vec;

    // Weight
    #[test]
    fn weight_zero_rejected() {
        assert!(Weight::new(0).is_none());
    }
    #[test]
    fn weight_one_accepted() {
        assert_eq!(Weight::new(1).unwrap().get(), 1);
    }
    #[test]
    fn weight_ten_accepted() {
        assert_eq!(Weight::new(10).unwrap().get(), 10);
    }
    #[test]
    fn weight_eleven_rejected() {
        assert!(Weight::new(11).is_none());
    }

    // Stratum
    #[test]
    fn stratum_zero_rejected() {
        assert!(Stratum::new(0).is_none());
    }
    #[test]
    fn stratum_one_accepted() {
        assert!(Stratum::new(1).is_some());
    }
    #[test]
    fn stratum_fifteen_accepted() {
        assert!(Stratum::new(15).is_some());
    }
    #[test]
    fn stratum_sixteen_rejected() {
        assert!(Stratum::new(16).is_none());
    }

    // CorrectionMicros
    #[test]
    fn correction_min_accepted() {
        assert!(CorrectionMicros::new(-127_000_000).is_some());
    }
    #[test]
    fn correction_max_accepted() {
        assert!(CorrectionMicros::new(127_000_000).is_some());
    }
    #[test]
    fn correction_below_min_rejected() {
        assert!(CorrectionMicros::new(-127_000_001).is_none());
    }
    #[test]
    fn correction_above_max_rejected() {
        assert!(CorrectionMicros::new(127_000_001).is_none());
    }
    #[test]
    fn correction_zero_accepted() {
        assert_eq!(CorrectionMicros::new(0).unwrap().get(), 0);
    }

    // RefId (1–4 bytes)
    #[test]
    fn refid_empty_rejected() {
        assert!(RefId::from_bytes(b"").is_none());
    }
    #[test]
    fn refid_one_byte() {
        let r = RefId::from_bytes(b"G").unwrap();
        assert_eq!(r.len(), 1);
        assert_eq!(r.bytes()[0], b'G');
    }
    #[test]
    fn refid_four_bytes() {
        let r = RefId::from_bytes(b"GPS1").unwrap();
        assert_eq!(r.len(), 4);
    }
    #[test]
    fn refid_nul_rejected() {
        assert!(RefId::from_bytes(b"GPS\0").is_none());
    }
    #[test]
    fn refid_five_bytes_rejected() {
        assert!(RefId::from_bytes(b"LONG5").is_none());
    }
    #[test]
    fn refid_display_ascii() {
        let r = RefId::from_bytes(b"GOES").unwrap();
        let s = r.to_string();
        assert!(s.contains("GOES"));
    }

    // ServerOptions
    #[test]
    fn server_options_defaults() {
        let o = ServerOptions::default();
        assert_eq!(o.weight, Weight::ONE);
        assert!(!o.trusted);
    }

    // SensorOptions
    #[test]
    fn sensor_options_defaults() {
        let o = SensorOptions::default();
        assert_eq!(o.weight, Weight::ONE);
        assert_eq!(o.stratum, Stratum::ONE);
        assert!(!o.trusted);
    }

    // Config
    #[test]
    fn config_empty() {
        assert!(Config::new().directives.is_empty());
    }

    // SourceSpan
    #[test]
    fn span_union() {
        let a = SourceSpan::new(5, 10);
        let b = SourceSpan::new(0, 15);
        let u = a.union(b);
        assert_eq!(u.start, 0);
        assert_eq!(u.end, 15);
    }

    // Directive construction smoke tests
    #[test]
    fn listen_wildcard() {
        let d = Directive::Listen(ListenDirective {
            address: ListenAddress::Wildcard,
            rtable: RoutingTable::new(0),
        });
        assert!(matches!(d, Directive::Listen(_)));
    }
    #[test]
    fn listen_hostname() {
        let d = ListenDirective {
            address: ListenAddress::Name(
                ConfigString::new(b"time.internal.example".to_vec()).unwrap(),
            ),
            rtable: RoutingTable::new(0),
        };
        assert!(matches!(d.address, ListenAddress::Name(_)));
    }
    #[test]
    fn server_directive() {
        let d = Directive::Server(ServerDirective::Single {
            address: ServerAddress::Name(ConfigString::new(b"pool.ntp.org".to_vec()).unwrap()),
            options: ServerOptions::default(),
        });
        assert!(matches!(d, Directive::Server(_)));
    }
    #[test]
    fn server_pool_directive() {
        let d = Directive::Server(ServerDirective::Pool {
            address: ServerAddress::Numeric("127.0.0.1".parse().unwrap()),
            options: ServerOptions {
                weight: Weight::new(5).unwrap(),
                trusted: true,
            },
        });
        assert!(matches!(d, Directive::Server(_)));
    }
    #[test]
    fn query_from_ip() {
        let d = Directive::QueryFrom("10.0.0.1".parse().unwrap());
        assert!(matches!(d, Directive::QueryFrom(_)));
    }
    #[test]
    fn constraint_single() {
        let d = Directive::Constraint(ConstraintDirective::Single {
            endpoint: ConstraintEndpoint {
                host: HostNameOrIp::Name(ConfigString::new(b"pool.ntp.org".to_vec()).unwrap()),
                path: ConfigString::new(b"/".to_vec()).unwrap(),
            },
            pinned_addresses: vec![],
        });
        assert!(matches!(d, Directive::Constraint(_)));
    }
    #[test]
    fn constraint_pool() {
        let d = Directive::Constraint(ConstraintDirective::Pool {
            endpoint: ConstraintEndpoint {
                host: HostNameOrIp::Name(ConfigString::new(b"pool.ntp.org".to_vec()).unwrap()),
                path: ConfigString::new(b"/".to_vec()).unwrap(),
            },
        });
        assert!(matches!(d, Directive::Constraint(_)));
    }
    #[test]
    fn sensor_directive() {
        let d = Directive::Sensor(SensorDirective {
            device: ConfigString::new(b"/dev/pps0".to_vec()).unwrap(),
            options: SensorOptions::default(),
        });
        assert!(matches!(d, Directive::Sensor(_)));
    }
}
