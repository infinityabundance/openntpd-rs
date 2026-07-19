//! # Config runtime lowering
//!
//! Corresponds to OpenNTPD's `config.c`.  Lowers parsed directives into
//! runtime objects (peers, listeners, constraints, sensors) and produces
//! DNS requests for hostnames that must be resolved before peers can be
//! created.

use alloc::string::String;
use alloc::vec::Vec;
use core::net::{IpAddr, Ipv4Addr, SocketAddr};

use crate::config::directive::*;
use crate::dns::{AddressFamily, DnsRequest};

/// Default NTP port.
const NTP_PORT: u16 = 123;

/// Runtime configuration — the "lowered" form of a parsed `ntpd.conf`.
#[derive(Debug, Clone)]
pub struct RuntimeConfig {
    pub listeners: Vec<ListenConfig>,
    pub servers: Vec<ServerConfig>,
    pub constraints: Vec<ConstraintConfig>,
    pub sensors: Vec<SensorConfig>,
    pub query_from: Option<IpAddr>,
}

/// A socket the daemon should bind to.
#[derive(Debug, Clone)]
pub struct ListenConfig {
    pub address: SocketAddr,
    pub rtable: i64,
}

/// A configured NTP server peer.
#[derive(Debug, Clone)]
pub struct ServerConfig {
    pub address: IpAddr,
    pub weight: u8,
    pub trusted: bool,
    /// Original hostname (for DNS); the string form of the IP if numeric.
    pub hostname: String,
}

/// An HTTPS constraint endpoint.
#[derive(Debug, Clone)]
pub struct ConstraintConfig {
    pub host: String,
    pub path: String,
    pub pinned_address: Option<IpAddr>,
}

/// A hardware sensor configuration.
#[derive(Debug, Clone)]
pub struct SensorConfig {
    pub device: String,
    pub correction: i64,
    pub refid: Option<[u8; 4]>,
    pub stratum: u8,
    pub weight: u8,
    pub trusted: bool,
}

impl RuntimeConfig {
    /// Lower a parsed `Config` into runtime configuration objects.
    ///
    /// Returns a tuple of:
    /// - `RuntimeConfig` — resolved values for listeners, servers, constraints,
    ///   sensors, and the `query from` address.
    /// - `Vec<DnsRequest>` — DNS queries needed for hostnames in `listen`,
    ///   `server`, `servers`, and `constraint` directives.  These must be
    ///   dispatched and resolved before the corresponding runtime objects can
    ///   be used (OpenNTPD calls `host_dns()` and wires results back via
    ///   `imsg`).
    pub fn lower(config: &Config) -> (Self, Vec<DnsRequest>) {
        let mut listeners: Vec<ListenConfig> = Vec::new();
        let mut servers: Vec<ServerConfig> = Vec::new();
        let mut constraints: Vec<ConstraintConfig> = Vec::new();
        let mut sensors: Vec<SensorConfig> = Vec::new();
        let mut query_from: Option<IpAddr> = None;
        let mut dns_requests: Vec<DnsRequest> = Vec::new();
        let mut dns_id: u64 = 0;

        for spanned in &config.directives {
            match &spanned.value {
                Directive::Listen(ld) => {
                    let rtable = ld.rtable.get();
                    match &ld.address {
                        ListenAddress::Wildcard => {
                            // OpenNTPD binds both IPv4 and IPv6 wildcards.
                            // Emit IPv4 INADDR_ANY by default.
                            listeners.push(ListenConfig {
                                address: SocketAddr::new(
                                    IpAddr::V4(Ipv4Addr::UNSPECIFIED),
                                    NTP_PORT,
                                ),
                                rtable,
                            });
                        }
                        ListenAddress::Numeric(ip) => {
                            listeners.push(ListenConfig {
                                address: SocketAddr::new(*ip, NTP_PORT),
                                rtable,
                            });
                        }
                        ListenAddress::Name(name) => {
                            if let Some(hostname) = name.to_utf8_string() {
                                dns_id += 1;
                                dns_requests.push(DnsRequest {
                                    id: dns_id,
                                    hostname,
                                    address_family: AddressFamily::Any,
                                });
                                // Listener not added until DNS resolves
                                // (matching OpenNTPD's deferred binding in
                                //  `config.c` → `host_dns()` → imsg round-trip).
                            }
                        }
                    }
                }

                Directive::Server(sd) => {
                    let (address, options) = match sd {
                        ServerDirective::Single { address, options } => (address, options),
                        ServerDirective::Pool { address, options } => (address, options),
                    };
                    let weight = options.weight.get();
                    let trusted = options.trusted;

                    match address {
                        ServerAddress::Numeric(ip) => {
                            servers.push(ServerConfig {
                                address: *ip,
                                weight,
                                trusted,
                                hostname: alloc::format!("{}", ip),
                            });
                        }
                        ServerAddress::Name(name) => {
                            if let Some(hostname) = name.to_utf8_string() {
                                dns_id += 1;
                                dns_requests.push(DnsRequest {
                                    id: dns_id,
                                    hostname: hostname.clone(),
                                    address_family: AddressFamily::Any,
                                });
                                // Placeholder address until DNS resolves.
                                servers.push(ServerConfig {
                                    address: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
                                    weight,
                                    trusted,
                                    hostname,
                                });
                            }
                        }
                    }
                }

                Directive::Constraint(cd) => {
                    let (endpoint, pinned) = match cd {
                        ConstraintDirective::Single {
                            endpoint,
                            pinned_addresses,
                        } => (endpoint, pinned_addresses.first().copied()),
                        ConstraintDirective::Pool { endpoint } => (endpoint, None),
                    };

                    let host_str: String = match &endpoint.host {
                        HostNameOrIp::Numeric(ip) => alloc::format!("{}", ip),
                        HostNameOrIp::Name(name) => name.to_utf8_string().unwrap_or_default(),
                    };
                    let path_str: String = endpoint.path.to_utf8_string().unwrap_or_default();

                    // Generate DNS request if the constraint host is a name.
                    if let HostNameOrIp::Name(name) = &endpoint.host {
                        if let Some(hostname) = name.to_utf8_string() {
                            dns_id += 1;
                            dns_requests.push(DnsRequest {
                                id: dns_id,
                                hostname,
                                address_family: AddressFamily::Any,
                            });
                        }
                    }

                    constraints.push(ConstraintConfig {
                        host: host_str,
                        path: path_str,
                        pinned_address: pinned,
                    });
                }

                Directive::Sensor(sd) => {
                    let device_str: String = sd.device.to_utf8_string().unwrap_or_default();
                    sensors.push(SensorConfig {
                        device: device_str,
                        correction: sd.options.correction.get() as i64,
                        refid: sd.options.refid.map(|r| r.bytes()),
                        stratum: sd.options.stratum.get(),
                        weight: sd.options.weight.get(),
                        trusted: sd.options.trusted,
                    });
                }

                Directive::QueryFrom(ip) => {
                    query_from = Some(*ip);
                }
            }
        }

        let runtime = RuntimeConfig {
            listeners,
            servers,
            constraints,
            sensors,
            query_from,
        };

        (runtime, dns_requests)
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use core::net::Ipv6Addr;

    // ------------------------------------------------------------------
    // Helpers
    // ------------------------------------------------------------------

    /// Parse bytes and lower the result, panicking on parse errors.
    fn lower_bytes(bytes: &[u8]) -> (RuntimeConfig, Vec<DnsRequest>) {
        let parsed = crate::config::parser::parse_config(bytes);
        assert!(
            parsed.is_valid(),
            "config should be valid: {:?}",
            parsed.diagnostics
        );
        RuntimeConfig::lower(&parsed.config)
    }

    /// Parse bytes that are expected to be invalid; return the config anyway.
    fn lower_invalid(bytes: &[u8]) -> (RuntimeConfig, Vec<DnsRequest>) {
        let parsed = crate::config::parser::parse_config(bytes);
        RuntimeConfig::lower(&parsed.config)
    }

    // ------------------------------------------------------------------
    // 1. Empty config produces empty runtime
    // ------------------------------------------------------------------

    #[test]
    fn empty_config() {
        let (rt, dns) = lower_bytes(b"");
        assert!(rt.listeners.is_empty());
        assert!(rt.servers.is_empty());
        assert!(rt.constraints.is_empty());
        assert!(rt.sensors.is_empty());
        assert!(rt.query_from.is_none());
        assert!(dns.is_empty());
    }

    // ------------------------------------------------------------------
    // 2. Listen wildcard → INADDR_ANY
    // ------------------------------------------------------------------

    #[test]
    fn listen_wildcard() {
        let (rt, dns) = lower_bytes(b"listen on *\n");
        assert_eq!(rt.listeners.len(), 1);
        assert_eq!(
            rt.listeners[0].address,
            SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), NTP_PORT)
        );
        assert_eq!(rt.listeners[0].rtable, 0);
        assert!(dns.is_empty());
    }

    // ------------------------------------------------------------------
    // 3. Listen numeric IP → SocketAddr
    // ------------------------------------------------------------------

    #[test]
    fn listen_numeric_ipv4() {
        let (rt, dns) = lower_bytes(b"listen on 192.168.1.1\n");
        assert_eq!(rt.listeners.len(), 1);
        assert_eq!(
            rt.listeners[0].address,
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)), NTP_PORT)
        );
        assert!(dns.is_empty());
    }

    #[test]
    fn listen_numeric_ipv6() {
        let (rt, dns) = lower_bytes(b"listen on ::1\n");
        assert_eq!(rt.listeners.len(), 1);
        assert_eq!(
            rt.listeners[0].address,
            SocketAddr::new(IpAddr::V6(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1)), NTP_PORT)
        );
        assert!(dns.is_empty());
    }

    // ------------------------------------------------------------------
    // 4. Server with numeric address → ServerConfig
    // ------------------------------------------------------------------

    #[test]
    fn server_numeric_ipv4() {
        let (rt, dns) = lower_bytes(b"server 203.0.113.1\n");
        assert_eq!(rt.servers.len(), 1);
        assert_eq!(
            rt.servers[0].address,
            IpAddr::V4(Ipv4Addr::new(203, 0, 113, 1))
        );
        assert_eq!(rt.servers[0].weight, 1);
        assert!(!rt.servers[0].trusted);
        assert_eq!(rt.servers[0].hostname, "203.0.113.1");
        assert!(dns.is_empty());
    }

    #[test]
    fn server_numeric_with_options() {
        let (rt, dns) = lower_bytes(b"server 198.51.100.1 weight 5 trusted\n");
        assert_eq!(rt.servers.len(), 1);
        assert_eq!(
            rt.servers[0].address,
            IpAddr::V4(Ipv4Addr::new(198, 51, 100, 1))
        );
        assert_eq!(rt.servers[0].weight, 5);
        assert!(rt.servers[0].trusted);
        assert!(dns.is_empty());
    }

    // ------------------------------------------------------------------
    // 5. Server with hostname → DnsRequest
    // ------------------------------------------------------------------

    #[test]
    fn server_hostname_generates_dns() {
        let (rt, dns) = lower_bytes(b"server pool.ntp.org\n");
        assert_eq!(rt.servers.len(), 1);
        // Placeholder address
        assert_eq!(rt.servers[0].address, IpAddr::V4(Ipv4Addr::UNSPECIFIED));
        assert_eq!(rt.servers[0].hostname, "pool.ntp.org");
        assert_eq!(rt.servers[0].weight, 1);

        assert_eq!(dns.len(), 1);
        assert_eq!(dns[0].hostname, "pool.ntp.org");
        assert_eq!(dns[0].address_family, AddressFamily::Any);
    }

    #[test]
    fn server_hostname_preserves_weight_and_trusted() {
        let (rt, dns) = lower_bytes(b"server time.example.com weight 10 trusted\n");
        assert_eq!(rt.servers.len(), 1);
        assert_eq!(rt.servers[0].weight, 10);
        assert!(rt.servers[0].trusted);
        assert_eq!(rt.servers[0].hostname, "time.example.com");

        assert_eq!(dns.len(), 1);
        assert_eq!(dns[0].hostname, "time.example.com");
    }

    #[test]
    fn servers_pool_hostname_generates_dns() {
        let (rt, dns) = lower_bytes(b"servers pool.ntp.org\n");
        assert_eq!(rt.servers.len(), 1);
        assert_eq!(rt.servers[0].hostname, "pool.ntp.org");
        assert_eq!(dns.len(), 1);
        assert_eq!(dns[0].hostname, "pool.ntp.org");
    }

    // ------------------------------------------------------------------
    // 6. Constraint with URL splitting
    //
    // NOTE: URLs containing `/` must be **quoted** because the lexer
    // terminates unquoted strings at `/`.
    // ------------------------------------------------------------------

    #[test]
    fn constraint_from_url() {
        let (rt, dns) = lower_bytes(b"constraint from \"https://example.com/foo\"\n");
        assert_eq!(rt.constraints.len(), 1);
        assert_eq!(rt.constraints[0].host, "example.com");
        assert_eq!(rt.constraints[0].path, "/foo");
        assert!(rt.constraints[0].pinned_address.is_none());
        assert_eq!(dns.len(), 1);
        assert_eq!(dns[0].hostname, "example.com");
    }

    #[test]
    fn constraint_default_path() {
        let (rt, _dns) = lower_bytes(b"constraint from \"https://example.com\"\n");
        assert_eq!(rt.constraints.len(), 1);
        assert_eq!(rt.constraints[0].host, "example.com");
        assert_eq!(rt.constraints[0].path, "/");
    }

    #[test]
    fn constraint_with_pinned_address() {
        let (rt, dns) = lower_bytes(b"constraint from \"https://example.com/check\" 192.0.2.1\n");
        assert_eq!(rt.constraints.len(), 1);
        assert_eq!(rt.constraints[0].host, "example.com");
        assert_eq!(rt.constraints[0].path, "/check");
        assert_eq!(
            rt.constraints[0].pinned_address,
            Some(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)))
        );
        assert_eq!(dns.len(), 1);
    }

    #[test]
    fn constraint_numeric_host() {
        let (rt, dns) = lower_bytes(b"constraint from 203.0.113.1\n");
        assert_eq!(rt.constraints.len(), 1);
        assert_eq!(rt.constraints[0].host, "203.0.113.1");
        assert_eq!(rt.constraints[0].path, "/");
        // Numeric IP — no DNS request
        assert!(dns.is_empty());
    }

    #[test]
    fn constraint_unquoted_hostname() {
        let (rt, dns) = lower_bytes(b"constraint from www.example.com\n");
        assert_eq!(rt.constraints.len(), 1);
        assert_eq!(rt.constraints[0].host, "www.example.com");
        assert_eq!(rt.constraints[0].path, "/");
        // Hostname — should generate DNS request
        assert_eq!(dns.len(), 1);
        assert_eq!(dns[0].hostname, "www.example.com");
    }

    // ------------------------------------------------------------------
    // 7. Sensor with all options
    // ------------------------------------------------------------------

    #[test]
    fn sensor_all_options() {
        let (rt, dns) =
            lower_bytes(b"sensor nmea0 correction 100000 refid GPS stratum 5 weight 3 trusted\n");
        assert_eq!(rt.sensors.len(), 1);
        assert_eq!(rt.sensors[0].device, "nmea0");
        assert_eq!(rt.sensors[0].correction, 100_000_i64);
        assert_eq!(rt.sensors[0].refid, Some([b'G', b'P', b'S', 0]));
        assert_eq!(rt.sensors[0].stratum, 5);
        assert_eq!(rt.sensors[0].weight, 3);
        assert!(rt.sensors[0].trusted);
        assert!(dns.is_empty());
    }

    #[test]
    fn sensor_minimal() {
        let (rt, dns) = lower_bytes(b"sensor nmea0\n");
        assert_eq!(rt.sensors.len(), 1);
        assert_eq!(rt.sensors[0].device, "nmea0");
        assert_eq!(rt.sensors[0].correction, 0);
        assert!(rt.sensors[0].refid.is_none());
        assert_eq!(rt.sensors[0].stratum, 1);
        assert_eq!(rt.sensors[0].weight, 1);
        assert!(!rt.sensors[0].trusted);
        assert!(dns.is_empty());
    }

    #[test]
    fn sensor_no_refid() {
        // Device path with `/` must be quoted
        let (rt, dns) = lower_bytes(b"sensor \"/dev/pps0\" correction -50000 stratum 2\n");
        assert_eq!(rt.sensors.len(), 1);
        assert_eq!(rt.sensors[0].device, "/dev/pps0");
        assert_eq!(rt.sensors[0].correction, -50_000_i64);
        assert!(rt.sensors[0].refid.is_none());
        assert_eq!(rt.sensors[0].stratum, 2);
        assert_eq!(rt.sensors[0].weight, 1);
        assert!(dns.is_empty());
    }

    // ------------------------------------------------------------------
    // 8. query_from directive
    // ------------------------------------------------------------------

    #[test]
    fn query_from_ipv4() {
        let (rt, dns) = lower_bytes(b"query from 10.0.0.1\n");
        assert_eq!(rt.query_from, Some(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))));
        assert!(dns.is_empty());
    }

    #[test]
    fn query_from_ipv6() {
        let (rt, dns) = lower_bytes(b"query from ::1\n");
        assert_eq!(
            rt.query_from,
            Some(IpAddr::V6(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1)))
        );
        assert!(dns.is_empty());
    }

    // ------------------------------------------------------------------
    // 9. rtable preservation
    // ------------------------------------------------------------------

    #[test]
    fn listen_rtable_preserved() {
        let (rt, dns) = lower_bytes(b"listen on * rtable 42\n");
        assert_eq!(rt.listeners.len(), 1);
        assert_eq!(rt.listeners[0].rtable, 42);
        assert!(dns.is_empty());
    }

    #[test]
    fn listen_numeric_with_rtable() {
        let (rt, dns) = lower_bytes(b"listen on 10.0.0.1 rtable 7\n");
        assert_eq!(rt.listeners.len(), 1);
        assert_eq!(
            rt.listeners[0].address,
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), NTP_PORT)
        );
        assert_eq!(rt.listeners[0].rtable, 7);
        assert!(dns.is_empty());
    }

    // ------------------------------------------------------------------
    // Multiple directives
    // ------------------------------------------------------------------

    #[test]
    fn multiple_directives() {
        let (rt, dns) = lower_bytes(
            b"\
            listen on *\n\
            listen on 127.0.0.1\n\
            server 203.0.113.1\n\
            server pool.ntp.org\n\
            constraint from \"https://example.com/check\"\n\
            sensor nmea0\n\
            query from 10.0.0.1\n\
            ",
        );
        assert_eq!(rt.listeners.len(), 2);
        assert_eq!(rt.servers.len(), 2);
        assert_eq!(rt.constraints.len(), 1);
        assert_eq!(rt.sensors.len(), 1);
        assert_eq!(rt.query_from, Some(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))));
        // Two DNS requests: hostname server + constraint hostname
        assert_eq!(dns.len(), 2);
        assert_eq!(dns[0].hostname, "pool.ntp.org");
        assert_eq!(dns[1].hostname, "example.com");
    }

    // ------------------------------------------------------------------
    // Edge cases: DNS request ID uniqueness
    // ------------------------------------------------------------------

    #[test]
    fn dns_ids_are_incremental() {
        let (_rt, dns) = lower_bytes(
            b"\
            server pool.ntp.org\n\
            server time.example.com\n\
            constraint from \"https://constraint.example.com/path\"\n\
            ",
        );
        assert_eq!(dns.len(), 3);
        assert_eq!(dns[0].id, 1);
        assert_eq!(dns[1].id, 2);
        assert_eq!(dns[2].id, 3);
        assert_ne!(dns[0].hostname, dns[1].hostname);
    }

    // ------------------------------------------------------------------
    // Invalid config — lowering should still succeed (graceful handling)
    // ------------------------------------------------------------------

    #[test]
    fn invalid_config_lowers_gracefully() {
        // Config with errors should still produce a (partial) runtime.
        let (rt, dns) = lower_invalid(b"listen on *\nserver pool.ntp.org weight 100\n");
        // listen on * should still be lowered
        assert_eq!(rt.listeners.len(), 1);
        // server with invalid weight (100) may or may not produce a
        // server config — depends on parser recovery.  At minimum no panic.
        assert!(dns.is_empty() || dns.len() == 1);
    }
}
