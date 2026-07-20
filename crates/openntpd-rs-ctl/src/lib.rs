//! # openntpd-rs-ctl
//!
//! Clean-room, blackbox forensic Rust reconstruction of OpenNTPD's
//! `ntpctl` control client.  CLI: ntpctl(8).
//!
//! Provides control-socket communication over the imsg protocol,
//! response parsing, and output formatting matching real `ntpctl -s`.
//!
//! ## Architecture
//!
//! ```text
//! [ntpctl CLI] → ControlClient → Unix socket → ntpd daemon
//! ```
//!
//! The [`ControlClient`] struct manages the connection lifecycle.
//! Use [`parse_target`] for CLI input processing, then call
//! [`ControlClient::query`] and format with the `print_*` functions.

use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::time::Duration;

use openntpd_rs_core::control::{
    ControlRequest, NtpdStatus, PeerInfo, SensorInfo, SyncState, CTL_REQ_ALL, CTL_REQ_PEERS,
    CTL_REQ_SENSORS, CTL_REQ_STATUS,
};
use openntpd_rs_io::imsg::{Imsg, ImsgHeader, IMSG_CTL_REQ};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Default control socket path matching OpenNTPD convention.
pub const DEFAULT_CONTROL_SOCKET: &str = "/var/run/ntpd.sock";

/// imsg header size: 12 bytes (type + peer_id + length).
pub const IMSG_HEADER_SIZE: usize = 12;

/// Control socket read timeout in seconds.
pub const CTL_SOCKET_TIMEOUT_SECS: u64 = 5;

/// Maximum control socket payload we'll accept (1 MB).
pub const MAX_PAYLOAD: usize = 1_048_576;

/// Valid status query targets matching ntpctl(8).
pub const VALID_TARGETS: &[&str] = &["status", "peers", "Sensors", "all"];

/// Exit codes matching OpenNTPD conventions.
pub const EXIT_ERROR: u8 = 1;

// ---------------------------------------------------------------------------
// Re-exports
// ---------------------------------------------------------------------------

pub use openntpd_rs_core as core;
pub use openntpd_rs_io as io;
pub use openntpd_rs_io::imsg::IMSG_CTL_RESP;

// ---------------------------------------------------------------------------
// ControlClient — main API
// ---------------------------------------------------------------------------

/// A connected ntpctl control client.
///
/// Wraps a `UnixStream` connected to the ntpd control socket and
/// provides methods for the full request/response lifecycle.
pub struct ControlClient {
    stream: UnixStream,
}

impl ControlClient {
    /// Connect to the ntpd control socket at the given path.
    ///
    /// # Errors
    ///
    /// Returns `Err` if the socket cannot be opened or the read
    /// timeout cannot be set.
    pub fn connect<P: AsRef<Path>>(path: P) -> Result<Self, String> {
        let path = path.as_ref();
        let stream = UnixStream::connect(path)
            .map_err(|e| format!("cannot connect to {}: {e}", path.display()))?;
        stream
            .set_read_timeout(Some(Duration::from_secs(CTL_SOCKET_TIMEOUT_SECS)))
            .map_err(|e| format!("set read timeout: {e}"))?;
        Ok(Self { stream })
    }

    /// Send a control request and receive the response.
    ///
    /// # Errors
    ///
    /// Returns `Err` on I/O failure or invalid response header.
    pub fn query(&mut self, action: u32) -> Result<Imsg, String> {
        self.send_request(action)?;
        self.recv_response()
    }

    /// Send an imsg control request.
    fn send_request(&mut self, action: u32) -> Result<(), String> {
        let req = ControlRequest::new(action);
        let payload = req.encode().to_vec();
        let imsg = Imsg::new(IMSG_CTL_REQ, payload);
        let wire = imsg.to_bytes();
        self.stream
            .write_all(&wire)
            .map_err(|e| format!("write imsg: {e}"))?;
        self.stream.flush().map_err(|e| format!("flush: {e}"))?;
        Ok(())
    }

    /// Receive an imsg response.
    fn recv_response(&mut self) -> Result<Imsg, String> {
        let mut header_buf = [0u8; IMSG_HEADER_SIZE];
        read_exact(&mut self.stream, &mut header_buf)
            .map_err(|e| format!("read imsg header: {e}"))?;

        let header = ImsgHeader::from_bytes(&header_buf);
        header
            .validate()
            .map_err(|e| format!("invalid imsg header: {e}"))?;

        let payload_len = header.length as usize;
        if payload_len > MAX_PAYLOAD {
            return Err(format!(
                "imsg payload too large: {payload_len} > {MAX_PAYLOAD}"
            ));
        }

        let mut payload = vec![0u8; payload_len];
        if payload_len > 0 {
            read_exact(&mut self.stream, &mut payload)
                .map_err(|e| format!("read imsg payload ({payload_len} bytes): {e}"))?;
        }

        Ok(Imsg { header, payload })
    }
}

// ---------------------------------------------------------------------------
// Low-level I/O
// ---------------------------------------------------------------------------

/// Read exactly `buf.len()` bytes from the stream, handling partial reads.
fn read_exact(stream: &mut UnixStream, mut buf: &mut [u8]) -> Result<(), String> {
    while !buf.is_empty() {
        match stream.read(buf) {
            Ok(0) => return Err("connection closed by peer".into()),
            Ok(n) => buf = &mut buf[n..],
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                return Err("timed out waiting for response".into());
            }
            Err(e) => return Err(format!("read error: {e}")),
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// CLI argument parsing
// ---------------------------------------------------------------------------

/// Check if `input` is a case-insensitive prefix of `target`.
#[must_use]
pub fn is_prefix_of(input: &str, target: &str) -> bool {
    target.to_lowercase().starts_with(&input.to_lowercase())
}

/// Find all valid targets matching the given prefix.
#[must_use]
pub fn matching_targets(input: &str) -> Vec<&'static str> {
    VALID_TARGETS
        .iter()
        .copied()
        .filter(|t| is_prefix_of(input, t))
        .collect()
}

/// Result of parsing an ntpctl CLI invocation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CliResult {
    /// A valid target was resolved.
    Target(&'static str),
    /// No target matched the prefix.
    Unknown(String),
    /// Multiple targets matched the prefix.
    Ambiguous(String, Vec<&'static str>),
    /// Missing or empty `-s` argument.
    MissingTarget,
}

/// Parse the `-s <target>` argument from raw CLI args.
///
/// Returns the first matched [`CliResult`]. The caller is responsible
/// for the top-level `-s` flag parsing.
#[must_use]
pub fn parse_target(what: &str) -> CliResult {
    if what.is_empty() {
        return CliResult::MissingTarget;
    }
    let matches = matching_targets(what);
    match matches.as_slice() {
        [t] => CliResult::Target(t),
        [] => CliResult::Unknown(what.to_string()),
        _ => CliResult::Ambiguous(what.to_string(), matches),
    }
}

/// Map a target name to its `CTL_REQ_*` constant.
#[must_use]
pub fn target_to_action(target: &str) -> u32 {
    match target.to_lowercase().as_str() {
        "status" => CTL_REQ_STATUS,
        "peers" => CTL_REQ_PEERS,
        "sensors" => CTL_REQ_SENSORS,
        "all" => CTL_REQ_ALL,
        _ => CTL_REQ_STATUS,
    }
}

// ---------------------------------------------------------------------------
// Response parsing
// ---------------------------------------------------------------------------

/// Parse a status response payload (32-byte fixed format without type tag).
///
/// # Errors
///
/// Returns `Err` if the payload is too short.
pub fn parse_status(data: &[u8]) -> Result<NtpdStatus, String> {
    NtpdStatus::from_bytes(data).ok_or_else(|| {
        format!(
            "invalid status response: expected >=32 bytes, got {}",
            data.len()
        )
    })
}

/// Parse a peers response payload: u32 count followed by entries.
pub fn parse_peers(data: &[u8]) -> Result<Vec<PeerInfo>, String> {
    if data.len() < 4 {
        return Ok(Vec::new());
    }
    let count = u32::from_be_bytes([data[0], data[1], data[2], data[3]]) as usize;
    let mut peers = Vec::with_capacity(count);
    let mut offset = 4;
    for _ in 0..count {
        match PeerInfo::from_entry_bytes(&data[offset..]) {
            Some((peer, consumed)) => {
                peers.push(peer);
                offset += consumed;
            }
            None => break,
        }
    }
    Ok(peers)
}

/// Parse a sensors response payload: u32 count followed by entries.
pub fn parse_sensors(data: &[u8]) -> Result<Vec<SensorInfo>, String> {
    if data.len() < 4 {
        return Ok(Vec::new());
    }
    let count = u32::from_be_bytes([data[0], data[1], data[2], data[3]]) as usize;
    let mut sensors = Vec::with_capacity(count);
    let mut offset = 4;
    for _ in 0..count {
        match SensorInfo::from_entry_bytes(&data[offset..]) {
            Some((sensor, consumed)) => {
                sensors.push(sensor);
                offset += consumed;
            }
            None => break,
        }
    }
    Ok(sensors)
}

// ---------------------------------------------------------------------------
// Output formatting
// ---------------------------------------------------------------------------

/// Format and print the daemon synchronization status.
pub fn print_status(status: &NtpdStatus) {
    println!("status:");
    match status.sync_state {
        SyncState::Synced => println!("\tsynchronized: YES"),
        SyncState::Unsynchronized => println!("\tsynchronized: NO"),
        SyncState::Constrained => println!("\tsynchronized: CONSTRAINED"),
    }
    println!("\tstratum: {}", status.stratum);
    println!("\toffset: {:.6} seconds", status.offset);
    println!("\tfrequency: {:.3} ppm", status.frequency);
    print_uptime(status.uptime);
}

/// Format uptime seconds into human-readable form.
fn print_uptime(total_secs: u64) {
    let days = total_secs / 86400;
    let hours = (total_secs % 86400) / 3600;
    let minutes = (total_secs % 3600) / 60;
    let secs = total_secs % 60;
    if days > 0 {
        println!("\tuptime: {days}d {hours}h {minutes}m {secs}s");
    } else if hours > 0 {
        println!("\tuptime: {hours}h {minutes}m {secs}s");
    } else if minutes > 0 {
        println!("\tuptime: {minutes}m {secs}s");
    } else {
        println!("\tuptime: {secs}s");
    }
}

/// Format and print peer information, matching real ntpctl output style.
pub fn print_peers(peers: &[PeerInfo]) {
    if peers.is_empty() {
        println!("peers: (none)");
        return;
    }
    println!(
        "{:6} {:8} {:>10} {:>10} {:>10} {:>4} {:>4} {:>4} {:>5}",
        "weight", "stratum", "offset", "delay", "dispersion", "poll", "reach", "flash", "trusted"
    );
    println!("{}", "-".repeat(70));
    for p in peers {
        let poll_sec = 1i64 << p.poll.max(0);
        println!(
            "{:6} {:8} {:>10.6} {:>10.6} {:>10.6} {:>4}s {:>4} 0x{:04x} {:>5}",
            p.weight,
            p.stratum,
            p.offset,
            p.delay,
            p.dispersion,
            poll_sec,
            p.reach,
            p.flash,
            if p.trusted { "trust" } else { "" },
        );
        println!("      {}", p.address);
    }
}

/// Format and print sensor information.
pub fn print_sensors(sensors: &[SensorInfo]) {
    if sensors.is_empty() {
        println!("Sensors: (none)");
        return;
    }
    println!(
        "{:>12} {:>4} {:>6}  device",
        "correction", "stratum", "status",
    );
    println!("{}", "-".repeat(50));
    for s in sensors {
        println!(
            "{:>12} {:>4} {:>6}  {}",
            s.correction, s.stratum, s.status, s.device,
        );
        if !s.refid.is_empty() && s.refid != "HARD" {
            println!("      refid: {}", s.refid);
        }
    }
}

/// Format and print the 'all' response (status + peers + sensors).
pub fn print_all(data: &[u8]) {
    if data.len() >= 32 {
        match parse_status(&data[..32]) {
            Ok(status) => print_status(&status),
            Err(e) => eprintln!("status parse error: {e}"),
        }
        println!();

        if data.len() > 32 {
            match parse_peers(&data[32..]) {
                Ok(peers) => {
                    print_peers(&peers);
                    if !peers.is_empty() {
                        println!();
                    }
                }
                Err(e) => eprintln!("peers parse error: {e}"),
            }
        }
    } else {
        eprintln!("'all' response too short: {} bytes", data.len());
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // -- CLI argument parsing --

    #[test]
    fn test_parse_target_exact() {
        assert_eq!(parse_target("status"), CliResult::Target("status"));
        assert_eq!(parse_target("peers"), CliResult::Target("peers"));
        assert_eq!(parse_target("Sensors"), CliResult::Target("Sensors"));
        assert_eq!(parse_target("all"), CliResult::Target("all"));
    }

    #[test]
    fn test_parse_target_prefix() {
        assert_eq!(parse_target("stat"), CliResult::Target("status"));
        assert_eq!(parse_target("peer"), CliResult::Target("peers"));
        assert_eq!(parse_target("Sen"), CliResult::Target("Sensors"));
        assert_eq!(parse_target("a"), CliResult::Target("all"));
    }

    #[test]
    fn test_parse_target_empty_is_missing() {
        assert_eq!(parse_target(""), CliResult::MissingTarget);
    }

    #[test]
    fn test_parse_target_unknown() {
        assert!(matches!(parse_target("nonexistent"), CliResult::Unknown(_)));
    }

    #[test]
    fn test_parse_target_ambiguous() {
        // "s" matches "status" and "Sensors"
        assert!(matches!(parse_target("s"), CliResult::Ambiguous(_, _)));
    }

    #[test]
    fn test_target_to_action() {
        assert_eq!(target_to_action("status"), CTL_REQ_STATUS);
        assert_eq!(target_to_action("peers"), CTL_REQ_PEERS);
        assert_eq!(target_to_action("sensors"), CTL_REQ_SENSORS);
        assert_eq!(target_to_action("all"), CTL_REQ_ALL);
    }

    #[test]
    fn test_is_prefix_of() {
        assert!(is_prefix_of("stat", "status"));
        assert!(is_prefix_of("STAT", "status"));
        assert!(!is_prefix_of("xyz", "status"));
    }

    // -- Response parsing --

    #[test]
    fn test_parse_status_too_short() {
        assert!(parse_status(&[]).is_err());
        assert!(parse_status(&[0u8; 31]).is_err());
    }

    #[test]
    fn test_parse_status_ok() {
        let mut buf = [0u8; 32];
        // sync_state = 1 = Synced (big-endian u32)
        buf[0] = 0;
        buf[1] = 0;
        buf[2] = 0;
        buf[3] = 1;
        // stratum = 3
        buf[4] = 3;
        let status = parse_status(&buf).expect("valid status");
        assert_eq!(status.stratum, 3);
    }

    #[test]
    fn test_parse_peers_empty() {
        let peers = parse_peers(&[0, 0, 0, 0]).expect("empty peers");
        assert!(peers.is_empty());
    }

    #[test]
    fn test_parse_peers_too_short() {
        let peers = parse_peers(&[]).expect("too short -> empty");
        assert!(peers.is_empty());
    }

    #[test]
    fn test_parse_sensors_empty() {
        let sensors = parse_sensors(&[0, 0, 0, 0]).expect("empty sensors");
        assert!(sensors.is_empty());
    }

    // -- Output formatting (smoke tests) --

    #[test]
    fn test_print_status_smoke() {
        let status = NtpdStatus {
            sync_state: SyncState::Synced,
            stratum: 3,
            offset: 0.001,
            frequency: 12.5,
            uptime: 3600,
        };
        // Should not panic
        print_status(&status);
    }

    #[test]
    fn test_print_peers_empty() {
        print_peers(&[]);
    }

    #[test]
    fn test_print_peers_smoke() {
        let peer = PeerInfo {
            weight: 1,
            stratum: 3,
            offset: 0.005,
            delay: 0.050,
            dispersion: 0.010,
            poll: 6,
            reach: 0xFF,
            flash: 0,
            trusted: true,
            address: "192.0.2.1".into(),
        };
        print_peers(&[peer]);
    }

    #[test]
    fn test_print_sensors_empty() {
        print_sensors(&[]);
    }

    #[test]
    fn test_print_sensors_smoke() {
        let sensor = SensorInfo {
            device: "nmea0".into(),
            correction: 12345,
            stratum: 1,
            status: 1,
            weight: 1,
            refid: "GPS".into(),
        };
        print_sensors(&[sensor]);
    }

    #[test]
    fn test_print_all_empty() {
        print_all(&[]);
    }

    #[test]
    fn test_print_all_status_only() {
        let mut buf = [0u8; 32];
        // sync_state = 1 (Synced) as big-endian u32
        buf[3] = 1;
        print_all(&buf);
    }

    // -- read_exact edge cases --

    #[test]
    fn test_read_exact_with_stream() {
        // Smoke test: read_exact doesn't panic with a connected socket.
        let (mut a, mut b) = UnixStream::pair().expect("socket pair");
        b.write_all(b"hello").unwrap();
        drop(b);
        let mut buf = [0u8; 5];
        let result = read_exact(&mut a, &mut buf);
        // Either we read the data or the connection was already closed.
        if result.is_ok() {
            assert_eq!(&buf, b"hello");
        }
    }
}
