//! # ntpctl — OpenNTPD-rs control client
//!
//! Clean-room, blackbox forensic Rust reconstruction of OpenNTPD's
//! `ntpctl` control client.  CLI: ntpctl(8).
//!
//! ## CLI (OpenNTPD-compatible)
//!
//! ```text
//! ntpctl -s <status|peers|Sensors|all>
//! ```
//!
//! Accepts unambiguous prefixes (e.g. `stat`, `peer`, `Sen`, `a`).
//! Communication via Unix-domain socket to `ntpd` using the imsg control
//! protocol (`IMSG_CTL_REQ` / `IMSG_CTL_RESP`).

use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::process::ExitCode;
use std::time::Duration;

use openntpd_rs_core::control::{
    self, ControlRequest, NtpdStatus, PeerInfo, SensorInfo, SyncState, CTL_REQ_ALL, CTL_REQ_PEERS,
    CTL_REQ_SENSORS, CTL_REQ_STATUS,
};
use openntpd_rs_io::imsg::{Imsg, ImsgHeader, IMSG_CTL_REQ, IMSG_CTL_RESP};

/// Exit codes matching OpenNTPD conventions.
const EXIT_ERROR: u8 = 1;

/// Default control socket path.
const DEFAULT_CONTROL_SOCKET: &str = "/var/run/ntpd.sock";

/// imsg header size: 12 bytes (type + peer_id + length).
const IMSG_HEADER_SIZE: usize = 12;

/// Control socket read timeout in seconds.
const CTL_SOCKET_TIMEOUT_SECS: u64 = 5;

/// Maximum control socket payload we'll accept (1 MB).
const MAX_PAYLOAD: usize = 1_048_576;

/// Valid status query targets.
const VALID_TARGETS: &[&str] = &["status", "peers", "Sensors", "all"];

// ---------------------------------------------------------------------------
// CLI argument parsing
// ---------------------------------------------------------------------------

/// Check if `input` is a case-insensitive prefix of `target`.
fn is_prefix_of(input: &str, target: &str) -> bool {
    target.to_lowercase().starts_with(&input.to_lowercase())
}

/// Find all valid targets matching the given prefix.
fn matching_targets(input: &str) -> Vec<&'static str> {
    VALID_TARGETS
        .iter()
        .copied()
        .filter(|t| is_prefix_of(input, t))
        .collect()
}

/// Map a target name to its `CTL_REQ_*` constant.
fn target_to_action(target: &str) -> u32 {
    match target.to_lowercase().as_str() {
        "status" => CTL_REQ_STATUS,
        "peers" => CTL_REQ_PEERS,
        "sensors" => CTL_REQ_SENSORS,
        "all" => CTL_REQ_ALL,
        _ => CTL_REQ_STATUS,
    }
}

// ---------------------------------------------------------------------------
// Control socket I/O
// ---------------------------------------------------------------------------

/// Connect to the ntpd control socket.
fn connect_control_socket(path: &str) -> Result<UnixStream, String> {
    let stream = UnixStream::connect(path).map_err(|e| format!("cannot connect to {path}: {e}"))?;
    stream
        .set_read_timeout(Some(Duration::from_secs(CTL_SOCKET_TIMEOUT_SECS)))
        .map_err(|e| format!("set read timeout: {e}"))?;
    Ok(stream)
}

/// Send an imsg control request.
fn send_imsg_request(stream: &mut UnixStream, action: u32) -> Result<(), String> {
    let req = ControlRequest::new(action);
    let payload = req.encode().to_vec();
    let imsg = Imsg::new(IMSG_CTL_REQ, payload);
    let wire = imsg.to_bytes();
    stream
        .write_all(&wire)
        .map_err(|e| format!("write imsg: {e}"))?;
    stream.flush().map_err(|e| format!("flush: {e}"))?;
    Ok(())
}

/// Receive an imsg response.  Reads exactly the number of bytes indicated
/// by the imsg length field.
fn recv_imsg_response(stream: &mut UnixStream) -> Result<Imsg, String> {
    let mut header_buf = [0u8; IMSG_HEADER_SIZE];
    read_exact(stream, &mut header_buf).map_err(|e| format!("read imsg header: {e}"))?;

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
        read_exact(stream, &mut payload)
            .map_err(|e| format!("read imsg payload ({payload_len} bytes): {e}"))?;
    }

    Ok(Imsg { header, payload })
}

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
// Response parsing
// ---------------------------------------------------------------------------

/// Parse a status response payload (32-byte fixed format without type tag).
fn parse_status(data: &[u8]) -> Result<NtpdStatus, String> {
    NtpdStatus::from_bytes(data).ok_or_else(|| {
        format!(
            "invalid status response: expected >=32 bytes, got {}",
            data.len()
        )
    })
}

/// Parse a peers response payload: u32 count followed by entries.
fn parse_peers(data: &[u8]) -> Result<Vec<PeerInfo>, String> {
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
            None => break, // malformed entry, return what we have
        }
    }
    Ok(peers)
}

/// Parse a sensors response payload: u32 count followed by entries.
fn parse_sensors(data: &[u8]) -> Result<Vec<SensorInfo>, String> {
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
fn print_status(status: &NtpdStatus) {
    println!("status:");
    match status.sync_state {
        SyncState::Synced => println!("\tsynchronized: YES"),
        SyncState::Unsynchronized => println!("\tsynchronized: NO"),
        SyncState::Constrained => println!("\tsynchronized: CONSTRAINED"),
    }
    println!("\tstratum: {}", status.stratum);
    println!("\toffset: {:.6} seconds", status.offset);
    println!("\tfrequency: {:.3} ppm", status.frequency);
    format_uptime(status.uptime);
}

/// Format uptime seconds into human-readable form.
fn format_uptime(total_secs: u64) {
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
fn print_peers(peers: &[PeerInfo]) {
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
fn print_sensors(sensors: &[SensorInfo]) {
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
fn print_all(data: &[u8]) {
    // Status: first 32 bytes
    if data.len() >= 32 {
        match parse_status(&data[..32]) {
            Ok(status) => print_status(&status),
            Err(e) => eprintln!("status parse error: {e}"),
        }
        println!();

        // Peers: rest of data
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
// Main
// ---------------------------------------------------------------------------

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().collect();
    let prog = args.first().map(|s| s.as_str()).unwrap_or("ntpctl");

    let control_socket =
        std::env::var("NTPD_CONTROL_SOCKET").unwrap_or_else(|_| DEFAULT_CONTROL_SOCKET.to_string());

    // Parse arguments
    let mut show_target: Option<String> = None;
    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "-s" => {
                i += 1;
                show_target = args.get(i).cloned();
            }
            _ => {
                eprintln!("Usage: {prog} -s <status|peers|Sensors|all>");
                return ExitCode::from(EXIT_ERROR);
            }
        }
        i += 1;
    }

    let what = match show_target {
        Some(t) if !t.is_empty() => t,
        _ => {
            eprintln!("Usage: {prog} -s <status|peers|Sensors|all>");
            return ExitCode::from(EXIT_ERROR);
        }
    };

    let matches = matching_targets(&what);
    let target = match matches.as_slice() {
        [t] => *t,
        [] => {
            eprintln!("{prog}: unknown status type '{what}'");
            return ExitCode::from(EXIT_ERROR);
        }
        _ => {
            eprintln!(
                "{prog}: ambiguous prefix '{what}' — matches: {}",
                matches.join(", ")
            );
            return ExitCode::from(EXIT_ERROR);
        }
    };

    // Connect to daemon
    let mut stream = match connect_control_socket(&control_socket) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("{prog}: {e}");
            return ExitCode::from(EXIT_ERROR);
        }
    };

    // Send request
    let action = target_to_action(target);
    if let Err(e) = send_imsg_request(&mut stream, action) {
        eprintln!("{prog}: {e}");
        return ExitCode::from(EXIT_ERROR);
    }

    // Receive response
    let imsg = match recv_imsg_response(&mut stream) {
        Ok(m) => m,
        Err(e) => {
            eprintln!("{prog}: {e}");
            return ExitCode::from(EXIT_ERROR);
        }
    };

    // Verify response type
    if imsg.header.type_ != IMSG_CTL_RESP {
        eprintln!(
            "{prog}: unexpected imsg type 0x{:02x}, expected IMSG_CTL_RESP (0x{IMSG_CTL_RESP:02x})",
            imsg.header.type_
        );
        return ExitCode::from(EXIT_ERROR);
    }

    // Parse and display based on target
    match target.to_lowercase().as_str() {
        "status" => match parse_status(&imsg.payload) {
            Ok(status) => print_status(&status),
            Err(e) => {
                eprintln!("{prog}: {e}");
                return ExitCode::from(EXIT_ERROR);
            }
        },
        "peers" => match parse_peers(&imsg.payload) {
            Ok(peers) => print_peers(&peers),
            Err(e) => {
                eprintln!("{prog}: {e}");
                return ExitCode::from(EXIT_ERROR);
            }
        },
        "sensors" => match parse_sensors(&imsg.payload) {
            Ok(sensors) => print_sensors(&sensors),
            Err(e) => {
                eprintln!("{prog}: {e}");
                return ExitCode::from(EXIT_ERROR);
            }
        },
        "all" => print_all(&imsg.payload),
        _ => {
            println!("{} response ({} bytes):", target, imsg.payload.len());
            println!("{:?}", String::from_utf8_lossy(&imsg.payload));
        }
    }

    ExitCode::SUCCESS
}
