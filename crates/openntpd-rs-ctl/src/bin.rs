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
//! - `-s` selects status type.  Accepts unambiguous prefixes
//!   (e.g. `stat`, `peer`, `Sen`, `a`).  The historical capitalized
//!   `Sensors` spelling is accepted.  Ambiguous or empty prefixes
//!   are rejected.
//! - Communication happens over a Unix-domain socket to `ntpd`.

use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::process::ExitCode;
use std::time::Duration;

/// Exit codes.
const EXIT_ERROR: u8 = 1;
const EXIT_CONFIG: u8 = 78;

const DEFAULT_CONTROL_SOCKET: &str = "/var/run/ntpd.sock";

/// The valid status query targets.
const VALID_TARGETS: &[&str] = &["status", "peers", "Sensors", "all"];

/// IMSG type constants matching openntpd-rs-io::imsg
const IMSG_CTL_REQ: u32 = 0x0c;
const IMSG_CTL_RESP: u32 = 0x0d;

/// IMSG header size: 12 bytes (type + peer_id + length)
const IMSG_HEADER_SIZE: usize = 12;

/// Control action codes matching openntpd-rs-core::control
const CTL_SHOW_STATUS: u32 = 0;
const CTL_SHOW_PEERS: u32 = 1;
const CTL_SHOW_SENSORS: u32 = 2;
const CTL_SHOW_ALL: u32 = 3;

/// Check if `input` is a prefix of `target` (case-insensitive).
fn is_prefix_of(input: &str, target: &str) -> bool {
    let lower_input = input.to_lowercase();
    let lower_target = target.to_lowercase();
    lower_target.starts_with(&lower_input)
}

/// Find all valid targets that `input` is a prefix of.
fn matching_targets(input: &str) -> Vec<&'static str> {
    VALID_TARGETS
        .iter()
        .copied()
        .filter(|&t| is_prefix_of(input, t))
        .collect()
}

/// Map a target name to the control action code.
fn target_to_action(target: &str) -> u32 {
    match target.to_lowercase().as_str() {
        "status" => CTL_SHOW_STATUS,
        "peers" => CTL_SHOW_PEERS,
        "sensors" => CTL_SHOW_SENSORS,
        "all" => CTL_SHOW_ALL,
        _ => CTL_SHOW_STATUS,
    }
}

/// Connect to the ntpd control socket and send an imsg request.
fn send_control_request(socket_path: &str, action: u32) -> Result<Vec<u8>, String> {
    let mut stream = UnixStream::connect(socket_path)
        .map_err(|e| format!("cannot connect to {socket_path}: {e}"))?;

    // Build imsg header (12 bytes) + payload (4 bytes action)
    let mut buf = Vec::with_capacity(IMSG_HEADER_SIZE + 4);
    // type (u32 big-endian)
    buf.extend_from_slice(&IMSG_CTL_REQ.to_be_bytes());
    // peer_id (u32 big-endian)
    buf.extend_from_slice(&0u32.to_be_bytes());
    // length (u32 big-endian): payload only
    buf.extend_from_slice(&4u32.to_be_bytes());
    // payload: action (u32 big-endian)
    buf.extend_from_slice(&action.to_be_bytes());

    // Send the request
    stream
        .write_all(&buf)
        .map_err(|e| format!("write to {socket_path}: {e}"))?;
    stream
        .flush()
        .map_err(|e| format!("flush to {socket_path}: {e}"))?;

    // Set a read timeout (5 seconds)
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .map_err(|e| format!("set read timeout: {e}"))?;

    // Read the response imsg header
    let mut header_buf = [0u8; IMSG_HEADER_SIZE];
    let mut read_total = 0usize;
    while read_total < IMSG_HEADER_SIZE {
        match stream.read(&mut header_buf[read_total..]) {
            Ok(0) => break, // EOF
            Ok(n) => read_total += n,
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                // Timed out waiting for response
                return Err(format!("timed out waiting for response from {socket_path}"));
            }
            Err(e) => return Err(format!("read from {socket_path}: {e}")),
        }
    }

    if read_total < IMSG_HEADER_SIZE {
        return Err(format!(
            "incomplete imsg header from {socket_path}: got {read_total} bytes"
        ));
    }

    // Parse the response header
    let resp_type = u32::from_be_bytes(header_buf[0..4].try_into().unwrap());
    let _resp_peer = u32::from_be_bytes(header_buf[4..8].try_into().unwrap());
    let resp_len = u32::from_be_bytes(header_buf[8..12].try_into().unwrap()) as usize;

    // Verify we got the expected response type
    if resp_type != IMSG_CTL_RESP {
        return Err(format!(
            "unexpected imsg type from {socket_path}: expected {IMSG_CTL_RESP}, got {resp_type}"
        ));
    }

    // Read the payload
    let mut payload = vec![0u8; resp_len];
    let mut read_payload = 0usize;
    while read_payload < resp_len {
        match stream.read(&mut payload[read_payload..]) {
            Ok(0) => break,
            Ok(n) => read_payload += n,
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => break,
            Err(e) => return Err(format!("read payload from {socket_path}: {e}")),
        }
    }

    payload.truncate(read_payload);
    Ok(payload)
}

/// Format and print a status response.
fn format_status_response(payload: &[u8]) {
    if payload.len() < 32 {
        println!("status: incomplete response ({} bytes)", payload.len());
        return;
    }

    let synced = payload[0];
    let stratum = payload[1];
    let peer_cnt = u32::from_be_bytes(payload[4..8].try_into().unwrap_or([0; 4]));
    let sensor_cnt = u32::from_be_bytes(payload[8..12].try_into().unwrap_or([0; 4]));

    println!("status:");
    println!("\tsynchronized: {}", if synced != 0 { "YES" } else { "NO" });
    println!("\tstratum: {}", stratum);

    // Try to parse additional fields if available
    if payload.len() >= 24 {
        let clock_offset_bytes = &payload[16..24];
        if clock_offset_bytes.len() == 8 {
            let clock_offset = f64::from_be_bytes(clock_offset_bytes.try_into().unwrap_or([0; 8]));
            println!("\tclock offset: {:.6}s", clock_offset);
        }
    }

    if payload.len() >= 32 {
        let constraint_median = i64::from_be_bytes(payload[24..32].try_into().unwrap_or([0; 8]));
        if constraint_median != 0 {
            println!("\tconstraint median: {}", constraint_median);
        }
    }

    println!("\tpeers: {peer_cnt}");
    println!("\tsensors: {sensor_cnt}");
}

/// Format and print a peers response.
fn format_peers_response(payload: &[u8]) {
    if payload.is_empty() {
        println!("peers: (none)");
        return;
    }

    println!("peers:");
    // Each peer entry: variable-length address string (null-terminated) + fixed data
    let mut offset = 0;
    let mut peer_num = 0;
    while offset < payload.len() {
        // Find null terminator for address
        let addr_end = payload[offset..]
            .iter()
            .position(|&b| b == 0)
            .map(|p| offset + p)
            .unwrap_or(payload.len());

        let addr = String::from_utf8_lossy(&payload[offset..addr_end]);
        offset = addr_end + 1; // skip null

        // Fixed data: reach(1) + offset(8) + delay(8) + stratum(1) + weight(1) + poll(1)
        if offset + 20 <= payload.len() {
            let reach = payload[offset];
            let peer_offset =
                f64::from_be_bytes(payload[offset + 1..offset + 9].try_into().unwrap_or([0; 8]));
            let delay = f64::from_be_bytes(
                payload[offset + 9..offset + 17]
                    .try_into()
                    .unwrap_or([0; 8]),
            );
            let stratum = payload[offset + 17];
            let weight = payload[offset + 18];
            let poll = payload[offset + 19] as i8;

            println!("\tpeer {peer_num}: {addr}");
            println!("\t\treach: 0x{reach:02x}");
            println!("\t\toffset: {peer_offset:.6}s");
            println!("\t\tdelay: {delay:.6}s");
            println!("\t\tstratum: {stratum}");
            println!("\t\tweight: {weight}");
            println!("\t\tpoll: {}s", 1i64 << poll.max(0));

            offset += 20;
            peer_num += 1;
        } else {
            break;
        }
    }

    if peer_num == 0 {
        println!("\t(none)");
    }
}

/// Format and print a sensors response.
fn format_sensors_response(payload: &[u8]) {
    if payload.is_empty() {
        println!("Sensors: (none)");
        return;
    }

    println!("Sensors:");
    let mut offset = 0;
    let mut sensor_num = 0;
    while offset < payload.len() {
        // Find null terminator for device name
        let dev_end = payload[offset..]
            .iter()
            .position(|&b| b == 0)
            .map(|p| offset + p)
            .unwrap_or(payload.len());

        let device = String::from_utf8_lossy(&payload[offset..dev_end]);
        offset = dev_end + 1;

        // Fixed data: status(1) + offset(8) + correction(4) + stratum(1) + weight(1)
        if offset + 15 <= payload.len() {
            let status = payload[offset];
            let sensor_offset =
                f64::from_be_bytes(payload[offset + 1..offset + 9].try_into().unwrap_or([0; 8]));
            let correction = i32::from_be_bytes(
                payload[offset + 9..offset + 13]
                    .try_into()
                    .unwrap_or([0; 4]),
            );
            let stratum = payload[offset + 13];
            let weight = payload[offset + 14];

            println!("\tsensor {sensor_num}: {device}");
            println!("\t\toffset: {sensor_offset:.6}s");
            println!("\t\tcorrection: {correction}us");
            println!("\t\tstratum: {stratum}");
            println!("\t\tweight: {weight}");
            println!("\t\tstatus: {status}");

            offset += 15;
            sensor_num += 1;
        } else {
            break;
        }
    }
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().collect();
    let prog = args.first().map(|s| s.as_str()).unwrap_or("ntpctl");

    let control_socket =
        std::env::var("NTPD_CONTROL_SOCKET").unwrap_or_else(|_| DEFAULT_CONTROL_SOCKET.to_string());

    if args.len() < 3 || args[1] != "-s" {
        eprintln!("Usage: {prog} -s <status|peers|Sensors|all>");
        return ExitCode::from(EXIT_ERROR);
    }

    let what = &args[2];
    if what.is_empty() {
        eprintln!("{prog}: empty status type");
        return ExitCode::from(EXIT_ERROR);
    }

    let matches = matching_targets(what);
    match matches.as_slice() {
        [target] => {
            let action = target_to_action(target);
            match send_control_request(&control_socket, action) {
                Ok(payload) => {
                    match target.to_lowercase().as_str() {
                        "status" => format_status_response(&payload),
                        "peers" => format_peers_response(&payload),
                        "sensors" => format_sensors_response(&payload),
                        "all" => {
                            // 'all' returns status first, then peers, then sensors
                            // Split payload at boundaries (first 32 bytes = status, rest = peers+sensors)
                            if payload.len() >= 32 {
                                format_status_response(&payload[..32]);
                                if payload.len() > 32 {
                                    format_peers_response(&payload[32..]);
                                }
                            } else {
                                format_status_response(&payload);
                            }
                        }
                        _ => {
                            println!("{} response ({} bytes):", target, payload.len());
                            println!("{:?}", String::from_utf8_lossy(&payload));
                        }
                    }
                    ExitCode::SUCCESS
                }
                Err(e) => {
                    eprintln!("{prog}: {e}");
                    ExitCode::from(EXIT_ERROR)
                }
            }
        }
        [] => {
            eprintln!("{prog}: unknown status type '{what}'");
            ExitCode::from(EXIT_ERROR)
        }
        _ => {
            eprintln!(
                "{prog}: ambiguous prefix '{what}' — matches: {}",
                matches.join(", ")
            );
            ExitCode::from(EXIT_ERROR)
        }
    }
}
