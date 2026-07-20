//! # ntpctl — OpenNTPD-rs control client binary
//!
//! Thin CLI wrapper around the [`openntpd_rs_ctl`] library.
//! All protocol logic, parsing, and formatting lives in the library.
//!
//! ## CLI (OpenNTPD-compatible)
//!
//! ```text
//! ntpctl -s <status|peers|Sensors|all>
//! ```
//!
//! Accepts unambiguous prefixes (e.g. `stat`, `peer`, `Sen`, `a`).

use std::process::ExitCode;

use openntpd_rs_ctl::{
    self as ctl, parse_target, print_all, print_peers, print_sensors, print_status,
    target_to_action, CliResult, ControlClient, IMSG_CTL_RESP,
};

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().collect();
    let prog = args.first().map(|s| s.as_str()).unwrap_or("ntpctl");

    let control_socket = std::env::var("NTPD_CONTROL_SOCKET")
        .unwrap_or_else(|_| ctl::DEFAULT_CONTROL_SOCKET.to_string());

    // Parse -s argument
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
                return ExitCode::from(ctl::EXIT_ERROR);
            }
        }
        i += 1;
    }

    let what = match show_target {
        Some(t) if !t.is_empty() => t,
        _ => {
            eprintln!("Usage: {prog} -s <status|peers|Sensors|all>");
            return ExitCode::from(ctl::EXIT_ERROR);
        }
    };

    // Resolve target via prefix matching
    let target = match parse_target(&what) {
        CliResult::Target(t) => t,
        CliResult::Unknown(u) => {
            eprintln!("{prog}: unknown status type '{u}'");
            return ExitCode::from(ctl::EXIT_ERROR);
        }
        CliResult::Ambiguous(u, matches) => {
            eprintln!(
                "{prog}: ambiguous prefix '{u}' — matches: {}",
                matches.join(", ")
            );
            return ExitCode::from(ctl::EXIT_ERROR);
        }
        CliResult::MissingTarget => {
            eprintln!("Usage: {prog} -s <status|peers|Sensors|all>");
            return ExitCode::from(ctl::EXIT_ERROR);
        }
    };

    // Connect to daemon
    let mut client = match ControlClient::connect(&control_socket) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("{prog}: {e}");
            return ExitCode::from(ctl::EXIT_ERROR);
        }
    };

    // Send request and receive response
    let action = target_to_action(target);
    let imsg = match client.query(action) {
        Ok(msg) => msg,
        Err(e) => {
            eprintln!("{prog}: {e}");
            return ExitCode::from(ctl::EXIT_ERROR);
        }
    };

    // Verify response type
    if imsg.header.type_ != IMSG_CTL_RESP {
        eprintln!(
            "{prog}: unexpected imsg type 0x{0:02x}, expected IMSG_CTL_RESP (0x{IMSG_CTL_RESP:02x})",
            imsg.header.type_
        );
        return ExitCode::from(ctl::EXIT_ERROR);
    }

    // Parse and display based on target
    match target.to_lowercase().as_str() {
        "status" => match ctl::parse_status(&imsg.payload) {
            Ok(status) => print_status(&status),
            Err(e) => {
                eprintln!("{prog}: {e}");
                return ExitCode::from(ctl::EXIT_ERROR);
            }
        },
        "peers" => match ctl::parse_peers(&imsg.payload) {
            Ok(peers) => print_peers(&peers),
            Err(e) => {
                eprintln!("{prog}: {e}");
                return ExitCode::from(ctl::EXIT_ERROR);
            }
        },
        "sensors" => match ctl::parse_sensors(&imsg.payload) {
            Ok(sensors) => print_sensors(&sensors),
            Err(e) => {
                eprintln!("{prog}: {e}");
                return ExitCode::from(ctl::EXIT_ERROR);
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
