//! # ntpctl — OpenNTPD-rs control client
//!
//! Clean-room, blackbox forensic Rust reconstruction of OpenNTPD's
//! `ntpctl` control client.  CL: ntpctl(8).
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

use std::process::ExitCode;

/// Exit code for unimplemented functionality (EX_CONFIG).
const EXIT_UNIMPLEMENTED: u8 = 78;

const DEFAULT_CONTROL_SOCKET: &str = "/var/run/ntpd.sock";

/// The valid status query targets.
const VALID_TARGETS: &[&str] = &["status", "peers", "Sensors", "all"];

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

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().collect();
    let prog = args.first().map(|s| s.as_str()).unwrap_or("ntpctl");

    let control_socket =
        std::env::var("NTPD_CONTROL_SOCKET").unwrap_or_else(|_| DEFAULT_CONTROL_SOCKET.to_string());

    if args.len() < 3 || args[1] != "-s" {
        eprintln!("Usage: {prog} -s <status|peers|Sensors|all>");
        return ExitCode::from(EXIT_UNIMPLEMENTED);
    }

    let what = &args[2];
    if what.is_empty() {
        eprintln!("{prog}: empty status type");
        return ExitCode::from(EXIT_UNIMPLEMENTED);
    }

    let matches = matching_targets(what);
    match matches.as_slice() {
        [target] => {
            eprintln!(
                "{prog}: would query ntpd at {control_socket} for '{target}' \
                 (control protocol not yet wired)"
            );
            ExitCode::from(EXIT_UNIMPLEMENTED)
        }
        [] => {
            eprintln!("{prog}: unknown status type '{what}'");
            ExitCode::from(EXIT_UNIMPLEMENTED)
        }
        _ => {
            eprintln!(
                "{prog}: ambiguous prefix '{what}' — matches: {}",
                matches.join(", ")
            );
            ExitCode::from(EXIT_UNIMPLEMENTED)
        }
    }
}
