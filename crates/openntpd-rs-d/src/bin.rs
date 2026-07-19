//! # ntpd — OpenNTPD-rs daemon
//!
//! Clean-room, blackbox forensic Rust reconstruction of OpenNTPD's
//! `ntpd` daemon.  CLI: ntpd(8).
//!
//! ## CLI (OpenNTPD 7.9p1 flags)
//!
//! ```text
//! ntpd [-dfnv] [-P process] [-p file]
//! ```
//!
//! - `-d`  Debug mode (do not daemonize, log to stderr).
//! - `-f`  Config file (default: SYSCONFDIR/ntpd.conf).
//! - `-n`  Config/test mode: parse config, print result, exit.
//! - `-P`  Parent process name (for setproctitle).
//! - `-p`  PID file path (portable patch 0007).
//! - `-s`  Deprecated — prints warning, ignored.
//! - `-S`  Deprecated — prints warning, ignored.
//! - `-v`  Verbose (repeatable: -v, -vv).

use std::process::ExitCode;

const DEFAULT_CONFIG: &str = "/etc/ntpd.conf";

fn main() -> ExitCode {
    let (args, extra) = match openntpd_rs_d::parse_args() {
        Ok(a) => a,
        Err(code) => return ExitCode::from(code),
    };

    let prog = std::env::args().next().unwrap_or_else(|| "ntpd".into());

    // Deprecated flags
    let mut saw_deprecated = false;
    for flag in &extra {
        if !saw_deprecated {
            match flag.as_str() {
                "-s" | "-S" => {
                    eprintln!("{prog}: warning: {flag} is deprecated and ignored");
                    saw_deprecated = true;
                }
                _ => {}
            }
        }
    }

    if args.config_test {
        let config_path = args.config_path.as_deref().unwrap_or(DEFAULT_CONFIG);
        let result = openntpd_rs_d::check_config_file(config_path);
        if result.is_valid {
            eprintln!("configuration OK");
            ExitCode::SUCCESS
        } else {
            for err in &result.errors {
                eprintln!("{prog}: {err}");
            }
            ExitCode::from(openntpd_rs_d::EXIT_CONFIG)
        }
    } else {
        let config_path = args.config_path.as_deref().unwrap_or(DEFAULT_CONFIG);
        eprintln!("{prog}: OpenNTPD-rs (forensic reconstruction)");

        if args.debug_mode {
            eprintln!(
                "{prog}: debug mode, config: {config_path}, verbosity: {}",
                args.verbose
            );
        }

        eprintln!("{prog}: daemon mode not yet implemented");
        eprintln!("{prog}: exiting with code {}.", openntpd_rs_d::EXIT_CONFIG);
        ExitCode::from(openntpd_rs_d::EXIT_CONFIG)
    }
}
