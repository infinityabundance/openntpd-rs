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

use openntpd_rs_d::{CliError, DaemonConfig, EXIT_ERROR};

const DEFAULT_CONFIG: &str = "/etc/ntpd.conf";

fn main() -> ExitCode {
    let prog = std::env::args().next().unwrap_or_else(|| "ntpd".into());

    let (args, extra) = match openntpd_rs_d::parse_args() {
        Ok(a) => a,
        Err(CliError::UnknownFlag(flag)) => {
            eprintln!("{prog}: unknown flag '{flag}'");
            return ExitCode::from(EXIT_ERROR);
        }
        Err(CliError::MissingArgument(flag)) => {
            eprintln!("{prog}: {flag} requires argument");
            return ExitCode::from(EXIT_ERROR);
        }
    };

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

    let config_path = args
        .config_path
        .clone()
        .unwrap_or_else(|| DEFAULT_CONFIG.into());

    let daemon_config = DaemonConfig {
        config_path: config_path.into(),
        debug_mode: args.debug_mode,
        verbose: args.verbose,
        parent_proc: args.parent_proc.clone(),
        pid_file: args.pid_file.clone(),
        config_test: args.config_test,
    };

    eprintln!("{prog}: OpenNTPD-rs (forensic reconstruction)");

    // Use run_daemon_full which dispatches to:
    //   -n  → config test
    //   -d  → foreground daemon
    //   default → background daemon (fork + PID file)
    let result = openntpd_rs_d::run_daemon_full(&daemon_config);
    if !result.message.is_empty() {
        eprintln!("{prog}: {}", result.message);
    }
    ExitCode::from(result.exit_code)
}
