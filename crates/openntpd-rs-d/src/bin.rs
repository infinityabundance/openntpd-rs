//! # ntpd — OpenNTPD-rs daemon
//!
//! Clean-room, blackbox forensic Rust reconstruction of OpenNTPD's
//! `ntpd` daemon.  CL: ntpd(8).
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

/// Exit code for unimplemented functionality (EX_CONFIG on most systems).
/// This ensures we fail closed rather than silently succeeding.
const EXIT_UNIMPLEMENTED: u8 = 78;

const DEFAULT_CONFIG: &str = "/etc/ntpd.conf";

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().collect();
    let prog = args.first().map(|s| s.as_str()).unwrap_or("ntpd");

    let mut config_path: Option<String> = None;
    let mut debug_mode = false;
    let mut config_test = false;
    let mut verbose: u8 = 0;
    let mut _parent_proc: Option<String> = None;
    let mut _pid_file: Option<String> = None;
    let mut saw_deprecated = false;

    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "-d" => debug_mode = true,
            "-f" => {
                i += 1;
                config_path = Some(args.get(i).cloned().unwrap_or_else(|| {
                    eprintln!("{prog}: -f requires path argument");
                    std::process::exit(EXIT_UNIMPLEMENTED.into());
                }));
            }
            "-n" => config_test = true,
            "-P" => {
                i += 1;
                _parent_proc = Some(args.get(i).cloned().unwrap_or_else(|| {
                    eprintln!("{prog}: -P requires process name");
                    std::process::exit(EXIT_UNIMPLEMENTED.into());
                }));
            }
            "-p" => {
                i += 1;
                _pid_file = Some(args.get(i).cloned().unwrap_or_else(|| {
                    eprintln!("{prog}: -p requires path argument");
                    std::process::exit(EXIT_UNIMPLEMENTED.into());
                }));
            }
            "-s" | "-S" => {
                if !saw_deprecated {
                    eprintln!(
                        "{prog}: warning: -{}/ -{} is deprecated and ignored",
                        if args[i] == "-s" { "s" } else { "S" },
                        if args[i] == "-s" { "S" } else { "s" }
                    );
                    saw_deprecated = true;
                }
            }
            "-v" => verbose = verbose.saturating_add(1),
            other => {
                eprintln!("{prog}: unknown flag '{other}'");
                return ExitCode::from(EXIT_UNIMPLEMENTED);
            }
        }
        i += 1;
    }

    if config_test {
        let config_path = config_path.as_deref().unwrap_or(DEFAULT_CONFIG);
        eprintln!("{prog}: configuration check: {config_path}");
        eprintln!("{prog}: configuration parser not yet implemented");
        return ExitCode::from(EXIT_UNIMPLEMENTED);
    }

    let config_path = config_path.as_deref().unwrap_or(DEFAULT_CONFIG);
    eprintln!("{prog}: OpenNTPD-rs 0.1.0 (forensic reconstruction)");

    if debug_mode {
        eprintln!("{prog}: debug mode, config: {config_path}, verbosity: {verbose}");
    }

    eprintln!("{prog}: not yet implemented — this is a scaffold.");
    eprintln!("{prog}: exiting with code {EXIT_UNIMPLEMENTED}.");
    ExitCode::from(EXIT_UNIMPLEMENTED)
}
