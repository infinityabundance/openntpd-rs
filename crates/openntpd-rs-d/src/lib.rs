//! `ntpd` daemon library — OpenNTPD-rs forensic reconstruction.
//!
//! Provides the `-n` (config check) logic for the `ntpd` binary, separated
//! into a library for testability.

use std::path::Path;

/// Result of checking an `ntpd.conf` configuration.
#[derive(Debug)]
pub struct CheckResult {
    pub is_valid: bool,
    pub errors: Vec<String>,
}

/// Read and parse an `ntpd.conf` file, returning a `CheckResult`.
pub fn check_config_file(path: impl AsRef<Path>) -> CheckResult {
    let path = path.as_ref();
    let bytes = match std::fs::read(path) {
        Ok(b) => b,
        Err(e) => {
            return CheckResult {
                is_valid: false,
                errors: vec![format!("cannot read '{}': {e}", path.display())],
            };
        }
    };
    check_config_bytes(&bytes)
}

/// Parse configuration bytes and return a `CheckResult`.
pub fn check_config_bytes(bytes: &[u8]) -> CheckResult {
    let result = openntpd_rs_core::config::parser::parse_config(bytes);
    if result.is_valid() {
        CheckResult {
            is_valid: true,
            errors: Vec::new(),
        }
    } else {
        CheckResult {
            is_valid: false,
            errors: result
                .diagnostics
                .iter()
                .filter(|d| d.severity == openntpd_rs_core::config::diagnostic::Severity::Error)
                .map(|d| {
                    let span = match d.span {
                        Some(s) => format!("{}:{}: ", s.start, s.end),
                        None => String::new(),
                    };
                    format!("{span}{}", d.message)
                })
                .collect(),
        }
    }
}

// ---------------------------------------------------------------------------
// CLI argument parsing (shared with binary)
// ---------------------------------------------------------------------------

#[derive(Debug, Default)]
pub struct CliArgs {
    pub config_path: Option<String>,
    pub debug_mode: bool,
    pub config_test: bool,
    pub verbose: u8,
    pub parent_proc: Option<String>,
    pub pid_file: Option<String>,
}

/// Exit code for configuration errors (EX_CONFIG).
pub const EXIT_CONFIG: u8 = 78;

/// Parse CLI arguments.  Returns `Ok(args)` on success, or `Err(code)` if
/// the process should exit immediately.
pub fn parse_args() -> Result<(CliArgs, Vec<String>), u8> {
    let args: Vec<String> = std::env::args().collect();
    let prog = args.first().map(|s| s.as_str()).unwrap_or("ntpd");

    let mut out = CliArgs::default();
    let mut extra: Vec<String> = Vec::new();
    let mut i = 1;

    while i < args.len() {
        match args[i].as_str() {
            "-d" => out.debug_mode = true,
            "-f" => {
                i += 1;
                out.config_path = Some(args.get(i).cloned().unwrap_or_else(|| {
                    eprintln!("{prog}: -f requires path argument");
                    std::process::exit(EXIT_CONFIG.into());
                }));
            }
            "-n" => out.config_test = true,
            "-P" => {
                i += 1;
                out.parent_proc = Some(args.get(i).cloned().unwrap_or_else(|| {
                    eprintln!("{prog}: -P requires process name");
                    std::process::exit(EXIT_CONFIG.into());
                }));
            }
            "-p" => {
                i += 1;
                out.pid_file = Some(args.get(i).cloned().unwrap_or_else(|| {
                    eprintln!("{prog}: -p requires path argument");
                    std::process::exit(EXIT_CONFIG.into());
                }));
            }
            "-s" | "-S" => {
                extra.push(args[i].clone());
            }
            "-v" => out.verbose = out.verbose.saturating_add(1),
            other => {
                eprintln!("{prog}: unknown flag '{other}'");
                return Err(EXIT_CONFIG);
            }
        }
        i += 1;
    }

    Ok((out, extra))
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn valid_config_returns_ok() {
        let result = check_config_bytes(b"listen on *\nserver pool.ntp.org\n");
        assert!(result.is_valid);
        assert!(result.errors.is_empty());
    }

    #[test]
    fn invalid_config_returns_errors() {
        let result = check_config_bytes(b"listen on *\nserver pool.ntp.org weight 100\n");
        assert!(!result.is_valid);
        assert!(!result.errors.is_empty());
    }

    #[test]
    fn empty_config_is_valid() {
        let result = check_config_bytes(b"");
        assert!(result.is_valid);
    }

    #[test]
    fn parser_error_reported() {
        let result = check_config_bytes(b"listen on *\n\0bad\n");
        assert!(!result.is_valid);
    }

    #[test]
    fn multiple_errors_collected() {
        let result = check_config_bytes(
            b"listen on *\nserver pool.ntp.org weight 0\nsensor nmea0 stratum 100\n",
        );
        // Two invalid directives should produce at least 2 errors
        assert!(result.errors.len() >= 2);
    }

    #[test]
    fn config_test_exit_code() {
        // Valid config → SUCCESS
        let r1 = check_config_bytes(b"listen on *\n");
        assert_eq!(r1.is_valid, true);

        // Invalid config → EXIT_CONFIG
        let r2 = check_config_bytes(b"listen on *\ninvalid_directive\n");
        assert_eq!(r2.is_valid, false);
    }
}
