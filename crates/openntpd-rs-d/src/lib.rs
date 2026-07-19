//! `ntpd` daemon library — OpenNTPD-rs forensic reconstruction.
//!
//! Provides the `-n` (config check) logic and injectable CLI argument
//! parsing for the `ntpd` binary.

use std::path::Path;

// ---------------------------------------------------------------------------
// Exit codes
// ---------------------------------------------------------------------------

/// Exit code for runtime errors (EXIT_FAILURE = 1).
pub const EXIT_ERROR: u8 = 1;

/// Exit code for unimplemented functionality (EX_CONFIG = 78).
/// Used for the unwired daemon-mode scaffold only.
pub const EXIT_UNIMPLEMENTED: u8 = 78;

// ---------------------------------------------------------------------------
// Config checking
// ---------------------------------------------------------------------------

/// Result of checking an `ntpd.conf` configuration.
#[derive(Debug)]
pub struct CheckResult {
    pub is_valid: bool,
    pub errors: Vec<String>,
}

/// Read and parse an `ntpd.conf` file, returning a `CheckResult`.
pub fn check_config_file(path: impl AsRef<Path>) -> CheckResult {
    let path = path.as_ref();
    match std::fs::read(path) {
        Ok(b) => check_config_bytes(&b),
        Err(e) => CheckResult {
            is_valid: false,
            errors: vec![format!("cannot read '{}': {e}", path.display())],
        },
    }
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
// CLI argument parsing — injectable and group-flag–aware
// ---------------------------------------------------------------------------

/// Parsed CLI arguments for the `ntpd` binary.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct CliArgs {
    pub config_path: Option<String>,
    pub debug_mode: bool,
    pub config_test: bool,
    pub verbose: u8,
    pub parent_proc: Option<String>,
    pub pid_file: Option<String>,
}

/// Structured CLI parse error.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CliError {
    /// An unknown flag was encountered.
    UnknownFlag(String),
    /// A flag that requires an argument was missing it.
    MissingArgument(String),
}

impl CliError {
    pub fn exit_code(&self) -> u8 {
        EXIT_ERROR
    }
}

/// Parse arguments from an iterator.  Supports grouped short flags
/// (e.g. `-dn`, `-dnv`, `-vv`).
pub fn parse_args_from<I, S>(args: I) -> Result<(CliArgs, Vec<String>), CliError>
where
    I: IntoIterator<Item = S>,
    S: Into<String>,
{
    let mut out = CliArgs::default();
    let mut extra: Vec<String> = Vec::new();
    let args: Vec<String> = args.into_iter().map(|s| s.into()).collect();
    let mut i = 1;

    while i < args.len() {
        let arg = &args[i];
        let mut chars = arg.chars();

        // Must start with '-'
        if !arg.starts_with('-') || arg.len() < 2 {
            return Err(CliError::UnknownFlag(arg.clone()));
        }

        chars.next(); // consume leading '-'
        let mut flag_chars: Vec<char> = chars.collect();

        // Grouped flags: iterate each character after '-'
        // For flags that consume a following argument, only the last
        // character in the group may be the flag.
        while let Some(c) = flag_chars.first().copied() {
            let is_last = flag_chars.len() == 1;
            match c {
                'd' => {
                    out.debug_mode = true;
                    flag_chars.remove(0);
                }
                'n' => {
                    out.config_test = true;
                    flag_chars.remove(0);
                }
                'v' => {
                    out.verbose = out.verbose.saturating_add(1);
                    flag_chars.remove(0);
                }
                'f' if is_last => {
                    i += 1;
                    out.config_path = Some(
                        args.get(i)
                            .ok_or_else(|| CliError::MissingArgument("-f".into()))?
                            .clone(),
                    );
                    flag_chars.remove(0); // consumed
                }
                'P' if is_last => {
                    i += 1;
                    out.parent_proc = Some(
                        args.get(i)
                            .ok_or_else(|| CliError::MissingArgument("-P".into()))?
                            .clone(),
                    );
                    flag_chars.remove(0);
                }
                'p' if is_last => {
                    i += 1;
                    out.pid_file = Some(
                        args.get(i)
                            .ok_or_else(|| CliError::MissingArgument("-p".into()))?
                            .clone(),
                    );
                    flag_chars.remove(0);
                }
                's' | 'S' if is_last => {
                    extra.push(arg.clone());
                    flag_chars.clear();
                }
                _ => {
                    return Err(CliError::UnknownFlag(format!("-{c}")));
                }
            }
        }

        i += 1;
    }

    Ok((out, extra))
}

/// Parse CLI arguments from [`std::env::args`].
pub fn parse_args() -> Result<(CliArgs, Vec<String>), CliError> {
    parse_args_from(std::env::args())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // -- Config checking --

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
        assert!(result.errors.len() >= 2);
    }

    // -- CLI argument parsing --

    #[test]
    fn cli_defaults() {
        let (args, extra) = parse_args_from(["ntpd"]).unwrap();
        assert_eq!(
            args,
            CliArgs {
                config_path: None,
                debug_mode: false,
                config_test: false,
                verbose: 0,
                parent_proc: None,
                pid_file: None,
            }
        );
        assert!(extra.is_empty());
    }

    #[test]
    fn cli_dash_n() {
        let (args, _) = parse_args_from(["ntpd", "-n"]).unwrap();
        assert!(args.config_test);
    }

    #[test]
    fn cli_dash_f() {
        let (args, _) = parse_args_from(["ntpd", "-f", "/etc/ntpd.conf"]).unwrap();
        assert_eq!(args.config_path, Some("/etc/ntpd.conf".into()));
    }

    #[test]
    fn cli_grouped_dn() {
        let (args, _) = parse_args_from(["ntpd", "-dn"]).unwrap();
        assert!(args.debug_mode);
        assert!(args.config_test);
    }

    #[test]
    fn cli_grouped_dnv() {
        let (args, _) = parse_args_from(["ntpd", "-dnv"]).unwrap();
        assert!(args.debug_mode);
        assert!(args.config_test);
        assert_eq!(args.verbose, 1);
    }

    #[test]
    fn cli_repeated_v() {
        let (args, _) = parse_args_from(["ntpd", "-vv"]).unwrap();
        assert_eq!(args.verbose, 2);
    }

    #[test]
    fn cli_missing_f_argument() {
        let err = parse_args_from(["ntpd", "-f"]).unwrap_err();
        assert!(matches!(err, CliError::MissingArgument(_)));
    }

    #[test]
    fn cli_unknown_option() {
        let err = parse_args_from(["ntpd", "--xyz"]).unwrap_err();
        assert!(matches!(err, CliError::UnknownFlag(_)));
    }

    #[test]
    fn cli_positional_argument_rejected() {
        let err = parse_args_from(["ntpd", "positional"]).unwrap_err();
        assert!(matches!(err, CliError::UnknownFlag(_)));
    }
}
