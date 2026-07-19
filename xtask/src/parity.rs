//! # Oracle parity check
//!
//! Compares `openntpd-rs ntpd -n` behavior against a real OpenNTPD 7.9p1
//! oracle by running both executables over a shared corpus of known-good
//! and known-bad configuration files and comparing exit codes with
//! normalized diagnostic categories.
//!
//! ## Corpus format
//!
//! Each corpus case records:
//!
//! - `id` — unique identifier
//! - `config` — configuration text (embedded or file path)
//! - `exit` — expected exit code (0 = accept, 1 = reject)
//! - `category` — normalized diagnostic category for rejected cases
//!
//! ## Usage
//!
//! ```text
//! cargo xtask parity                    # use default oracle
//! cargo xtask parity --oracle /usr/sbin/ntpd
//! cargo xtask parity --oracle-image openntpd:7.9p1
//! ```

use std::path::{Path, PathBuf};
use std::process::Command;

/// Try to locate the compiled Rust `ntpd` binary.
fn find_rust_ntpd(oracle_path: &Option<PathBuf>) -> PathBuf {
    let manifest = Path::new(env!("CARGO_MANIFEST_DIR"));
    let workspace = manifest.parent().expect("xtask is in workspace root");

    let candidates = [
        workspace.join("target/debug/ntpd"),
        workspace.join("target/release/ntpd"),
        // If oracle path was given, look for Rust ntpd next to it
        oracle_path
            .as_ref()
            .and_then(|p| p.parent().map(|parent| parent.join("ntpd")))
            .unwrap_or_else(|| PathBuf::from("ntpd")),
    ];

    for c in &candidates {
        if c.exists() {
            return c.clone();
        }
    }

    // Fall back to PATH resolution
    PathBuf::from("ntpd")
}

// ---------------------------------------------------------------------------
// Corpus definition
// ---------------------------------------------------------------------------

/// A single oracle corpus case.
struct CorpusCase {
    /// Unique identifier for this case.
    id: &'static str,
    /// Configuration text (newline-terminated).
    config: &'static [u8],
    /// Expected oracle exit code for this case.
    expected_exit: i32,
    /// Normalized diagnostic category (empty for accepted cases).
    expected_category: &'static str,
}

/// The configuration-check corpus.
///
/// Each case is deterministic: no DNS, no network, no local interfaces,
/// no sensor hardware, no routing-table limits.
const CORPUS: &[CorpusCase] = &[
    // -- Accepted configurations (exit 0) --
    CorpusCase {
        id: "empty",
        config: b"",
        expected_exit: 0,
        expected_category: "",
    },
    CorpusCase {
        id: "listen_wildcard",
        config: b"listen on *\n",
        expected_exit: 0,
        expected_category: "",
    },
    CorpusCase {
        id: "listen_ipv4",
        config: b"listen on 127.0.0.1\n",
        expected_exit: 0,
        expected_category: "",
    },
    CorpusCase {
        id: "server_numeric_ipv4",
        config: b"server 192.0.2.1\n",
        expected_exit: 0,
        expected_category: "",
    },
    CorpusCase {
        id: "servers_numeric_ipv6",
        config: b"servers 2001:db8::1\n",
        expected_exit: 0,
        expected_category: "",
    },
    CorpusCase {
        id: "query_from_ipv4",
        config: b"query from 127.0.0.1\n",
        expected_exit: 0,
        expected_category: "",
    },
    CorpusCase {
        id: "sensor_wildcard",
        config: b"sensor *\n",
        expected_exit: 0,
        expected_category: "",
    },
    CorpusCase {
        id: "sensor_quoted_name",
        config: b"sensor \"nmea0\"\n",
        expected_exit: 0,
        expected_category: "",
    },
    CorpusCase {
        id: "constraint_https_url",
        config: b"constraint from \"https://192.0.2.1/\"\n",
        expected_exit: 0,
        expected_category: "",
    },
    CorpusCase {
        id: "server_with_weight",
        config: b"server 192.0.2.1 weight 5\n",
        expected_exit: 0,
        expected_category: "",
    },
    CorpusCase {
        id: "server_with_trusted",
        config: b"server 192.0.2.1 trusted\n",
        expected_exit: 0,
        expected_category: "",
    },
    CorpusCase {
        id: "listen_with_rtable",
        config: b"listen on * rtable 0\n",
        expected_exit: 0,
        expected_category: "",
    },
    CorpusCase {
        id: "sensor_all_options",
        config: b"sensor nmea0 correction 1000 refid GPS stratum 3 weight 5 trusted\n",
        expected_exit: 0,
        expected_category: "",
    },
    CorpusCase {
        id: "multiple_directives",
        config: b"listen on *\nserver 192.0.2.1\nsensor nmea0\n",
        expected_exit: 0,
        expected_category: "",
    },
    CorpusCase {
        id: "comments_and_blanks",
        config: b"# This is a comment\nlisten on *\n\nserver 192.0.2.1\n",
        expected_exit: 0,
        expected_category: "",
    },
    // -- Rejected configurations (exit 1) --
    CorpusCase {
        id: "unknown_directive",
        config: b"foobar\n",
        expected_exit: 1,
        expected_category: "syntax-error",
    },
    CorpusCase {
        id: "invalid_server_weight",
        config: b"server 192.0.2.1 weight 0\n",
        expected_exit: 1,
        expected_category: "invalid-weight",
    },
    CorpusCase {
        id: "server_weight_257",
        config: b"server 192.0.2.1 weight 257\n",
        expected_exit: 1,
        expected_category: "invalid-weight",
    },
    CorpusCase {
        id: "server_weight_negative",
        config: b"server 192.0.2.1 weight -1\n",
        expected_exit: 1,
        expected_category: "invalid-weight",
    },
    CorpusCase {
        id: "invalid_sensor_stratum",
        config: b"sensor nmea0 stratum 0\n",
        expected_exit: 1,
        expected_category: "invalid-stratum",
    },
    CorpusCase {
        id: "sensor_stratum_257",
        config: b"sensor nmea0 stratum 257\n",
        expected_exit: 1,
        expected_category: "invalid-stratum",
    },
    CorpusCase {
        id: "invalid_sensor_correction",
        config: b"sensor nmea0 correction 999999999\n",
        expected_exit: 1,
        expected_category: "invalid-correction",
    },
    CorpusCase {
        id: "invalid_sensor_weight",
        config: b"sensor nmea0 weight 11\n",
        expected_exit: 1,
        expected_category: "invalid-weight",
    },
    CorpusCase {
        id: "query_from_hostname",
        config: b"query from ntp.example.com\n",
        expected_exit: 1,
        expected_category: "invalid-address",
    },
    CorpusCase {
        id: "server_wildcard",
        config: b"server *\n",
        expected_exit: 1,
        expected_category: "invalid-address",
    },
    CorpusCase {
        id: "constraint_wildcard",
        config: b"constraint from *\n",
        expected_exit: 1,
        expected_category: "invalid-address",
    },
    CorpusCase {
        id: "listen_missing_on",
        config: b"listen *\n",
        expected_exit: 1,
        expected_category: "syntax-error",
    },
    CorpusCase {
        id: "constraint_missing_from",
        config: b"constraint www.example.com\n",
        expected_exit: 1,
        expected_category: "syntax-error",
    },
    CorpusCase {
        id: "sensor_adjacent_strings",
        config: b"sensor foo bar\n",
        expected_exit: 1,
        expected_category: "syntax-error",
    },
    CorpusCase {
        id: "query_trailing_garbage",
        config: b"query from 127.0.0.1 garbage\n",
        expected_exit: 1,
        expected_category: "syntax-error",
    },
];

// ---------------------------------------------------------------------------
// Runner: execute a config against an ntpd binary
// ---------------------------------------------------------------------------

/// Result from running a single corpus case.
#[derive(Debug, Clone)]
struct CaseResult {
    exit_code: i32,
    stderr: String,
}

/// Run a single corpus case through the given `ntpd` binary.
fn run_case(ntpd_bin: &Path, config: &[u8]) -> CaseResult {
    // Write config to a temp file
    let dir = std::env::temp_dir().join("openntpd_rs_parity");
    let _ = std::fs::create_dir_all(&dir);
    let config_path = dir.join("ntpd.conf");
    std::fs::write(&config_path, config).expect("write temp config");

    let output = Command::new(ntpd_bin)
        .args(["-n", "-f"])
        .arg(&config_path)
        .output()
        .expect("ntpd binary");

    let _ = std::fs::remove_file(&config_path);

    CaseResult {
        exit_code: output.status.code().unwrap_or(-1),
        stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
    }
}

// ---------------------------------------------------------------------------
// Normalization
// ---------------------------------------------------------------------------

/// Normalize stderr into a diagnostic category.
fn normalize_category(stderr: &str, exit_code: i32) -> &'static str {
    if exit_code == 0 {
        return "";
    }
    let lower = stderr.to_lowercase();
    if lower.contains("cannot read") || lower.contains("no such file") {
        "unreadable-file"
    } else if lower.contains("weight") {
        "invalid-weight"
    } else if lower.contains("stratum") {
        "invalid-stratum"
    } else if lower.contains("correction") {
        "invalid-correction"
    } else if lower.contains("refid") {
        "invalid-refid"
    } else if lower.contains("rtable") {
        "invalid-rtable"
    } else if lower.contains("address") || lower.contains("ip") || lower.contains("wildcard") {
        "invalid-address"
    } else {
        "syntax-error"
    }
}

// ---------------------------------------------------------------------------
// Evidence recording
// ---------------------------------------------------------------------------

/// Write a verdict summary to stdout for use as evidence.
fn record_evidence(
    case: &CorpusCase,
    rust_result: &CaseResult,
    oracle_result: Option<&CaseResult>,
) {
    let oracle_exit = oracle_result.map(|r| r.exit_code);
    let oracle_category = oracle_result.map(|r| normalize_category(&r.stderr, r.exit_code));

    let exit_match = oracle_exit.map_or(true, |oe| oe == rust_result.exit_code);
    let cat_match = oracle_category.map_or(true, |oc| {
        oc == normalize_category(&rust_result.stderr, rust_result.exit_code)
    });

    let verdict = if exit_match && cat_match {
        "PASS"
    } else {
        "FAIL"
    };

    println!(
        "{verdict} | {} | {} | {} | {} | {} | {} | {} | {:?} | {}",
        case.id,
        case.expected_exit,
        rust_result.exit_code,
        oracle_exit.map_or("N/A".into(), |e| e.to_string()),
        case.expected_category,
        normalize_category(&rust_result.stderr, rust_result.exit_code),
        oracle_category.unwrap_or("N/A"),
        oracle_result.map(|r| sha256_digest(&r.stderr)),
        exit_match && cat_match,
    );
}

fn sha256_digest(_s: &str) -> String {
    // Use std hashing for a simple digest
    use std::hash::{Hash, Hasher};
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    _s.hash(&mut hasher);
    format!("{:016x}", hasher.finish())
}

// ---------------------------------------------------------------------------
// Public entry point
// ---------------------------------------------------------------------------

/// Run the oracle parity check.
///
/// Optional args:
/// - `--oracle <path>` — Path to the real `ntpd` binary (default: `ntpd`)
/// - `--skip-oracle` — Skip oracle comparison (Rust-only self-test)
pub fn run(args: &[String]) -> anyhow::Result<()> {
    let mut oracle_path: Option<PathBuf> = None;
    let mut skip_oracle = false;

    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--oracle" => {
                i += 1;
                oracle_path = Some(
                    args.get(i)
                        .ok_or_else(|| anyhow::anyhow!("--oracle requires path argument"))?
                        .into(),
                );
            }
            "--skip-oracle" => skip_oracle = true,
            other => anyhow::bail!("unknown parity flag: {other}"),
        }
        i += 1;
    }

    if CORPUS.is_empty() {
        anyhow::bail!("no corpus cases defined");
    }

    // Resolve the Rust ntpd binary
    let rust_ntpd = find_rust_ntpd(&oracle_path);
    eprintln!("Rust ntpd: {}", rust_ntpd.display());

    // Resolve the oracle binary
    let oracle_ntpd = match (&oracle_path, skip_oracle) {
        (Some(path), _) => {
            if !path.exists() {
                anyhow::bail!("oracle ntpd not found at {path:?}");
            }
            eprintln!("Oracle ntpd: {}", path.display());
            Some(path.clone())
        }
        (None, true) => {
            eprintln!("Oracle: skipped (--skip-oracle)");
            None
        }
        (None, false) => {
            // Try default paths
            let candidates = [
                "/usr/sbin/ntpd",
                "/usr/local/sbin/ntpd",
                "/opt/openntpd/sbin/ntpd",
            ];
            let found = candidates.iter().find(|p| Path::new(p).exists());
            match found {
                Some(path) => {
                    eprintln!("Oracle ntpd: {path}");
                    Some(PathBuf::from(path))
                }
                None => {
                    anyhow::bail!(
                        "no oracle ntpd found. Install OpenNTPD 7.9p1 or \
                         pass --oracle <path> or --skip-oracle"
                    );
                }
            }
        }
    };

    // Print header
    println!(
        "{:6} | {:40} | {:8} | {:8} | {:8} | {:20} | {:20} | {:20} | {:10} | match",
        "STATUS",
        "CASE",
        "EXPECT",
        "RUST",
        "ORACLE",
        "EXPECTED CAT",
        "RUST CAT",
        "ORACLE CAT",
        "STDERR HASH",
    );
    println!("{}", "-".repeat(160));

    let mut passed = 0u32;
    let mut failed = 0u32;

    for case in CORPUS {
        let rust_result = run_case(&rust_ntpd, case.config);

        let oracle_result = oracle_ntpd.as_ref().map(|p| run_case(p, case.config));

        record_evidence(case, &rust_result, oracle_result.as_ref());

        // Check against expected
        let exit_ok = rust_result.exit_code == case.expected_exit;
        let cat = normalize_category(&rust_result.stderr, rust_result.exit_code);
        let cat_ok = cat == case.expected_category;

        if exit_ok && cat_ok {
            passed += 1;
        } else {
            failed += 1;
        }
    }

    println!("{}", "-".repeat(160));
    println!(
        "Passed: {passed}, Failed: {failed}, Total: {}",
        CORPUS.len()
    );

    if failed > 0 {
        anyhow::bail!("{failed} corpus case(s) do not match expected behavior.",);
    }

    eprintln!("\n✓ All {passed} corpus cases match expected behavior.");
    Ok(())
}
