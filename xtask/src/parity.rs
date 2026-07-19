//! # Oracle parity check
//!
//! Compares `openntpd-rs ntpd -n` behavior against a real OpenNTPD 7.9p1
//! oracle by running both executables over a shared corpus of known-good
//! and known-bad configuration files and comparing exit codes with
//! normalized diagnostic categories.
//!
//! ## Usage
//!
//! ```text
//! # Self-test (no oracle needed)
//! cargo xtask parity --skip-oracle
//!
//! # Against local oracle binary
//! cargo xtask parity --oracle /usr/sbin/ntpd
//! ```
//!
//! ## Evidence
//!
//! A JSON receipt is written to `research/oracle/receipts/<timestamp>.json`
//! containing per-case results with SHA-256 content digests and binary
//! identity information.

use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::Command;

use sha2::{Digest, Sha256};

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
        config: b"# comment\nlisten on *\n\nserver 192.0.2.1\n",
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
// SHA-256 helper
// ---------------------------------------------------------------------------

fn sha256_digest(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

// ---------------------------------------------------------------------------
// Binary resolve
// ---------------------------------------------------------------------------

/// Locate the compiled Rust `ntpd` binary by building it.
fn resolve_rust_ntpd() -> anyhow::Result<PathBuf> {
    let manifest_dir = Path::new(env!("CARGO_MANIFEST_DIR"));
    let workspace = manifest_dir.parent().unwrap();

    // Build the Rust ntpd binary to ensure it exists
    let status = Command::new("cargo")
        .args(["build", "-p", "openntpd-rs-d", "--bin", "ntpd"])
        .current_dir(workspace)
        .status()
        .map_err(|e| anyhow::anyhow!("failed to run cargo build: {e}"))?;

    if !status.success() {
        anyhow::bail!("cargo build -p openntpd-rs-d --bin ntpd failed");
    }

    // Find the built binary
    let profile = if workspace.join("target/release/ntpd").exists() {
        "release"
    } else {
        "debug"
    };

    let path = workspace.join(format!("target/{profile}/ntpd"));
    if !path.exists() {
        anyhow::bail!("Rust ntpd binary not found after build at {path:?}");
    }

    Ok(path)
}

/// Canonicalize a binary path and check it exists.
fn resolve_binary(path: &Path) -> anyhow::Result<PathBuf> {
    let canonical =
        std::fs::canonicalize(path).map_err(|e| anyhow::anyhow!("cannot resolve {path:?}: {e}"))?;
    if !canonical.is_file() {
        anyhow::bail!("{canonical:?} is not a file");
    }
    Ok(canonical)
}

// ---------------------------------------------------------------------------
// Runner
// ---------------------------------------------------------------------------

/// Result from executing a single corpus case.
#[derive(Debug, Clone)]
struct CaseResult {
    exit_code: i32,
    stderr: Vec<u8>,
}

fn run_case(ntpd_bin: &Path, config: &[u8]) -> CaseResult {
    let dir = std::env::temp_dir().join("openntpd_rs_parity");
    let _ = std::fs::create_dir_all(&dir);
    let config_path = dir.join("ntpd.conf");
    std::fs::write(&config_path, config).expect("write temp config");

    let output = Command::new(ntpd_bin)
        .args(["-n", "-f"])
        .arg(&config_path)
        .output()
        .expect("execute ntpd binary");

    let _ = std::fs::remove_file(&config_path);

    CaseResult {
        exit_code: output.status.code().unwrap_or(-1),
        stderr: output.stderr,
    }
}

// ---------------------------------------------------------------------------
// Normalization
// ---------------------------------------------------------------------------

fn normalize_category(stderr: &[u8], exit_code: i32) -> &'static str {
    if exit_code == 0 {
        return "";
    }
    let lower = String::from_utf8_lossy(stderr).to_lowercase();
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
// Evidence receipt
// ---------------------------------------------------------------------------

#[derive(serde::Serialize)]
struct Receipt {
    schema_version: u32,
    timestamp: String,
    corpus_revision: String,
    corpus_size: usize,
    rust_binary: BinaryInfo,
    oracle_binary: Option<BinaryInfo>,
    results: Vec<CaseReceipt>,
    summary: Summary,
}

#[derive(serde::Serialize)]
struct BinaryInfo {
    path: String,
    sha256: String,
}

#[derive(serde::Serialize)]
struct CaseReceipt {
    case_id: String,
    config_sha256: String,
    expected_exit: i32,
    expected_category: String,
    rust_exit: i32,
    rust_category: String,
    rust_stderr_sha256: String,
    oracle_exit: Option<i32>,
    oracle_category: Option<String>,
    oracle_stderr_sha256: Option<String>,
    expected_match: bool,
    oracle_parity: Option<bool>,
    verdict: String,
}

#[derive(serde::Serialize)]
struct Summary {
    passed: u32,
    failed: u32,
    total: u32,
}

fn write_receipt(receipt: &Receipt) -> anyhow::Result<PathBuf> {
    let manifest_dir = Path::new(env!("CARGO_MANIFEST_DIR"));
    let receipts_dir = manifest_dir
        .parent()
        .unwrap()
        .join("research")
        .join("oracle")
        .join("receipts");
    std::fs::create_dir_all(&receipts_dir)?;

    let ts = &receipt.timestamp.replace([' ', ':'], "_");
    let path = receipts_dir.join(format!("parity_{ts}.json"));

    let json = serde_json::to_string_pretty(receipt)?;
    let mut f = std::fs::File::create(&path)?;
    f.write_all(json.as_bytes())?;
    f.write_all(b"\n")?;

    eprintln!("Evidence written to {}", path.display());
    Ok(path)
}

// ---------------------------------------------------------------------------
// Public entry point
// ---------------------------------------------------------------------------

/// Run the oracle parity check.
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
    let rust_ntpd = resolve_rust_ntpd()?;
    eprintln!("Rust ntpd: {}", rust_ntpd.display());
    let rust_sha = sha256_digest(&std::fs::read(&rust_ntpd)?);

    // Resolve the oracle binary
    let oracle_ntpd: Option<PathBuf> = match (&oracle_path, skip_oracle) {
        (Some(path), _) => {
            let resolved = resolve_binary(path)?;
            eprintln!("Oracle ntpd: {}", resolved.display());
            Some(resolved)
        }
        (None, true) => {
            eprintln!("Oracle: skipped");
            None
        }
        (None, false) => {
            anyhow::bail!("no oracle path given. Pass --oracle <path> or --skip-oracle")
        }
    };

    // Prevent self-comparison
    if let Some(ref oracle) = oracle_ntpd {
        let rust_canonical = std::fs::canonicalize(&rust_ntpd)?;
        let oracle_canonical = std::fs::canonicalize(oracle)?;
        if rust_canonical == oracle_canonical {
            anyhow::bail!(
                "Rust ntpd and oracle resolve to the same binary: {}",
                rust_canonical.display(),
            );
        }
    }

    // Binary info for receipt
    let oracle_binary_info = oracle_ntpd.as_ref().map(|p| BinaryInfo {
        path: p.display().to_string(),
        sha256: sha256_digest(&std::fs::read(p).unwrap_or_default()),
    });

    // Print header
    println!(
        "{:6} | {:40} | {:8} | {:8} | {:8} | {:20} | {:20} | {:20} | match",
        "STATUS", "CASE", "EXPECT", "RUST", "ORACLE", "EXPECTED CAT", "RUST CAT", "ORACLE CAT",
    );
    println!("{}", "-".repeat(155));

    let mut results = Vec::new();
    let mut passed = 0u32;
    let mut failed = 0u32;

    for case in CORPUS {
        let config_sha = sha256_digest(case.config);
        let rust_result = run_case(&rust_ntpd, case.config);
        let rust_category = normalize_category(&rust_result.stderr, rust_result.exit_code);

        let oracle_result = oracle_ntpd.as_ref().map(|p| run_case(p, case.config));
        let oracle_category = oracle_result
            .as_ref()
            .map(|r| normalize_category(&r.stderr, r.exit_code));

        // Check: Rust matches expected
        let rust_expected_ok =
            rust_result.exit_code == case.expected_exit && rust_category == case.expected_category;

        // Check: oracle matches expected (if present)
        let oracle_expected_ok = oracle_result.as_ref().map_or(true, |oracle| {
            oracle.exit_code == case.expected_exit
                && normalize_category(&oracle.stderr, oracle.exit_code) == case.expected_category
        });

        // Check: Rust and oracle agree (if oracle present)
        let parity_ok = oracle_result.as_ref().map_or(true, |oracle| {
            oracle.exit_code == rust_result.exit_code
                && normalize_category(&oracle.stderr, oracle.exit_code) == rust_category
        });

        let case_pass = rust_expected_ok && oracle_expected_ok && parity_ok;

        let verdict = if case_pass { "PASS" } else { "FAIL" };

        // Print row
        println!(
            "{:6} | {:40} | {:8} | {:8} | {:8} | {:20} | {:20} | {:20} | {}",
            verdict,
            case.id,
            case.expected_exit,
            rust_result.exit_code,
            oracle_result.as_ref().map_or(-1, |r| r.exit_code),
            case.expected_category,
            rust_category,
            oracle_category.unwrap_or("N/A"),
            case_pass,
        );

        if case_pass {
            passed += 1;
        } else {
            failed += 1;
        }

        results.push(CaseReceipt {
            case_id: case.id.to_string(),
            config_sha256: config_sha,
            expected_exit: case.expected_exit,
            expected_category: case.expected_category.to_string(),
            rust_exit: rust_result.exit_code,
            rust_category: rust_category.to_string(),
            rust_stderr_sha256: sha256_digest(&rust_result.stderr),
            oracle_exit: oracle_result.as_ref().map(|r| r.exit_code),
            oracle_category: oracle_category.map(|s| s.to_string()),
            oracle_stderr_sha256: oracle_result.as_ref().map(|r| sha256_digest(&r.stderr)),
            expected_match: rust_expected_ok && oracle_expected_ok,
            oracle_parity: parity_ok.then_some(true),
            verdict: verdict.to_string(),
        });
    }

    println!("{}", "-".repeat(155));
    println!(
        "Passed: {passed}, Failed: {failed}, Total: {}",
        CORPUS.len()
    );

    // Write evidence receipt
    let receipt = Receipt {
        schema_version: 1,
        timestamp: chrono_now(),
        corpus_revision: sha256_digest(b"corpus-v1"),
        corpus_size: CORPUS.len(),
        rust_binary: BinaryInfo {
            path: rust_ntpd.display().to_string(),
            sha256: rust_sha,
        },
        oracle_binary: oracle_binary_info,
        results,
        summary: Summary {
            passed,
            failed,
            total: CORPUS.len() as u32,
        },
    };

    write_receipt(&receipt)?;

    if failed > 0 {
        anyhow::bail!(
            "{failed} corpus case(s) failed: expected-match and/or oracle-parity violation.",
        );
    }

    eprintln!("\n✓ All {passed} corpus cases match expected behavior.");
    Ok(())
}

/// Simple ISO-8601 timestamp without pulling in a datetime crate.
fn chrono_now() -> String {
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    // Split into date/time components using simple integer math
    let days = secs / 86400;
    let time_secs = secs % 86400;
    let hours = time_secs / 3600;
    let minutes = (time_secs % 3600) / 60;
    let seconds = time_secs % 60;

    // Compute year/month/day from days since epoch (1970-01-01)
    let (y, m, d) = days_to_date(days as i64);

    format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z",
        y, m, d, hours, minutes, seconds
    )
}

fn days_to_date(mut days: i64) -> (i64, i64, i64) {
    // Algorithm from Howard Hinnant
    days += 719468;
    let era = if days >= 0 { days } else { days - 146096 } / 146097;
    let doe = days - era * 146097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    (y, m, d)
}
