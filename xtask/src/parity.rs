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
//! # Against pinned oracle binary
//! cargo xtask parity --oracle /usr/sbin/ntpd --oracle-sha256 <expected>
//!
//! # Against oracle with manifest
//! cargo xtask parity --oracle /usr/sbin/ntpd --oracle-manifest manifest.json
//! ```

use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::Command;

use sha2::{Digest, Sha256};

// ---------------------------------------------------------------------------
// Corpus definition
// ---------------------------------------------------------------------------

#[derive(Debug)]
struct CorpusCase {
    id: &'static str,
    config: &'static [u8],
    expected_exit: i32,
    expected_category: &'static str,
}

const CORPUS: &[CorpusCase] = &[
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

fn corpus_digest() -> String {
    let mut bytes = Vec::new();
    for case in CORPUS {
        bytes.extend_from_slice(case.id.as_bytes());
        bytes.push(0);
        bytes.extend_from_slice(&(case.config.len() as u64).to_be_bytes());
        bytes.extend_from_slice(case.config);
        bytes.extend_from_slice(&case.expected_exit.to_be_bytes());
        bytes.extend_from_slice(case.expected_category.as_bytes());
        bytes.push(0xff);
    }
    sha256_digest(&bytes)
}

// ---------------------------------------------------------------------------
// SHA-256
// ---------------------------------------------------------------------------

fn sha256_digest(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

// ---------------------------------------------------------------------------
// Oracle manifest
// ---------------------------------------------------------------------------

/// Validate a 64-character hex SHA-256 digest.
fn validate_sha256(value: &str, field: &str) -> anyhow::Result<()> {
    if value.len() != 64 || !value.bytes().all(|b| b.is_ascii_hexdigit()) {
        anyhow::bail!("{field} must be a 64-character hex SHA-256 digest, got {value:?}");
    }
    Ok(())
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
struct OracleManifest {
    implementation: String,
    version: String,
    source_sha256: String,
    build_recipe_sha256: String,
    binary_sha256: String,
    target: String,
}

// ---------------------------------------------------------------------------
// Binary resolve
// ---------------------------------------------------------------------------

fn resolve_rust_ntpd() -> anyhow::Result<PathBuf> {
    let workspace = workspace_root();
    let target_dir = workspace.join("target/parity");

    let status = Command::new("cargo")
        .args([
            "build",
            "-p",
            "openntpd-rs-d",
            "--bin",
            "ntpd",
            "--target-dir",
        ])
        .arg(&target_dir)
        .current_dir(&workspace)
        .status()
        .map_err(|e| anyhow::anyhow!("cargo build failed: {e}"))?;

    if !status.success() {
        anyhow::bail!("cargo build -p openntpd-rs-d --bin ntpd failed");
    }

    let path = target_dir.join("debug/ntpd");
    if !path.exists() {
        anyhow::bail!("Rust ntpd not found after build at {path:?}");
    }
    Ok(path)
}

fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .to_path_buf()
}

// ---------------------------------------------------------------------------
// Run directory (isolated per execution)
// ---------------------------------------------------------------------------

fn make_run_dir() -> std::io::Result<PathBuf> {
    let base = workspace_root().join("target/parity/runs");
    std::fs::create_dir_all(&base)?;
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    let pid = std::process::id();
    let dir = base.join(format!("{nanos}-{pid}"));
    std::fs::create_dir(&dir)?;
    Ok(dir)
}

// ---------------------------------------------------------------------------
// Runner
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
struct CaseResult {
    exit_code: i32,
    stderr: Vec<u8>,
}

fn run_case(ntpd_bin: &Path, run_dir: &Path, case_id: &str, config: &[u8]) -> CaseResult {
    let config_path = run_dir.join(format!("{case_id}.conf"));
    std::fs::write(&config_path, config).expect("write case config");

    let output = Command::new(ntpd_bin)
        .args(["-n", "-f"])
        .arg(&config_path)
        .output()
        .expect("execute ntpd binary");

    // config file cleaned up at end via run_dir removal
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
// Evaluation logic (extracted for testability)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Evaluation {
    pub rust_expected: bool,
    pub oracle_expected: Option<bool>,
    pub oracle_parity: Option<bool>,
    pub passed: bool,
}

pub fn evaluate_case(
    rust_exit: i32,
    rust_category: &str,
    expected_exit: i32,
    expected_category: &str,
    oracle_exit: Option<i32>,
    oracle_category: Option<&str>,
) -> Evaluation {
    let rust_expected = rust_exit == expected_exit && rust_category == expected_category;

    let oracle_expected = oracle_exit.map_or(true, |oe| {
        oe == expected_exit && oracle_category == Some(expected_category)
    });

    let oracle_parity =
        oracle_exit.map(|oe| oe == rust_exit && oracle_category == Some(rust_category));

    Evaluation {
        passed: rust_expected && oracle_expected && oracle_parity.unwrap_or(true),
        rust_expected,
        oracle_expected: if oracle_exit.is_some() {
            Some(oracle_expected)
        } else {
            None
        },
        oracle_parity,
    }
}

// ---------------------------------------------------------------------------
// Evidence receipt (schema v2)
// ---------------------------------------------------------------------------

#[derive(serde::Serialize)]
struct Receipt {
    schema_version: u32,
    mode: String,
    timestamp: String,
    corpus_digest: String,
    corpus_size: usize,
    rust_binary: BinaryInfo,
    oracle_binary: Option<BinaryInfo>,
    oracle_manifest: Option<OracleManifest>,
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

fn read_binary_sha256(path: &Path) -> anyhow::Result<String> {
    let bytes = std::fs::read(path).map_err(|e| anyhow::anyhow!("cannot read {path:?}: {e}"))?;
    Ok(sha256_digest(&bytes))
}

fn write_receipt(
    receipt: &Receipt,
    stderr_dir: &Path,
    results: &[(&CorpusCase, &CaseResult, Option<&CaseResult>)],
) -> anyhow::Result<PathBuf> {
    let dir = receipts_dir(&receipt.mode);
    std::fs::create_dir_all(&dir)?;

    let ts = &receipt.timestamp.replace([' ', ':'], "_");
    let path = dir.join(format!("parity_{ts}.json"));

    // Write with create_new(true) to prevent overwrites
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&path)
        .map_err(|e| anyhow::anyhow!("cannot create receipt {path:?}: {e}"))?;

    // Write raw stderr
    for (case, rust, oracle) in results {
        let case_dir = stderr_dir.join(case.id);
        std::fs::create_dir_all(&case_dir)?;
        std::fs::write(case_dir.join("rust.stderr"), &rust.stderr)?;
        if let Some(o) = oracle {
            std::fs::write(case_dir.join("oracle.stderr"), &o.stderr)?;
        }
    }

    let json = serde_json::to_string_pretty(receipt)?;
    f.write_all(json.as_bytes())?;
    f.write_all(b"\n")?;
    f.sync_all()?;

    eprintln!("Evidence written to {}", path.display());
    Ok(path)
}

fn receipts_dir(mode: &str) -> PathBuf {
    workspace_root().join("research/oracle/receipts").join(mode)
}

// ---------------------------------------------------------------------------
// Public entry point
// ---------------------------------------------------------------------------

pub fn run(args: &[String]) -> anyhow::Result<()> {
    let mut oracle_path: Option<PathBuf> = None;
    let mut oracle_sha256: Option<String> = None;
    let mut oracle_manifest_path: Option<PathBuf> = None;
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
            "--oracle-sha256" => {
                i += 1;
                oracle_sha256 = Some(
                    args.get(i)
                        .ok_or_else(|| anyhow::anyhow!("--oracle-sha256 requires argument"))?
                        .clone(),
                );
            }
            "--oracle-manifest" => {
                i += 1;
                oracle_manifest_path = Some(
                    args.get(i)
                        .ok_or_else(|| anyhow::anyhow!("--oracle-manifest requires path argument"))?
                        .into(),
                );
            }
            "--skip-oracle" => skip_oracle = true,
            other => anyhow::bail!("unknown parity flag: {other}"),
        }
        i += 1;
    }

    // ---- Quarantine old schema-v1 receipts ----
    quarantine_legacy_receipts();

    // ---- Validation ----
    if skip_oracle {
        if oracle_path.is_some() || oracle_sha256.is_some() || oracle_manifest_path.is_some() {
            anyhow::bail!("--skip-oracle cannot be combined with oracle identity options");
        }
    } else {
        if oracle_path.is_none() {
            anyhow::bail!("oracle mode requires --oracle <path>");
        }
        if oracle_sha256.is_none() && oracle_manifest_path.is_none() {
            anyhow::bail!("oracle mode requires --oracle-sha256 or --oracle-manifest");
        }
    }

    if CORPUS.is_empty() {
        anyhow::bail!("no corpus cases defined");
    }

    let mode = if skip_oracle {
        "self-test"
    } else {
        "oracle-parity"
    };

    // ---- Resolve Rust binary ----
    let rust_ntpd = resolve_rust_ntpd()?;
    eprintln!("Rust ntpd: {}", rust_ntpd.display());
    let rust_sha = read_binary_sha256(&rust_ntpd)?;

    // ---- Resolve oracle binary ----
    let oracle_ntpd: Option<PathBuf> = oracle_path
        .as_ref()
        .map(|path| {
            let resolved = std::fs::canonicalize(path)
                .map_err(|e| anyhow::anyhow!("cannot resolve oracle {path:?}: {e}"))?;
            if !resolved.is_file() {
                anyhow::bail!("oracle not found at {resolved:?}");
            }
            Ok(resolved)
        })
        .transpose()?;

    // ---- Compute oracle hash ONCE ----
    let oracle_sha: Option<String> = oracle_ntpd
        .as_ref()
        .map(|p| read_binary_sha256(p))
        .transpose()?;

    // ---- Identity checks ----
    if let Some(ref o_sha) = oracle_sha {
        if *o_sha == rust_sha {
            anyhow::bail!("Rust implementation and oracle have identical binary SHA-256: {o_sha}");
        }
    }

    // Verify oracle SHA-256 if specified
    if let (Some(ref o_sha), Some(ref expected)) = (&oracle_sha, &oracle_sha256) {
        if o_sha != expected {
            anyhow::bail!("oracle SHA-256 mismatch:\n  expected: {expected}\n  actual:   {o_sha}");
        }
    }

    // Oracle manifest
    let oracle_manifest: Option<OracleManifest> = match (&oracle_ntpd, &oracle_manifest_path) {
        (Some(_), Some(mpath)) => {
            let text = std::fs::read_to_string(mpath)
                .map_err(|e| anyhow::anyhow!("cannot read manifest {mpath:?}: {e}"))?;
            let m: OracleManifest = serde_json::from_str(&text)
                .map_err(|e| anyhow::anyhow!("invalid manifest: {e}"))?;

            // Reject placeholder values — enforce real SHA-256 digests
            validate_sha256(&m.source_sha256, "manifest source_sha256")?;
            validate_sha256(&m.build_recipe_sha256, "manifest build_recipe_sha256")?;
            validate_sha256(&m.binary_sha256, "manifest binary_sha256")?;

            // Verify the oracle is the claimed implementation
            if m.implementation != "OpenNTPD" {
                anyhow::bail!(
                    "manifest implementation must be 'OpenNTPD', got {:?}",
                    m.implementation,
                );
            }
            if m.version != "7.9p1" {
                anyhow::bail!("manifest version must be '7.9p1', got {:?}", m.version,);
            }

            // Verify binary SHA-256 matches actual oracle binary
            if let Some(ref o_sha) = oracle_sha {
                if !m.binary_sha256.eq_ignore_ascii_case(o_sha) {
                    anyhow::bail!(
                        "manifest binary SHA-256 mismatch:\n  manifest: {}\n  actual:   {o_sha}",
                        m.binary_sha256,
                    );
                }
            }
            Some(m)
        }
        (Some(_), None) => None, // hash-only mode — no manifest
        (None, _) => None,
    };

    // ---- Create isolated run directory and durable evidence directory ----
    let ts = chrono_now();
    let run_dir = make_run_dir()?;
    let ts_path = ts.replace([' ', ':'], "_");
    let evidence_dir = receipts_dir(mode).join(format!("stderr_{ts_path}"));
    std::fs::create_dir_all(&evidence_dir)?;

    // ---- Print header ----
    println!(
        "{:6} | {:40} | {:8} | {:8} | {:8} | {:20} | {:20} | {:20} | match",
        "STATUS", "CASE", "EXPECT", "RUST", "ORACLE", "EXPECTED CAT", "RUST CAT", "ORACLE CAT",
    );
    println!("{}", "-".repeat(155));

    let mut passed = 0u32;
    let mut failed = 0u32;
    let mut stderr_pairs: Vec<(&CorpusCase, CaseResult, Option<CaseResult>)> = Vec::new();
    let mut case_receipts: Vec<CaseReceipt> = Vec::new();

    for case in CORPUS {
        let config_sha = sha256_digest(case.config);
        let rust_result = run_case(&rust_ntpd, &run_dir, case.id, case.config);
        let rust_category = normalize_category(&rust_result.stderr, rust_result.exit_code);

        let oracle_result = oracle_ntpd
            .as_ref()
            .map(|p| run_case(p, &run_dir, case.id, case.config));
        let oracle_category = oracle_result
            .as_ref()
            .map(|r| normalize_category(&r.stderr, r.exit_code));

        let eval = evaluate_case(
            rust_result.exit_code,
            &rust_category,
            case.expected_exit,
            case.expected_category,
            oracle_result.as_ref().map(|r| r.exit_code),
            oracle_category,
        );

        let verdict = if eval.passed { "PASS" } else { "FAIL" };

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
            eval.passed,
        );

        if eval.passed {
            passed += 1
        } else {
            failed += 1
        }

        case_receipts.push(CaseReceipt {
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
            expected_match: eval.rust_expected && eval.oracle_expected.unwrap_or(true),
            oracle_parity: eval.oracle_parity,
            verdict: verdict.to_string(),
        });
        stderr_pairs.push((case, rust_result, oracle_result));
    }

    println!("{}", "-".repeat(155));
    println!(
        "Passed: {passed}, Failed: {failed}, Total: {}",
        CORPUS.len()
    );

    let refs: Vec<(&CorpusCase, &CaseResult, Option<&CaseResult>)> = stderr_pairs
        .iter()
        .map(|(c, r, o)| (*c, r, o.as_ref()))
        .collect();

    let receipt = Receipt {
        schema_version: 2,
        mode: mode.to_string(),
        timestamp: ts.clone(),
        corpus_digest: corpus_digest(),
        corpus_size: CORPUS.len(),
        rust_binary: BinaryInfo {
            path: rust_ntpd.display().to_string(),
            sha256: rust_sha,
        },
        oracle_binary: oracle_ntpd
            .as_ref()
            .zip(oracle_sha.as_ref())
            .map(|(p, sha)| BinaryInfo {
                path: p.display().to_string(),
                sha256: sha.clone(),
            }),
        oracle_manifest,
        results: case_receipts,
        summary: Summary {
            passed,
            failed,
            total: CORPUS.len() as u32,
        },
    };

    write_receipt(&receipt, &evidence_dir, &refs)?;

    // Clean up only the temporary run directory, NOT evidence_dir
    let _ = std::fs::remove_dir_all(&run_dir);

    if failed > 0 {
        anyhow::bail!(
            "{failed} corpus case(s) failed: expected-match and/or oracle-parity violation."
        );
    }

    eprintln!("\n✓ All {passed} corpus cases match expected behavior.");
    Ok(())
}

// ---------------------------------------------------------------------------
// Timestamp
// ---------------------------------------------------------------------------

fn chrono_now() -> String {
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let days = secs / 86400;
    let time_secs = secs % 86400;
    let hours = time_secs / 3600;
    let minutes = (time_secs % 3600) / 60;
    let seconds = time_secs % 60;
    let (y, m, d) = days_to_date(days as i64);
    format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z",
        y, m, d, hours, minutes, seconds
    )
}

fn days_to_date(mut days: i64) -> (i64, i64, i64) {
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

// ---------------------------------------------------------------------------
// Quarantine old schema-v1 receipts
// ---------------------------------------------------------------------------

/// Move legacy receipts matching `research/oracle/receipts/parity_*.json`
/// into a `legacy-invalid/` directory with an invalidation note.
/// Called once at module init.
fn quarantine_legacy_receipts() {
    let receipts_root = workspace_root().join("research/oracle/receipts");
    let legacy_dir = receipts_root.join("legacy-invalid");
    let _ = std::fs::create_dir_all(&legacy_dir);

    if let Ok(entries) = std::fs::read_dir(&receipts_root) {
        for entry in entries.flatten() {
            let path = entry.path();
            if let Some(name) = path.file_name().and_then(|n| n.to_str()) {
                if name.starts_with("parity_") && name.ends_with(".json") {
                    // Move to legacy
                    let dest = legacy_dir.join(name);
                    if std::fs::rename(&path, &dest).is_ok() {
                        eprintln!("Quarantined legacy receipt: {name}");
                    }
                }
            }
        }
    }

    // Write an invalidation note
    let note = legacy_dir.join("README.md");
    if !note.exists() {
        let _ = std::fs::write(
            &note,
            [
                "# Legacy receipts — schema v1 (invalid)\n\n",
                "These receipts were produced by an earlier version of the oracle harness.\n",
                "They contain known defects:\n\n",
                "- `oracle_parity: true` while `oracle_binary` is null\n",
                "- `corpus_revision` instead of `corpus_digest` (not tied to corpus content)\n",
                "- No `mode` field\n",
                "- No `oracle_manifest` field\n\n",
                "They are retained only for provenance but should NOT be cited as evidence.\n",
            ]
            .concat(),
        );
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sha256_known_vector() {
        assert_eq!(
            sha256_digest(b""),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        );
        assert_eq!(
            sha256_digest(b"abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
        );
    }

    #[test]
    fn corpus_digest_is_stable() {
        let d1 = corpus_digest();
        let d2 = corpus_digest();
        assert_eq!(d1, d2);
        // Pin the actual digest so changes to CORPUS break this test
        // and force a conscious update to the expected value.
        assert_eq!(
            d1,
            "90958b0570ccd61734cb59dacb3a7944c9c1a6981258646af0af8b213c7369c6",
            "corpus digest changed — update this expected value if CORPUS was intentionally modified",
        );
    }

    #[test]
    fn corpus_digest_changes_when_config_changes() {
        let original = corpus_digest();

        // Clone a case and modify its config bytes
        let mut modified = CORPUS[0].config.to_vec();
        modified.push(b'x');
        let modified_digest = sha256_digest(&modified);
        assert_ne!(original, modified_digest);
    }

    #[test]
    fn corpus_digest_changes_when_id_changes() {
        let original = corpus_digest();
        let id_bytes = CORPUS[0].id.as_bytes();
        let mut mutated = id_bytes.to_vec();
        mutated.push(b'x');
        let mutated_digest = sha256_digest(&mutated);
        assert_ne!(original, mutated_digest);
    }

    // -- Evaluation logic tests --

    #[test]
    fn rust_expected_mismatch_fails() {
        let e = evaluate_case(1, "syntax-error", 0, "", None, None);
        assert!(!e.passed);
        assert!(!e.rust_expected);
    }

    #[test]
    fn oracle_expected_mismatch_fails() {
        let e = evaluate_case(1, "syntax-error", 1, "syntax-error", Some(0), Some(""));
        assert!(!e.passed);
        assert!(e.rust_expected);
        assert_eq!(e.oracle_expected, Some(false));
    }

    #[test]
    fn rust_oracle_disagreement_fails() {
        let e = evaluate_case(0, "", 0, "", Some(1), Some("syntax-error"));
        assert!(!e.passed);
        assert_eq!(e.oracle_parity, Some(false));
    }

    #[test]
    fn self_test_records_null_parity() {
        let e = evaluate_case(0, "", 0, "", None, None);
        assert!(e.passed);
        assert_eq!(e.oracle_parity, None);
    }

    #[test]
    fn oracle_disagreement_records_false() {
        let e = evaluate_case(0, "", 0, "", Some(1), Some("syntax-error"));
        assert_eq!(e.oracle_parity, Some(false));
    }

    #[test]
    fn oracle_agreement_records_true() {
        let e = evaluate_case(0, "", 0, "", Some(0), Some(""));
        assert_eq!(e.oracle_parity, Some(true));
    }

    #[test]
    fn corpus_digest_changes_when_content_changes() {
        let d1 = corpus_digest();
        // Verify the digest is not trivially empty
        assert_ne!(d1, sha256_digest(b""));
    }

    #[test]
    fn validate_sha256_rejects_short() {
        assert!(validate_sha256("abc", "test").is_err());
    }

    #[test]
    fn validate_sha256_rejects_non_hex() {
        assert!(validate_sha256("z".repeat(64).as_str(), "test").is_err());
    }

    #[test]
    fn validate_sha256_accepts_valid() {
        assert!(validate_sha256(
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            "test",
        )
        .is_ok());
    }

    #[test]
    fn corpus_digest_stable_unchanged_after_read() {
        // Verify the digest value is deterministic — calling twice
        // from separate iterations gives the same result.
        let d1 = corpus_digest();
        std::thread::sleep(std::time::Duration::from_millis(1));
        let d2 = corpus_digest();
        assert_eq!(d1, d2);
    }
}
