//! Binary-level integration tests for `ntpd`.
//!
//! These tests exercise the actual `ntpd` binary via
//! `std::process::Command`, verifying exit codes and stderr output
//! against the real OpenNTPD 7.9p1 oracle behavior.

use std::io::Write;
use std::process::Command;

/// Path to the compiled `ntpd` binary (provided by Cargo's `CARGO_BIN_EXE_`).
const NTPD: &str = env!("CARGO_BIN_EXE_ntpd");

fn ntpd() -> Command {
    Command::new(NTPD)
}

/// Create a temporary file with the given content, return its path.
fn temp_config(content: &[u8]) -> std::path::PathBuf {
    let dir = std::env::temp_dir();
    let mut path = dir.join("ntpd_test_config");
    // Append a random suffix to avoid collisions
    use std::time::{SystemTime, UNIX_EPOCH};
    let ts = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    path.set_file_name(format!("ntpd_test_{ts}"));
    let mut f = std::fs::File::create(&path).expect("create temp config");
    f.write_all(content).expect("write temp config");
    path
}

fn clean_up(path: &std::path::Path) {
    let _ = std::fs::remove_file(path);
}

// -- Valid config tests --

#[test]
fn binary_valid_config_exit_0() {
    let path = temp_config(b"listen on *\nserver pool.ntp.org\n");
    let output = ntpd()
        .args(["-n", "-f"])
        .arg(&path)
        .output()
        .expect("ntpd binary");
    clean_up(&path);

    assert!(output.status.success());
}

#[test]
fn binary_valid_config_prints_configuration_ok() {
    let path = temp_config(b"listen on *\n");
    let output = ntpd()
        .args(["-n", "-f"])
        .arg(&path)
        .output()
        .expect("ntpd binary");
    clean_up(&path);

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("configuration OK"),
        "expected 'configuration OK' on stderr, got: {stderr}",
    );
}

// -- Invalid config tests --

#[test]
fn binary_invalid_config_exit_1() {
    let path = temp_config(b"listen on *\nserver pool.ntp.org weight 100\n");
    let output = ntpd()
        .args(["-n", "-f"])
        .arg(&path)
        .output()
        .expect("ntpd binary");
    clean_up(&path);

    assert_eq!(
        output.status.code(),
        Some(1),
        "invalid config should exit 1, got status: {:?}",
        output.status.code(),
    );
}

#[test]
fn binary_invalid_config_prints_error() {
    let path = temp_config(b"listen on *\nserver pool.ntp.org weight 100\n");
    let output = ntpd()
        .args(["-n", "-f"])
        .arg(&path)
        .output()
        .expect("ntpd binary");
    clean_up(&path);

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("weight"),
        "expected error mentioning 'weight' on stderr, got: {stderr}",
    );
}

// -- Unreadable file --

#[test]
fn binary_unreadable_file_exit_1() {
    let path = std::path::PathBuf::from("/nonexistent/ntpd.conf");
    let output = ntpd()
        .args(["-n", "-f"])
        .arg(&path)
        .output()
        .expect("ntpd binary");

    assert_eq!(
        output.status.code(),
        Some(1),
        "unreadable file should exit 1, got status: {:?}",
        output.status.code(),
    );
}

// -- -f option selects config --

#[test]
fn binary_f_option_selects_config() {
    let path = temp_config(b"server pool.ntp.org\n");
    let output = ntpd()
        .args(["-n", "-f"])
        .arg(&path)
        .output()
        .expect("ntpd binary");
    clean_up(&path);

    assert!(output.status.success());
}

// -- Grouped flags --

#[test]
fn binary_grouped_dn() {
    let path = temp_config(b"listen on *\n");
    let output = ntpd()
        .args(["-dn", "-f"])
        .arg(&path)
        .output()
        .expect("ntpd binary");
    clean_up(&path);

    assert!(output.status.success());
}
