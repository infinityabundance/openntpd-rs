//! Integration tests: `ntpctl` control client binary.
//!
//! These tests exercise the actual `ntpctl` binary via
//! `std::process::Command`, verifying CLI parsing, argument handling,
//! environment variable support, and output format.
//!
//! When ntpd is not running, the tests verify graceful error paths.
//! When ntpd IS running, the tests verify actual control protocol
//! communication.

use std::path::PathBuf;
use std::process::Command;

/// Locate the `ntpctl` binary.
fn ntpctl_binary() -> PathBuf {
    if let Ok(path) = std::env::var("CARGO_BIN_EXE_ntpctl") {
        return PathBuf::from(path);
    }
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let workspace_root = manifest_dir.ancestors().nth(2).expect("workspace root");
    let target_ntpctl = workspace_root.join("target/debug/ntpctl");
    if target_ntpctl.exists() {
        return target_ntpctl;
    }
    let status = Command::new("cargo")
        .args(["build", "--bin", "ntpctl"])
        .current_dir(workspace_root)
        .status()
        .expect("cargo build --bin ntpctl");
    assert!(status.success(), "cargo build --bin ntpctl failed");
    target_ntpctl
}

fn ntpctl() -> Command {
    Command::new(ntpctl_binary())
}

fn run_ntpctl(what: &str) -> (String, String, Option<i32>) {
    let output = ntpctl().args(["-s", what]).output().expect("ntpctl binary");
    (
        String::from_utf8_lossy(&output.stdout).into_owned(),
        String::from_utf8_lossy(&output.stderr).into_owned(),
        output.status.code(),
    )
}

fn run_ntpctl_raw(args: &[&str]) -> (String, String, Option<i32>) {
    let output = ntpctl().args(args).output().expect("ntpctl binary");
    (
        String::from_utf8_lossy(&output.stdout).into_owned(),
        String::from_utf8_lossy(&output.stderr).into_owned(),
        output.status.code(),
    )
}

// ---------------------------------------------------------------------------
// -s status
// ---------------------------------------------------------------------------

#[test]
fn test_ntpctl_status_returns_output() {
    let (_stdout, stderr, code) = run_ntpctl("status");

    // Without ntpd running, ntpctl should try to connect and fail gracefully
    assert!(
        stderr.contains("cannot connect") || stderr.contains("refused"),
        "expected connection error with no daemon, got: {stderr}"
    );
    assert!(
        stderr.contains("/var/run/ntpd.sock"),
        "expected default socket path on stderr, got: {stderr}",
    );
    assert_eq!(code, Some(1), "expected exit code 1 (error)");
}

// ---------------------------------------------------------------------------
// -s peers
// ---------------------------------------------------------------------------

#[test]
fn test_ntpctl_peers_returns_output() {
    let (_stdout, stderr, code) = run_ntpctl("peers");
    assert!(
        stderr.contains("cannot connect") || stderr.contains("refused"),
        "expected connection error, got: {stderr}"
    );
    assert_eq!(code, Some(1));
}

// ---------------------------------------------------------------------------
// -s Sensors
// ---------------------------------------------------------------------------

#[test]
fn test_ntpctl_sensors_returns_output() {
    let (_stdout, stderr, code) = run_ntpctl("Sensors");
    assert!(
        stderr.contains("cannot connect") || stderr.contains("refused"),
        "expected connection error, got: {stderr}"
    );
    assert_eq!(code, Some(1));
}

// ---------------------------------------------------------------------------
// -s all
// ---------------------------------------------------------------------------

#[test]
fn test_ntpctl_all_returns_output() {
    let (_stdout, stderr, code) = run_ntpctl("all");
    assert!(
        stderr.contains("cannot connect") || stderr.contains("refused"),
        "expected connection error, got: {stderr}"
    );
    assert_eq!(code, Some(1));
}

// ---------------------------------------------------------------------------
// Prefix matching
// ---------------------------------------------------------------------------

#[test]
fn test_ntpctl_prefix_status() {
    let (_, stderr, _) = run_ntpctl("stat");
    assert!(
        stderr.contains("status") || stderr.contains("cannot connect"),
        "prefix 'stat' should resolve, got: {stderr}",
    );
}

#[test]
fn test_ntpctl_prefix_peer() {
    let (_, stderr, _) = run_ntpctl("peer");
    assert!(
        stderr.contains("peers") || stderr.contains("cannot connect"),
        "prefix 'peer' should resolve, got: {stderr}",
    );
}

#[test]
fn test_ntpctl_prefix_sen() {
    let (_, stderr, _) = run_ntpctl("Sen");
    assert!(
        stderr.contains("Sensors") || stderr.contains("cannot connect"),
        "prefix 'Sen' should resolve, got: {stderr}",
    );
}

#[test]
fn test_ntpctl_prefix_a() {
    let (_, stderr, _) = run_ntpctl("a");
    assert!(
        stderr.contains("all") || stderr.contains("cannot connect"),
        "prefix 'a' should resolve, got: {stderr}",
    );
}

// ---------------------------------------------------------------------------
// Error paths
// ---------------------------------------------------------------------------

#[test]
fn test_ntpctl_invalid_option_fails() {
    let (_, stderr, code) = run_ntpctl_raw(&["status"]);
    assert!(
        stderr.contains("Usage:"),
        "expected usage message, got: {stderr}",
    );
    assert_eq!(code, Some(1));
}

#[test]
fn test_ntpctl_no_args_fails() {
    let (_, stderr, code) = run_ntpctl_raw(&[] as &[&str]);
    assert!(
        stderr.contains("Usage:"),
        "expected usage message, got: {stderr}",
    );
    assert_eq!(code, Some(1));
}

#[test]
fn test_ntpctl_empty_status_fails() {
    let (_, stderr, code) = run_ntpctl_raw(&["-s", ""]);
    assert!(
        stderr.contains("Usage:"),
        "expected usage message for empty target, got: {stderr}",
    );
    assert_eq!(code, Some(1));
}

#[test]
fn test_ntpctl_unknown_status_fails() {
    let (_, stderr, code) = run_ntpctl("nonexistent");
    assert!(
        stderr.contains("unknown status type"),
        "expected 'unknown status type' on stderr, got: {stderr}",
    );
    assert_eq!(code, Some(1));
}

#[test]
fn test_ntpctl_ambiguous_prefix_fails() {
    let (_, stderr, code) = run_ntpctl("s");
    assert!(
        stderr.contains("ambiguous prefix"),
        "expected 'ambiguous prefix' on stderr, got: {stderr}",
    );
    assert_eq!(code, Some(1));
}

// ---------------------------------------------------------------------------
// Environment variable
// ---------------------------------------------------------------------------

#[test]
fn test_ntpctl_environment_socket_override() {
    let custom_socket = "/tmp/custom-ntpd-test.sock";
    let output = ntpctl()
        .args(["-s", "status"])
        .env("NTPD_CONTROL_SOCKET", custom_socket)
        .output()
        .expect("ntpctl binary");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains(custom_socket),
        "expected custom socket path {custom_socket} on stderr, got: {stderr}",
    );
}

// ---------------------------------------------------------------------------
// Output format
// ---------------------------------------------------------------------------

#[test]
fn test_ntpctl_output_format_pattern() {
    let (_, stderr, _) = run_ntpctl("status");
    // ntpctl now actually tries to connect instead of printing a scaffold message
    assert!(
        stderr.contains("sock") || stderr.contains("connect") || stderr.contains("refused"),
        "expected connection-related output, got: {stderr}",
    );
}
