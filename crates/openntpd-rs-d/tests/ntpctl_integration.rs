//! Integration tests: `ntpctl` control client binary.
//!
//! These tests exercise the actual `ntpctl` binary via
//! `std::process::Command`, verifying CLI parsing, argument handling,
//! environment variable support, and output format.
//!
//! The control protocol is not yet wired in the binary, so these tests
//! validate CLI correctness and output format rather than actual
//! daemon communication. Once the control protocol is wired, these
//! tests should be extended to start `ntpd -d` and verify real
//! daemon interaction.

use std::path::PathBuf;
use std::process::Command;

/// Locate the `ntpctl` binary.
///
/// Prefers `CARGO_BIN_EXE_ntpctl` (set by Cargo when the binary is in
/// the same package, or via workspace test). Falls back to building
/// the binary and returning its expected path.
fn ntpctl_binary() -> PathBuf {
    // CARGO_BIN_EXE_ntpctl is set when tests are run across the workspace
    // or when the binary belongs to the same package.
    if let Ok(path) = std::env::var("CARGO_BIN_EXE_ntpctl") {
        return PathBuf::from(path);
    }

    // Fallback: build ntpctl and find it in the target directory.
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    // openntpd-rs/crates/openntpd-rs-d → openntpd-rs
    let workspace_root = manifest_dir
        .ancestors()
        .nth(2)
        .expect("workspace root from manifest dir");

    // Only build if the binary doesn't already exist.
    let target_ntpctl = workspace_root.join("target/debug/ntpctl");
    if target_ntpctl.exists() {
        return target_ntpctl;
    }

    let status = Command::new("cargo")
        .args(["build", "--bin", "ntpctl"])
        .current_dir(workspace_root)
        .status()
        .expect("failed to spawn cargo build --bin ntpctl");
    assert!(
        status.success(),
        "cargo build --bin ntpctl exited with {status:?}",
    );
    target_ntpctl
}

fn ntpctl() -> Command {
    Command::new(ntpctl_binary())
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Runs `ntpctl -s <what>` and returns the captured stdout, stderr, and exit code.
fn run_ntpctl(what: &str) -> (String, String, Option<i32>) {
    let output = ntpctl().args(["-s", what]).output().expect("ntpctl binary");
    (
        String::from_utf8_lossy(&output.stdout).into_owned(),
        String::from_utf8_lossy(&output.stderr).into_owned(),
        output.status.code(),
    )
}

/// Runs `ntpctl` with custom args and returns stderr + exit code.
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
    let (stdout, stderr, code) = run_ntpctl("status");

    assert_eq!(stdout, "", "ntpctl should not print to stdout");
    assert!(
        stderr.contains("would query ntpd"),
        "expected 'would query ntpd' on stderr, got: {stderr}",
    );
    assert!(
        stderr.contains("status"),
        "expected 'status' in output, got: {stderr}",
    );
    assert!(
        stderr.contains("/var/run/ntpd.sock"),
        "expected default socket path on stderr, got: {stderr}",
    );
    // Currently all paths return EXIT_UNIMPLEMENTED (78)
    assert_eq!(code, Some(78), "expected exit code 78 (unimplemented)");
}

// ---------------------------------------------------------------------------
// -s peers
// ---------------------------------------------------------------------------

#[test]
fn test_ntpctl_peers_returns_output() {
    let (stdout, stderr, code) = run_ntpctl("peers");

    assert_eq!(stdout, "", "ntpctl should not print to stdout");
    assert!(
        stderr.contains("would query ntpd"),
        "expected 'would query ntpd' on stderr, got: {stderr}",
    );
    assert!(
        stderr.contains("peers"),
        "expected 'peers' in output, got: {stderr}",
    );
    assert_eq!(code, Some(78), "expected exit code 78 (unimplemented)");
}

// ---------------------------------------------------------------------------
// -s Sensors
// ---------------------------------------------------------------------------

#[test]
fn test_ntpctl_sensors_returns_output() {
    let (stdout, stderr, code) = run_ntpctl("Sensors");

    assert_eq!(stdout, "", "ntpctl should not print to stdout");
    assert!(
        stderr.contains("would query ntpd"),
        "expected 'would query ntpd' on stderr, got: {stderr}",
    );
    assert!(
        stderr.contains("Sensors"),
        "expected 'Sensors' in output, got: {stderr}",
    );
    assert_eq!(code, Some(78), "expected exit code 78 (unimplemented)");
}

// ---------------------------------------------------------------------------
// -s all
// ---------------------------------------------------------------------------

#[test]
fn test_ntpctl_all_returns_output() {
    let (stdout, stderr, code) = run_ntpctl("all");

    assert_eq!(stdout, "", "ntpctl should not print to stdout");
    assert!(
        stderr.contains("would query ntpd"),
        "expected 'would query ntpd' on stderr, got: {stderr}",
    );
    assert!(
        stderr.contains("all"),
        "expected 'all' in output, got: {stderr}",
    );
    assert_eq!(code, Some(78), "expected exit code 78 (unimplemented)");
}

// ---------------------------------------------------------------------------
// Prefix matching — unambiguous prefixes should resolve
// ---------------------------------------------------------------------------

#[test]
fn test_ntpctl_prefix_status() {
    let (_, stderr, code) = run_ntpctl("stat");
    assert!(
        stderr.contains("status"),
        "prefix 'stat' should resolve to 'status', got: {stderr}",
    );
    assert_eq!(code, Some(78));
}

#[test]
fn test_ntpctl_prefix_peer() {
    let (_, stderr, code) = run_ntpctl("peer");
    assert!(
        stderr.contains("peers"),
        "prefix 'peer' should resolve to 'peers', got: {stderr}",
    );
    assert_eq!(code, Some(78));
}

#[test]
fn test_ntpctl_prefix_sen() {
    let (_, stderr, code) = run_ntpctl("Sen");
    assert!(
        stderr.contains("Sensors"),
        "prefix 'Sen' should resolve to 'Sensors', got: {stderr}",
    );
    assert_eq!(code, Some(78));
}

#[test]
fn test_ntpctl_prefix_a() {
    let (_, stderr, code) = run_ntpctl("a");
    assert!(
        stderr.contains("all"),
        "prefix 'a' should resolve to 'all', got: {stderr}",
    );
    assert_eq!(code, Some(78));
}

// ---------------------------------------------------------------------------
// Invalid option tests
// ---------------------------------------------------------------------------

#[test]
fn test_ntpctl_invalid_option_fails() {
    // No `-s` flag at all
    let (_, stderr, code) = run_ntpctl_raw(&["status"]);
    assert!(
        stderr.contains("Usage:"),
        "expected usage message on stderr, got: {stderr}",
    );
    assert_eq!(code, Some(78));
}

#[test]
fn test_ntpctl_no_args_fails() {
    let (_, stderr, code) = run_ntpctl_raw(&[] as &[&str]);
    assert!(
        stderr.contains("Usage:"),
        "expected usage message on stderr, got: {stderr}",
    );
    assert_eq!(code, Some(78));
}

#[test]
fn test_ntpctl_empty_status_fails() {
    let (_, stderr, code) = run_ntpctl_raw(&["-s", ""]);
    assert!(
        stderr.contains("empty status type"),
        "expected 'empty status type' on stderr, got: {stderr}",
    );
    assert_eq!(code, Some(78));
}

#[test]
fn test_ntpctl_unknown_status_fails() {
    let (_, stderr, code) = run_ntpctl("nonexistent");
    assert!(
        stderr.contains("unknown status type"),
        "expected 'unknown status type' on stderr, got: {stderr}",
    );
    assert_eq!(code, Some(78));
}

#[test]
fn test_ntpctl_ambiguous_prefix_fails() {
    // 's' matches both "status" and "Sensors"
    let (_, stderr, code) = run_ntpctl("s");
    assert!(
        stderr.contains("ambiguous prefix"),
        "expected 'ambiguous prefix' on stderr, got: {stderr}",
    );
    assert_eq!(code, Some(78));
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
// Output format — the message should follow expected pattern
// ---------------------------------------------------------------------------

#[test]
fn test_ntpctl_output_format_pattern() {
    let (_, stderr, _) = run_ntpctl("status");
    // Pattern: "<prog>: would query ntpd at <socket> for '<target>' (control protocol not yet wired)"
    assert!(
        stderr.contains("would query ntpd at"),
        "expected formatted message, got: {stderr}",
    );
    assert!(
        stderr.contains("control protocol not yet wired"),
        "expected 'not yet wired' note, got: {stderr}",
    );
}
