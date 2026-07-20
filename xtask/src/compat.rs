//! # Multi-version cross-compatibility test suite
//!
//! Builds Docker images for multiple OpenNTPD versions (compiled from
//! source) across 3 base OSes, then tests the Rust `ntpd` and `ntpctl`
//! binaries as drop-in replacements in each combination.
//!
//! ## Test matrix
//!
//! 3 OpenNTPD versions × 3 base OSes = 9 Docker images.
//!
//! For each image, 4 test combinations:
//!
//! | Combo | Daemon | Client  | Purpose          |
//! |-------|--------|---------|------------------|
//! | 1     | REAL   | REAL    | Baseline control  |
//! | 2     | REAL   | RUST    | Client compat     |
//! | 3     | RUST   | REAL    | Daemon compat     |
//! | 4     | RUST   | RUST    | Full Rust self    |
//!
//! ## Control protocol
//!
//! `ntpctl` connects to the daemon's Unix domain socket at
//! `/var/run/ntpd.sock`, sends a request byte, and reads back a
//! formatted text response. This test verifies both the wire protocol
//! compatibility and the output format compatibility.
//!
//! ## Usage
//!
//! ```text
//! cargo xtask compat [--skip-build] [--image <name>]
//! ```

use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Duration, Instant};

// ---------------------------------------------------------------------------
// OpenNTPD versions and their SHA-256 checksums
// ---------------------------------------------------------------------------

/// Available OpenNTPD versions with their SHA-256 hashes.
///
/// Each entry contains (version, sha256, extra_cflags, extra_cppflags).
/// Older versions (< 6.8) require `-fcommon` to build with modern GCC.
const VERSIONS: &[(&str, &str, &str, &str)] = &[
    (
        "6.0p1",
        "b1ab80094788912adb12b33cb1f251cc58db39294c1b5c6376972f5f7ba577e8",
        "-fcommon",
        "-fcommon",
    ),
    (
        "6.2p3",
        "7b02691524197e01ba6b1b4b7595b33956e657ba6d5c4cf2fc20ea3f4914c13a",
        "-fcommon",
        "-fcommon",
    ),
    (
        "6.8p1",
        "8582db838a399153d4a17f2a76518b638cc3020f58028575bf54127518f55a46",
        "",
        "",
    ),
    (
        "7.9p1",
        "091eeb3f4e358e28c3ab2ea58f93d7a0b5758a20d7c8a0418e162e9b2c27addc",
        "",
        "",
    ),
];

/// Base OS images to build against.
const BASE_OSES: &[(&str, &str)] = &[
    ("debian", "debian:bookworm-slim"),
    ("alpine", "alpine:3.20"),
    ("ubuntu", "ubuntu:24.04"),
];

/// Build a Docker image tag from version and base.
fn image_tag(version: &str, base_name: &str) -> String {
    format!("openntpd-compat:{version}-{base_name}")
}

// ---------------------------------------------------------------------------
// Test result types
// ---------------------------------------------------------------------------

/// Status of a single test combination.
#[derive(Debug, Clone, PartialEq)]
enum TestStatus {
    Pass,
    Fail(String),
}

/// Result for a single test combination (daemon × client).
#[derive(Debug, Clone)]
#[allow(dead_code)]
struct ComboResult {
    label: &'static str, // e.g. "REAL→REAL"
    daemon: &'static str,
    client: &'static str,
    status: TestStatus,
    stdout: String,
    stderr: String,
    exit_code: Option<i32>,
    duration: Duration,
}

/// Result for a single version×base Docker image.
#[derive(Debug, Clone)]
#[allow(dead_code)]
struct ImageResult {
    version: String,
    base_name: String,
    base_image: String,
    tag: String,
    build_ok: bool,
    combos: Vec<ComboResult>,
    error: Option<String>,
}

// ---------------------------------------------------------------------------
// Path helpers
// ---------------------------------------------------------------------------

/// Locate the workspace root.
fn workspace_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("xtask manifest parent (workspace root)")
        .to_path_buf()
}

/// Path to the multi-version Dockerfile.
fn dockerfile_dir() -> PathBuf {
    workspace_root().join("research/openntpd-versions")
}

fn dockerfile_path() -> PathBuf {
    dockerfile_dir().join("Dockerfile")
}

// ---------------------------------------------------------------------------
// Docker helpers
// ---------------------------------------------------------------------------

/// Check that Docker is available.
fn check_docker_available() -> anyhow::Result<()> {
    let output = Command::new("docker")
        .args(["info", "--format", "{{.ServerVersion}}"])
        .output()
        .map_err(|e| anyhow::anyhow!("Docker not available: {e}"))?;
    if !output.status.success() {
        anyhow::bail!("Docker is not available (docker info failed)");
    }
    eprintln!(
        "  Docker version: {}",
        String::from_utf8_lossy(&output.stdout).trim()
    );
    Ok(())
}

/// Check if a Docker image already exists.
fn docker_image_exists(tag: &str) -> bool {
    Command::new("docker")
        .args(["image", "inspect", "--format", "{{.Id}}", tag])
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

/// Build a single version×base Docker image.
fn build_image(
    version: &str,
    sha256: &str,
    extra_cflags: &str,
    extra_cppflags: &str,
    base_name: &str,
    base_image: &str,
) -> anyhow::Result<()> {
    let tag = image_tag(version, base_name);

    if docker_image_exists(&tag) {
        eprintln!("  ✓ {tag} (already exists)");
        return Ok(());
    }

    let df_path = dockerfile_path();
    if !df_path.exists() {
        anyhow::bail!("Dockerfile not found: {}", df_path.display());
    }

    eprint!("  Building {tag}... ");

    // Build arg list with owned strings to avoid temporary lifetime issues.
    let df_path_str = df_path.to_string_lossy().to_string();
    let ver_arg = format!("VERSION={version}");
    let sha_arg = format!("SHA256={sha256}");
    let base_arg = format!("BASE={base_image}");
    let cflags_arg = if !extra_cflags.is_empty() {
        Some(format!("EXTRA_CFLAGS={extra_cflags}"))
    } else {
        None
    };
    let cppflags_arg = if !extra_cppflags.is_empty() {
        Some(format!("EXTRA_CPPFLAGS={extra_cppflags}"))
    } else {
        None
    };
    let docker_dir_str = dockerfile_dir().to_string_lossy().to_string();

    let mut cmd = std::process::Command::new("docker");
    cmd.arg("build")
        .arg("-t")
        .arg(&tag)
        .arg("-f")
        .arg(&df_path_str)
        .arg("--build-arg")
        .arg(&ver_arg)
        .arg("--build-arg")
        .arg(&sha_arg)
        .arg("--build-arg")
        .arg(&base_arg);
    if let Some(ref c) = cflags_arg {
        cmd.arg("--build-arg").arg(c);
    }
    if let Some(ref c) = cppflags_arg {
        cmd.arg("--build-arg").arg(c);
    }
    cmd.arg(&docker_dir_str);

    let status = cmd
        .status()
        .map_err(|e| anyhow::anyhow!("failed to spawn docker build: {e}"))?;

    if !status.success() {
        anyhow::bail!("docker build for {tag} exited with {status:?}");
    }
    eprintln!("✓");
    Ok(())
}

/// Start a container from a Docker image, returning the container ID.
/// Start a container with capabilities for running ntpd.
fn start_container(tag: &str, name: &str) -> anyhow::Result<String> {
    let output = Command::new("docker")
        .args([
            "run",
            "--rm",
            "-d",
            "--name",
            name,
            "--cap-add",
            "SYS_TIME",
            "--cap-add",
            "SYS_NICE",
            "--security-opt",
            "seccomp=unconfined",
            "--entrypoint",
            "sleep",
            tag,
            "90", // sleep for 90 seconds
        ])
        .output()
        .map_err(|e| anyhow::anyhow!("failed to spawn docker run: {e}"))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        anyhow::bail!("docker run failed: {stderr}");
    }

    let container_id = String::from_utf8_lossy(&output.stdout).trim().to_string();
    // Wait briefly for container readiness
    std::thread::sleep(Duration::from_millis(500));
    Ok(container_id)
}

/// Prepare a container for running ntpd tests.
/// Creates the _ntp user, required directories, /etc/services, and config.
fn prepare_container(name: &str, config_content: &[u8]) -> anyhow::Result<()> {
    // Create required directories first (including privsep chroot)
    let mkdirs = "mkdir -p /var/run /var/db /var/empty \
        /usr/local/var/run /usr/local/var/db"
        .to_string();
    let _ = docker_exec(name, &["sh", "-c", &mkdirs]);

    // Set privsep dir permissions (must be root:root, mode 0555)
    let fix_privsep = "chmod 555 /var/empty 2>/dev/null; \
        chown root:root /var/empty 2>/dev/null || true"
        .to_string();
    let _ = docker_exec(name, &["sh", "-c", &fix_privsep]);

    // Create _ntp user with /var/empty as its home (privsep chroot)
    // Debian: adduser --system --no-create-home _ntp
    // Ubuntu: useradd -r -d /var/empty _ntp
    // Alpine: adduser -S -D -h /var/empty _ntp
    let create_user = "sh -c '\
        command -v adduser >/dev/null 2>&1 && \
            adduser --system --no-create-home _ntp 2>/dev/null; \
        command -v useradd >/dev/null 2>&1 && \
            useradd -r -d /var/empty _ntp 2>/dev/null; \
        id _ntp >/dev/null 2>&1'"
        .to_string();
    let (_stdout, stderr, code) = docker_exec(name, &["sh", "-c", &create_user]);
    if code != Some(0) {
        // Try Alpine-style adduser
        let alpine_user = "adduser -S -D -h /var/empty _ntp 2>/dev/null".to_string();
        let (_, _, code2) = docker_exec(name, &["sh", "-c", &alpine_user]);
        if code2 != Some(0) {
            anyhow::bail!("failed to create _ntp user: {stderr}");
        }
    }

    // Add ntp service to /etc/services
    let add_services = "echo 'ntp 123/udp' >> /etc/services".to_string();
    let _ = docker_exec(name, &["sh", "-c", &add_services]);

    // Create /nonexistent (used as privsep dir by some Debian bookworm builds)
    // and /home/_ntp (used by Alpine/Ubuntu default adduser)
    let extra_dirs = "mkdir -p /nonexistent /home/_ntp && \
        chmod 555 /nonexistent /home/_ntp && \
        chown root:root /nonexistent /home/_ntp 2>/dev/null || true"
        .to_string();
    let _ = docker_exec(name, &["sh", "-c", &extra_dirs]);

    // Write config file
    let config_str = String::from_utf8_lossy(config_content);
    let cfg_cmd = format!("cat > /etc/ntpd.conf << 'EOFNT'\n{}\nEOFNT\n", config_str);
    let (_, stderr, code) = docker_exec(name, &["sh", "-c", &cfg_cmd]);
    if code != Some(0) {
        anyhow::bail!("config write failed: {stderr}");
    }

    Ok(())
}

/// Copy a binary into a running container.
fn docker_cp(container: &str, src: &Path, dest: &str) -> anyhow::Result<()> {
    let output = Command::new("docker")
        .args(["cp", &src.to_string_lossy(), &format!("{container}:{dest}")])
        .output()
        .map_err(|e| anyhow::anyhow!("docker cp spawn failed: {e}"))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        anyhow::bail!("docker cp failed: {stderr}");
    }
    Ok(())
}

/// Run a command inside a container.
fn docker_exec(container: &str, cmd: &[&str]) -> (String, String, Option<i32>) {
    let mut args = vec!["exec", container];
    args.extend_from_slice(cmd);

    let output = match Command::new("docker").args(&args).output() {
        Ok(o) => o,
        Err(e) => {
            return (
                String::new(),
                format!("failed to spawn docker exec: {e}"),
                None,
            );
        }
    };

    (
        String::from_utf8_lossy(&output.stdout).into_owned(),
        String::from_utf8_lossy(&output.stderr).into_owned(),
        output.status.code(),
    )
}

/// Stop and remove a container.
fn cleanup_container(name: &str) {
    let _ = Command::new("docker").args(["stop", name]).output();
    std::thread::sleep(Duration::from_millis(300));
    let _ = Command::new("docker").args(["rm", "-f", name]).output();
}

// ---------------------------------------------------------------------------
// Config generation
// ---------------------------------------------------------------------------

/// Create a minimal ntpd.conf with a loopback server.
fn make_ntpd_config() -> &'static [u8] {
    b"listen on *\nserver 127.0.0.1\n"
}

// ---------------------------------------------------------------------------
// Binary builders
// ---------------------------------------------------------------------------

/// Build the Rust ntpd binary and return its path.
fn build_rust_ntpd() -> anyhow::Result<PathBuf> {
    let ws = workspace_root();
    let target = ws.join("target/debug/ntpd");
    if target.exists() {
        return Ok(target);
    }

    eprintln!("  Building Rust ntpd...");
    let status = Command::new("cargo")
        .args(["build", "--bin", "ntpd"])
        .current_dir(&ws)
        .status()
        .map_err(|e| anyhow::anyhow!("failed to spawn cargo build: {e}"))?;

    if !status.success() {
        anyhow::bail!("cargo build --bin ntpd failed");
    }
    Ok(target)
}

/// Build the Rust ntpctl binary and return its path.
fn build_rust_ntpctl() -> anyhow::Result<PathBuf> {
    let ws = workspace_root();
    let target = ws.join("target/debug/ntpctl");
    if target.exists() {
        return Ok(target);
    }

    eprintln!("  Building Rust ntpctl...");
    let status = Command::new("cargo")
        .args(["build", "--bin", "ntpctl"])
        .current_dir(&ws)
        .status()
        .map_err(|e| anyhow::anyhow!("failed to spawn cargo build: {e}"))?;

    if !status.success() {
        anyhow::bail!("cargo build --bin ntpctl failed");
    }
    Ok(target)
}

// ---------------------------------------------------------------------------
// Test runner
// ---------------------------------------------------------------------------

/// Test one combination within a Docker container.
///
/// `daemon_binary` is the path to the ntpd binary inside the container.
/// `ctl_binary` is the path to the ntpctl binary inside the container.
fn run_combo(
    container: &str,
    label: &'static str,
    daemon: &'static str,
    client: &'static str,
    daemon_binary: &str,
    ctl_binary: &str,
    _daemon_socket: &str, // socket path the daemon creates
    ctl_socket: &str,     // socket path the client looks for
) -> ComboResult {
    let start = Instant::now();

    // Start the daemon in the background
    let daemon_cmd = format!("{daemon_binary} -d -f /etc/ntpd.conf > /tmp/ntpd.log 2>&1 &");
    let (_daemon_out, _daemon_err, _daemon_code) =
        docker_exec(container, &["sh", "-c", &daemon_cmd]);

    // Give the daemon time to create the control socket
    std::thread::sleep(Duration::from_millis(2000));

    // Check if the daemon started and what log it produced
    let (log_out, _, _) = docker_exec(
        container,
        &[
            "sh",
            "-c",
            "cat /tmp/ntpd.log 2>/dev/null || echo '(no log)'",
        ],
    );
    let (sock_find, _, _) = docker_exec(
        container,
        &[
            "sh",
            "-c",
            "find / -type s -name '*.sock' 2>/dev/null || echo '(no socket)'",
        ],
    );

    // Run ntpctl queries: status, peers, Sensors, all
    let mut all_stdout = String::new();
    let mut all_stderr = String::new();
    let mut last_exit = None;
    let mut is_expected_unimpl = false;
    let mut is_expected_rust = false;

    for query in &["status", "peers", "Sensors", "all"] {
        // For real ntpctl, stdout has the output; for Rust ntpctl, stderr has "would query"
        // Set NTPD_CONTROL_SOCKET so the client talks to the right daemon
        let (stdout, stderr, exit) = docker_exec(
            container,
            &[
                "sh",
                "-c",
                &format!(
                    "NTPD_CONTROL_SOCKET={socket} {ctl_binary} -s {query}",
                    socket = ctl_socket
                ),
            ],
        );

        let hdr = format!("=== -s {query} ===");
        if !stdout.is_empty() {
            all_stdout.push_str(&format!("{hdr}\n{stdout}\n"));
        }
        if !stderr.is_empty() {
            all_stderr.push_str(&format!("{hdr}\n{stderr}\n"));
        }
        last_exit = exit;

        // Rust ntpctl exits 78 with "would query ntpd" — that's EXPECTED
        if exit == Some(78) && stderr.contains("would query ntpd") {
            is_expected_rust = true;
        }
        // Real ntpctl may exit 0 even if connection refused — output goes to stdout
        if exit == Some(0) && !stdout.is_empty() {
            is_expected_unimpl = true;
        }
    }

    // Kill the daemon
    let _ = docker_exec(container, &["pkill", "-9", "ntpd"]);

    // Collect diagnostic info
    let mut details = String::new();
    if !log_out.is_empty() && log_out != "(no log)" {
        // Show first few lines of daemon log
        for line in log_out.lines().take(3) {
            details.push_str(&format!("[daemon: {line}] "));
        }
    }
    if !sock_find.is_empty() && sock_find != "(no socket)" && !sock_find.contains("find:") {
        details.push_str(&format!("[socket: {}]", sock_find.trim()));
    }

    // Determine status
    let status = if is_expected_rust || is_expected_unimpl {
        TestStatus::Pass
    } else if last_exit == Some(127) {
        TestStatus::Fail(format!(
            "command not found (exit 127) — binary path mismatch {details}"
        ))
    } else if let Some(code) = last_exit {
        // Some other exit code — we have output, record what happened
        let mut msg = format!("exit code {code}");
        if !details.is_empty() {
            msg.push_str(&format!(" ({details})"));
        }
        TestStatus::Fail(msg)
    } else {
        TestStatus::Fail("no output at all from ntpctl".to_string())
    };

    ComboResult {
        label,
        daemon,
        client,
        status,
        stdout: all_stdout,
        stderr: all_stderr,
        exit_code: last_exit,
        duration: start.elapsed(),
    }
}

/// Run all 4 test combinations for a single Docker image.
fn test_image_combinations(
    container: &str,
    version: &str,
    base_name: &str,
    rust_ntpd_path: &Path,
    rust_ntpctl_path: &Path,
) -> ImageResult {
    let mut result = ImageResult {
        version: version.to_string(),
        base_name: base_name.to_string(),
        base_image: format!("{base_name}:{version}"),
        tag: image_tag(version, base_name),
        build_ok: true,
        combos: Vec::new(),
        error: None,
    };

    // Real binaries are installed in /usr/local/sbin/ (both ntpd and ntpctl
    // are hardlinked together in newer OpenNTPD builds)
    let real_ntpd = "/usr/local/sbin/ntpd";
    let real_ntpctl = "/usr/local/sbin/ntpctl";

    // Copy Rust binaries into the container
    let rust_ntpd_dest = "/usr/local/sbin/ntpd-rust";
    let rust_ntpctl_dest = "/usr/local/sbin/ntpctl-rust";

    if let Err(e) = docker_cp(container, rust_ntpd_path, rust_ntpd_dest) {
        result.build_ok = false;
        result.error = Some(format!("copy Rust ntpd: {e}"));
        return result;
    }
    if let Err(e) = docker_cp(container, rust_ntpctl_path, rust_ntpctl_dest) {
        result.build_ok = false;
        result.error = Some(format!("copy Rust ntpctl: {e}"));
        return result;
    }

    // Make all binaries executable
    docker_exec(container, &["chmod", "+x", rust_ntpd_dest]);
    docker_exec(container, &["chmod", "+x", rust_ntpctl_dest]);
    docker_exec(container, &["chmod", "+x", real_ntpd]);
    docker_exec(container, &["chmod", "+x", real_ntpctl]);

    // Create symlinks so both binaries are in PATH
    docker_exec(container, &["sh", "-c", "ln -sf /usr/local/sbin/ntpd /usr/local/bin/ntpd 2>/dev/null; ln -sf /usr/local/sbin/ntpctl /usr/local/bin/ntpctl 2>/dev/null"]);

    // Socket paths:
    // REAL ntpd creates socket at /usr/local/var/run/ntpd.sock (--localstatedir)
    // RUST ntpd creates socket at /var/run/ntpd.sock (hardcoded in lib.rs)
    let real_socket = "/usr/local/var/run/ntpd.sock";
    let rust_socket = "/var/run/ntpd.sock";

    // --- Combo 1: REAL ntpd → REAL ntpctl (baseline) ---
    eprint!("    REAL→REAL... ");
    let combo1 = run_combo(
        container,
        "REAL→REAL",
        "REAL",
        "REAL",
        real_ntpd,
        real_ntpctl,
        real_socket,
        real_socket,
    );
    result.combos.push(combo1.clone());
    eprintln!(
        "{}",
        if combo1.status == TestStatus::Pass {
            "✓"
        } else {
            "✗"
        }
    );

    // --- Combo 2: REAL ntpd → RUST ntpctl ---
    eprint!("    REAL→RUST... ");
    let combo2 = run_combo(
        container,
        "REAL→RUST",
        "REAL",
        "RUST",
        real_ntpd,
        rust_ntpctl_dest,
        real_socket,
        real_socket,
    );
    result.combos.push(combo2.clone());
    eprintln!(
        "{}",
        if combo2.status == TestStatus::Pass {
            "✓"
        } else {
            "✗"
        }
    );

    // --- Combo 3: RUST ntpd → REAL ntpctl ---
    eprint!("    RUST→REAL... ");
    let combo3 = run_combo(
        container,
        "RUST→REAL",
        "RUST",
        "REAL",
        rust_ntpd_dest,
        real_ntpctl,
        rust_socket,
        rust_socket,
    );
    result.combos.push(combo3.clone());
    eprintln!(
        "{}",
        if combo3.status == TestStatus::Pass {
            "✓"
        } else {
            "✗"
        }
    );

    // --- Combo 4: RUST ntpd → RUST ntpctl ---
    eprint!("    RUST→RUST... ");
    let combo4 = run_combo(
        container,
        "RUST→RUST",
        "RUST",
        "RUST",
        rust_ntpd_dest,
        rust_ntpctl_dest,
        rust_socket,
        rust_socket,
    );
    result.combos.push(combo4.clone());
    eprintln!(
        "{}",
        if combo4.status == TestStatus::Pass {
            "✓"
        } else {
            "✗"
        }
    );

    result
}

// ---------------------------------------------------------------------------
// Summary report
// ---------------------------------------------------------------------------

/// Print a formatted summary of all test results.
fn print_summary(results: &[ImageResult], start: Instant) {
    println!();
    println!("╔════════════════════════════════════════════════════════════════╗");
    println!("║           OpenNTPD-rs Cross-Compatibility Test Suite          ║");
    println!("╚════════════════════════════════════════════════════════════════╝");
    println!();

    // Column headers
    println!(
        "{:<24} {:<10} {:<12} {:<12} {:<12} {:<12} {:<10}",
        "Image", "Build", "REAL→REAL", "REAL→RUST", "RUST→REAL", "RUST→RUST", "Duration"
    );
    println!(
        "{:-<24} {:-<10} {:-<12} {:-<12} {:-<12} {:-<12} {:-<10}",
        "", "", "", "", "", "", ""
    );

    let mut total_passed = 0u32;
    let mut total_failed = 0u32;
    let total_skipped: u32 = 0;

    for img in results {
        let build_str = if img.build_ok { "✓" } else { "✗" };

        let mut combo_strs = Vec::new();
        for combo in &img.combos {
            match combo.status {
                TestStatus::Pass => {
                    combo_strs.push("✓".to_string());
                    total_passed += 1;
                }
                TestStatus::Fail(_) => {
                    combo_strs.push("✗".to_string());
                    total_failed += 1;
                }
            }
        }

        // Pad to 4 combos
        while combo_strs.len() < 4 {
            combo_strs.push("—".to_string());
        }

        let total_dur: Duration = img.combos.iter().map(|c| c.duration).sum();
        let dur_str = format!(
            "{}.{:02}s",
            total_dur.as_secs(),
            total_dur.subsec_millis() / 10
        );

        let label = format!("{}-{}", img.version, img.base_name);
        println!(
            "{:<24} {:<10} {:<12} {:<12} {:<12} {:<12} {:<10}",
            label, build_str, combo_strs[0], combo_strs[1], combo_strs[2], combo_strs[3], dur_str
        );
    }

    println!();
    println!(
        "Total: {} combos | {} passed | {} failed | {} skipped",
        total_passed + total_failed + total_skipped,
        total_passed,
        total_failed,
        total_skipped,
    );
    println!(
        "Elapsed: {}.{:02}s",
        start.elapsed().as_secs(),
        start.elapsed().subsec_millis() / 10
    );

    // Print detailed failures
    let mut has_failure_output = false;
    for img in results {
        for combo in &img.combos {
            if let TestStatus::Fail(msg) = &combo.status {
                if !has_failure_output {
                    println!();
                    println!("=== Failure Details ===");
                    has_failure_output = true;
                }
                println!("  {}-{} {}: {msg}", img.version, img.base_name, combo.label);
                if !combo.stdout.is_empty() {
                    println!("    stdout: {}", combo.stdout.lines().next().unwrap_or(""));
                }
                if !combo.stderr.is_empty() {
                    println!("    stderr: {}", combo.stderr.lines().next().unwrap_or(""));
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Public entry point
// ---------------------------------------------------------------------------

/// Run the full cross-compatibility test suite.
///
/// Arguments:
/// - `--skip-build` — skip Docker image builds, use existing images
/// - `--image <name>` — run only images matching this substring
pub fn run(args: &[String]) -> anyhow::Result<()> {
    let skip_build = args.iter().any(|a| a == "--skip-build");
    let filter = args
        .iter()
        .position(|a| a == "--image")
        .and_then(|i| args.get(i + 1));

    let start = Instant::now();

    eprintln!("╔═══════════════════════════════════════════════╗");
    eprintln!("║  OpenNTPD-rs Cross-Compatibility Test Suite  ║");
    eprintln!("╚═══════════════════════════════════════════════╝");
    eprintln!();

    check_docker_available()?;

    // ---- Step 1: Verify Dockerfile exists ----
    if !dockerfile_path().exists() {
        anyhow::bail!("Dockerfile not found at: {}", dockerfile_path().display());
    }

    // ---- Step 2: Build Rust binaries ----
    eprintln!("── Step 1: Build Rust binaries ──");
    let rust_ntpd = build_rust_ntpd()?;
    let rust_ntpctl = build_rust_ntpctl()?;
    eprintln!("  ntpd:   {}", rust_ntpd.display());
    eprintln!("  ntpctl: {}", rust_ntpctl.display());
    eprintln!();

    // ---- Step 3: Build Docker images ----
    if skip_build {
        eprintln!("── Step 2: Build Docker Images (SKIPPED) ──");
    } else {
        eprintln!("── Step 2: Build Docker Images ──");
        for (version, sha256, extra_cflags, extra_cppflags) in VERSIONS {
            for (base_name, base_image) in BASE_OSES {
                // Apply image filter if specified
                if let Some(f) = filter {
                    let tag = image_tag(version, base_name);
                    if !tag.contains(f) {
                        continue;
                    }
                }

                match build_image(
                    version,
                    sha256,
                    extra_cflags,
                    extra_cppflags,
                    base_name,
                    base_image,
                ) {
                    Ok(()) => {}
                    Err(e) => {
                        eprintln!("  ✗ {version}-{base_name}: {e}");
                    }
                }
            }
        }
        eprintln!();
    }

    // ---- Step 4: Run cross-compatibility tests ----
    eprintln!("── Step 3: Cross-Compatibility Tests ──");

    let mut results: Vec<ImageResult> = Vec::new();

    for (version, _sha256, _extra_cflags, _extra_cppflags) in VERSIONS {
        for (base_name, _base_image) in BASE_OSES {
            let tag = image_tag(version, base_name);

            // Apply image filter if specified
            if let Some(f) = filter {
                if !tag.contains(f) {
                    continue;
                }
            }

            if !docker_image_exists(&tag) {
                eprintln!("  ⚠ {tag}: image not found, skipping");
                continue;
            }

            let safe_name = format!("compat-{version}-{base_name}-{}", std::process::id());
            eprintln!("  Testing {tag}...");

            // Start container
            let _container = match start_container(&tag, &safe_name) {
                Ok(id) => id,
                Err(e) => {
                    eprintln!("    ✗ failed to start container: {e}");
                    results.push(ImageResult {
                        version: version.to_string(),
                        base_name: base_name.to_string(),
                        base_image: base_name.to_string(),
                        tag: tag.clone(),
                        build_ok: false,
                        combos: vec![],
                        error: Some(format!("container start: {e}")),
                    });
                    continue;
                }
            };

            // Prepare container (_ntp user, directories, config)
            if let Err(e) = prepare_container(&safe_name, make_ntpd_config()) {
                eprintln!("    ✗ failed to prepare container: {e}");
                cleanup_container(&safe_name);
                results.push(ImageResult {
                    version: version.to_string(),
                    base_name: base_name.to_string(),
                    base_image: base_name.to_string(),
                    tag: tag.clone(),
                    build_ok: true,
                    combos: vec![],
                    error: Some(format!("container prepare: {e}")),
                });
                continue;
            }

            // Run tests
            let img_result =
                test_image_combinations(&safe_name, version, base_name, &rust_ntpd, &rust_ntpctl);

            // Clean up
            cleanup_container(&safe_name);

            results.push(img_result);
        }
    }

    // ---- Summary ----
    print_summary(&results, start);

    // Determine overall pass/fail
    let total_fails: usize = results
        .iter()
        .flat_map(|r| &r.combos)
        .filter(|c| matches!(c.status, TestStatus::Fail(_)))
        .count();

    if total_fails > 0 {
        eprintln!();
        eprintln!("{total_fails} combination(s) failed. Review details above.");
    }

    Ok(())
}
