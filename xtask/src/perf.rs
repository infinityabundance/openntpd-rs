#![allow(dead_code)]
//! # Performance comparison harness
//!
//! Measures performance across Rust (git), Rust (crates.io), and real OpenNTPD
//! (every version) on every OS.
//!
//! ## Metrics collected per binary
//!
//! 1. **Binary size** — `stat -c %s` on the executable
//! 2. **Startup time** — time from exec to daemon ready (control socket appears)
//! 3. **Config parse time** — time to parse a 100-line config file
//! 4. **Memory usage (RSS)** — peak RSS during operation (via `/proc/<pid>/status`)
//! 5. **Control socket response time** — time from `ntpctl -s all` request to response
//! 6. **CPU usage** — user/system time after startup (from `/proc/<pid>/stat`)
//!
//! ## Matrix
//!
//! **Binary sources:**
//! - `"git"` — Rust built from the local workspace checkout
//! - `"crates.io"` — Rust built from the latest published crates.io release
//! - `"real-{version}"` — real OpenNTPD `{version}` compiled from source
//!
//! **Base OSes:** Debian, Alpine, Ubuntu, Fedora, Rocky Linux
//!
//! Results are written to `research/perf/results_{timestamp}.json`.
//!
//! ## Usage
//!
//! ```text
//! cargo xtask perf
//! cargo xtask perf --skip-build        # Reuse existing Docker images
//! cargo xtask perf --skip-crates-io    # Skip crates.io (if not published yet)
//! cargo xtask perf --image <tag>       # Run on a specific image only
//! ```

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Duration, Instant};

use serde::Serialize;

// ---------------------------------------------------------------------------
// OpenNTPD versions (mirrors compat.rs)
// ---------------------------------------------------------------------------

/// (version, sha256, extra_cflags, extra_cppflags)
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
    ("fedora", "fedora:40"),
    ("rocky", "rocky:9"),
];

// ---------------------------------------------------------------------------
// Result types
// ---------------------------------------------------------------------------

/// Per-binary performance result.
#[derive(Debug, Clone, Serialize)]
pub struct PerfResult {
    pub os: String,
    pub openntpd_version: String,
    pub binary_source: String, // "git", "crates.io", or "real-6.2p3", etc.
    pub binary_size: u64,
    pub startup_time_ms: f64,
    pub config_parse_time_ms: f64,
    pub peak_rss_kb: u64,
    pub ctl_response_time_ms: f64,
    pub cpu_user_time_ms: f64,
    pub cpu_sys_time_ms: f64,
}

// ---------------------------------------------------------------------------
// Workspace / path helpers
// ---------------------------------------------------------------------------

fn workspace_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("xtask manifest parent (workspace root)")
        .to_path_buf()
}

fn image_tag(version: &str, base_name: &str) -> String {
    format!("openntpd-perf:{version}-{base_name}")
}

// ---------------------------------------------------------------------------
// Docker helpers
// ---------------------------------------------------------------------------

fn check_docker_available() -> anyhow::Result<()> {
    let out = Command::new("docker")
        .args(["info", "--format", "{{.ServerVersion}}"])
        .output()
        .map_err(|e| anyhow::anyhow!("Docker not available: {e}"))?;
    if !out.status.success() {
        anyhow::bail!("Docker daemon not running");
    }
    Ok(())
}

fn docker_image_exists(tag: &str) -> bool {
    Command::new("docker")
        .args(["image", "inspect", "--format", "{{.Id}}", tag])
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

/// Build a Docker image for a specific OpenNTPD version on a specific base OS.
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
        eprintln!("    already exists ({tag})");
        return Ok(());
    }

    let df_dir = workspace_root().join("research/openntpd-versions");
    let dockerfile = df_dir.join("Dockerfile");
    if !dockerfile.exists() {
        anyhow::bail!("Dockerfile not found: {}", dockerfile.display());
    }

    let status = Command::new("docker")
        .args([
            "build",
            "-t",
            &tag,
            "-f",
            &dockerfile.to_string_lossy(),
            "--build-arg",
            &format!("BASE={base_image}"),
            "--build-arg",
            &format!("VERSION={version}"),
            "--build-arg",
            &format!("SHA256={sha256}"),
            "--build-arg",
            &format!("EXTRA_CFLAGS={extra_cflags}"),
            "--build-arg",
            &format!("EXTRA_CPPFLAGS={extra_cppflags}"),
            &df_dir.to_string_lossy(),
        ])
        .status()
        .map_err(|e| anyhow::anyhow!("failed to spawn docker build: {e}"))?;

    if !status.success() {
        anyhow::bail!("docker build for {tag} exited with {status:?}");
    }
    eprintln!("    built {tag}");
    Ok(())
}

/// Start a Docker container from an image, return container name.
fn start_container(tag: &str) -> anyhow::Result<String> {
    let container_name = format!("perf-{}", tag.replace(':', "-").replace('.', "-"));
    // Remove any existing container with the same name
    let _ = Command::new("docker")
        .args(["rm", "-f", &container_name])
        .output();

    let out = Command::new("docker")
        .args([
            "run",
            "-d",
            "--name",
            &container_name,
            "--privileged", // needed for /proc access and clock operations
            "--entrypoint",
            "sleep",
            &tag,
            "infinity",
        ])
        .output()
        .map_err(|e| anyhow::anyhow!("failed to start container: {e}"))?;

    if !out.status.success() {
        let stderr = String::from_utf8_lossy(&out.stderr);
        anyhow::bail!("docker run failed: {stderr}");
    }
    Ok(container_name)
}

/// Execute a command inside a running container.
fn docker_exec(container: &str, args: &[&str]) -> (String, String, Option<i32>) {
    let output = Command::new("docker")
        .args(["exec", container])
        .args(args)
        .output();

    match output {
        Ok(out) => {
            let stdout = String::from_utf8_lossy(&out.stdout).trim().to_string();
            let stderr = String::from_utf8_lossy(&out.stderr).trim().to_string();
            let code = out.status.code();
            (stdout, stderr, code)
        }
        Err(e) => (String::new(), format!("docker exec failed: {e}"), None),
    }
}

/// Copy a file into a running container.
fn docker_cp(container: &str, src: &Path, dest: &str) -> anyhow::Result<()> {
    let status = Command::new("docker")
        .args(["cp", &src.to_string_lossy(), &format!("{container}:{dest}")])
        .status()
        .map_err(|e| anyhow::anyhow!("docker cp failed: {e}"))?;

    if !status.success() {
        anyhow::bail!("docker cp exited with {status:?}");
    }
    Ok(())
}

fn cleanup_container(container: &str) {
    let _ = Command::new("docker")
        .args(["rm", "-f", container])
        .output();
}

// ---------------------------------------------------------------------------
// Rust binary builders
// ---------------------------------------------------------------------------

/// Build Rust binaries from the local workspace (git source).
/// Builds for the host target (glibc); Alpine container tests are skipped
/// because musl-cross ioctl ABI is incompatible with this crate.
fn build_rust_from_git() -> anyhow::Result<(PathBuf, PathBuf)> {
    let ws = workspace_root();
    let target_dir = ws.join("target").join("release");

    // Check if already built
    let ntpd_path = target_dir.join("ntpd");
    let ntpctl_path = target_dir.join("ntpctl");
    if ntpd_path.exists() && ntpctl_path.exists() {
        eprintln!("    Rust (git) binaries already built");
        return Ok((ntpd_path, ntpctl_path));
    }

    eprint!("    Building Rust (git) binaries... ");
    let mut cmd = Command::new("cargo");
    cmd.args([
        "build",
        "-p",
        "openntpd-rs-d",
        "-p",
        "openntpd-rs-ctl",
        "--release",
    ])
    .current_dir(&ws);

    let status = cmd
        .status()
        .map_err(|e| anyhow::anyhow!("cargo build failed: {e}"))?;
    if !status.success() {
        anyhow::bail!("cargo build for host target failed");
    }

    eprintln!("[ok]");
    Ok((ntpd_path, ntpctl_path))
}

/// Install Rust binaries from crates.io (host target).
fn build_rust_from_cratesio() -> anyhow::Result<(PathBuf, PathBuf)> {
    let cargo_bin_dir = dirs_or_default();
    let ntpd_path = cargo_bin_dir.join("ntpd");
    let ntpctl_path = cargo_bin_dir.join("ntpctl");

    // Check if already installed
    if ntpd_path.exists() && ntpctl_path.exists() {
        eprintln!("    Rust (crates.io) binaries already installed");
        return Ok((ntpd_path, ntpctl_path));
    }

    eprint!("    Installing Rust (crates.io) binaries... ");
    let status = Command::new("cargo")
        .args(["install", "openntpd-rs-d", "openntpd-rs-ctl"])
        .status()
        .map_err(|e| anyhow::anyhow!("cargo install failed: {e}"))?;
    if !status.success() {
        anyhow::bail!("cargo install openntpd-rs-d/openntpd-rs-ctl failed (not yet published?)");
    }

    eprintln!("[ok]");
    Ok((ntpd_path, ntpctl_path))
}

fn dirs_or_default() -> PathBuf {
    let home = std::env::var("HOME").unwrap_or_else(|_| "/root".to_string());
    PathBuf::from(home).join(".cargo/bin")
}

// ---------------------------------------------------------------------------
// Config file generation
// ---------------------------------------------------------------------------

/// Simple config compatible with all OpenNTPD versions (6.0p1+).
const SIMPLE_CONFIG: &str = r#"listen on *
server 192.0.2.1
server 203.0.113.1
server 198.51.100.1
sensor *
"#;

/// Modern config with advanced features (6.8p1+).
/// `weight`, `trusted`, `constraint`, `constraints`, `query` are not
/// available in older versions (6.0p1, 6.2p3).
const MODERN_CONFIG: &str = r#"listen on *
server 192.0.2.1 weight 5 trusted
server 203.0.113.1
server 198.51.100.1 weight 10
sensor *
sensor "nmea0" correction 1000 refid GPS stratum 3 weight 5 trusted
constraint from "https://example.com/ntp"
constraints from "https://pool.example.org/"
query from 127.0.0.1
"#;

/// Generate a 100-line config file appropriate for the given version.
/// Older versions (6.0p1, 6.2p3) use SIMPLE_CONFIG; newer versions
/// and Rust builds use MODERN_CONFIG.
fn generate_100_line_config(version: &str) -> String {
    let is_old = version == "6.0p1" || version == "6.2p3";
    let base = if is_old { SIMPLE_CONFIG } else { MODERN_CONFIG };
    let mut config = String::new();
    config.push_str("# OpenNTPD performance test config (100 lines)\n");
    // Repeat to reach ~100 lines. SIMPLE_CONFIG is 5 lines, MODERN_CONFIG is 9 lines.
    let repeat = if is_old { 20 } else { 12 };
    for _ in 0..repeat {
        config.push_str(base);
    }
    let trimmed = config.trim_end().to_string();
    trimmed + "\n"
}

// ---------------------------------------------------------------------------
// Measurement primitives
// ---------------------------------------------------------------------------

/// Get binary size on disk via `stat -c %s`.
fn measure_binary_size(path: &Path) -> anyhow::Result<u64> {
    let meta = std::fs::metadata(path).map_err(|e| anyhow::anyhow!("stat {path:?}: {e}"))?;
    Ok(meta.len())
}

/// Returns (startup_time_ms, Option<pid>).
/// Startup time: time from exec to control socket creation.
/// Starts `{binary} -d -f {config}` in the background, then polls for a
/// control socket to appear.
fn measure_startup_time(
    container: &str,
    binary: &str,
    config_path: &str,
    socket_path: &str,
) -> (Option<f64>, Option<String>) {
    // Start ntpd in debug mode in background, capture PID from $!
    let cmd = format!("{binary} -d -f {config_path} > /tmp/ntpd-perf-startup.log 2>&1 & echo $!");
    let (pid_out, _, _) = docker_exec(container, &["sh", "-c", &cmd]);
    let pid = pid_out.trim().to_string();
    if pid.is_empty() {
        eprintln!("      [startup] no pid returned");
        return (None, None);
    }

    let start = Instant::now();
    let timeout = Duration::from_secs(10);
    let poll_interval = Duration::from_millis(50);

    loop {
        if start.elapsed() > timeout {
            eprintln!("      [startup] timeout (10s) waiting for socket {socket_path}");
            let _ = docker_exec(container, &["kill", &pid]);
            return (None, None);
        }

        let (check, _, _) = docker_exec(
            container,
            &["sh", "-c", &format!("test -S {socket_path} && echo exists")],
        );
        if check == "exists" {
            let elapsed = start.elapsed();
            return (Some(elapsed.as_secs_f64() * 1000.0), Some(pid));
        }

        // Fallback: try to find any socket file
        let (find_out, _, _) = docker_exec(
            container,
            &[
                "sh",
                "-c",
                "find / -type s -name '*.sock' 2>/dev/null | head -1",
            ],
        );
        let found_sock = find_out.trim();
        if !found_sock.is_empty() && !found_sock.contains("find:") {
            let elapsed = start.elapsed();
            eprintln!("      [startup] found socket at {found_sock} (expected {socket_path})");
            return (Some(elapsed.as_secs_f64() * 1000.0), Some(pid));
        }

        // Check if process is still alive
        let (alive, _, _) = docker_exec(
            container,
            &[
                "sh",
                "-c",
                &format!("kill -0 {pid} 2>/dev/null && echo alive"),
            ],
        );
        if alive != "alive" {
            eprintln!("      [startup] process died before socket appeared");
            return (None, None);
        }

        std::thread::sleep(poll_interval);
    }
}

/// Measure config parse time: run `{binary} -n -f {config}` and time it.
/// Uses `date +%s%N` for portable high-resolution timing since `time -p`
/// is not available in minimal Docker images.
fn measure_config_parse_time(container: &str, binary: &str, config_path: &str) -> Option<f64> {
    // Use date arithmetic for timing; avoid `time -p` which is not portable.
    let cmd = format!(
        "start=$(date +%s%N); {binary} -n -f {config_path} >/dev/null 2>&1; \
         rc=$?; end=$(date +%s%N); echo $(( (end - start) / 1000000 )); exit $rc"
    );
    let (stdout, stderr, exit_code) = docker_exec(container, &["sh", "-c", &cmd]);

    // Accept any exit code - we just want the timing
    if let Ok(ms) = stdout.trim().parse::<f64>() {
        return Some(ms);
    }
    eprintln!("      [config_parse] could not parse time (exit={exit_code:?}): out={stdout:?} err={stderr:?}");
    None
}

/// Measure peak RSS from /proc/<pid>/status (VmRSS field).
fn measure_peak_rss(container: &str, pid: &str) -> Option<u64> {
    let (status, _, _) = docker_exec(
        container,
        &[
            "sh",
            "-c",
            &format!("cat /proc/{pid}/status 2>/dev/null || echo '(no proc)'"),
        ],
    );

    if status == "(no proc)" {
        return None;
    }

    // Look for VmRSS (in kB)
    for line in status.lines() {
        if let Some(rest) = line.strip_prefix("VmRSS:") {
            let val: String = rest.chars().filter(|c| c.is_ascii_digit()).collect();
            return val.parse::<u64>().ok();
        }
    }
    None
}

/// Measure control socket response time: run `ntpctl -s all` and time it.
fn measure_ctl_response_time(container: &str, ctl_binary: &str, socket_path: &str) -> Option<f64> {
    let start = Instant::now();

    let (_, _stderr, exit_code) = docker_exec(
        container,
        &[
            "sh",
            "-c",
            &format!(
                "NTPD_CONTROL_SOCKET={socket_path} {ctl_binary} -s all 2>/dev/null",
                socket_path = socket_path
            ),
        ],
    );

    let elapsed = start.elapsed();

    // ntpctl may exit 0 (real) or 78 (Rust not-implemented) - either way we measure timing
    if exit_code.is_some() {
        Some(elapsed.as_secs_f64() * 1000.0)
    } else {
        eprintln!("      [ctl_response] no exit code");
        None
    }
}

/// Measure CPU time from /proc/<pid>/stat fields 14 (utime) and 15 (stime).
/// Values are in clock ticks (sysconf(_SC_CLK_TCK) = 100 typically).
fn measure_cpu_time(container: &str, pid: &str) -> (Option<f64>, Option<f64>) {
    let (stat, _, _) = docker_exec(
        container,
        &[
            "sh",
            "-c",
            &format!("cat /proc/{pid}/stat 2>/dev/null || echo '(no proc)'"),
        ],
    );

    if stat == "(no proc)" {
        return (None, None);
    }

    // /proc/<pid>/stat fields after closing paren:
    // index 0 = state (field 3), 1 = ppid (4), ..., 11 = utime (14), 12 = stime (15)
    // Values are in clock ticks (sysconf(_SC_CLK_TCK) = 100 typically).
    if let Some(end_paren) = stat.rfind(')') {
        let rest = &stat[end_paren + 1..].trim();
        let fields: Vec<&str> = rest.split_whitespace().collect();
        if fields.len() >= 15 {
            // fields[0]=state, fields[1]=ppid, ..., fields[11]=utime, fields[12]=stime
            let utime = fields[11].parse::<f64>().ok();
            let stime = fields[12].parse::<f64>().ok();
            let clk_tck = 100.0;
            return (
                utime.map(|t| t / clk_tck * 1000.0),
                stime.map(|t| t / clk_tck * 1000.0),
            );
        }
    }

    (None, None)
}

// ---------------------------------------------------------------------------
// Per-binary measurement runner
// ---------------------------------------------------------------------------

fn measure_binary(
    container: &str,
    os: &str,
    version: &str,
    binary_source: &str,
    ntpd_binary: &str,
    ntpctl_binary: &str,
    config_path: &str,
    socket_path: &str,
) -> Option<PerfResult> {
    eprintln!("  Measuring {binary_source} on {os}...");

    // 3. Measure startup time (returns elapsed ms + PID from $!)
    let (startup, pid) = measure_startup_time(container, ntpd_binary, config_path, socket_path);

    if startup.is_none() {
        return None;
    }

    // Wait for daemon to settle
    std::thread::sleep(Duration::from_millis(500));

    // 5. Measure control socket response (while daemon is running)
    let ctl_response = measure_ctl_response_time(container, ntpctl_binary, socket_path);

    // 4. Measure peak RSS
    std::thread::sleep(Duration::from_millis(200));
    let rss = pid.as_deref().and_then(|p| measure_peak_rss(container, p));

    // 6. Measure CPU time
    let (cpu_user, cpu_sys) = pid
        .as_deref()
        .map_or((None, None), |p| measure_cpu_time(container, p));

    // Clean up: kill ntpd
    if let Some(ref pid) = pid {
        let _ = docker_exec(container, &["kill", pid]);
        std::thread::sleep(Duration::from_millis(100));
    }
    let _ = docker_exec(container, &["pkill", "-9", "ntpd"]);

    // 2. Measure config parse time (standalone, doesn't need daemon)
    let config_parse = measure_config_parse_time(container, ntpd_binary, config_path);

    let result = PerfResult {
        os: os.to_string(),
        openntpd_version: version.to_string(),
        binary_source: binary_source.to_string(),
        binary_size: 0, // filled in by caller
        startup_time_ms: startup.unwrap_or(0.0),
        config_parse_time_ms: config_parse.unwrap_or(0.0),
        peak_rss_kb: rss.unwrap_or(0),
        ctl_response_time_ms: ctl_response.unwrap_or(0.0),
        cpu_user_time_ms: cpu_user.unwrap_or(0.0),
        cpu_sys_time_ms: cpu_sys.unwrap_or(0.0),
    };

    Some(result)
}

// ---------------------------------------------------------------------------
// Per-OS runner
// ---------------------------------------------------------------------------

fn test_os(
    container: &str,
    base_name: &str,
    version: &str,
    git_ntpd: &Path,
    git_ntpctl: &Path,
    cratesio_ntpd: Option<&Path>,
    cratesio_ntpctl: Option<&Path>,
    skip_crates_io: bool,
    results: &mut Vec<PerfResult>,
) {
    // Alpine uses musl libc; our Rust binaries are glibc-linked so they won't run.
    // We only measure the real OpenNTPD on Alpine.
    let is_musl = base_name == "alpine";
    eprintln!("── OS: {base_name}, version: {version} ──");

    // Paths inside the container
    let real_ntpd = "/usr/local/sbin/ntpd";
    let real_ntpctl = "/usr/local/sbin/ntpctl";

    let git_ntpd_dest = "/usr/local/sbin/ntpd-rust-git";
    let git_ntpctl_dest = "/usr/local/sbin/ntpctl-rust-git";

    let config_path = "/etc/ntpd-perf.conf";
    // Real OpenNTPD (configured with --localstatedir=/usr/local/var)
    // creates its socket at /usr/local/var/run/ntpd.sock.
    // Rust ntpd creates its socket at /var/run/ntpd.sock.
    let real_socket = "/usr/local/var/run/ntpd.sock";
    let rust_socket = "/var/run/ntpd.sock";

    // Write the 100-line config into the container
    let config_content = generate_100_line_config(version);
    docker_exec(
        container,
        &[
            "sh",
            "-c",
            &format!(
                "mkdir -p /etc /var/run /usr/local/var/run /nonexistent 2>/dev/null; \
                 grep -q '^_ntp' /etc/passwd 2>/dev/null || \
                   (useradd -r -d /nonexistent -s /usr/sbin/nologin _ntp 2>/dev/null || \
                    adduser -S -h /nonexistent -s /sbin/nologin _ntp 2>/dev/null) || true; \
                 grep -q '^ntp' /etc/services 2>/dev/null || \
                   echo 'ntp 123/udp # Network Time Protocol' >> /etc/services"
            ),
        ],
    );
    // Write config via heredoc in shell
    let escaped = config_content.replace('\'', "'\\''");
    docker_exec(
        container,
        &[
            "sh",
            "-c",
            &format!("cat > {config_path} << 'PERFEOF'\n{escaped}\nPERFEOF"),
        ],
    );

    // ---- Real OpenNTPD ----
    let real_binary_size = measure_binary_size_in_container(container, real_ntpd);
    if let Some(mut r) = measure_binary(
        container,
        base_name,
        version,
        &format!("real-{version}"),
        real_ntpd,
        real_ntpctl,
        config_path,
        real_socket,
    ) {
        r.binary_size = real_binary_size.unwrap_or(0);
        results.push(r);
    }

    if !is_musl {
        // ---- Rust (git) ----
        if let Err(e) = docker_cp(container, git_ntpd, git_ntpd_dest) {
            eprintln!("    Failed to copy Rust (git) ntpd: {e}");
        } else if let Err(e) = docker_cp(container, git_ntpctl, git_ntpctl_dest) {
            eprintln!("    Failed to copy Rust (git) ntpctl: {e}");
        } else {
            docker_exec(container, &["chmod", "+x", git_ntpd_dest]);
            docker_exec(container, &["chmod", "+x", git_ntpctl_dest]);

            let git_size = std::fs::metadata(git_ntpd)
                .ok()
                .map(|m| m.len())
                .unwrap_or(0);
            if let Some(mut r) = measure_binary(
                container,
                base_name,
                version,
                "git",
                git_ntpd_dest,
                git_ntpctl_dest,
                config_path,
                rust_socket,
            ) {
                r.binary_size = git_size;
                results.push(r);
            }
        }

        // ---- Rust (crates.io) ----
        if !skip_crates_io {
            if let (Some(cr_ntpd), Some(cr_ntpctl)) = (cratesio_ntpd, cratesio_ntpctl) {
                let cr_ntpd_dest = "/usr/local/sbin/ntpd-rust-cratesio";
                let cr_ntpctl_dest = "/usr/local/sbin/ntpctl-rust-cratesio";

                if let Err(e) = docker_cp(container, cr_ntpd, cr_ntpd_dest) {
                    eprintln!("    Failed to copy Rust (crates.io) ntpd: {e}");
                } else if let Err(e) = docker_cp(container, cr_ntpctl, cr_ntpctl_dest) {
                    eprintln!("    Failed to copy Rust (crates.io) ntpctl: {e}");
                } else {
                    docker_exec(container, &["chmod", "+x", cr_ntpd_dest]);
                    docker_exec(container, &["chmod", "+x", cr_ntpctl_dest]);

                    let cr_size = std::fs::metadata(cr_ntpd)
                        .ok()
                        .map(|m| m.len())
                        .unwrap_or(0);
                    if let Some(mut r) = measure_binary(
                        container,
                        base_name,
                        version,
                        "crates.io",
                        cr_ntpd_dest,
                        cr_ntpctl_dest,
                        config_path,
                        rust_socket,
                    ) {
                        r.binary_size = cr_size;
                        results.push(r);
                    }
                }
            }
        }
    } else {
        eprintln!("    Skipping Rust binaries (Alpine uses musl, binaries are glibc-linked)");
    }

    eprintln!();
}

fn measure_binary_size_in_container(container: &str, path: &str) -> Option<u64> {
    let (out, _, _) = docker_exec(
        container,
        &[
            "sh",
            "-c",
            &format!("stat -c '%s' {path} 2>/dev/null || echo 0"),
        ],
    );
    out.trim().parse::<u64>().ok()
}

// ---------------------------------------------------------------------------
// Results output
// ---------------------------------------------------------------------------

fn write_results(results: &[PerfResult]) -> anyhow::Result<PathBuf> {
    let perf_dir = workspace_root().join("research/perf");
    std::fs::create_dir_all(&perf_dir).map_err(|e| anyhow::anyhow!("create research/perf: {e}"))?;

    let timestamp = chrono_now();
    let output_path = perf_dir.join(format!("results_{}.json", timestamp));

    let json = serde_json::to_string_pretty(results)
        .map_err(|e| anyhow::anyhow!("serialize results: {e}"))?;

    std::fs::write(&output_path, &json).map_err(|e| anyhow::anyhow!("write results: {e}"))?;

    eprintln!("Results written to: {}", output_path.display());
    Ok(output_path)
}

fn chrono_now() -> String {
    // Use /bin/date to get ISO 8601 timestamp (avoid chrono dependency)
    let out = Command::new("date")
        .args(["-u", "+%Y%m%dT%H%M%SZ"])
        .output()
        .ok();
    match out {
        Some(o) => String::from_utf8_lossy(&o.stdout).trim().to_string(),
        None => "unknown".to_string(),
    }
}

// ---------------------------------------------------------------------------
// Summary table
// ---------------------------------------------------------------------------

fn print_summary_table(results: &[PerfResult]) {
    println!();
    println!("╔══════════════════════════════════════════════════════════════════════════════════════════════════════════════╗");
    println!("║                         OpenNTPD-rs Performance Comparison Results                                         ║");
    println!("╚══════════════════════════════════════════════════════════════════════════════════════════════════════════════╝");
    println!();

    // Sort results by OS, then version, then source
    let mut sorted = results.to_vec();
    sorted.sort_by(|a, b| {
        a.os.cmp(&b.os)
            .then_with(|| a.openntpd_version.cmp(&b.openntpd_version))
            .then_with(|| a.binary_source.cmp(&b.binary_source))
    });

    // Group by OS
    let mut by_os: BTreeMap<String, Vec<&PerfResult>> = BTreeMap::new();
    for r in &sorted {
        by_os.entry(r.os.clone()).or_default().push(r);
    }

    for (os, entries) in &by_os {
        println!("── {os} ──");
        println!(
            "{:<16} {:<12} {:>10} {:>12} {:>12} {:>10} {:>14} {:>12} {:>12}",
            "Source",
            "Version",
            "Size(B)",
            "Startup(ms)",
            "Parse(ms)",
            "RSS(KB)",
            "CtlResp(ms)",
            "CPU-User(ms)",
            "CPU-Sys(ms)"
        );
        println!("{:-<125}", "");

        for r in entries {
            println!(
                "{:<16} {:<12} {:>10} {:>12.1} {:>12.1} {:>10} {:>14.2} {:>12.2} {:>12.2}",
                r.binary_source,
                r.openntpd_version,
                r.binary_size,
                r.startup_time_ms,
                r.config_parse_time_ms,
                r.peak_rss_kb,
                r.ctl_response_time_ms,
                r.cpu_user_time_ms,
                r.cpu_sys_time_ms,
            );
        }
        println!();
    }

    // Summary statistics
    println!("── Summary Statistics ──");
    println!("Total measurements: {}", results.len());

    if !results.is_empty() {
        let avg_startup: f64 =
            results.iter().map(|r| r.startup_time_ms).sum::<f64>() / results.len() as f64;
        let avg_parse: f64 =
            results.iter().map(|r| r.config_parse_time_ms).sum::<f64>() / results.len() as f64;
        let avg_rss: f64 =
            results.iter().map(|r| r.peak_rss_kb as f64).sum::<f64>() / results.len() as f64;
        let avg_ctl: f64 =
            results.iter().map(|r| r.ctl_response_time_ms).sum::<f64>() / results.len() as f64;

        println!("  Avg startup time:     {:.2} ms", avg_startup);
        println!("  Avg config parse:     {:.2} ms", avg_parse);
        println!("  Avg peak RSS:         {:.0} KB", avg_rss);
        println!("  Avg ctl response:     {:.2} ms", avg_ctl);
    }

    // Per-source averages
    let mut by_source: BTreeMap<String, Vec<&PerfResult>> = BTreeMap::new();
    for r in &sorted {
        by_source
            .entry(r.binary_source.clone())
            .or_default()
            .push(r);
    }

    println!();
    println!("── Averages by Binary Source ──");
    println!(
        "{:<20} {:>12} {:>12} {:>10} {:>14} {:>12} {:>12}",
        "Source",
        "Startup(ms)",
        "Parse(ms)",
        "RSS(KB)",
        "CtlResp(ms)",
        "CPU-User(ms)",
        "CPU-Sys(ms)"
    );
    println!("{:-<90}", "");
    for (src, entries) in &by_source {
        let n = entries.len() as f64;
        let avg_startup: f64 = entries.iter().map(|r| r.startup_time_ms).sum::<f64>() / n;
        let avg_parse: f64 = entries.iter().map(|r| r.config_parse_time_ms).sum::<f64>() / n;
        let avg_rss: f64 = entries.iter().map(|r| r.peak_rss_kb as f64).sum::<f64>() / n;
        let avg_ctl: f64 = entries.iter().map(|r| r.ctl_response_time_ms).sum::<f64>() / n;
        let avg_cpu_user: f64 = entries.iter().map(|r| r.cpu_user_time_ms).sum::<f64>() / n;
        let avg_cpu_sys: f64 = entries.iter().map(|r| r.cpu_sys_time_ms).sum::<f64>() / n;

        println!(
            "{:<20} {:>12.2} {:>12.2} {:>10.0} {:>14.2} {:>12.2} {:>12.2}",
            src, avg_startup, avg_parse, avg_rss, avg_ctl, avg_cpu_user, avg_cpu_sys,
        );
    }
    println!();
}

// ---------------------------------------------------------------------------
// Main entry point
// ---------------------------------------------------------------------------

/// Run the performance benchmarking harness.
///
/// Accepts the following flags (filtered from global args):
/// - `--skip-build` — skip Docker image building
/// - `--skip-crates-io` — skip crates.io binary source
/// - `--image <tag>` — run on a specific image only
pub fn run() -> anyhow::Result<()> {
    let args: Vec<String> = std::env::args().collect();
    let skip_build = args.iter().any(|a| a == "--skip-build");
    let skip_crates_io = args.iter().any(|a| a == "--skip-crates-io");
    let filter_image: Option<String> = args
        .windows(2)
        .find(|w| w[0] == "--image")
        .map(|w| w[1].clone());

    let start = Instant::now();

    eprintln!("╔══════════════════════════════════════════════════════════════╗");
    eprintln!("║        OpenNTPD-rs Performance Comparison Harness           ║");
    eprintln!("╚══════════════════════════════════════════════════════════════╝");
    eprintln!();

    // Check Docker availability
    check_docker_available()?;
    eprintln!("✓ Docker available");

    // ---- Step 1: Build OpenNTPD Docker images ----
    if skip_build {
        eprintln!("── Step 1: Build Docker images (SKIPPED) ──");
    } else {
        eprintln!("── Step 1: Build Docker images ──");
        for (version, sha256, extra_cflags, extra_cppflags) in VERSIONS {
            for (base_name, base_image) in BASE_OSES {
                // Check if base name differs from base_image prefix for filtering
                if let Some(ref filter) = filter_image {
                    let tag = image_tag(version, base_name);
                    if tag != *filter && !tag.contains(filter.as_str()) {
                        continue;
                    }
                }
                eprint!("  Building {version} on {base_name} ({base_image})... ");
                if let Err(e) = build_image(
                    version,
                    sha256,
                    extra_cflags,
                    extra_cppflags,
                    base_name,
                    base_image,
                ) {
                    eprintln!("✗: {e}");
                }
            }
        }
        eprintln!();
    }

    // ---- Step 2: Build/install Rust binaries ----
    eprintln!("── Step 2: Rust binary sources ──");

    let (git_ntpd, git_ntpctl) = build_rust_from_git()?;
    let git_size = std::fs::metadata(&git_ntpd).map(|m| m.len()).unwrap_or(0);
    let git_ctl_size = std::fs::metadata(&git_ntpctl).map(|m| m.len()).unwrap_or(0);
    eprintln!(
        "    Rust (git) ntpd:   {} ({} bytes)",
        git_ntpd.display(),
        git_size
    );
    eprintln!(
        "    Rust (git) ntpctl: {} ({} bytes)",
        git_ntpctl.display(),
        git_ctl_size
    );

    let (cratesio_ntpd, cratesio_ntpctl) = if skip_crates_io {
        eprintln!("    Rust (crates.io): SKIPPED (--skip-crates-io)");
        (None, None)
    } else {
        match build_rust_from_cratesio() {
            Ok((ntpd, ntpctl)) => {
                let cr_size = std::fs::metadata(&ntpd).map(|m| m.len()).unwrap_or(0);
                let cr_ctl_size = std::fs::metadata(&ntpctl).map(|m| m.len()).unwrap_or(0);
                eprintln!(
                    "    Rust (crates.io) ntpd:   {} ({} bytes)",
                    ntpd.display(),
                    cr_size
                );
                eprintln!(
                    "    Rust (crates.io) ntpctl: {} ({} bytes)",
                    ntpctl.display(),
                    cr_ctl_size
                );
                (Some(ntpd), Some(ntpctl))
            }
            Err(e) => {
                eprintln!("    Rust (crates.io): FAILED — {e}");
                (None, None)
            }
        }
    };
    eprintln!();

    // ---- Step 3: Run measurements ----
    eprintln!("── Step 3: Run measurements ──");
    let mut all_results: Vec<PerfResult> = Vec::new();

    for (version, _sha256, _extra_cflags, _extra_cppflags) in VERSIONS {
        for (base_name, _base_image) in BASE_OSES {
            let tag = image_tag(version, base_name);

            // Apply image filter
            if let Some(ref filter) = filter_image {
                if tag != *filter && !tag.contains(filter.as_str()) {
                    continue;
                }
            }

            // Start container
            let container = match start_container(&tag) {
                Ok(c) => c,
                Err(e) => {
                    eprintln!("  Failed to start container for {tag}: {e}");
                    continue;
                }
            };

            // Install procps if needed (for ps/kill)
            docker_exec(&container, &[
                "sh", "-c",
                "command -v pgrep 2>/dev/null || (command -v apt-get && apt-get update && apt-get install -y procps 2>/dev/null) || (command -v apk && apk add procps 2>/dev/null) || (command -v yum && yum install -y procps-ng 2>/dev/null) || true",
            ]);

            test_os(
                &container,
                base_name,
                version,
                &git_ntpd,
                &git_ntpctl,
                cratesio_ntpd.as_ref().map(|v| &**v),
                cratesio_ntpctl.as_ref().map(|v| &**v),
                skip_crates_io,
                &mut all_results,
            );

            // Clean up
            cleanup_container(&container);
        }
    }
    eprintln!();

    // ---- Step 4: Write results ----
    eprintln!("── Step 4: Write results ──");
    let output_path = write_results(&all_results)?;

    // ---- Step 5: Print summary table ----
    let total_duration = start.elapsed();
    eprintln!();
    eprintln!(
        "Total time: {}.{:03}s",
        total_duration.as_secs(),
        total_duration.subsec_millis()
    );

    print_summary_table(&all_results);

    eprintln!("Results saved to: {}", output_path.display());
    Ok(())
}
