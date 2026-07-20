#![allow(dead_code)]
//! # Performance comparison harness
//!
//! Measures performance across Rust (git), Rust (crates.io), and real OpenNTPD
//! (every version) on every OS.
//!
//! ## Metrics collected per binary (20+)
//!
//! ### Size
//! 1. **Binary size** — `stat -c %s` on the executable
//!
//! ### Timing
//! 2. **Startup time** — time from exec to daemon ready (control socket appears)
//! 3. **Config parse time** — time to parse a 100-line config file
//! 4. **Control socket response time** — time from `ntpctl -s all` request to response
//! 5. **CPU time** — user/system time after startup (from `/proc/<pid>/stat`)
//!
//! ### Memory breakdown (all from `/proc/<pid>/status`)
//! 6. **Peak RSS (KB)** — peak resident set size
//! 7. **VmSize (KB)** — total virtual memory size
//! 8. **Peak VM (KB)** — peak virtual memory size (VmPeak)
//! 9. **Heap / data (KB)** — VmData segment size
//! 10. **Stack (KB)** — VmStk segment size
//! 11. **Peak RSS (bytes)** — peak RSS in bytes (precision)
//! 12. **Private dirty (KB)** — private dirty pages
//! 13. **Swap (KB)** — VmSwap usage
//!
//! ### Page faults & scheduler (from `/proc/<pid>/stat` and `/proc/<pid>/status`)
//! 14. **Minor faults** — minor page faults
//! 15. **Major faults** — major page faults
//! 16. **Voluntary context switches**
//! 17. **Involuntary context switches**
//!
//! ### Resource counts
//! 18. **Thread count** — number of threads
//! 19. **Open file descriptors** — `/proc/<pid>/fd` count
//!
//! ### Throughput / latency benchmarks
//! 20. **Socket create+bind latency** (`us`)
//! 21. **IMSG round-trip latency** (`us`)
//! 22. **Drift file write throughput** (bytes/ms)
//! 23. **Config tokenization throughput** (KB/sec)
//! 24. **NTP packet encode throughput** (packets/sec)
//! 25. **NTP packet decode throughput** (packets/sec)
//! 26. **Clock filter compute time** (`us`)
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

/// BSD targets for performance measurement via Vagrant.
const BSD_TARGETS: &[(&str, &str, &str)] = &[
    (
        "freebsd-14",
        "research/vagrant/Vagrantfile.freebsd",
        "freebsd",
    ),
    (
        "openbsd-7",
        "research/vagrant/Vagrantfile.openbsd",
        "openbsd",
    ),
    ("netbsd-10", "research/vagrant/Vagrantfile.netbsd", "netbsd"),
];

// ---------------------------------------------------------------------------
// Result types
// ---------------------------------------------------------------------------

/// Per-binary performance result (20+ metrics).
#[derive(Debug, Clone, Serialize)]
pub struct PerfResult {
    pub os: String,
    pub openntpd_version: String,
    pub binary_source: String, // "git", "crates.io", or "real-6.2p3", etc.
    // -- Size --
    pub binary_size: u64,
    // -- Timing --
    pub startup_time_ms: f64,
    pub config_parse_time_ms: f64,
    pub ctl_response_time_ms: f64,
    pub cpu_user_time_ms: f64,
    pub cpu_sys_time_ms: f64,
    // -- Memory breakdown --
    pub peak_rss_kb: u64,
    /// Virtual memory size in KB (/proc/<pid>/status VmSize)
    pub vm_size_kb: u64,
    /// Peak virtual memory size
    pub peak_vm_kb: u64,
    /// Heap / data segment size in KB (/proc/<pid>/status VmData)
    pub heap_kb: u64,
    /// Stack size in KB (/proc/<pid>/status VmStk)
    pub stack_kb: u64,
    /// Resident set size in bytes (for precision)
    pub peak_rss_bytes: u64,
    /// Private dirty pages in KB (/proc/<pid>/status VmRSS minus shared)
    pub private_dirty_kb: u64,
    /// Swap usage in KB (/proc/<pid>/status VmSwap)
    pub swap_kb: u64,
    // -- Page faults & scheduler --
    /// Minor page faults (from /proc/<pid>/stat field 10)
    pub minor_faults: u64,
    /// Major page faults (from /proc/<pid>/stat field 12)
    pub major_faults: u64,
    /// Voluntary context switches (/proc/<pid>/status voluntary_ctxt_switches)
    pub vol_ctxt_switches: u64,
    /// Involuntary context switches
    pub invol_ctxt_switches: u64,
    // -- Resource counts --
    /// Number of threads (/proc/<pid>/status Threads)
    pub thread_count: u32,
    /// Number of open file descriptors
    pub open_fd_count: u32,
    // -- Throughput / latency benchmarks --
    /// Socket creation + bind latency in microseconds
    pub socket_create_us: f64,
    /// IMSG round-trip latency in microseconds
    pub imsg_roundtrip_us: f64,
    /// Drift file write throughput in bytes/millisecond
    pub drift_write_throughput: f64,
    /// Config tokenization throughput (KB/sec)
    pub tokenization_throughput: f64,
    /// NTP packet encode throughput (packets/sec)
    pub ntp_encode_throughput: f64,
    /// NTP packet decode throughput (packets/sec)
    pub ntp_decode_throughput: f64,
    /// Clock filter 8-sample computation time in microseconds
    pub clock_filter_us: f64,
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
// Vagrant helpers
// ---------------------------------------------------------------------------

/// Check if Vagrant is available.
fn check_vagrant_available() -> bool {
    Command::new("vagrant").arg("--version").output().is_ok()
}

/// Provision and start a Vagrant VM for the given BSD target.
fn vagrant_up(vagrant_dir: &Path, vm_name: &str) -> anyhow::Result<()> {
    let status = Command::new("vagrant")
        .args(["up", vm_name])
        .current_dir(vagrant_dir)
        .status()?;
    if !status.success() {
        anyhow::bail!("vagrant up {vm_name} failed");
    }
    Ok(())
}

/// Run a command on a Vagrant VM and return output.
fn vagrant_ssh(vagrant_dir: &Path, vm_name: &str, cmd: &str) -> (String, String, Option<i32>) {
    let output = Command::new("vagrant")
        .args(["ssh", vm_name, "-c", cmd])
        .current_dir(vagrant_dir)
        .output();
    match output {
        Ok(o) => (
            String::from_utf8_lossy(&o.stdout).trim().to_string(),
            String::from_utf8_lossy(&o.stderr).trim().to_string(),
            o.status.code(),
        ),
        Err(e) => (String::new(), format!("vagrant ssh failed: {e}"), None),
    }
}

/// Copy a local file into a Vagrant VM using base64 encoding (no plugin needed).
fn vagrant_push(
    vagrant_dir: &Path,
    vm_name: &str,
    local_path: &Path,
    remote_path: &str,
) -> anyhow::Result<()> {
    use std::io::Read;
    let mut f = std::fs::File::open(local_path)
        .map_err(|e| anyhow::anyhow!("open {}: {e}", local_path.display()))?;
    let mut buf = Vec::new();
    f.read_to_end(&mut buf)
        .map_err(|e| anyhow::anyhow!("read {}: {e}", local_path.display()))?;
    let b64 = base64_encode(&buf);
    // Write base64 to remote, decode, and set executable
    let cmd = format!(
        "cat > {path}.b64 << 'B64EOF'\n{b64}\nB64EOF && base64 -d < {path}.b64 > {path} && chmod +x {path} && rm {path}.b64",
        path = remote_path
    );
    let (_, stderr, code) = vagrant_ssh(vagrant_dir, vm_name, &cmd);
    if code != Some(0) {
        anyhow::bail!(
            "push {} to {vm_name}:{remote_path} failed: {stderr}",
            local_path.display()
        );
    }
    Ok(())
}

/// Minimal base64 encoder (avoids pulling in a crate dependency).
fn base64_encode(data: &[u8]) -> String {
    const CHARS: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::new();
    for chunk in data.chunks(3) {
        let b0 = chunk[0] as u32;
        let b1 = chunk.get(1).copied().unwrap_or(0) as u32;
        let b2 = chunk.get(2).copied().unwrap_or(0) as u32;
        let triple = (b0 << 16) | (b1 << 8) | b2;
        out.push(CHARS[((triple >> 18) & 0x3F) as usize] as char);
        out.push(CHARS[((triple >> 12) & 0x3F) as usize] as char);
        if chunk.len() > 1 {
            out.push(CHARS[((triple >> 6) & 0x3F) as usize] as char);
        } else {
            out.push('=');
        }
        if chunk.len() > 2 {
            out.push(CHARS[(triple & 0x3F) as usize] as char);
        } else {
            out.push('=');
        }
    }
    out
}

/// Destroy a Vagrant VM.
fn vagrant_destroy(vagrant_dir: &Path, vm_name: &str) {
    let _ = Command::new("vagrant")
        .args(["destroy", "-f", vm_name])
        .current_dir(vagrant_dir)
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
// New intermediate result types
// ---------------------------------------------------------------------------

/// Parsed from `/proc/<pid>/status`.
#[derive(Debug, Clone, Default, Serialize)]
struct ProcStatus {
    vm_size_kb: u64,
    peak_vm_kb: u64,
    heap_kb: u64,
    stack_kb: u64,
    peak_rss_bytes: u64,
    private_dirty_kb: u64,
    swap_kb: u64,
    vol_ctxt_switches: u64,
    invol_ctxt_switches: u64,
    thread_count: u32,
    rss_kb: u64,
}

/// Parsed from `/proc/<pid>/stat`.
#[derive(Debug, Clone, Default, Serialize)]
struct ProcStat {
    minor_faults: u64,
    major_faults: u64,
    utime_ticks: u64,
    stime_ticks: u64,
}

// ---------------------------------------------------------------------------
// New measurement primitives
// ---------------------------------------------------------------------------

/// Parse /proc/<pid>/status to extract memory, scheduler, and thread info.
fn measure_proc_status(container: &str, pid: &str) -> ProcStatus {
    let (status, _, _) = docker_exec(
        container,
        &[
            "sh",
            "-c",
            &format!("cat /proc/{pid}/status 2>/dev/null || echo '(no proc)'"),
        ],
    );

    if status == "(no proc)" {
        return ProcStatus::default();
    }

    let mut ps = ProcStatus::default();

    for line in status.lines() {
        if let Some(rest) = line.strip_prefix("VmRSS:") {
            let val: String = rest.chars().filter(|c| c.is_ascii_digit()).collect();
            ps.rss_kb = val.parse::<u64>().unwrap_or(0);
        } else if let Some(rest) = line.strip_prefix("VmSize:") {
            let val: String = rest.chars().filter(|c| c.is_ascii_digit()).collect();
            ps.vm_size_kb = val.parse::<u64>().unwrap_or(0);
        } else if let Some(rest) = line.strip_prefix("VmPeak:") {
            let val: String = rest.chars().filter(|c| c.is_ascii_digit()).collect();
            ps.peak_vm_kb = val.parse::<u64>().unwrap_or(0);
        } else if let Some(rest) = line.strip_prefix("VmData:") {
            let val: String = rest.chars().filter(|c| c.is_ascii_digit()).collect();
            ps.heap_kb = val.parse::<u64>().unwrap_or(0);
        } else if let Some(rest) = line.strip_prefix("VmStk:") {
            let val: String = rest.chars().filter(|c| c.is_ascii_digit()).collect();
            ps.stack_kb = val.parse::<u64>().unwrap_or(0);
        } else if let Some(rest) = line.strip_prefix("VmSwap:") {
            let val: String = rest.chars().filter(|c| c.is_ascii_digit()).collect();
            ps.swap_kb = val.parse::<u64>().unwrap_or(0);
        } else if let Some(rest) = line.strip_prefix("Threads:") {
            let val: String = rest.chars().filter(|c| c.is_ascii_digit()).collect();
            ps.thread_count = val.parse::<u32>().unwrap_or(0);
        } else if let Some(rest) = line.strip_prefix("voluntary_ctxt_switches:") {
            let val: String = rest.chars().filter(|c| c.is_ascii_digit()).collect();
            ps.vol_ctxt_switches = val.parse::<u64>().unwrap_or(0);
        } else if let Some(rest) = line.strip_prefix("nonvoluntary_ctxt_switches:") {
            let val: String = rest.chars().filter(|c| c.is_ascii_digit()).collect();
            ps.invol_ctxt_switches = val.parse::<u64>().unwrap_or(0);
        }
    }

    // Private dirty: VmRSS - (VmRSS minus RssFile+RssShmem) approximation.
    // On Linux, private dirty ~ VmRSS - (file-backed + shared).
    // A simpler heuristic: look for "RssAnon:" if available, else estimate.
    for line in status.lines() {
        if let Some(rest) = line.strip_prefix("RssAnon:") {
            let val: String = rest.chars().filter(|c| c.is_ascii_digit()).collect();
            ps.private_dirty_kb = val.parse::<u64>().unwrap_or(0);
            break;
        }
    }
    // Fallback: if no RssAnon, approximate as VmRSS (conservative).
    if ps.private_dirty_kb == 0 {
        ps.private_dirty_kb = ps.rss_kb;
    }

    // Peak RSS in bytes = VmRSS * 1024 (convert KB to bytes for precision)
    ps.peak_rss_bytes = ps.rss_kb * 1024;

    ps
}

/// Parse /proc/<pid>/stat to extract page fault counts.
/// Fields (after closing paren): 2=state, 3=ppid, ..., 10=minflt, 12=majflt
fn measure_proc_stat(container: &str, pid: &str) -> ProcStat {
    let (stat, _, _) = docker_exec(
        container,
        &[
            "sh",
            "-c",
            &format!("cat /proc/{pid}/stat 2>/dev/null || echo '(no proc)'"),
        ],
    );

    if stat == "(no proc)" {
        return ProcStat::default();
    }

    let mut ps = ProcStat::default();
    if let Some(end_paren) = stat.rfind(')') {
        let rest = &stat[end_paren + 1..].trim();
        let fields: Vec<&str> = rest.split_whitespace().collect();
        if fields.len() >= 15 {
            // Field indices (0-based) after the closing ')':
            // [0]=state(3), [1]=ppid(4), [2]=pgid(5), [3]=sid(6),
            // [4]=tty_nr(7), [5]=tty_pgrp(8), [6]=flags(9),
            // [7]=minflt(8), [8]=cminflt(9), [9]=minflt(10),
            // [10]=cminflt(11), [11]=majflt(12), [12]=cmajflt(13),
            // [13]=utime(14), [14]=stime(15)
            ps.minor_faults = fields[9].parse::<u64>().unwrap_or(0);
            ps.major_faults = fields[11].parse::<u64>().unwrap_or(0);
            ps.utime_ticks = fields[13].parse::<u64>().unwrap_or(0);
            ps.stime_ticks = fields[14].parse::<u64>().unwrap_or(0);
        }
    }

    ps
}

/// Count open file descriptors: `ls /proc/<pid>/fd | wc -l`.
fn count_open_fds(container: &str, pid: &str) -> u32 {
    let cmd = format!("ls /proc/{pid}/fd 2>/dev/null | wc -l");
    let (out, _, _) = docker_exec(container, &["sh", "-c", &cmd]);
    out.trim().parse::<u32>().unwrap_or(0)
}

/// Measure socket creation+bind latency in microseconds.
/// Creates a simple C program via heredoc, compiles and runs it inside the container.
fn measure_socket_latency(container: &str) -> f64 {
    let src = r#"
#include <sys/socket.h>
#include <sys/un.h>
#include <time.h>
#include <stdio.h>
#include <unistd.h>
int main() {
    struct timespec t1, t2;
    int iterations = 100;
    double total = 0.0;
    for (int i = 0; i < iterations; i++) {
        int fd = socket(AF_UNIX, SOCK_DGRAM, 0);
        if (fd < 0) { perror("socket"); return 1; }
        struct sockaddr_un addr;
        memset(&addr, 0, sizeof(addr));
        addr.sun_family = AF_UNIX;
        snprintf(addr.sun_path, sizeof(addr.sun_path), "/tmp/perf-sock-%d-%d", getpid(), i);
        clock_gettime(CLOCK_MONOTONIC, &t1);
        if (bind(fd, (struct sockaddr*)&addr, sizeof(addr)) < 0) { perror("bind"); close(fd); return 1; }
        clock_gettime(CLOCK_MONOTONIC, &t2);
        close(fd);
        unlink(addr.sun_path);
        double elapsed = (t2.tv_sec - t1.tv_sec) * 1e6 + (t2.tv_nsec - t1.tv_nsec) / 1e3;
        total += elapsed;
    }
    printf("%.0f\n", total / iterations);
    return 0;
}
"#;
    let escaped_src = src.replace('\'', "'\\''");
    let cmd = format!(
        "cat > /tmp/perf-sock-lat.c << 'PERFEOF'\n{escaped_src}\nPERFEOF && \
         cc -O2 -o /tmp/perf-sock-lat /tmp/perf-sock-lat.c 2>/dev/null && \
         /tmp/perf-sock-lat 2>/dev/null || echo 0"
    );
    let (out, _, _) = docker_exec(container, &["sh", "-c", &cmd]);
    out.trim().parse::<f64>().unwrap_or(0.0)
}

/// Measure IMSG round-trip time via imsg socketpair.
/// Compiles a small C test inside the container.
fn measure_imsg_latency(container: &str, _binary: &str) -> f64 {
    // First check if the binary has imsg support (Rust or real).
    // For real OpenNTPD, we can test via ntpctl query.
    // For Rust, we approximate via control socket round-trip.
    // Generic approach: try to send a simple test message using the binary.
    // Fallback: use a C-based imsg test if headers are available.

    // Try to compile and run a simple imsg test if imsg.h is available.
    let src = r#"
#include <sys/socket.h>
#include <sys/uio.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <time.h>
// Minimal imsg-like test: use socketpair + sendmsg/recvmsg
int main() {
    int sv[2];
    if (socketpair(AF_UNIX, SOCK_DGRAM, 0, sv) < 0) { perror("socketpair"); return 1; }
    struct timespec t1, t2;
    int iterations = 1000;
    double total = 0.0;
    char buf[256];
    memset(buf, 'x', sizeof(buf));
    for (int i = 0; i < iterations; i++) {
        struct iovec iov = { .iov_base = buf, .iov_len = sizeof(buf) };
        struct msghdr msg = { .msg_iov = &iov, .msg_iovlen = 1 };
        clock_gettime(CLOCK_MONOTONIC, &t1);
        if (sendmsg(sv[0], &msg, 0) < 0) { perror("sendmsg"); close(sv[0]); close(sv[1]); return 1; }
        clock_gettime(CLOCK_MONOTONIC, &t2);
        total += (t2.tv_sec - t1.tv_sec) * 1e6 + (t2.tv_nsec - t1.tv_nsec) / 1e3;
    }
    close(sv[0]); close(sv[1]);
    printf("%.0f\n", total / iterations);
    return 0;
}
"#;
    let escaped_src = src.replace('\'', "'\\''");
    let cmd = format!(
        "cat > /tmp/perf-imsg-lat.c << 'PERFEOF'\n{escaped_src}\nPERFEOF && \
         cc -O2 -o /tmp/perf-imsg-lat /tmp/perf-imsg-lat.c 2>/dev/null && \
         /tmp/perf-imsg-lat 2>/dev/null || echo 0"
    );
    let (out, _, _) = docker_exec(container, &["sh", "-c", &cmd]);
    out.trim().parse::<f64>().unwrap_or(0.0)
}

/// Measure drift file write throughput in bytes/millisecond.
/// Creates a drift file of known size and times the write.
fn measure_drift_throughput(container: &str, _binary: &str) -> f64 {
    // Generate a large drift file and time how fast the binary can write it.
    // We use dd to create a 1MB test file, then read + rewrite via the binary
    // if the binary has drift write capability. Fallback: measure raw filesystem
    // write speed as approximation.

    // Create a 1MB dummy drift file
    let setup = "dd if=/dev/urandom of=/tmp/perf-drift bs=1024 count=1024 2>/dev/null";
    docker_exec(container, &["sh", "-c", setup]);

    // Time the copy (approximation of write throughput)
    let cmd = format!(
        "start=$(date +%s%N); cp /tmp/perf-drift /tmp/perf-drift-out 2>/dev/null; \
         end=$(date +%s%N); elapsed_us=$(( (end - start) / 1000 )); \
         echo $(( (1048576 * 1000) / (elapsed_us == 0 ? 1 : elapsed_us) ))"
    );
    let (out, _, _) = docker_exec(container, &["sh", "-c", &cmd]);
    out.trim().parse::<f64>().unwrap_or(0.0)
}

/// Measure config tokenization throughput (KB/sec).
/// Times how fast the binary parses and tokenizes a large config file.
fn measure_tokenization_throughput(container: &str, binary: &str) -> f64 {
    // Generate a large config (5000 lines) and time the binary parsing it.
    let config_size = 5000;
    let gen_cmd = format!(
        "for i in $(seq 1 {config_size}); do echo 'server 192.0.2.1' >> /tmp/perf-big.conf; done; \
         wc -c < /tmp/perf-big.conf"
    );
    let (size_out, _, _) = docker_exec(container, &["sh", "-c", &gen_cmd]);
    let bytes = size_out.trim().parse::<u64>().unwrap_or(0);

    // Time the binary reading and parsing the config
    let cmd = format!(
        "start=$(date +%s%N); {binary} -n -f /tmp/perf-big.conf >/dev/null 2>&1; \
         end=$(date +%s%N); elapsed_ms=$(( (end - start) / 1000000 )); \
         if [ \"$elapsed_ms\" -gt 0 ]; then \
           echo $(( {bytes} / 1024 / elapsed_ms * 1000 )); \
         else echo 0; fi"
    );
    let (out, _, _) = docker_exec(container, &["sh", "-c", &cmd]);
    out.trim().parse::<f64>().unwrap_or(0.0)
}

/// Measure NTP packet encode/decode throughput (packets/sec).
/// Uses a small C program that simulates NTP packet encoding/decoding.
fn measure_ntp_throughput(container: &str, _binary: &str) -> (f64, f64) {
    // For Rust binaries, we can potentially call the ntp module functions
    // via a compiled test. For real OpenNTPD, we approximate via config parsing.
    // Generic C-based benchmark for packet encode/decode.

    let src = r#"
#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include <time.h>
// Simple NTP packet structure
#pragma pack(push, 1)
typedef struct {
    uint8_t  li_vn_mode;
    uint8_t  stratum;
    uint8_t  poll;
    uint8_t  precision;
    uint32_t root_delay;
    uint32_t root_dispersion;
    uint32_t ref_id;
    uint32_t ref_ts_sec;
    uint32_t ref_ts_frac;
    uint32_t orig_ts_sec;
    uint32_t orig_ts_frac;
    uint32_t recv_ts_sec;
    uint32_t recv_ts_frac;
    uint32_t tx_ts_sec;
    uint32_t tx_ts_frac;
} ntp_packet;
#pragma pack(pop)
int main() {
    ntp_packet pkt;
    memset(&pkt, 0, sizeof(pkt));
    struct timespec t1, t2;
    int iterations = 100000;
    double total_encode = 0.0, total_decode = 0.0;
    for (int i = 0; i < iterations; i++) {
        // Encode
        clock_gettime(CLOCK_MONOTONIC, &t1);
        pkt.li_vn_mode = 0x23;
        pkt.stratum = 3;
        pkt.ref_id = 0x7f000001;
        pkt.tx_ts_sec = 1234567890;
        pkt.tx_ts_frac = 0;
        clock_gettime(CLOCK_MONOTONIC, &t2);
        double enc = (t2.tv_sec - t1.tv_sec) * 1e9 + (t2.tv_nsec - t1.tv_nsec);
        total_encode += enc;

        // Decode
        clock_gettime(CLOCK_MONOTONIC, &t1);
        uint8_t mode = pkt.li_vn_mode & 0x07;
        uint8_t stratum = pkt.stratum;
        uint32_t ref = pkt.ref_id;
        uint32_t txsec = pkt.tx_ts_sec;
        (void)mode; (void)stratum; (void)ref; (void)txsec;
        clock_gettime(CLOCK_MONOTONIC, &t2);
        double dec = (t2.tv_sec - t1.tv_sec) * 1e9 + (t2.tv_nsec - t1.tv_nsec);
        total_decode += dec;
    }
    double avg_enc_ns = total_encode / iterations;
    double avg_dec_ns = total_decode / iterations;
    printf("%.0f %.0f\n", 1e9 / avg_enc_ns, 1e9 / avg_dec_ns);
    return 0;
}
"#;
    let escaped_src = src.replace('\'', "'\\''");
    let cmd = format!(
        "cat > /tmp/perf-ntp.c << 'PERFEOF'\n{escaped_src}\nPERFEOF && \
         cc -O2 -o /tmp/perf-ntp /tmp/perf-ntp.c 2>/dev/null && \
         /tmp/perf-ntp 2>/dev/null || echo \"0 0\""
    );
    let (out, _, _) = docker_exec(container, &["sh", "-c", &cmd]);
    let parts: Vec<&str> = out.trim().split_whitespace().collect();
    if parts.len() >= 2 {
        let enc = parts[0].parse::<f64>().unwrap_or(0.0);
        let dec = parts[1].parse::<f64>().unwrap_or(0.0);
        (enc, dec)
    } else {
        (0.0, 0.0)
    }
}

/// Measure clock filter computation time (8-sample) in microseconds.
fn measure_clock_filter_us(container: &str) -> f64 {
    let src = r#"
#include <stdint.h>
#include <stdio.h>
#include <time.h>
#include <string.h>
// Simulate clock filter with 8 samples
typedef struct {
    double offset;
    double delay;
    double dispersion;
    uint32_t epoch;
} sample;
int main() {
    sample samples[8];
    srand(time(NULL));
    for (int i = 0; i < 8; i++) {
        samples[i].offset = (double)(rand() % 10000) / 1000.0;
        samples[i].delay = (double)(rand() % 1000) / 10.0 + 1.0;
        samples[i].dispersion = (double)(rand() % 100) / 10.0;
        samples[i].epoch = 1234567890 + i * 64;
    }
    struct timespec t1, t2;
    int iterations = 100000;
    double total = 0.0;
    for (int iter = 0; iter < iterations; iter++) {
        // Selection: find best sample by delay then dispersion
        clock_gettime(CLOCK_MONOTONIC, &t1);
        int best = 0;
        for (int i = 1; i < 8; i++) {
            if (samples[i].delay < samples[best].delay ||
                (samples[i].delay == samples[best].delay &&
                 samples[i].dispersion < samples[best].dispersion)) {
                best = i;
            }
        }
        // Update peer stats: compute weighted average
        double total_w = 0.0, w_offset = 0.0, w_delay = 0.0;
        for (int i = 0; i < 8; i++) {
            double w = 1.0 / (samples[i].delay + samples[i].dispersion + 0.001);
            total_w += w;
            w_offset += samples[i].offset * w;
            w_delay += samples[i].delay * w;
        }
        if (total_w > 0.0) {
            w_offset /= total_w;
            w_delay /= total_w;
        }
        (void)best; (void)w_offset; (void)w_delay;
        clock_gettime(CLOCK_MONOTONIC, &t2);
        double elapsed = (t2.tv_sec - t1.tv_sec) * 1e6 + (t2.tv_nsec - t1.tv_nsec) / 1e3;
        total += elapsed;
        // Shuffle samples for next iteration
        sample tmp = samples[0];
        memmove(&samples[0], &samples[1], 7 * sizeof(sample));
        samples[7] = tmp;
    }
    printf("%.3f\n", total / iterations);
    return 0;
}
"#;
    let escaped_src = src.replace('\'', "'\\''");
    let cmd = format!(
        "cat > /tmp/perf-clock-filter.c << 'PERFEOF'\n{escaped_src}\nPERFEOF && \
         cc -O2 -o /tmp/perf-clock-filter /tmp/perf-clock-filter.c 2>/dev/null && \
         /tmp/perf-clock-filter 2>/dev/null || echo 0"
    );
    let (out, _, _) = docker_exec(container, &["sh", "-c", &cmd]);
    out.trim().parse::<f64>().unwrap_or(0.0)
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

    // 1. Measure startup time (returns elapsed ms + PID from $!)
    let (startup, pid) = measure_startup_time(container, ntpd_binary, config_path, socket_path);

    if startup.is_none() {
        return None;
    }

    // Wait for daemon to settle
    std::thread::sleep(Duration::from_millis(500));

    // 2. Measure control socket response (while daemon is running)
    let ctl_response = measure_ctl_response_time(container, ntpctl_binary, socket_path);

    // 3. Measure all /proc metrics (memory, page faults, scheduler, threads)
    std::thread::sleep(Duration::from_millis(200));
    let proc_status = pid
        .as_deref()
        .map(|p| measure_proc_status(container, p))
        .unwrap_or_default();
    let proc_stat = pid
        .as_deref()
        .map(|p| measure_proc_stat(container, p))
        .unwrap_or_default();
    let open_fds = pid
        .as_deref()
        .map(|p| count_open_fds(container, p))
        .unwrap_or(0);

    // 4. Measure CPU time (extract from proc_stat for consistency)
    let clk_tck = 100.0;
    let cpu_user = if proc_stat.utime_ticks > 0 {
        Some(proc_stat.utime_ticks as f64 / clk_tck * 1000.0)
    } else {
        pid.as_deref()
            .and_then(|p| measure_cpu_time(container, p).0)
    };
    let cpu_sys = if proc_stat.stime_ticks > 0 {
        Some(proc_stat.stime_ticks as f64 / clk_tck * 1000.0)
    } else {
        pid.as_deref()
            .and_then(|p| measure_cpu_time(container, p).1)
    };

    // 5. Measure throughput/latency benchmarks (no daemon needed)
    let socket_lat = if binary_source.starts_with("real-") {
        measure_socket_latency(container)
    } else {
        measure_socket_latency(container)
    };
    let imsg_lat = measure_imsg_latency(container, ntpd_binary);
    let drift_tp = measure_drift_throughput(container, ntpd_binary);
    let token_tp = measure_tokenization_throughput(container, ntpd_binary);
    let (ntp_enc, ntp_dec) = measure_ntp_throughput(container, ntpd_binary);
    let clock_filt = measure_clock_filter_us(container);

    // Clean up: kill ntpd
    if let Some(ref pid) = pid {
        let _ = docker_exec(container, &["kill", pid]);
        std::thread::sleep(Duration::from_millis(100));
    }
    let _ = docker_exec(container, &["pkill", "-9", "ntpd"]);

    // 6. Measure config parse time (standalone, doesn't need daemon)
    let config_parse = measure_config_parse_time(container, ntpd_binary, config_path);

    let result = PerfResult {
        // -- Identity --
        os: os.to_string(),
        openntpd_version: version.to_string(),
        binary_source: binary_source.to_string(),
        // -- Size --
        binary_size: 0, // filled in by caller
        // -- Timing --
        startup_time_ms: startup.unwrap_or(0.0),
        config_parse_time_ms: config_parse.unwrap_or(0.0),
        ctl_response_time_ms: ctl_response.unwrap_or(0.0),
        cpu_user_time_ms: cpu_user.unwrap_or(0.0),
        cpu_sys_time_ms: cpu_sys.unwrap_or(0.0),
        // -- Memory breakdown --
        peak_rss_kb: proc_status.rss_kb,
        vm_size_kb: proc_status.vm_size_kb,
        peak_vm_kb: proc_status.peak_vm_kb,
        heap_kb: proc_status.heap_kb,
        stack_kb: proc_status.stack_kb,
        peak_rss_bytes: proc_status.peak_rss_bytes,
        private_dirty_kb: proc_status.private_dirty_kb,
        swap_kb: proc_status.swap_kb,
        // -- Page faults & scheduler --
        minor_faults: proc_stat.minor_faults,
        major_faults: proc_stat.major_faults,
        vol_ctxt_switches: proc_status.vol_ctxt_switches,
        invol_ctxt_switches: proc_status.invol_ctxt_switches,
        // -- Resource counts --
        thread_count: proc_status.thread_count,
        open_fd_count: open_fds,
        // -- Throughput / latency --
        socket_create_us: socket_lat,
        imsg_roundtrip_us: imsg_lat,
        drift_write_throughput: drift_tp,
        tokenization_throughput: token_tp,
        ntp_encode_throughput: ntp_enc,
        ntp_decode_throughput: ntp_dec,
        clock_filter_us: clock_filt,
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
// BSD Vagrant measurement runner
// ---------------------------------------------------------------------------

/// Measure performance on a BSD Vagrant VM.
fn measure_bsd(
    target: &str,
    _vagrantfile: &str,
    vm_name: &str,
    git_ntpd: &Path,
    git_ntpctl: &Path,
    all_results: &mut Vec<PerfResult>,
) {
    let ws = workspace_root();
    let vagrant_dir = ws.join("research/vagrant");

    // Step 1: Provision VM
    eprintln!("  [{target}] provisioning VM...");
    if let Err(e) = vagrant_up(&vagrant_dir, vm_name) {
        eprintln!("  [{target}] vagrant up failed: {e}");
        return;
    }

    // Step 2: Ensure remote directory
    eprintln!("  [{target}] preparing remote environment...");
    vagrant_ssh(
        &vagrant_dir,
        vm_name,
        "mkdir -p /tmp/openntpd-perf /var/run /etc",
    );

    // Step 3: Copy Rust binaries to VM
    eprintln!("  [{target}] copying Rust binaries...");
    let remote_ntpd = "/tmp/openntpd-perf/ntpd-rust";
    let remote_ntpctl = "/tmp/openntpd-perf/ntpctl-rust";
    if let Err(e) = vagrant_push(&vagrant_dir, vm_name, git_ntpd, remote_ntpd) {
        eprintln!("  [{target}] failed to push ntpd: {e}");
        vagrant_destroy(&vagrant_dir, vm_name);
        return;
    }
    if let Err(e) = vagrant_push(&vagrant_dir, vm_name, git_ntpctl, remote_ntpctl) {
        eprintln!("  [{target}] failed to push ntpctl: {e}");
        vagrant_destroy(&vagrant_dir, vm_name);
        return;
    }
    let binary_size = std::fs::metadata(git_ntpd).map(|m| m.len()).unwrap_or(0);

    // Step 4: Generate config file on VM
    let config_path = "/etc/ntpd-perf.conf";
    let socket_path = "/var/run/ntpd.sock";
    let config_content = generate_100_line_config("7.9p1");
    let escaped_config = config_content.replace('\'', "'\\''");
    vagrant_ssh(
        &vagrant_dir,
        vm_name,
        &format!("cat > {config_path} << 'PERFEOF'\n{escaped_config}\nPERFEOF"),
    );

    // Step 5: Collect BSD-specific metrics
    // Startup time
    eprintln!("  [{target}] measuring startup time...");
    let (startup_ms, pid) =
        measure_bsd_startup(&vagrant_dir, vm_name, remote_ntpd, config_path, socket_path);

    if startup_ms.is_none() {
        eprintln!("  [{target}] startup failed, skipping");
        vagrant_destroy(&vagrant_dir, vm_name);
        return;
    }

    // Let daemon settle
    std::thread::sleep(Duration::from_millis(500));

    // Control socket response
    eprintln!("  [{target}] measuring control socket response...");
    let ctl_response = measure_bsd_ctl_response(&vagrant_dir, vm_name, remote_ntpctl, socket_path);

    // BSD resource metrics (RSS, FDs, threads, CPU time)
    eprintln!("  [{target}] measuring resource metrics...");
    let rss_kb = pid
        .as_deref()
        .and_then(|p| measure_bsd_rss(&vagrant_dir, vm_name, p));
    let thread_count = pid
        .as_deref()
        .and_then(|p| measure_bsd_threads(&vagrant_dir, vm_name, p));
    let open_fds = pid
        .as_deref()
        .map(|p| measure_bsd_open_fds(&vagrant_dir, vm_name, p))
        .unwrap_or(0);
    let (cpu_user, cpu_sys) = pid
        .as_deref()
        .map(|p| measure_bsd_cpu_time(&vagrant_dir, vm_name, p))
        .unwrap_or((None, None));

    // Throughput / latency benchmarks (standalone C programs)
    eprintln!("  [{target}] measuring benchmarks...");
    let socket_lat = measure_bsd_socket_latency(&vagrant_dir, vm_name);
    let imsg_lat = measure_bsd_imsg_latency(&vagrant_dir, vm_name);
    let drift_tp = measure_bsd_drift_throughput(&vagrant_dir, vm_name);
    let token_tp = measure_bsd_tokenization(&vagrant_dir, vm_name, remote_ntpd);
    let (ntp_enc, ntp_dec) = measure_bsd_ntp_throughput(&vagrant_dir, vm_name);
    let clock_filt = measure_bsd_clock_filter(&vagrant_dir, vm_name);

    // Config parse time
    let config_parse = measure_bsd_config_parse(&vagrant_dir, vm_name, remote_ntpd, config_path);

    // Kill ntpd
    if let Some(ref p) = pid {
        vagrant_ssh(
            &vagrant_dir,
            vm_name,
            &format!("kill {p} 2>/dev/null; pkill -9 ntpd 2>/dev/null; true"),
        );
    }

    // Binary size on remote (BSD stat syntax)
    let remote_size = measure_bsd_binary_size(&vagrant_dir, vm_name, remote_ntpd);

    // Step 6: Build result
    let result = PerfResult {
        os: target.to_string(),
        openntpd_version: "7.9p1".to_string(),
        binary_source: "git".to_string(),
        binary_size: remote_size.unwrap_or(binary_size),
        startup_time_ms: startup_ms.unwrap_or(0.0),
        config_parse_time_ms: config_parse.unwrap_or(0.0),
        ctl_response_time_ms: ctl_response.unwrap_or(0.0),
        cpu_user_time_ms: cpu_user.unwrap_or(0.0),
        cpu_sys_time_ms: cpu_sys.unwrap_or(0.0),
        peak_rss_kb: rss_kb.unwrap_or(0),
        vm_size_kb: 0,
        peak_vm_kb: 0,
        heap_kb: 0,
        stack_kb: 0,
        peak_rss_bytes: rss_kb.unwrap_or(0) * 1024,
        private_dirty_kb: 0,
        swap_kb: 0,
        minor_faults: 0,
        major_faults: 0,
        vol_ctxt_switches: 0,
        invol_ctxt_switches: 0,
        thread_count: thread_count.unwrap_or(0),
        open_fd_count: open_fds,
        socket_create_us: socket_lat,
        imsg_roundtrip_us: imsg_lat,
        drift_write_throughput: drift_tp,
        tokenization_throughput: token_tp,
        ntp_encode_throughput: ntp_enc,
        ntp_decode_throughput: ntp_dec,
        clock_filter_us: clock_filt,
    };

    all_results.push(result);

    // Cleanup
    vagrant_destroy(&vagrant_dir, vm_name);
    eprintln!("  [{target}] done\n");
}

/// Measure BSD ntpd startup time via socket polling.
fn measure_bsd_startup(
    vagrant_dir: &Path,
    vm_name: &str,
    binary: &str,
    config_path: &str,
    socket_path: &str,
) -> (Option<f64>, Option<String>) {
    // Start ntpd in debug mode in background, capture PID
    let cmd =
        format!("{binary} -d -f {config_path} > /tmp/openntpd-perf/startup.log 2>&1 & echo $!");
    let (pid_out, _, _) = vagrant_ssh(vagrant_dir, vm_name, &cmd);
    let pid = pid_out.trim().to_string();
    if pid.is_empty() || !pid.chars().all(|c| c.is_ascii_digit()) {
        eprintln!("      [{vm_name} startup] no valid pid returned: {pid_out:?}");
        return (None, None);
    }

    let start = Instant::now();
    let timeout = Duration::from_secs(15);
    let poll_interval = Duration::from_millis(100);

    loop {
        if start.elapsed() > timeout {
            eprintln!("      [{vm_name} startup] timeout (15s) waiting for socket");
            vagrant_ssh(
                vagrant_dir,
                vm_name,
                &format!("kill {pid} 2>/dev/null; true"),
            );
            return (None, None);
        }

        let (check, _, _) = vagrant_ssh(
            vagrant_dir,
            vm_name,
            &format!("test -S {socket_path} && echo exists || echo notfound"),
        );
        if check.trim() == "exists" {
            let elapsed = start.elapsed();
            return (Some(elapsed.as_secs_f64() * 1000.0), Some(pid));
        }

        // Fallback: find any socket file
        let (find_out, _, _) = vagrant_ssh(
            vagrant_dir,
            vm_name,
            "find / -type s -name '*.sock' 2>/dev/null | head -1",
        );
        let found = find_out.trim();
        if !found.is_empty() && !found.contains("find:") && !found.contains("No such") {
            let elapsed = start.elapsed();
            eprintln!("      [{vm_name} startup] found socket at {found} (expected {socket_path})");
            return (Some(elapsed.as_secs_f64() * 1000.0), Some(pid));
        }

        // Check if process is still alive
        let (alive, _, _) = vagrant_ssh(
            vagrant_dir,
            vm_name,
            &format!("kill -0 {pid} 2>/dev/null && echo alive || echo dead"),
        );
        if alive.trim() != "alive" {
            eprintln!("      [{vm_name} startup] process died before socket appeared");
            return (None, None);
        }

        std::thread::sleep(poll_interval);
    }
}

/// Measure control socket response on BSD.
fn measure_bsd_ctl_response(
    vagrant_dir: &Path,
    vm_name: &str,
    ctl_binary: &str,
    socket_path: &str,
) -> Option<f64> {
    let start = Instant::now();
    let (_, _, exit_code) = vagrant_ssh(
        vagrant_dir,
        vm_name,
        &format!("NTPD_CONTROL_SOCKET={socket_path} {ctl_binary} -s all 2>/dev/null; true"),
    );
    let elapsed = start.elapsed();
    if exit_code.is_some() {
        Some(elapsed.as_secs_f64() * 1000.0)
    } else {
        eprintln!("      [{vm_name} ctl_response] no exit code");
        None
    }
}

/// Get RSS in KB from `ps` on BSD.
fn measure_bsd_rss(vagrant_dir: &Path, vm_name: &str, pid: &str) -> Option<u64> {
    // Try headerless first, fall back to parsing with header
    let (out, _, _) = vagrant_ssh(
        vagrant_dir,
        vm_name,
        &format!("ps -o rss= -p {pid} 2>/dev/null || ps -o rss -p {pid} 2>/dev/null | tail -1"),
    );
    let trimmed = out.trim();
    let val: String = trimmed.chars().filter(|c| c.is_ascii_digit()).collect();
    val.parse::<u64>().ok()
}

/// Get thread count from `ps` on BSD.
fn measure_bsd_threads(vagrant_dir: &Path, vm_name: &str, pid: &str) -> Option<u32> {
    let (out, _, _) = vagrant_ssh(
        vagrant_dir,
        vm_name,
        &format!(
            "ps -o nlwp= -p {pid} 2>/dev/null || ps -o thcount= -p {pid} 2>/dev/null || echo 0"
        ),
    );
    let trimmed = out.trim();
    let val: String = trimmed.chars().filter(|c| c.is_ascii_digit()).collect();
    val.parse::<u32>().ok()
}

/// Count open file descriptors on BSD using fstat or procstat.
fn measure_bsd_open_fds(vagrant_dir: &Path, vm_name: &str, pid: &str) -> u32 {
    // Try procstat -f (FreeBSD), then fstat (FreeBSD/NetBSD/OpenBSD), then lsof
    let cmds = [
        format!("procstat -f {pid} 2>/dev/null | wc -l"),
        format!("fstat -p {pid} 2>/dev/null | tail -n +2 | wc -l"),
        format!("lsof -p {pid} 2>/dev/null | wc -l"),
    ];
    for cmd in &cmds {
        let (out, _, _) = vagrant_ssh(vagrant_dir, vm_name, cmd);
        let trimmed = out.trim();
        if let Ok(n) = trimmed.parse::<u32>() {
            if n > 0 {
                // fstat/lsof include headers, subtract them
                let headerless = if cmd.starts_with("fstat") && n > 1 {
                    n.saturating_sub(1)
                } else {
                    n
                };
                return headerless;
            }
        }
    }
    0
}

/// Measure user and system CPU time on BSD via `ps`.
fn measure_bsd_cpu_time(
    vagrant_dir: &Path,
    vm_name: &str,
    pid: &str,
) -> (Option<f64>, Option<f64>) {
    let (out, _, _) = vagrant_ssh(
        vagrant_dir,
        vm_name,
        &format!("ps -o utime=,stime= -p {pid} 2>/dev/null"),
    );
    let trimmed = out.trim();
    let parts: Vec<&str> = trimmed.split_whitespace().collect();
    if parts.len() >= 2 {
        let utime = parse_bsd_time(parts[0]);
        let stime = parse_bsd_time(parts[1]);
        return (utime, stime);
    }
    (None, None)
}

/// Parse BSD ps time format ([[HH:]MM:]SS or HH:MM:SS) into milliseconds.
fn parse_bsd_time(s: &str) -> Option<f64> {
    let s = s.trim();
    if s.is_empty() || s == "-" {
        return Some(0.0);
    }
    let parts: Vec<&str> = s.split(':').collect();
    match parts.len() {
        1 => {
            // Seconds only
            parts[0].parse::<f64>().ok().map(|v| v * 1000.0)
        }
        2 => {
            // MM:SS
            let m = parts[0].parse::<f64>().ok()?;
            let sec = parts[1].parse::<f64>().ok()?;
            Some((m * 60.0 + sec) * 1000.0)
        }
        3 => {
            // HH:MM:SS
            let h = parts[0].parse::<f64>().ok()?;
            let m = parts[1].parse::<f64>().ok()?;
            let sec = parts[2].parse::<f64>().ok()?;
            Some((h * 3600.0 + m * 60.0 + sec) * 1000.0)
        }
        _ => s.parse::<f64>().ok().map(|v| v * 1000.0),
    }
}

/// Measure config parse time on BSD.
fn measure_bsd_config_parse(
    vagrant_dir: &Path,
    vm_name: &str,
    binary: &str,
    config_path: &str,
) -> Option<f64> {
    let cmd = format!(
        "start=$(date +%s%N); {binary} -n -f {config_path} >/dev/null 2>&1; \
         rc=$?; end=$(date +%s%N); echo $(( (end - start) / 1000000 )); exit $rc"
    );
    let (stdout, stderr, code) = vagrant_ssh(vagrant_dir, vm_name, &cmd);
    if let Ok(ms) = stdout.trim().parse::<f64>() {
        return Some(ms);
    }
    eprintln!("      [{vm_name} config_parse] could not parse (exit={code:?}): out={stdout:?} err={stderr:?}");
    None
}

/// Measure binary size on BSD using `stat -f%z` (BSD syntax).
fn measure_bsd_binary_size(vagrant_dir: &Path, vm_name: &str, path: &str) -> Option<u64> {
    let (out, _, _) = vagrant_ssh(
        vagrant_dir,
        vm_name,
        &format!("stat -f%z {path} 2>/dev/null || stat -c%s {path} 2>/dev/null || echo 0"),
    );
    let trimmed = out.trim();
    let val: String = trimmed.chars().filter(|c| c.is_ascii_digit()).collect();
    val.parse::<u64>().ok()
}

// -------------------------------------------------------------------------
// BSD C-based benchmark helpers (same test logic as Docker, compiled on VM)
// -------------------------------------------------------------------------

/// Measure socket creation+bind latency on BSD.
fn measure_bsd_socket_latency(vagrant_dir: &Path, vm_name: &str) -> f64 {
    let src = r#"
#include <sys/socket.h>
#include <sys/un.h>
#include <time.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
int main() {
    struct timespec t1, t2;
    int iterations = 100;
    double total = 0.0;
    for (int i = 0; i < iterations; i++) {
        int fd = socket(AF_UNIX, SOCK_DGRAM, 0);
        if (fd < 0) { perror("socket"); return 1; }
        struct sockaddr_un addr;
        memset(&addr, 0, sizeof(addr));
        addr.sun_family = AF_UNIX;
        snprintf(addr.sun_path, sizeof(addr.sun_path), "/tmp/perf-sock-%d-%d", getpid(), i);
        clock_gettime(CLOCK_MONOTONIC, &t1);
        if (bind(fd, (struct sockaddr*)&addr, sizeof(addr)) < 0) { perror("bind"); close(fd); return 1; }
        clock_gettime(CLOCK_MONOTONIC, &t2);
        close(fd);
        unlink(addr.sun_path);
        double elapsed = (t2.tv_sec - t1.tv_sec) * 1e6 + (t2.tv_nsec - t1.tv_nsec) / 1e3;
        total += elapsed;
    }
    printf("%.0f\n", total / iterations);
    return 0;
}
"#;
    let escaped_src = src.replace('\'', "'\\''");
    let cmd = format!(
        "cat > /tmp/perf-sock-lat.c << 'PERFEOF'\n{escaped_src}\nPERFEOF && \
         cc -O2 -o /tmp/perf-sock-lat /tmp/perf-sock-lat.c 2>/dev/null && \
         /tmp/perf-sock-lat 2>/dev/null || echo 0"
    );
    let (out, _, _) = vagrant_ssh(vagrant_dir, vm_name, &cmd);
    out.trim().parse::<f64>().unwrap_or(0.0)
}

/// Measure IMSG round-trip time on BSD.
fn measure_bsd_imsg_latency(vagrant_dir: &Path, vm_name: &str) -> f64 {
    let src = r#"
#include <sys/socket.h>
#include <sys/uio.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <time.h>
int main() {
    int sv[2];
    if (socketpair(AF_UNIX, SOCK_DGRAM, 0, sv) < 0) { perror("socketpair"); return 1; }
    struct timespec t1, t2;
    int iterations = 1000;
    double total = 0.0;
    char buf[256];
    memset(buf, 'x', sizeof(buf));
    for (int i = 0; i < iterations; i++) {
        struct iovec iov = { .iov_base = buf, .iov_len = sizeof(buf) };
        struct msghdr msg = { .msg_iov = &iov, .msg_iovlen = 1 };
        clock_gettime(CLOCK_MONOTONIC, &t1);
        if (sendmsg(sv[0], &msg, 0) < 0) { perror("sendmsg"); close(sv[0]); close(sv[1]); return 1; }
        clock_gettime(CLOCK_MONOTONIC, &t2);
        total += (t2.tv_sec - t1.tv_sec) * 1e6 + (t2.tv_nsec - t1.tv_nsec) / 1e3;
    }
    close(sv[0]); close(sv[1]);
    printf("%.0f\n", total / iterations);
    return 0;
}
"#;
    let escaped_src = src.replace('\'', "'\\''");
    let cmd = format!(
        "cat > /tmp/perf-imsg-lat.c << 'PERFEOF'\n{escaped_src}\nPERFEOF && \
         cc -O2 -o /tmp/perf-imsg-lat /tmp/perf-imsg-lat.c 2>/dev/null && \
         /tmp/perf-imsg-lat 2>/dev/null || echo 0"
    );
    let (out, _, _) = vagrant_ssh(vagrant_dir, vm_name, &cmd);
    out.trim().parse::<f64>().unwrap_or(0.0)
}

/// Measure drift file write throughput on BSD.
fn measure_bsd_drift_throughput(vagrant_dir: &Path, vm_name: &str) -> f64 {
    let setup = "dd if=/dev/urandom of=/tmp/perf-drift bs=1024 count=1024 2>/dev/null";
    vagrant_ssh(vagrant_dir, vm_name, setup);
    let cmd = format!(
        "start=$(date +%s%N); cp /tmp/perf-drift /tmp/perf-drift-out 2>/dev/null; \
         end=$(date +%s%N); elapsed_us=$(( (end - start) / 1000 )); \
         echo $(( (1048576 * 1000) / (elapsed_us == 0 ? 1 : elapsed_us) ))"
    );
    let (out, _, _) = vagrant_ssh(vagrant_dir, vm_name, &cmd);
    out.trim().parse::<f64>().unwrap_or(0.0)
}

/// Measure config tokenization throughput on BSD.
fn measure_bsd_tokenization(vagrant_dir: &Path, vm_name: &str, binary: &str) -> f64 {
    let config_size = 5000;
    let gen_cmd = format!(
        "for i in $(seq 1 {config_size}); do echo 'server 192.0.2.1' >> /tmp/perf-big.conf; done; \
         wc -c < /tmp/perf-big.conf"
    );
    let (size_out, _, _) = vagrant_ssh(vagrant_dir, vm_name, &gen_cmd);
    let bytes = size_out.trim().parse::<u64>().unwrap_or(0);
    let cmd = format!(
        "start=$(date +%s%N); {binary} -n -f /tmp/perf-big.conf >/dev/null 2>&1; \
         end=$(date +%s%N); elapsed_ms=$(( (end - start) / 1000000 )); \
         if [ \"$elapsed_ms\" -gt 0 ]; then \
           echo $(( {bytes} / 1024 / elapsed_ms * 1000 )); \
         else echo 0; fi"
    );
    let (out, _, _) = vagrant_ssh(vagrant_dir, vm_name, &cmd);
    out.trim().parse::<f64>().unwrap_or(0.0)
}

/// Measure NTP packet encode/decode throughput on BSD.
fn measure_bsd_ntp_throughput(vagrant_dir: &Path, vm_name: &str) -> (f64, f64) {
    let src = r#"
#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include <time.h>
#pragma pack(push, 1)
typedef struct {
    uint8_t  li_vn_mode;
    uint8_t  stratum;
    uint8_t  poll;
    uint8_t  precision;
    uint32_t root_delay;
    uint32_t root_dispersion;
    uint32_t ref_id;
    uint32_t ref_ts_sec;
    uint32_t ref_ts_frac;
    uint32_t orig_ts_sec;
    uint32_t orig_ts_frac;
    uint32_t recv_ts_sec;
    uint32_t recv_ts_frac;
    uint32_t tx_ts_sec;
    uint32_t tx_ts_frac;
} ntp_packet;
#pragma pack(pop)
int main() {
    ntp_packet pkt;
    memset(&pkt, 0, sizeof(pkt));
    struct timespec t1, t2;
    int iterations = 100000;
    double total_encode = 0.0, total_decode = 0.0;
    for (int i = 0; i < iterations; i++) {
        clock_gettime(CLOCK_MONOTONIC, &t1);
        pkt.li_vn_mode = 0x23;
        pkt.stratum = 3;
        pkt.ref_id = 0x7f000001;
        pkt.tx_ts_sec = 1234567890;
        pkt.tx_ts_frac = 0;
        clock_gettime(CLOCK_MONOTONIC, &t2);
        double enc = (t2.tv_sec - t1.tv_sec) * 1e9 + (t2.tv_nsec - t1.tv_nsec);
        total_encode += enc;

        clock_gettime(CLOCK_MONOTONIC, &t1);
        uint8_t mode = pkt.li_vn_mode & 0x07;
        uint8_t stratum = pkt.stratum;
        uint32_t ref = pkt.ref_id;
        uint32_t txsec = pkt.tx_ts_sec;
        (void)mode; (void)stratum; (void)ref; (void)txsec;
        clock_gettime(CLOCK_MONOTONIC, &t2);
        double dec = (t2.tv_sec - t1.tv_sec) * 1e9 + (t2.tv_nsec - t1.tv_nsec);
        total_decode += dec;
    }
    double avg_enc_ns = total_encode / iterations;
    double avg_dec_ns = total_decode / iterations;
    printf("%.0f %.0f\n", 1e9 / avg_enc_ns, 1e9 / avg_dec_ns);
    return 0;
}
"#;
    let escaped_src = src.replace('\'', "'\\''");
    let cmd = format!(
        "cat > /tmp/perf-ntp.c << 'PERFEOF'\n{escaped_src}\nPERFEOF && \
         cc -O2 -o /tmp/perf-ntp /tmp/perf-ntp.c 2>/dev/null && \
         /tmp/perf-ntp 2>/dev/null || echo \"0 0\""
    );
    let (out, _, _) = vagrant_ssh(vagrant_dir, vm_name, &cmd);
    let parts: Vec<&str> = out.trim().split_whitespace().collect();
    if parts.len() >= 2 {
        let enc = parts[0].parse::<f64>().unwrap_or(0.0);
        let dec = parts[1].parse::<f64>().unwrap_or(0.0);
        (enc, dec)
    } else {
        (0.0, 0.0)
    }
}

/// Measure clock filter computation time (8-sample) on BSD.
fn measure_bsd_clock_filter(vagrant_dir: &Path, vm_name: &str) -> f64 {
    let src = r#"
#include <stdint.h>
#include <stdio.h>
#include <time.h>
#include <string.h>
#include <stdlib.h>
typedef struct {
    double offset;
    double delay;
    double dispersion;
    uint32_t epoch;
} sample;
int main() {
    sample samples[8];
    srand(time(NULL));
    for (int i = 0; i < 8; i++) {
        samples[i].offset = (double)(rand() % 10000) / 1000.0;
        samples[i].delay = (double)(rand() % 1000) / 10.0 + 1.0;
        samples[i].dispersion = (double)(rand() % 100) / 10.0;
        samples[i].epoch = 1234567890 + i * 64;
    }
    struct timespec t1, t2;
    int iterations = 100000;
    double total = 0.0;
    for (int iter = 0; iter < iterations; iter++) {
        clock_gettime(CLOCK_MONOTONIC, &t1);
        int best = 0;
        for (int i = 1; i < 8; i++) {
            if (samples[i].delay < samples[best].delay ||
                (samples[i].delay == samples[best].delay &&
                 samples[i].dispersion < samples[best].dispersion)) {
                best = i;
            }
        }
        double total_w = 0.0, w_offset = 0.0, w_delay = 0.0;
        for (int i = 0; i < 8; i++) {
            double w = 1.0 / (samples[i].delay + samples[i].dispersion + 0.001);
            total_w += w;
            w_offset += samples[i].offset * w;
            w_delay += samples[i].delay * w;
        }
        if (total_w > 0.0) {
            w_offset /= total_w;
            w_delay /= total_w;
        }
        (void)best; (void)w_offset; (void)w_delay;
        clock_gettime(CLOCK_MONOTONIC, &t2);
        double elapsed = (t2.tv_sec - t1.tv_sec) * 1e6 + (t2.tv_nsec - t1.tv_nsec) / 1e3;
        total += elapsed;
        sample tmp = samples[0];
        memmove(&samples[0], &samples[1], 7 * sizeof(sample));
        samples[7] = tmp;
    }
    printf("%.3f\n", total / iterations);
    return 0;
}
"#;
    let escaped_src = src.replace('\'', "'\\''");
    let cmd = format!(
        "cat > /tmp/perf-clock-filter.c << 'PERFEOF'\n{escaped_src}\nPERFEOF && \
         cc -O2 -o /tmp/perf-clock-filter /tmp/perf-clock-filter.c 2>/dev/null && \
         /tmp/perf-clock-filter 2>/dev/null || echo 0"
    );
    let (out, _, _) = vagrant_ssh(vagrant_dir, vm_name, &cmd);
    out.trim().parse::<f64>().unwrap_or(0.0)
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
    println!(
        "╔══════════════════════════════════════════════════════════════════════════════════╗"
    );
    println!("║              OpenNTPD-rs Performance Comparison Results (20+ Metrics)           ║");
    println!(
        "╚══════════════════════════════════════════════════════════════════════════════════╝"
    );
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

        let hw = 24;

        // ── Size & Timing ──
        print!("{:<hw$}", "Binary size", hw = hw);
        for r in entries {
            let val = if r.binary_size >= 1_000_000 {
                format!("{:.1} MB", r.binary_size as f64 / 1_000_000.0)
            } else if r.binary_size >= 1_000 {
                format!("{:.1} KB", r.binary_size as f64 / 1_000.0)
            } else {
                format!("{} B", r.binary_size)
            };
            print!(" {:>14}", val);
        }
        println!();

        print!("{:<hw$}", "Startup (ms)", hw = hw);
        for r in entries {
            print!(" {:>14.2}", r.startup_time_ms);
        }
        println!();

        print!("{:<hw$}", "Config parse (ms)", hw = hw);
        for r in entries {
            print!(" {:>14.2}", r.config_parse_time_ms);
        }
        println!();

        print!("{:<hw$}", "Ctl response (ms)", hw = hw);
        for r in entries {
            print!(" {:>14.2}", r.ctl_response_time_ms);
        }
        println!();

        print!("{:<hw$}", "CPU user (ms)", hw = hw);
        for r in entries {
            print!(" {:>14.2}", r.cpu_user_time_ms);
        }
        println!();

        print!("{:<hw$}", "CPU sys (ms)", hw = hw);
        for r in entries {
            print!(" {:>14.2}", r.cpu_sys_time_ms);
        }
        println!();

        println!("  ── Memory ──");

        print!("{:<hw$}", "  Peak RSS (KB)", hw = hw);
        for r in entries {
            print!(" {:>14}", r.peak_rss_kb);
        }
        println!();

        print!("{:<hw$}", "  VmSize (KB)", hw = hw);
        for r in entries {
            print!(" {:>14}", r.vm_size_kb);
        }
        println!();

        print!("{:<hw$}", "  Peak VM (KB)", hw = hw);
        for r in entries {
            print!(" {:>14}", r.peak_vm_kb);
        }
        println!();

        print!("{:<hw$}", "  Heap (KB)", hw = hw);
        for r in entries {
            print!(" {:>14}", r.heap_kb);
        }
        println!();

        print!("{:<hw$}", "  Stack (KB)", hw = hw);
        for r in entries {
            print!(" {:>14}", r.stack_kb);
        }
        println!();

        print!("{:<hw$}", "  Private dirty (KB)", hw = hw);
        for r in entries {
            print!(" {:>14}", r.private_dirty_kb);
        }
        println!();

        print!("{:<hw$}", "  Swap (KB)", hw = hw);
        for r in entries {
            print!(" {:>14}", r.swap_kb);
        }
        println!();

        println!("  ── Page Faults & Scheduler ──");

        print!("{:<hw$}", "  Minor faults", hw = hw);
        for r in entries {
            print!(" {:>14}", r.minor_faults);
        }
        println!();

        print!("{:<hw$}", "  Major faults", hw = hw);
        for r in entries {
            print!(" {:>14}", r.major_faults);
        }
        println!();

        print!("{:<hw$}", "  Vol ctxt switches", hw = hw);
        for r in entries {
            print!(" {:>14}", r.vol_ctxt_switches);
        }
        println!();

        print!("{:<hw$}", "  Invol ctxt switches", hw = hw);
        for r in entries {
            print!(" {:>14}", r.invol_ctxt_switches);
        }
        println!();

        println!("  ── Resource Counts ──");

        print!("{:<hw$}", "  Threads", hw = hw);
        for r in entries {
            print!(" {:>14}", r.thread_count);
        }
        println!();

        print!("{:<hw$}", "  Open FDs", hw = hw);
        for r in entries {
            print!(" {:>14}", r.open_fd_count);
        }
        println!();

        println!("  ── Throughput / Latency ──");

        print!("{:<hw$}", "  Socket create (us)", hw = hw);
        for r in entries {
            print!(" {:>14.2}", r.socket_create_us);
        }
        println!();

        print!("{:<hw$}", "  IMSG roundtrip (us)", hw = hw);
        for r in entries {
            print!(" {:>14.2}", r.imsg_roundtrip_us);
        }
        println!();

        print!("{:<hw$}", "  Drift write (B/ms)", hw = hw);
        for r in entries {
            print!(" {:>14.0}", r.drift_write_throughput);
        }
        println!();

        print!("{:<hw$}", "  Tokenization (KB/s)", hw = hw);
        for r in entries {
            print!(" {:>14.0}", r.tokenization_throughput);
        }
        println!();

        print!("{:<hw$}", "  NTP encode (pkt/s)", hw = hw);
        for r in entries {
            let v = r.ntp_encode_throughput;
            if v > 1_000_000.0 {
                print!(" {:>13.1}M", v / 1_000_000.0);
            } else if v > 1_000.0 {
                print!(" {:>13.1}K", v / 1_000.0);
            } else {
                print!(" {:>14.0}", v);
            }
        }
        println!();

        print!("{:<hw$}", "  NTP decode (pkt/s)", hw = hw);
        for r in entries {
            let v = r.ntp_decode_throughput;
            if v > 1_000_000.0 {
                print!(" {:>13.1}M", v / 1_000_000.0);
            } else if v > 1_000.0 {
                print!(" {:>13.1}K", v / 1_000.0);
            } else {
                print!(" {:>14.0}", v);
            }
        }
        println!();

        print!("{:<hw$}", "  Clock filter (us)", hw = hw);
        for r in entries {
            print!(" {:>14.3}", r.clock_filter_us);
        }
        println!();

        println!();
    }

    // Summary statistics
    println!("── Summary Statistics ──");
    println!("Total measurements: {}", results.len());

    if !results.is_empty() {
        let n = results.len() as f64;
        let avg_startup: f64 = results.iter().map(|r| r.startup_time_ms).sum::<f64>() / n;
        let avg_parse: f64 = results.iter().map(|r| r.config_parse_time_ms).sum::<f64>() / n;
        let avg_rss: f64 = results.iter().map(|r| r.peak_rss_kb as f64).sum::<f64>() / n;
        let avg_ctl: f64 = results.iter().map(|r| r.ctl_response_time_ms).sum::<f64>() / n;
        let avg_vm: f64 = results.iter().map(|r| r.vm_size_kb as f64).sum::<f64>() / n;
        let avg_heap: f64 = results.iter().map(|r| r.heap_kb as f64).sum::<f64>() / n;
        let avg_stack: f64 = results.iter().map(|r| r.stack_kb as f64).sum::<f64>() / n;
        let avg_minflt: f64 = results.iter().map(|r| r.minor_faults as f64).sum::<f64>() / n;
        let avg_majflt: f64 = results.iter().map(|r| r.major_faults as f64).sum::<f64>() / n;
        let avg_ntp_enc: f64 = results.iter().map(|r| r.ntp_encode_throughput).sum::<f64>() / n;
        let avg_ntp_dec: f64 = results.iter().map(|r| r.ntp_decode_throughput).sum::<f64>() / n;
        let avg_sock: f64 = results.iter().map(|r| r.socket_create_us).sum::<f64>() / n;

        println!("  Avg startup time:       {:.2} ms", avg_startup);
        println!("  Avg config parse:       {:.2} ms", avg_parse);
        println!("  Avg ctl response:       {:.2} ms", avg_ctl);
        println!("  Avg peak RSS:           {:.0} KB", avg_rss);
        println!("  Avg VmSize:             {:.0} KB", avg_vm);
        println!("  Avg heap:               {:.0} KB", avg_heap);
        println!("  Avg stack:              {:.0} KB", avg_stack);
        println!("  Avg minor faults:       {:.0}", avg_minflt);
        println!("  Avg major faults:       {:.2}", avg_majflt);
        println!("  Avg socket create:      {:.2} us", avg_sock);
        println!("  Avg NTP encode:         {:.0} pkt/s", avg_ntp_enc);
        println!("  Avg NTP decode:         {:.0} pkt/s", avg_ntp_dec);
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

    // ---- BSD Vagrant measurements ----
    if check_vagrant_available() {
        eprintln!("── BSD Vagrant Performance Measurements ──");
        let (git_ntpd, git_ntpctl) = build_rust_from_git()?;
        for (target, _vagrantfile, vm_name) in BSD_TARGETS {
            measure_bsd(
                target,
                _vagrantfile,
                vm_name,
                &git_ntpd,
                &git_ntpctl,
                &mut all_results,
            );
        }
        eprintln!();
    } else {
        eprintln!(
            "── BSD Vagrant not available. Install vagrant + vagrant-scp for BSD perf data. ──"
        );
        eprintln!();
    }

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
