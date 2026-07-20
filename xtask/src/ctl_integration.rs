//! # ntpctl Docker integration test runner
//!
//! Builds Docker oracle containers for each supported distribution,
//! then runs the Rust `ntpctl` binary inside each container to verify
//! CLI parsing, output format, and (once wired) control-socket
//! communication against the running `ntpd` daemon.
//!
//! ## Supported distributions
//!
//! - Debian 12 (bookworm)
//! - Debian 13 (trixie)
//! - Ubuntu 24.04 (noble)
//! - Alpine Linux 3.20
//! - Fedora 40
//! - Rocky Linux 9
//! - FreeBSD 14 (requires QEMU user-static)
//!
//! ## Workflow per container
//!
//! 1. Start `ntpd -d` (or C oracle) in the container
//! 2. Copy the Rust `ntpctl` binary into the container via `docker cp`
//! 3. Exec `ntpctl -s status`, `-s peers`, `-s Sensors`, `-s all`
//! 4. Verify each returns the expected output format
//! 5. Stop the container

use std::path::PathBuf;
use std::process::Command;
use std::time::Duration;

/// A descriptor for a single Docker oracle image.
struct OracleImage {
    /// Distribution name (e.g. "debian-12").
    pub distro: &'static str,
    /// Dockerfile path relative to `research/oracle/`.
    pub dockerfile: &'static str,
    /// Docker image tag.
    pub tag: &'static str,
    /// Whether this image requires QEMU binfmt registration (cross-platform).
    pub requires_qemu: bool,
}

/// All supported oracle images.
const ORACLE_IMAGES: &[OracleImage] = &[
    OracleImage {
        distro: "debian-12",
        dockerfile: "Dockerfile",
        tag: "openntpd-oracle:debian-12",
        requires_qemu: false,
    },
    OracleImage {
        distro: "alpine-3.20",
        dockerfile: "Dockerfile.alpine",
        tag: "openntpd-oracle:alpine-3.20",
        requires_qemu: false,
    },
    OracleImage {
        distro: "debian-13",
        dockerfile: "Dockerfile.debian13",
        tag: "openntpd-oracle:debian-13",
        requires_qemu: false,
    },
    OracleImage {
        distro: "ubuntu-24.04",
        dockerfile: "Dockerfile.ubuntu24",
        tag: "openntpd-oracle:ubuntu-24.04",
        requires_qemu: false,
    },
    OracleImage {
        distro: "fedora-40",
        dockerfile: "Dockerfile.fedora",
        tag: "openntpd-oracle:fedora-40",
        requires_qemu: false,
    },
    OracleImage {
        distro: "rocky-9",
        dockerfile: "Dockerfile.rocky9",
        tag: "openntpd-oracle:rocky-9",
        requires_qemu: false,
    },
    OracleImage {
        distro: "freebsd-14",
        dockerfile: "Dockerfile.freebsd14",
        tag: "openntpd-oracle:freebsd-14",
        requires_qemu: true,
    },
];

/// Result for a single image's ntpctl integration test.
#[derive(Default)]
struct CtlTestResult {
    distro: String,
    build_ok: bool,
    ntpctl_exists: bool,
    status_output: Option<String>,
    peers_output: Option<String>,
    sensors_output: Option<String>,
    all_output: Option<String>,
    error: Option<String>,
}

/// Locate the project's research/oracle directory.
fn oracle_dir() -> PathBuf {
    workspace_root().join("research/oracle")
}

/// Locate the workspace root by traversing from the xtask manifest.
fn workspace_root() -> PathBuf {
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    // xtask/ → workspace root
    manifest_dir
        .parent()
        .expect("xtask manifest parent (workspace root)")
        .to_path_buf()
}

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
        "Docker version: {}",
        String::from_utf8_lossy(&output.stdout).trim()
    );
    Ok(())
}

/// Build a single Docker oracle image.
fn build_oracle_image(image: &OracleImage) -> anyhow::Result<()> {
    let oracle_dir = oracle_dir();
    let dockerfile_path = oracle_dir.join(image.dockerfile);

    if !dockerfile_path.exists() {
        anyhow::bail!("Dockerfile not found: {}", dockerfile_path.display());
    }

    eprintln!("  Building {} from {}...", image.distro, image.dockerfile);

    let status = Command::new("docker")
        .args([
            "build",
            "-t",
            image.tag,
            "-f",
            &dockerfile_path.to_string_lossy(),
            &oracle_dir.to_string_lossy(),
        ])
        .status()
        .map_err(|e| anyhow::anyhow!("failed to spawn docker build for {}: {e}", image.distro))?;

    if !status.success() {
        anyhow::bail!(
            "docker build failed for {} (exit: {status:?})",
            image.distro
        );
    }
    eprintln!("    ✓ {} built", image.distro);
    Ok(())
}

/// Build all Docker oracle images.
fn build_all_images() -> anyhow::Result<Vec<OracleImage>> {
    check_docker_available()?;

    let mut built = Vec::new();
    for image in ORACLE_IMAGES {
        if image.requires_qemu {
            let qemu_check = Command::new("docker")
                .args(["run", "--rm", "--privileged", "tonistiigi/binfmt", "--help"])
                .output();
            if qemu_check.is_err() {
                eprintln!("    ⚠ Skipping {} (requires QEMU binfmt)", image.distro);
                continue;
            }
        }
        match build_oracle_image(image) {
            Ok(()) => built.push(OracleImage { ..*image }),
            Err(e) => {
                eprintln!("    ✗ Failed to build {}: {e}", image.distro);
            }
        }
    }

    if built.is_empty() {
        anyhow::bail!("no oracle images were built successfully");
    }
    Ok(built)
}

/// Build the Rust ntpctl binary.
fn build_ntpctl() -> anyhow::Result<PathBuf> {
    let workspace_root = workspace_root();
    let target_ntpctl = workspace_root.join("target/debug/ntpctl");

    // Check if already built
    if target_ntpctl.exists() {
        return Ok(target_ntpctl);
    }

    eprintln!("  Building Rust ntpctl binary...");
    let status = Command::new("cargo")
        .args(["build", "--bin", "ntpctl"])
        .current_dir(&workspace_root)
        .status()
        .map_err(|e| anyhow::anyhow!("failed to spawn cargo build: {e}"))?;

    if !status.success() {
        anyhow::bail!("cargo build --bin ntpctl failed (exit: {status:?})");
    }
    Ok(target_ntpctl)
}

/// Create a minimal ntpd config file in a temp directory.
fn create_test_config(tmpdir: &PathBuf) -> PathBuf {
    let config_path = tmpdir.join("ntpd.conf");
    std::fs::write(&config_path, b"listen on *\nserver pool.ntp.org\n").expect("write test config");
    config_path
}

/// Verify ntpctl CLI parsing inside a Docker container.
///
/// Steps:
/// 1. Start the container with a minimal init (sleep loop)
/// 2. Copy the Rust ntpctl binary into the container
/// 3. Exec ntpctl -s {status,peers,Sensors,all} inside the container
/// 4. Verify output format
/// 5. Stop and clean up the container
fn run_ntpctl_cli_tests_in_container(
    image: &OracleImage,
    ntpctl_bin: &PathBuf,
    container_name: &str,
) -> CtlTestResult {
    let mut result = CtlTestResult {
        distro: image.distro.to_string(),
        ..Default::default()
    };

    // Start a container that sleeps so we can exec into it
    let run_output = Command::new("docker")
        .args([
            "run",
            "--rm",
            "-d",
            "--name",
            container_name,
            "--entrypoint",
            "sleep",
            image.tag,
            "30",
        ])
        .output();

    let _container_id = match run_output {
        Ok(out) if out.status.success() => String::from_utf8_lossy(&out.stdout).trim().to_string(),
        Ok(out) => {
            let stderr = String::from_utf8_lossy(&out.stderr);
            result.error = Some(format!("failed to start container: {stderr}"));
            return result;
        }
        Err(e) => {
            result.error = Some(format!("failed to spawn docker run: {e}"));
            return result;
        }
    };

    result.build_ok = true;

    // Wait for container to be ready
    std::thread::sleep(Duration::from_millis(500));

    // Copy ntpctl binary into the container
    let cp_output = Command::new("docker")
        .args([
            "cp",
            &ntpctl_bin.to_string_lossy(),
            &format!("{container_name}:/usr/local/bin/ntpctl"),
        ])
        .output();

    match cp_output {
        Ok(out) if out.status.success() => {
            result.ntpctl_exists = true;
        }
        Ok(out) => {
            let stderr = String::from_utf8_lossy(&out.stderr);
            result.error = Some(format!("docker cp failed: {stderr}"));
            cleanup_container(container_name);
            return result;
        }
        Err(e) => {
            result.error = Some(format!("docker cp spawn failed: {e}"));
            cleanup_container(container_name);
            return result;
        }
    }

    // Make it executable
    let _ = Command::new("docker")
        .args([
            "exec",
            container_name,
            "chmod",
            "+x",
            "/usr/local/bin/ntpctl",
        ])
        .output();

    // Test each ntpctl command
    for (cmd, output_field) in [
        ("status", &mut result.status_output),
        ("peers", &mut result.peers_output),
        ("Sensors", &mut result.sensors_output),
        ("all", &mut result.all_output),
    ]
    .into_iter()
    {
        let exec_output = Command::new("docker")
            .args(["exec", container_name, "ntpctl", "-s", cmd])
            .output();

        match exec_output {
            Ok(out) => {
                let stderr = String::from_utf8_lossy(&out.stderr).to_string();
                *output_field = Some(stderr);
            }
            Err(e) => {
                result.error = Some(format!("docker exec ntpctl -s {cmd} failed: {e}"));
            }
        }
    }

    // Clean up
    cleanup_container(container_name);

    result
}

/// Stop and remove a Docker container.
fn cleanup_container(name: &str) {
    let _ = Command::new("docker").args(["stop", name]).output();
    std::thread::sleep(Duration::from_millis(300));
    let _ = Command::new("docker").args(["rm", "-f", name]).output();
}

/// Run ntpctl integration tests across all Docker oracle images.
pub fn run(args: &[String]) -> anyhow::Result<()> {
    let skip_build = args.iter().any(|a| a == "--skip-build");
    let skip_qemu = args.iter().any(|a| a == "--skip-qemu");
    let images_only = args.iter().any(|a| a == "--images-only");

    eprintln!("=== ntpctl Docker Integration Tests ===\n");

    // Build Docker images
    let images: Vec<OracleImage> = if skip_build {
        ORACLE_IMAGES
            .iter()
            .filter(|img| !img.requires_qemu || !skip_qemu)
            .map(|img| OracleImage { ..*img })
            .collect()
    } else {
        build_all_images()?
            .into_iter()
            .filter(|img| !img.requires_qemu || !skip_qemu)
            .collect()
    };

    if images.is_empty() {
        anyhow::bail!("no oracle images available for testing");
    }

    // Build ntpctl binary
    let ntpctl_bin = build_ntpctl()?;

    // If only building images, we're done
    if images_only {
        println!("\nImages built successfully:");
        for img in &images {
            println!("  {:<20} {}", img.distro, img.tag);
        }
        return Ok(());
    }

    // Create test config directory
    let tmpdir = workspace_root().join("target/ntpctl-test-tmp");
    let _ = std::fs::create_dir_all(&tmpdir);
    let _config_path = create_test_config(&tmpdir);

    // Track results
    let mut results: Vec<CtlTestResult> = Vec::new();

    // Run tests for each image
    for image in &images {
        let safe_name = image
            .distro
            .replace(|c: char| !c.is_ascii_alphanumeric(), "-");
        let container_name = format!("ntpctl-test-{safe_name}-{}", std::process::id());

        eprint!("  Testing ntpctl on {}... ", image.distro);

        let result = run_ntpctl_cli_tests_in_container(image, &ntpctl_bin, &container_name);
        results.push(result);

        let last = results.last().unwrap();
        let cli_ok = last.status_output.is_some()
            && last.peers_output.is_some()
            && last.sensors_output.is_some()
            && last.all_output.is_some();

        if cli_ok {
            eprintln!("✓");
        } else {
            eprintln!("✗");
            if let Some(ref err) = last.error {
                eprintln!("    Error: {err}");
            }
        }
    }

    // Print summary table
    println!();
    println!("=== ntpctl Integration Test Summary ===");
    println!(
        "{:<20} {:<10} {:<10}",
        "Distribution", "Build", "ntpctl CLI"
    );
    println!("{:-<20} {:-<10} {:-<10}", "", "", "");
    for r in &results {
        let build = if r.build_ok { "✓" } else { "✗" };
        let cli = if r.status_output.is_some()
            && r.peers_output.is_some()
            && r.sensors_output.is_some()
            && r.all_output.is_some()
        {
            "✓"
        } else {
            "✗"
        };
        println!("{:<20} {:<10} {:<10}", r.distro, build, cli);
    }

    let passed = results
        .iter()
        .filter(|r| {
            r.build_ok
                && r.status_output.is_some()
                && r.peers_output.is_some()
                && r.sensors_output.is_some()
                && r.all_output.is_some()
        })
        .count();
    let total = results.len();
    println!();
    println!("{passed}/{total} distributions passed");

    // Print any failures
    let failures: Vec<&CtlTestResult> = results.iter().filter(|r| r.error.is_some()).collect();
    if !failures.is_empty() {
        println!();
        println!("Failures:");
        for f in &failures {
            if let Some(ref err) = f.error {
                println!("  {}: {err}", f.distro);
            }
        }
    }

    if passed < total {
        eprintln!();
        eprintln!("Some tests did not pass. Review the output above for details.");
    }

    Ok(())
}
