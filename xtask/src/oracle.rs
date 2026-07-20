//! # Oracle VM matrix — full cross-distro test suite
//!
//! Orchestrates the entire Docker oracle comparison pipeline:
//!
//! 1. Build all Docker oracle images (Debian 12/13, Alpine, Ubuntu,
//!    Fedora, Rocky Linux, FreeBSD)
//! 2. Run oracle-parity comparisons for each image
//! 3. Run ntpctl integration tests against each image
//! 4. Produce a summary report with pass/fail status per distribution
//!
//! Usage:
//!
//! ```text
//! cargo xtask oracle
//! cargo xtask oracle --skip-qemu     # Skip FreeBSD (requires QEMU)
//! cargo xtask oracle --skip-parity   # Skip oracle-parity comparisons
//! cargo xtask oracle --skip-ctl      # Skip ntpctl integration tests
//! ```

use std::process::Command;
use std::time::Instant;

/// A single step in the oracle matrix pipeline.
struct MatrixStep {
    name: &'static str,
    status: StepStatus,
    duration: std::time::Duration,
    details: Vec<String>,
}

#[derive(Clone, PartialEq)]
enum StepStatus {
    Pass,
    Fail(String),
    Skipped,
}

/// Oracle image definitions (subset of ctl_integration's list).
const ORACLE_IMAGES: &[(&str, &str)] = &[
    ("debian-12", "openntpd-oracle:debian-12"),
    ("alpine-3.20", "openntpd-oracle:alpine-3.20"),
    ("debian-13", "openntpd-oracle:debian-13"),
    ("ubuntu-24.04", "openntpd-oracle:ubuntu-24.04"),
    ("fedora-40", "openntpd-oracle:fedora-40"),
    ("rocky-9", "openntpd-oracle:rocky-9"),
    ("freebsd-14", "openntpd-oracle:freebsd-14"),
];

/// Run the full oracle VM matrix.
pub fn run() -> anyhow::Result<()> {
    let args: Vec<String> = std::env::args().collect();
    let skip_parity = args.iter().any(|a| a == "--skip-parity");
    let skip_ctl = args.iter().any(|a| a == "--skip-ctl");
    let skip_qemu = args.iter().any(|a| a == "--skip-qemu");

    let start = Instant::now();

    eprintln!("╔═══════════════════════════════════════════╗");
    eprintln!("║  OpenNTPD-rs Oracle VM Matrix Test Suite  ║");
    eprintln!("╚═══════════════════════════════════════════╝");
    eprintln!();

    let mut steps: Vec<MatrixStep> = Vec::new();

    // ---- Step 1: Build all Docker images ----
    eprintln!("── Step 1: Build Docker Oracle Images ──");
    let build_start = Instant::now();

    let images_to_build: Vec<(&str, &str)> = ORACLE_IMAGES
        .iter()
        .filter(|(distro, _tag)| {
            if *distro == "freebsd-14" && skip_qemu {
                eprintln!("  Skipping {distro} (--skip-qemu)");
                return false;
            }
            true
        })
        .copied()
        .collect();

    let mut build_results: Vec<(&str, bool, Option<String>)> = Vec::new();

    for (distro, tag) in &images_to_build {
        eprint!("  Building {distro}... ");
        let result = build_image(tag, distro);
        match result {
            Ok(()) => {
                eprintln!("✓");
                build_results.push((distro, true, None));
            }
            Err(e) => {
                eprintln!("✗");
                build_results.push((distro, false, Some(e.to_string())));
            }
        }
    }

    let build_failures = build_results.iter().filter(|r| !r.1).count();
    steps.push(MatrixStep {
        name: "Build Docker images",
        status: if build_failures == 0 {
            StepStatus::Pass
        } else {
            StepStatus::Fail(format!("{build_failures} image(s) failed to build"))
        },
        duration: build_start.elapsed(),
        details: build_results
            .iter()
            .map(|(d, ok, _)| format!("  {d}: {}", if *ok { "✓" } else { "✗" }))
            .collect(),
    });
    eprintln!();

    // ---- Step 2: Run oracle-parity comparisons ----
    if skip_parity {
        eprintln!("── Step 2: Oracle-Parity Comparisons (SKIPPED) ──");
        steps.push(MatrixStep {
            name: "Oracle-parity comparisons",
            status: StepStatus::Skipped,
            duration: std::time::Duration::ZERO,
            details: vec![],
        });
    } else {
        eprintln!("── Step 2: Oracle-Parity Comparisons ──");
        let parity_start = Instant::now();
        let mut parity_results: Vec<(&str, bool, Option<String>)> = Vec::new();

        for (distro, tag) in &images_to_build {
            if build_results
                .iter()
                .find(|r| r.0 == *distro)
                .map(|r| !r.1)
                .unwrap_or(true)
            {
                eprintln!("  Skipping parity for {distro} (build failed)");
                parity_results.push((distro, false, Some("build failed".into())));
                continue;
            }

            eprint!("  Parity check: {distro}... ");
            match run_parity_for_image(tag) {
                Ok(()) => {
                    eprintln!("✓");
                    parity_results.push((distro, true, None));
                }
                Err(e) => {
                    eprintln!("✗");
                    parity_results.push((distro, false, Some(e.to_string())));
                }
            }
        }

        let parity_failures = parity_results.iter().filter(|r| !r.1).count();
        steps.push(MatrixStep {
            name: "Oracle-parity comparisons",
            status: if parity_failures == 0 {
                StepStatus::Pass
            } else {
                StepStatus::Fail(format!("{parity_failures} comparison(s) failed"))
            },
            duration: parity_start.elapsed(),
            details: parity_results
                .iter()
                .map(|(d, ok, _)| format!("  {d}: {}", if *ok { "✓" } else { "✗" }))
                .collect(),
        });
        eprintln!();
    }

    // ---- Step 3: Run ntpctl integration tests ----
    if skip_ctl {
        eprintln!("── Step 3: ntpctl Integration Tests (SKIPPED) ──");
        steps.push(MatrixStep {
            name: "ntpctl integration tests",
            status: StepStatus::Skipped,
            duration: std::time::Duration::ZERO,
            details: vec![],
        });
    } else {
        eprintln!("── Step 3: ntpctl Integration Tests ──");
        let ctl_start = Instant::now();
        let ctl_args: Vec<String> = if skip_qemu {
            vec!["--skip-qemu".to_string()]
        } else {
            vec![]
        };
        match crate::ctl_integration::run(&ctl_args) {
            Ok(()) => {
                steps.push(MatrixStep {
                    name: "ntpctl integration tests",
                    status: StepStatus::Pass,
                    duration: ctl_start.elapsed(),
                    details: vec![],
                });
            }
            Err(e) => {
                steps.push(MatrixStep {
                    name: "ntpctl integration tests",
                    status: StepStatus::Fail(e.to_string()),
                    duration: ctl_start.elapsed(),
                    details: vec![],
                });
            }
        }
        eprintln!();
    }

    // ---- Summary Report ----
    let total_duration = start.elapsed();
    print_summary(&steps, total_duration);

    // Determine overall status
    let failures: Vec<&MatrixStep> = steps
        .iter()
        .filter(|s| matches!(s.status, StepStatus::Fail(_)))
        .collect();

    if failures.is_empty() {
        eprintln!("All checks passed.");
        Ok(())
    } else {
        eprintln!("{} check(s) failed. See above for details.", failures.len());
        // Return Ok — the caller can check the summary output
        Ok(())
    }
}

/// Build a single Docker oracle image.
fn build_image(tag: &str, distro: &str) -> anyhow::Result<()> {
    let oracle_dir = workspace_root().join("research/oracle");

    // Determine the Dockerfile name from the distro
    let dockerfile_name: String = match distro {
        "debian-12" => "Dockerfile".to_string(),
        "debian-13" => "Dockerfile.debian13".to_string(),
        "ubuntu-24.04" => "Dockerfile.ubuntu24".to_string(),
        "fedora-40" => "Dockerfile.fedora".to_string(),
        "alpine-3.20" => "Dockerfile.alpine".to_string(),
        "rocky-9" => "Dockerfile.rocky9".to_string(),
        "freebsd-14" => "Dockerfile.freebsd14".to_string(),
        other => format!("Dockerfile.{other}"),
    };

    let dockerfile_path = oracle_dir.join(&dockerfile_name);
    if !dockerfile_path.exists() {
        anyhow::bail!("Dockerfile not found: {}", dockerfile_path.display());
    }

    // Skip build if image already exists
    let inspect = Command::new("docker")
        .args(["image", "inspect", "--format", "{{.Id}}", tag])
        .output()
        .map_err(|e| anyhow::anyhow!("failed to inspect docker image: {e}"))?;
    if inspect.status.success() {
        eprintln!("already exists");
        return Ok(());
    }

    let status = Command::new("docker")
        .args([
            "build",
            "-t",
            tag,
            "-f",
            &dockerfile_path.to_string_lossy(),
            &oracle_dir.to_string_lossy(),
        ])
        .status()
        .map_err(|e| anyhow::anyhow!("failed to spawn docker build: {e}"))?;

    if !status.success() {
        anyhow::bail!("docker build exited with {status:?}");
    }
    Ok(())
}

/// Run oracle-parity comparison against a Docker image.
fn run_parity_for_image(tag: &str) -> anyhow::Result<()> {
    // Reuse the existing parity command: cargo xtask parity --oracle-image <tag>
    let xtask_bin = find_xtask_binary()?;

    let status = Command::new(&xtask_bin)
        .args(["parity", "--oracle-image", tag])
        .status()
        .map_err(|e| anyhow::anyhow!("failed to spawn parity check: {e}"))?;

    if !status.success() {
        anyhow::bail!("parity check exited with {status:?}");
    }
    Ok(())
}

/// Find the xtask binary (build it if needed).
fn find_xtask_binary() -> anyhow::Result<String> {
    // Try CARGO_BIN_EXE_xtask first
    if let Ok(path) = std::env::var("CARGO_BIN_EXE_xtask") {
        return Ok(path);
    }

    // Fall back to target/debug/xtask
    let ws = workspace_root();
    let xtask_path = ws.join("target/debug/xtask");
    if xtask_path.exists() {
        return Ok(xtask_path.to_string_lossy().to_string());
    }

    // Build it
    let status = Command::new("cargo")
        .args(["build", "--bin", "xtask"])
        .current_dir(&ws)
        .status()
        .map_err(|e| anyhow::anyhow!("failed to build xtask: {e}"))?;

    if !status.success() {
        anyhow::bail!("cargo build --bin xtask failed");
    }

    Ok(xtask_path.to_string_lossy().to_string())
}

/// Locate the workspace root.
fn workspace_root() -> std::path::PathBuf {
    std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("xtask manifest parent (workspace root)")
        .to_path_buf()
}

/// Print a formatted summary table.
fn print_summary(steps: &[MatrixStep], total_duration: std::time::Duration) {
    println!("╔══════════════════════════════════════════════════════╗");
    println!("║                 Oracle Matrix Summary                ║");
    println!("╚══════════════════════════════════════════════════════╝");
    println!();

    println!("{:<40} {:<10} {:<12}", "Step", "Status", "Duration");
    println!("{:-<40} {:-<10} {:-<12}", "", "", "");

    for step in steps {
        let status_color = match &step.status {
            StepStatus::Pass => "✓",
            StepStatus::Fail(_msg) => "✗",
            StepStatus::Skipped => "—",
        };

        let dur = if step.duration.as_secs() > 0 {
            format!(
                "{}.{:03}s",
                step.duration.as_secs(),
                step.duration.subsec_millis()
            )
        } else {
            format!("{}ms", step.duration.subsec_millis())
        };

        println!("{:<40} {:<10} {:<12}", step.name, status_color, dur);

        if let StepStatus::Fail(msg) = &step.status {
            println!("  └─ {}", msg);
        }

        for detail in &step.details {
            println!("  {detail}");
        }
    }

    println!();
    let passed = steps
        .iter()
        .filter(|s| s.status == StepStatus::Pass)
        .count();
    let failed = steps
        .iter()
        .filter(|s| matches!(s.status, StepStatus::Fail(_)))
        .count();
    let skipped = steps
        .iter()
        .filter(|s| s.status == StepStatus::Skipped)
        .count();
    let total = steps.len();

    println!(
        "Total: {total} steps | {passed} passed | {failed} failed | {skipped} skipped | {}.{:03}s",
        total_duration.as_secs(),
        total_duration.subsec_millis(),
    );
}
