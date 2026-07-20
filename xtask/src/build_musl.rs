//! # build-musl — Cross-compile all Rust binaries for `x86_64-unknown-linux-musl`.
//!
//! Builds statically-linked musl binaries for maximum portability across
//! Linux distributions (no glibc version dependency).
//!
//! ## Usage
//!
//! ```text
//! cargo xtask build-musl [--release]
//! ```
//!
//! ## Prerequisites
//!
//! - `rustup target add x86_64-unknown-linux-musl`
//! - musl cross toolchain (`musl-tools` on Debian, `musl-dev` on Alpine)
//!
//! ## Output
//!
//! Binaries are placed in `target/x86_64-unknown-linux-musl/{debug,release}/`.

use std::path::PathBuf;
use std::process::Command;

/// Locate the workspace root.
fn workspace_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("xtask manifest parent (workspace root)")
        .to_path_buf()
}

/// Run the musl cross-compilation.
pub fn run(args: &[String]) -> anyhow::Result<()> {
    let release = args.iter().any(|a| a == "--release");
    let profile = if release { "release" } else { "debug" };

    let ws = workspace_root();

    eprintln!("╔══════════════════════════════════════════════════════╗");
    eprintln!("║    OpenNTPD-rs musl cross-compile                   ║");
    eprintln!("║    target: x86_64-unknown-linux-musl                ║");
    eprintln!("║    profile: {profile:<38} ║");
    eprintln!("╚══════════════════════════════════════════════════════╝");
    eprintln!();

    // Step 1: Verify the musl target is installed
    eprintln!("── Step 1: Check target ──");
    let target_check = Command::new("rustup")
        .args(["target", "list", "--installed"])
        .output()
        .map_err(|e| anyhow::anyhow!("failed to run rustup: {e}"))?;

    let installed_targets = String::from_utf8_lossy(&target_check.stdout);
    if !installed_targets.contains("x86_64-unknown-linux-musl") {
        eprintln!("  Target x86_64-unknown-linux-musl not installed. Installing...");
        let install_status = Command::new("rustup")
            .args(["target", "add", "x86_64-unknown-linux-musl"])
            .status()
            .map_err(|e| anyhow::anyhow!("failed to run rustup target add: {e}"))?;
        if !install_status.success() {
            anyhow::bail!("rustup target add x86_64-unknown-linux-musl failed");
        }
        eprintln!("  ✓ Installed x86_64-unknown-linux-musl");
    } else {
        eprintln!("  ✓ x86_64-unknown-linux-musl is already installed");
    }
    eprintln!();

    // Step 2: Build all binaries for musl target
    eprintln!("── Step 2: Cross-compile all binaries ──");

    let mut cargo_args = vec![
        "build".to_string(),
        "--target".to_string(),
        "x86_64-unknown-linux-musl".to_string(),
        "--workspace".to_string(),
        "--bins".to_string(),
    ];
    if release {
        cargo_args.push("--release".to_string());
    }

    let mut envs: Vec<(&str, &str)> = vec![];
    // On Linux with x86_64, we need +crt-static for fully static build
    if cfg!(target_os = "linux") && cfg!(target_arch = "x86_64") {
        envs.push(("RUSTFLAGS", "-C target-feature=+crt-static"));
    }

    let mut cmd = Command::new("cargo");
    cmd.args(&cargo_args).current_dir(&ws);
    for (k, v) in envs {
        cmd.env(k, v);
    }

    let status = cmd
        .status()
        .map_err(|e| anyhow::anyhow!("cargo build failed: {e}"))?;
    if !status.success() {
        anyhow::bail!("cargo build for x86_64-unknown-linux-musl failed");
    }

    eprintln!("  ✓ Build succeeded");

    // Step 3: List produced binaries
    eprintln!();
    eprintln!("── Step 3: Output ──");
    let target_dir = ws
        .join("target")
        .join("x86_64-unknown-linux-musl")
        .join(profile);
    if target_dir.exists() {
        let actual_bin_dir = target_dir;
        let _ = actual_bin_dir.as_path(); // satisfy unused warning
        eprintln!("  Output directory: {}", actual_bin_dir.display());

        if let Ok(entries) = std::fs::read_dir(&actual_bin_dir) {
            for entry in entries.flatten() {
                let path = entry.path();
                if let Some(name) = path.file_name() {
                    let name_str = name.to_string_lossy();
                    // Only list binary files (no .d files)
                    if !name_str.ends_with(".d") {
                        let metadata = std::fs::metadata(&path);
                        if let Ok(md) = metadata {
                            let size = md.len();
                            eprintln!("  {:<30} {:>8} bytes", name_str, size);
                        }
                    }
                }
            }
        }
    }

    eprintln!();
    eprintln!("╔══════════════════════════════════════════════════════╗");
    eprintln!("║    musl build complete                              ║");
    eprintln!("╚══════════════════════════════════════════════════════╝");

    Ok(())
}
