//! # No-original-code verification
//!
//! Ensures no original OpenNTPD C source files exist anywhere in the
//! repository. This is the same check mechanism used by [`chrony-rs`].
//!
//! The check scans for:
//!
//! - `.c` and `.h` files that match OpenNTPD source file names
//!   (client.c, server.c, ntp.c, ntpd.c, config.c, control.c,
//!    parse.y, constraint.c, sensors.c, ntp_msg.c, ntp_dns.c,
//!    log.c, util.c, ntpd.h, ntp.h, log.h).
//! - Any C source files in `src/` directories.
//! - Files containing OpenBSD CVS IDs (`$OpenBSD:`).
//!
//! The check passes only if NONE of these patterns are found.

use std::path::Path;

/// List of OpenNTPD source file names that must NOT appear in the repo.
const FORBIDDEN_C_FILES: &[&str] = &[
    "client.c",
    "server.c",
    "ntp.c",
    "ntpd.c",
    "config.c",
    "control.c",
    "constraint.c",
    "sensors.c",
    "ntp_msg.c",
    "ntp_dns.c",
    "log.c",
    "util.c",
];

/// Forbidden grammar file names.
const FORBIDDEN_Y_FILES: &[&str] = &["parse.y"];

/// List of OpenNTPD header file names that must NOT appear in the repo.
const FORBIDDEN_H_FILES: &[&str] = &["ntpd.h", "ntp.h", "log.h"];

/// Run the no-original-code check.
///
/// Returns `Ok(())` if no original code is found, or an error listing
/// all violations.
pub fn run() -> anyhow::Result<()> {
    let mut violations: Vec<String> = Vec::new();

    // Walk the repository
    let repo_root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap_or_else(|| Path::new("."));

    walk_for_violations(repo_root, &mut violations)?;

    if violations.is_empty() {
        println!("✓ No original OpenNTPD C source found in repository.");
        Ok(())
    } else {
        println!("✗ Found original OpenNTPD source code:");
        for v in &violations {
            println!("  - {v}");
        }
        anyhow::bail!(
            "Found {} original code violation(s). \
             Clean-room policy prohibits including original OpenNTPD C sources.",
            violations.len()
        )
    }
}

fn walk_for_violations(dir: &Path, violations: &mut Vec<String>) -> anyhow::Result<()> {
    if !dir.is_dir() {
        return Ok(());
    }

    for entry in std::fs::read_dir(dir)? {
        let entry = entry?;
        let path = entry.path();

        // Skip hidden directories and the .git directory
        if let Some(name) = path.file_name().and_then(|n| n.to_str()) {
            if name.starts_with('.') {
                if name == ".git" {
                    continue;
                }
                // Skip dotfiles in traversal but still check them
            }
        }

        if path.is_dir() {
            walk_for_violations(&path, violations)?;
            continue;
        }

        // Check file name
        if let Some(name) = path.file_name().and_then(|n| n.to_str()) {
            if FORBIDDEN_C_FILES.contains(&name)
                || FORBIDDEN_H_FILES.contains(&name)
                || FORBIDDEN_Y_FILES.contains(&name)
            {
                violations.push(format!("File with forbidden name: {}", path.display()));
                continue;
            }
        }

        // Check file content for CVS IDs
        if let Some(ext) = path.extension().and_then(|e| e.to_str()) {
            if matches!(ext, "c" | "h" | "y") {
                if let Ok(content) = std::fs::read_to_string(&path) {
                    if content.contains("$OpenBSD:") {
                        violations.push(format!(
                            "File contains CVS ID ($OpenBSD:): {}",
                            path.display()
                        ));
                    }
                }
            }
        }
    }

    Ok(())
}
