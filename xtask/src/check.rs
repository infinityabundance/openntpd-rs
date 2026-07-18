//! # Freshness check
//!
//! Verifies that all generated docs are up-to-date by regenerating
//! them and comparing against what's on disk.
//!
//! Returns an error (non-zero exit) if any file differs.

use std::path::Path;

/// Run the freshness check.
pub fn run() -> anyhow::Result<()> {
    let repo_root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap_or_else(|| Path::new("."));

    let docs_gen = repo_root.join("docs").join("generated");

    // Re-generate into a temp dir
    let tmp = std::env::temp_dir().join("openntpd-rs-check");
    let _ = std::fs::remove_dir_all(&tmp);
    std::fs::create_dir_all(&tmp)?;

    // Generate fresh copies
    crate::gen::run_inner(&tmp)?;

    // Compare each expected file
    let expected_files = &["port-parity.md", "negative-capabilities.md"];

    let mut ok = true;
    for fname in expected_files {
        let generated = docs_gen.join(fname);
        let fresh = tmp.join(fname);

        let gen_content = std::fs::read_to_string(&generated).unwrap_or_default();
        let fresh_content = std::fs::read_to_string(&fresh).unwrap_or_default();

        if gen_content != fresh_content {
            println!("✗ {fname} is stale — re-run `cargo xtask gen`");
            ok = false;
        } else {
            println!("✓ {fname} is fresh");
        }
    }

    let _ = std::fs::remove_dir_all(&tmp);

    if ok {
        println!("✓ All generated docs are fresh.");
        Ok(())
    } else {
        anyhow::bail!("Generated docs are stale. Run `cargo xtask gen`.");
    }
}
