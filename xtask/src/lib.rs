//! # xtask — OpenNTPD-rs build automation
//!
//! Provides `cargo xtask <command>` subcommands:
//!
//! - `gen`       — Generate documentation (port-parity matrix,
//!                 negative-capabilities ledger, crate READMEs).
//! - `check`     — Verify generated docs are fresh (CI gate).
//! - `parity`    — Compare against the real `ntpd` oracle.
//! - `no-orig`   — Verify no original OpenNTPD C source is present.
//! - `completions` — Generate shell completions.

// Re-export subcommand modules.
pub mod check;
pub mod forensic;
pub mod gen;
pub mod no_orig;
pub mod parity;
