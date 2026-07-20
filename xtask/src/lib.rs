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
//! - `oracle`    — Build Docker oracle VM matrix and run integration tests.
//! - `ctl-test`  — Run ntpctl integration tests against Docker oracles.
//! - `compat`    — Multi-version cross-compatibility test suite.

// Re-export subcommand modules.
pub mod build_musl;
pub mod check;
pub mod compat;
pub mod compat_crates;
pub mod ctl_integration;
pub mod forensic;
pub mod gen;
pub mod no_orig;
pub mod oracle;
pub mod parity;
pub mod perf;
