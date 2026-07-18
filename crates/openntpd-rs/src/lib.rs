//! # openntpd-rs
//!
//! Umbrella facade crate for the openntpd-rs workspace.
//! Re-exports `openntpd-rs-core` and `openntpd-rs-io`.
//!
//! ## Binaries
//!
//! - `ntpd` — daemon binary (in `openntpd-rs-d` crate)
//! - `ntpctl` — control client binary (in `openntpd-rs-ctl` crate)
//!
//! ## License
//!
//! MIT OR Apache-2.0

pub use openntpd_rs_core as core;
pub use openntpd_rs_io as io;
