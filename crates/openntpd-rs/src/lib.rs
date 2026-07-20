//! # openntpd-rs
//!
//! Umbrella facade crate for the openntpd-rs workspace.
//! Re-exports `openntpd-rs-core`, `openntpd-rs-io`, `openntpd-rs-d`,
//! and `openntpd-rs-ctl`.
//!
//! ## Binaries
//!
//! - `ntpd` — daemon binary (in `openntpd-rs-d` crate)
//! - `ntpctl` — control client binary (in `openntpd-rs-ctl` crate)
//!
//! ## Library
//!
//! When used as a library dependency, this crate re-exports all
//! modules from the core and io crates.
//!
//! ## License
//!
//! MIT OR Apache-2.0

pub use openntpd_rs_core as core;
pub use openntpd_rs_ctl as ctl;
pub use openntpd_rs_d as daemon;
pub use openntpd_rs_io as io;
