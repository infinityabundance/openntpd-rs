//! # openntpd-rs-ctl
//!
//! Library component for the `ntpctl` control client binary.
//! Corresponds to OpenNTPD's `ntpctl` command (ntpctl(8)).
//!
//! Provides control-socket communication over the imsg protocol
//! used by `ntpd` for administration.

pub use openntpd_rs_core as core;
pub use openntpd_rs_io as io;

/// Default control socket path matching OpenNTPD convention.
pub const DEFAULT_CONTROL_SOCKET: &str = "/var/run/ntpd.sock";

/// imsg header size: 12 bytes (type + peer_id + length).
pub const IMSG_HEADER_SIZE: usize = 12;

/// Control socket read timeout in seconds.
pub const CTL_SOCKET_TIMEOUT_SECS: u64 = 5;

/// Maximum control socket payload we'll accept (1 MB).
pub const MAX_PAYLOAD: usize = 1_048_576;

/// Valid status query targets matching ntpctl(8).
pub const VALID_TARGETS: &[&str] = &["status", "peers", "Sensors", "all"];

/// Exit codes matching OpenNTPD conventions.
pub const EXIT_ERROR: u8 = 1;
