//! # openntpd-rs-io
//!
//! Real OS I/O layer for OpenNTPD-rs. Provides libc syscall wrappers
//! for:
//!
//! - Clock operations: `adjtime`, `adjtimex`, `clock_gettime`
//! - Socket operations: `socket`, `bind`, `sendto`, `recvmsg`
//! - Process lifecycle: daemonization, credential dropping, PID files
//! - File I/O: drift file read/write
//!
//! ## SAFETY note
//!
//! This crate contains `unsafe` blocks for FFI calls to libc. Each
//! unsafe block is annotated with `// SAFETY:` justification. The
//! densest unsafe surface is `socket.rs` (recvmsg, CMSG macros,
//! sockaddr casts).

pub mod clock;
pub mod constraint_io;
pub mod ctl;
pub mod daemon;
pub mod daemon_impl;
pub mod dns_child;
pub mod dns_io;
pub mod file;
pub mod imsg;
pub mod ntp_child;
pub mod platform;
pub mod privsep;
pub mod process;
pub mod sensor_io;
pub mod socket;
pub mod util;
