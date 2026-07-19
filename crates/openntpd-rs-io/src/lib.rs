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
pub mod file;
pub mod imsg;
pub mod process;
pub mod socket;
