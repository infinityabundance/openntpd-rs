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

// Crate-level clippy allows for pre-existing items that need a wider
// cleanup pass. These are all mechanical style issues, not bugs.
#![allow(
    clippy::too_many_arguments,
    clippy::type_complexity,
    clippy::module_name_repetitions,
    clippy::manual_c_str_literals,
    clippy::redundant_closure,
    clippy::unnecessary_cast,
    clippy::let_and_return,
    clippy::collapsible_if,
    clippy::needless_pass_by_ref_mut,
    clippy::needless_return,
    clippy::question_mark,
    clippy::needless_borrow,
    clippy::needless_range_loop,
    clippy::manual_range_contains,
    clippy::needless_ifs,
    clippy::option_map_or_none,
    clippy::unused_assignments
)]

pub mod clock;
pub mod constraint_io;
pub mod ctl;
pub mod daemon;
pub mod daemon_impl;
pub mod dns_child;
pub mod dns_io;
pub mod file;
pub mod globals;
pub mod imsg;
pub mod ntp_child;
pub mod platform;
#[cfg(target_os = "openbsd")]
pub mod pledge;
pub mod privsep;
pub mod process;
pub mod ptp_io;
pub mod refclock_io;
#[cfg(target_os = "linux")]
pub mod seccomp;
pub mod sensor_io;
pub mod socket;
pub mod util;
