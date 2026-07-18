# openntpd-rs-io

[![crates.io](https://img.shields.io/crates/v/openntpd-rs-io.svg)](https://crates.io/crates/openntpd-rs-io)
[![docs.rs](https://img.shields.io/docsrs/openntpd-rs-io)](https://docs.rs/openntpd-rs-io)

Real OS I/O layer for [openntpd-rs](https://github.com/infinityabundance/openntpd-rs) —
a clean-room forensic Rust reconstruction of [OpenNTPD](https://www.openntpd.org/) 7.9p1.

Provides libc syscall wrappers for:

- **Clock**: `adjtimex(2)`, `clock_gettime(2)`, `adjtime(2)` — with
  correct OpenBSD→Linux frequency unit conversion
- **Socket**: `socket(2)`, `bind(2)`, `sendto(2)`, `recvmsg(2)` — with
  `SO_TIMESTAMP` ancillary data parsing and `SO_REUSEPORT`
- **Process**: `setresuid(2)`, `setresgid(2)`, double-fork daemonization,
  PID file management
- **File**: Atomic drift file read/write (temp + rename)

## `unsafe` usage

All `unsafe` blocks are annotated with `// SAFETY:` justification.
The densest unsafe surface is `socket.rs` (recvmsg, CMSG macros,
sockaddr casts).

## License

MIT OR Apache-2.0
