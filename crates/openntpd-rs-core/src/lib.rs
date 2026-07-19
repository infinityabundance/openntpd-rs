//! # openntpd-rs-core
//!
//! **Forensic Rust reconstruction of OpenNTPD's time-synchronization
//! behavior.**  Deterministic, side-effect-free NTP protocol engine.
//!
//! ## no_std
//!
//! This crate is `#![no_std]` but requires the `alloc` crate for
//! `String`, `Vec`, and formatting.  No `std` features are used.
//!
//! ## Ported surfaces
//!
//! | Surface               | Status                              |
//! |-----------------------|-------------------------------------|
//! | `ntp` (wire format)   | Implemented — internally tested     |
//! | `ntp::msg`            | Implemented — internally tested     |
//! | `util`                | Implemented — internally tested     |
//! | `config` (AST types)  | Implemented — internally tested     |
//! | `config` (lexer)      | Implemented — internally tested     |
//! | `config` (parser)     | Implemented — internally tested     |
//!
//! ## Implemented surfaces
//!
//! | Surface               | Status                              |
//! |-----------------------|-------------------------------------|
//! | `config::runtime`     | Implemented — internally tested     |
//! | `peer`                | Implemented — internally tested     |
//! | `server`              | Implemented — internally tested     |
//! | `control`             | Implemented — internally tested     |
//! | `constraint`          | Implemented — internally tested     |
//! | `sensor`              | Implemented — internally tested     |
//! | `dns`                 | Implemented — internally tested     |
//! | `log`                 | Implemented — internally tested     |
//!
//! ## Implemented surfaces (Phase 5+ runtime)
//!
//! | Surface               | Status                              |
//! |-----------------------|-------------------------------------|
//! | `ntp::query`          | Implemented — internally tested     |
//! | `ntp::clock`          | Implemented — internally tested     |
//!
//! ## Planned (Phase 6+)
//!
//! - Runtime privilege separation (privsep fork, credential drop)
//! - TLS constraint connections
//! - Sensor device I/O
//! - DNS resolution child process
//! - Full daemon mode (background, signal-based lifecycle)
//! - seccomp/pledge sandboxing

#![no_std]
#![deny(unsafe_code)]

extern crate alloc;

pub mod config;
pub mod constraint;
pub mod control;
pub mod dns;
pub mod log;
pub mod ntp;
pub mod peer;
pub mod sensor;
pub mod server;
pub mod util;
