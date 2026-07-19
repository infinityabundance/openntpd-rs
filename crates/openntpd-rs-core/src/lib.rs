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
//! ## Planned surfaces (Phase 5+)
//!
//! - `daemon` — full event loop, clock discipline, poll dispatch
//! - Runtime privilege separation (privsep fork, credential drop)
//! - Actual NTP network queries (mode 3 client over UDP)
//! - Full clock discipline (PLL/FLL via adjtimex)
//! - TLS constraint connections
//! - Sensor device I/O
//! - Daemon background mode

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
