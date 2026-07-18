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
//!
//! ## Planned surfaces
//!
//! - `config` lexer — tokenizer matching parse.y lexical rules
//! - `config` parser — directive grammar
//! - `config` runtime lowering — DNS resolution, peer creation
//! - `peer` — client state machine
//! - `server` — NTP responder
//! - `control` — imsg protocol
//! - `constraint` — HTTPS constraint validation
//! - `sensor` — hardware sensor framework
//! - `dns` — DNS child process
//! - `log` — logging subsystem
//! - `daemon` — event loop, clock discipline

#![no_std]
#![deny(unsafe_code)]

extern crate alloc;

pub mod config;
pub mod ntp;
pub mod util;
