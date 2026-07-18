# openntpd-rs-core

[![crates.io](https://img.shields.io/crates/v/openntpd-rs-core.svg)](https://crates.io/crates/openntpd-rs-core)
[![docs.rs](https://img.shields.io/docsrs/openntpd-rs-core)](https://docs.rs/openntpd-rs-core)

Deterministic, side-effect-free NTP protocol engine for
[openntpd-rs](https://github.com/infinityabundance/openntpd-rs) —
a clean-room forensic Rust reconstruction of [OpenNTPD](https://www.openntpd.org/) 7.9p1.

This crate is `#![no_std]` and **deterministic by design**:
- No file I/O
- No network I/O
- No host-clock reads
- No privilege separation

All external interactions are abstracted behind traits that the
parent crate wires to real OS implementations or test doubles.

## Ported surfaces

| Surface | Status |
|---------|--------|
| NTPv4 wire format (`ntp`) | Implemented — internally tested (13 tests) |
| NTP message I/O (`ntp::msg`) | Implemented — internally tested (4 tests) |
| Utility types (`util`) | Implemented — internally tested (12 tests) |
| Config AST (`config::directive`) | Implemented — internally tested (31 tests) |
| Config diagnostics (`config::diagnostic`) | Implemented — internally tested (3 tests) |

See the [workspace umbrella crate](https://crates.io/crates/openntpd-rs) for
the full list of crates.

## License

MIT OR Apache-2.0
