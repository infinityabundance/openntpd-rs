# openntpd-rs

[![crates.io](https://img.shields.io/crates/v/openntpd-rs.svg)](https://crates.io/crates/openntpd-rs)
[![docs.rs](https://img.shields.io/docsrs/openntpd-rs)](https://docs.rs/openntpd-rs)

Umbrella facade crate for the [openntpd-rs](https://github.com/infinityabundance/openntpd-rs)
workspace. Re-exports `openntpd-rs-core` and `openntpd-rs-io`.

This crate is a **clean-room, blackbox forensic Rust reconstruction** of
[OpenNTPD](https://www.openntpd.org/) 7.9p1. It is **not** a production replacement.

## Sub-crates

| Crate | crates.io | Description |
|-------|-----------|-------------|
| [`openntpd-rs-core`] | [![crates.io](https://img.shields.io/crates/v/openntpd-rs-core.svg)](https://crates.io/crates/openntpd-rs-core) | Deterministic NTP protocol engine (no I/O, no host clock) |
| [`openntpd-rs-io`] | [![crates.io](https://img.shields.io/crates/v/openntpd-rs-io.svg)](https://crates.io/crates/openntpd-rs-io) | Real OS I/O layer (libc syscall wrappers) |
| [`openntpd-rs-d`] | [![crates.io](https://img.shields.io/crates/v/openntpd-rs-d.svg)](https://crates.io/crates/openntpd-rs-d) | ntpd daemon binary |
| [`openntpd-rs-ctl`] | [![crates.io](https://img.shields.io/crates/v/openntpd-rs-ctl.svg)](https://crates.io/crates/openntpd-rs-ctl) | ntpctl control client binary |

[`openntpd-rs-core`]: https://github.com/infinityabundance/openntpd-rs/tree/main/crates/openntpd-rs-core
[`openntpd-rs-io`]: https://github.com/infinityabundance/openntpd-rs/tree/main/crates/openntpd-rs-io
[`openntpd-rs-d`]: https://github.com/infinityabundance/openntpd-rs/tree/main/crates/openntpd-rs-d
[`openntpd-rs-ctl`]: https://github.com/infinityabundance/openntpd-rs/tree/main/crates/openntpd-rs-ctl

## Binaries

- `ntpd` — daemon binary (in `openntpd-rs-d` crate)
- `ntpctl` — control client binary (in `openntpd-rs-ctl` crate)

## License

MIT OR Apache-2.0
