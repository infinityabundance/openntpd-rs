# openntpd-rs

[![crates.io](https://img.shields.io/crates/v/openntpd-rs.svg)](https://crates.io/crates/openntpd-rs)
[![docs.rs](https://img.shields.io/docsrs/openntpd-rs)](https://docs.rs/openntpd-rs)
[![MIT OR Apache-2.0](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue)](https://github.com/infinityabundance/openntpd-rs#license)

Clean-room, blackbox forensic Rust reconstruction of [OpenNTPD](https://www.openntpd.org/) 7.9p1.

**Zero original C code.** Every function has a court-backed counterpart.

## Crates

| Crate | crates.io | Description |
|-------|-----------|-------------|
| [`openntpd-rs`] | [![crates.io](https://img.shields.io/crates/v/openntpd-rs.svg)](https://crates.io/crates/openntpd-rs) | Umbrella facade (re-exports core + io) |
| [`openntpd-rs-core`] | [![crates.io](https://img.shields.io/crates/v/openntpd-rs-core.svg)](https://crates.io/crates/openntpd-rs-core) | Deterministic NTP protocol engine |
| [`openntpd-rs-io`] | [![crates.io](https://img.shields.io/crates/v/openntpd-rs-io.svg)](https://crates.io/crates/openntpd-rs-io) | Real OS I/O layer (libc wrappers) |
| [`openntpd-rs-d`] | [![crates.io](https://img.shields.io/crates/v/openntpd-rs-d.svg)](https://crates.io/crates/openntpd-rs-d) | ntpd daemon binary |
| [`openntpd-rs-ctl`] | [![crates.io](https://img.shields.io/crates/v/openntpd-rs-ctl.svg)](https://crates.io/crates/openntpd-rs-ctl) | ntpctl control client binary |

[`openntpd-rs`]: https://github.com/infinityabundance/openntpd-rs/tree/main/crates/openntpd-rs
[`openntpd-rs-core`]: https://github.com/infinityabundance/openntpd-rs/tree/main/crates/openntpd-rs-core
[`openntpd-rs-io`]: https://github.com/infinityabundance/openntpd-rs/tree/main/crates/openntpd-rs-io
[`openntpd-rs-d`]: https://github.com/infinityabundance/openntpd-rs/tree/main/crates/openntpd-rs-d
[`openntpd-rs-ctl`]: https://github.com/infinityabundance/openntpd-rs/tree/main/crates/openntpd-rs-ctl

## Architecture

```
xtask/                              # build automation (cargo xtask gen|check|no-orig|parity)
crates/
  openntpd-rs/                      # umbrella facade (re-exports core + io)
  openntpd-rs-core/                 # deterministic NTP brain (no_std, no I/O, no host clock)
  openntpd-rs-io/                   # real OS I/O layer (libc syscall wrappers)
  openntpd-rs-d/                    # ntpd daemon binary
  openntpd-rs-ctl/                  # ntpctl control client binary
```

## Project doctrine

> Byte parity, behavior parity, operational-knowledge parity.

Every admitted behavior must be backed by a court with reproducible
evidence. Code ports are not transliterations; they are archaeological
restorations with executable evidence.

**No surface is labelled `Ported`** until `cargo xtask parity` produces
a verified evidence artifact against the real OpenNTPD 7.9p1 oracle.

## Generated docs & freshness gate

Machine-derivable facts are generated into [`docs/generated/`](docs/generated/)
by `cargo xtask gen`. Run `cargo xtask check` to verify freshness.

## No original code policy

Run `cargo xtask no-orig` to verify that no original OpenNTPD C source
code exists.

## License

MIT OR Apache-2.0

## Acknowledgements

OpenNTPD was primarily developed by **Henning Brauer** as part of the
OpenBSD Project. The portable version is maintained by **Brent Cook**.
This project is an independently implemented forensic reconstruction —
it does not contain any derived OpenNTPD C code.
