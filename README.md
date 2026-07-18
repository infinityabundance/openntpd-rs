# openntpd-rs

`openntpd-rs` is a **clean-room, blackbox forensic Rust reconstruction**
of [OpenNTPD](https://www.openntpd.org/) 7.9p1 time-synchronization
behavior. It is developed through differential comparison against the
real C sources of OpenNTPD, deterministic trace replay, and packet-level
byte receipts.

This is not a production replacement — it is a **forensic
parity reconstruction**.

**Zero original OpenNTPD C code** exists in this repository.

## Project doctrine

> Byte parity, behavior parity, operational-knowledge parity.

Every admitted behavior must be backed by a court with reproducible
evidence. Code ports are not transliterations; they are archaeological
restorations with executable evidence.

**No surface is labelled "Ported"** until `cargo xtask parity` produces
a verified evidence artifact against the real OpenNTPD 7.9p1 oracle.

## Current status

### Implemented (internally tested, no oracle evidence yet)

| Surface | Module | Tests |
|---------|--------|-------|
| NTP protocol wire format | `openntpd-rs-core::ntp` | 15 tests: strict 48/68‑byte model, unsigned dispersion, authenticated suffix |
| NTP message I/O | `openntpd-rs-core::ntp::msg` | 4 tests: exact-length validation, authenticated round-trip |
| Utility types (time, frequency) | `openntpd-rs-core::util` | 9 tests: Timespec normalization, Frequency Linux/OpenBSD boundary, NaN/Inf rejection |
| Linux clock I/O (adjtimex) | `openntpd-rs-io::clock` | 3 tests: adjtimex frequency conversion, overflow check |
| Socket I/O | `openntpd-rs-io::socket` | Code-reviewed, no runtime test yet |
| Process lifecycle | `openntpd-rs-io::process` | Build-tested, no runtime credential test |
| Drift file I/O | `openntpd-rs-io::file` | Build-tested, format differs from OpenNTPD |

### Scaffold (type/signature only)

| Surface | Module |
|---------|--------|
| Daemon entry point | `openntpd-rs-d` (ntpd binary) |
| Control client | `openntpd-rs-ctl` (ntpctl binary) |

### Planned (not started)

Config parser (`parse.y`), peer/client state machine, server responder,
control socket imsg, constraint validation, sensor framework, DNS child
process, logging subsystem.

## Architecture

```
Cargo.toml                          # workspace root
.cargo/config.toml                  # cargo xtask alias
xtask/                              # build automation (cargo xtask gen|check|no-orig|parity)
crates/
  openntpd-rs/                      # umbrella facade crate (re-exports openntpd-rs-core)
  openntpd-rs-core/                 # deterministic NTP brain (no_std, no I/O, no host clock)
  openntpd-rs-io/                   # real OS I/O layer (libc syscall wrappers)
  openntpd-rs-d/                    # ntpd daemon binary
  openntpd-rs-ctl/                  # ntpctl control client binary
```

## Generated docs & freshness gate

Machine-derivable facts are generated into [`docs/generated/`](docs/generated/)
by `cargo xtask gen`:

- [Port parity matrix](docs/generated/port-parity.md)
- [Negative capabilities ledger](docs/generated/negative-capabilities.md)

Run `cargo xtask check` to verify freshness. Activate the git hook:

```sh
git config core.hooksPath .githooks
```

## No original code policy

Run `cargo xtask no-orig` to verify that no original OpenNTPD C source
code exists in the repository. Scans for `.c`, `.h`, and `.y` files and
CVS IDs (`$OpenBSD:`).

## License

MIT OR Apache-2.0

## Acknowledgements

OpenNTPD was primarily developed by **Henning Brauer** as part of the
OpenBSD Project. The portable version is maintained by **Brent Cook**.
This project is an independently implemented forensic reconstruction —
it does not contain any derived OpenNTPD C code.
