# openntpd-rs-xtask

[![crates.io](https://img.shields.io/crates/v/openntpd-rs-xtask.svg)](https://crates.io/crates/openntpd-rs-xtask)

Build automation and freshness gating for the
[openntpd-rs](https://github.com/infinityabundance/openntpd-rs) workspace.

**Not intended for independent use.** This crate is a workspace-internal
build tool.

## Commands

```text
cargo xtask gen       — Generate documentation (port-parity, negative-capabilities)
cargo xtask check     — Verify generated docs are fresh (CI gate)
cargo xtask no-orig   — Verify no original OpenNTPD C source code exists
cargo xtask parity    — Compare against real ntpd oracle (not yet wired)
```

## Alias

The workspace provides a Cargo alias in `.cargo/config.toml`:

```toml
[alias]
xtask = "run -p xtask --"
```

So you can run `cargo xtask gen` instead of `cargo run -p xtask -- gen`.

## License

MIT OR Apache-2.0
