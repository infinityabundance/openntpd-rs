# openntpd-rs-ctl

[![crates.io](https://img.shields.io/crates/v/openntpd-rs-ctl.svg)](https://crates.io/crates/openntpd-rs-ctl)

`ntpctl` control client binary for [openntpd-rs](https://github.com/infinityabundance/openntpd-rs) —
a clean-room forensic Rust reconstruction of [OpenNTPD](https://www.openntpd.org/) 7.9p1.

## CLI (OpenNTPD-compatible)

```text
ntpctl -s <status|peers|Sensors|all>
```

- `-s` selects status type. Accepts unambiguous prefixes
  (e.g. `stat`, `peer`, `Sen`, `a`). Ambiguous or empty inputs
  are rejected with an error.

**Note**: This is a scaffold. Communication over the Unix-domain
control socket is not yet wired.

See the [workspace umbrella crate](https://crates.io/crates/openntpd-rs)
for the full list of crates.

## License

MIT OR Apache-2.0
