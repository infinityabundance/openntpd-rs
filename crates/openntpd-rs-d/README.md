# openntpd-rs-d

[![crates.io](https://img.shields.io/crates/v/openntpd-rs-d.svg)](https://crates.io/crates/openntpd-rs-d)

`ntpd` daemon binary for [openntpd-rs](https://github.com/infinityabundance/openntpd-rs) —
a clean-room forensic Rust reconstruction of [OpenNTPD](https://www.openntpd.org/) 7.9p1.

## CLI (OpenNTPD 7.9p1-compatible)

```text
ntpd [-dfnv] [-P process] [-p file]
```

- `-d` — Debug mode (do not daemonize, log to stderr)
- `-f` — Config file (default: `/etc/ntpd.conf`)
- `-n` — Config/test mode: parse config, print result, exit
- `-P` — Parent process name (for setproctitle)
- `-p` — PID file path
- `-s` / `-S` — Deprecated (prints warning, ignored)
- `-v` — Verbose (repeatable)

**Note**: This is a scaffold. The daemon exits with code 78 (EX_CONFIG)
until the event loop, clock discipline, and drift file are wired.

See the [workspace umbrella crate](https://crates.io/crates/openntpd-rs)
for the full list of crates.

## License

MIT OR Apache-2.0
