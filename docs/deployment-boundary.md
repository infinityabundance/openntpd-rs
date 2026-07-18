# Deployment boundary

`openntpd-rs` is a **forensic reconstruction** of OpenNTPD. It is **not**
a production replacement. This document states what `openntpd-rs` does
and does not do.

## What openntpd-rs does

- Replicates the NTP protocol logic of OpenNTPD 7.9p1 in Rust.
- Provides `ntpd` and `ntpctl` binaries with OpenNTPD-compatible CLI.
- Supports the same `ntpd.conf` directives.
- Runs a client/server mode NTP daemon.
- Disciplines the system clock via `adjtime`/`adjtimex`.

## What openntpd-rs does NOT do

- Replace the real OpenNTPD in production (yet).
- Offer security guarantees beyond what OpenNTPD provides.
- Support every platform OpenNTPD supports (Linux only, for now).
- Include any original OpenNTPD C source code.

## Documentation only on success

We document only what we have verified by court-backed evidence.
No feature is claimed that has not been differentially tested against
the real `ntpd` oracle or protocol vectors.

## Clean-room policy

- No original OpenNTPD C source is copied, transliterated, or derived.
- The Rust implementation is built by observing OpenNTPD's behavior
  through differential testing and protocol specification analysis.
- The `cargo xtask no-orig` command verifies this policy.
