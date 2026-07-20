# xtask

Build automation and freshness gating for the openntpd-rs workspace.

Commands via `cargo xtask`:

- `gen` — regenerate docs
- `check` — verify docs are fresh
- `no-orig` — verify no original C code
- `parity` — oracle comparison (not yet wired)
- `oracle` — Build Docker oracle VM matrix and run integration tests
- `ctl-test` — Run ntpctl integration tests against Docker oracles
- `compat` — Multi-version cross-compatibility test suite

## compat — Cross-compatibility testing

Builds Docker images for multiple OpenNTPD versions (6.8p1, 7.9p1) across
3 base OSes (Debian 12, Alpine 3.20, Ubuntu 24.04), then tests Rust
`ntpd` and `ntpctl` as drop-in replacements against the real C binaries
in each combination.

```text
cargo xtask compat
cargo xtask compat --skip-build   # Skip Docker image builds
cargo xtask compat --image 6.8    # Filter by image name
```

### Test matrix

| Combo | Daemon | Client  | Purpose           |
|-------|--------|---------|-------------------|
| 1     | REAL   | REAL    | Baseline control   |
| 2     | REAL   | RUST    | Client compat      |
| 3     | RUST   | REAL    | Daemon compat      |
| 4     | RUST   | RUST    | Full Rust self     |

### Known limitations

- **Alpine musl/glibc**: Rust binaries are linked against glibc and
  cannot execute on musl-based Alpine. All RUST-* tests fail on Alpine.
  Fix: cross-compile Rust binaries with `x86_64-unknown-linux-musl` target.
- **RUST ntpd → REAL ntpctl**: The Rust ntpd creates the control socket
  but the control protocol handler is not yet wired. Real ntpctl connects
  but receives no response.
- **6.2p3**: Oldest available version from the FTP server but fails to
  compile on modern GCC (GCC >= 10 conflicts with `__packed` macro).
