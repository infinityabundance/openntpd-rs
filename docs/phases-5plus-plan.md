# Phase 5+ implementation plan — Docker oracle VM matrix & cross-distro sealing

## Phase 5: Docker oracle VM matrix

Build Docker images for every supported distribution, each containing a
compiled OpenNTPD 7.9p1 oracle. Run `cargo xtask parity` against each.

### 5.1 Base images

| Distribution | Base image | Package source | OpenNTPD version | Init |
|-------------|------------|----------------|------------------|------|
| Debian 12   | debian:bookworm-slim | apt | 6.2p3 (or build 7.9p1 from source) | systemd |
| Ubuntu 24.04| ubuntu:noble-slim | apt | 6.2p3 (or build 7.9p1 from source) | systemd |
| Alpine 3.20 | alpine:3.20 | apk | 7.0 (or build 7.9p1 from source) | OpenRC |
| Fedora 40   | fedora:40 | dnf | 6.2p3 (or build 7.9p1 from source) | systemd |
| FreeBSD 14  | freebsd:14 | pkg / ports | 7.9p1 (or build from source) | rc |

### 5.2 Build recipe: openntpd 7.9p1 from source

Each Dockerfile must:
1. Install build deps (gcc, make, libssl-dev, libtls-dev, bison, flex)
2. Download openntpd-7.9p1.tar.gz from openntpd.org
3. Verify SHA-256 against pinned value
4. `./configure && make && make install`
5. Strip binary
6. Record binary SHA-256
7. Save binary and manifest.json as build artifacts

### 5.3 Manifest schema

```json
{
  "schema_version": 1,
  "implementation": "OpenNTPD",
  "version": "7.9p1",
  "source_url": "https://ftp.openbsd.org/pub/OpenBSD/OpenNTPD/openntpd-7.9p1.tar.gz",
  "source_sha256": "<pinned>",
  "build_recipe_sha256": "<dockerfile hash>",
  "binary_sha256": "<from built binary>",
  "target": "x86_64-unknown-linux-gnu",
  "distribution": "debian-12",
  "build_date": "<ISO-8601>"
}
```

### 5.4 `cargo xtask parity --oracle-image`

Extend the parity command to:
1. Accept `--oracle-image openntpd:7.9p1-debian-12`
2. Pull/build image if not present
3. Copy corpus configs into container
4. Run `ntpd -n -f <config>` inside container
5. Collect exit code and stderr
6. Compare against Rust binary (run outside container)
7. Generate oracle evidence receipt

### 5.5 Cross-distro oracle evidence

Each receipt must record:
- Distribution name and version
- OpenNTPD package version and binary SHA-256
- Source build recipe and hash
- Per-case exit code and normalized category
- Rust vs oracle comparison verdict

## Phase 6: Oracle corpus expansion

### 6.1 Syntax-stable corpus (30 → 150 cases)

Add cases for every:
- Directive option permutation (all valid combos)
- Numeric boundary (±1 each side of every range)
- String encoding (all RefId lengths, non-UTF-8 quoted)
- Lexer edge case (every token boundary, continuation variant)
- Error recovery variant (lexer error in every position)
- CLI flag variant (every getopt form)

### 6.2 Environment-dependent corpus (separate, not counted)

Configurations that require:
- DNS resolution (hostnames → skip if no DNS)
- Network connectivity (constraint URLs → skip if offline)
- Local interfaces (listen on specific IPs)
- Sensor hardware (/dev/pps0)
- Routing tables (rtable > 0)
- Privileged ports (bind to port 123)

### 6.3 Diagnostic category stabilization

Before exact stderr comparison, normalize both Rust and oracle output into
stable categories. Audit every category assignment against real oracle stderr.

### 6.4 Exact stderr parity (Phase 6+)

Once categories are stable and all 150+ syntax cases pass category-level
parity, proceed to exact stderr comparison:
- Line number matching
- Error message wording
- Error count per directive
- Exit code agreement

## Phase 7: Platform porting

### 7.1 Linux (x86_64) — primary target (done)

Complete. All I/O paths use `libc` wrappers that compile on Linux.

### 7.2 Linux (aarch64, armv7, riscv64)

- Verify `adjtimex` syscall available
- Test cross-compilation
- Add CI matrix for alternate architectures

### 7.3 FreeBSD

- `adjfreq(2)` instead of `adjtimex(2)`
- Socket API is compatible (POSIX)
- `setproctitle()` uses `setproctitle(3)` (different from Linux)
- No `SO_TIMESTAMP` — use `SO_TIMESTAMP` with `timeval` (same API)
- PID file at `/var/run/ntpd.pid`
- Default config at `/etc/ntpd.conf`

### 7.4 OpenBSD

- Native target — imsg, adjfreq, pledge, all fit
- No portable `libtls` — use native LibreSSL
- Default config at `/etc/ntpd.conf`
- `/var/db/ntpd.drift` for drift file

### 7.5 macOS

- `mach_timebase` for clock (no adjtimex/adjfreq)
- No `SO_TIMESTAMP` on all versions — use `mach_absolute_time`
- `setproctitle()` via <libproc.h>
- No `SOCK_CLOEXEC` flag — use `fcntl(FD_CLOEXEC)` after socket()
- Requires `proc_info` or similar for process name

### 7.6 NetBSD / DragonFly / Solaris

- Stub implementations for now
- `adjtime(2)` on Solaris (coarse, no frequency)
- `ntp_adjtime()` on NetBSD (similar to adjtimex)

## Phase 8: Evidence sealing

### 8.1 Per-surface evidence artifacts

| Surface | Oracle required | Status |
|---------|----------------|--------|
| Config lexer | Syntax corpus | Phase 6 |
| Config parser | Syntax corpus | Phase 6 |
| Daemon -n | 30-case corpus | Done |
| ntp wire format | Binary packet comparison | Pending |
| util (timespec/freq) | Frequency conversion oracle | Pending |
| Socket I/O | Timestamp behavior | Pending |
| adjtimex clock | Clock discipline comparison | Pending |
| Process / privsep | Credential behavior | Pending |
| Control protocol | imsg send/recv comparison | Pending |

### 8.2 Surface status promotion

```text
Planned → Implemented — internally tested
    → Implemented — unverified against oracle
    → Ported (oracle evidence exists)
```

Each promotion requires:
- Working code (compiles, passes unit tests)
- Binary integration test (for CLI surfaces)
- Oracle comparison test (for --oracle mode)
- Signed-off evidence receipt in research/oracle/

## Phase 9: Continuous integration

### 9.1 GitHub Actions CI

```yaml
on: [push, pull_request]
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - run: rustup toolchain install stable
      - run: cargo test --workspace
      - run: cargo xtask check
      - run: cargo xtask no-orig
      - run: cargo xtask parity --skip-oracle
      - run: RUSTFLAGS="-Dwarnings" cargo check
  cross:
    strategy:
      matrix:
        target: [aarch64-unknown-linux-gnu, armv7-unknown-linux-gnueabihf]
    runs-on: ubuntu-latest
    steps:
      - run: cargo check --target ${{ matrix.target }}
  docker-oracle:
    strategy:
      matrix:
        distro: [debian-12, ubuntu-24.04, alpine-3.20, fedora-40]
    runs-on: ubuntu-latest
    steps:
      - build Docker image
      - run: cargo xtask parity --oracle-image openntpd:7.9p1-${{ matrix.distro }}
```

## Phase 10: crate publishing & releases

### 10.1 Versioning

```text
0.2.0 — Core protocol + parser complete (current)
0.3.0 — Client state machine (peer module)
0.4.0 — Daemon event loop + -d mode
0.5.0 — Control socket + ntpctl
0.6.0 — Server mode + broadcast
0.7.0 — Constraint validation
0.8.0 — Sensor framework
0.9.0 — Full platform support (FreeBSD, macOS)
1.0.0 — All surfaces ported with oracle evidence
```

### 10.2 Release checklist

Each release:
- [ ] `cargo test --workspace` passes
- [ ] `RUSTFLAGS="-Dwarnings" cargo check` clean
- [ ] `cargo xtask check` fresh
- [ ] `cargo xtask parity --skip-oracle` 30/30 passes
- [ ] Evidence receipt committed
- [ ] `cargo publish` all 5 crates
- [ ] Git tag `v<version>`
- [ ] Release notes on GitHub
