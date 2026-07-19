---



## 17. Forensic code archaeology — OpenNTPD 7.9p1 vs openntpd-rs

### Files present in OpenNTPD 7.9p1 with NO Rust counterpart

| C source | Purpose | Rust status | Estimated LOC |
|----------|---------|-------------|---------------|
| `client.c` | Client state machine, poll loop, clock filter | **Planned** | ~2000 |
| `server.c` | Mode 4 symmetric/broadcast responder | **Planned** | ~800 |
| `control.c` | Control socket imsg protocol | **Planned** | ~1500 |
| `constraint.c` | HTTPS constraint validation engine | **Planned** | ~1200 |
| `sensors.c` | Sensor framework (PPS, NMEA, etc.) | **Planned** | ~600 |
| `dns.c` | Async DNS resolution child process | **Planned** | ~500 |
| `log.c` | syslog logging subsystem | **Planned** | ~300 |
| `ntp_dns.c` | DNS-to-address resolution helper | **Planned** | ~200 |
| `privsep.c` | Privilege separation engine (imsg parent/child) | **Planned** | ~1000 |
| `config.c` | Runtime lowering: peer creation, DNS, socket bind | **Planned** | ~800 |

**Total uncovered C source: ~9,000 lines of behavioral logic.**

### Files with partial Rust coverage

| C source | Rust surface | Coverage fraction | What's missing |
|----------|-------------|-------------------|----------------|
| `ntp.h` | `ntp` module | ~15% | Mode 6/7 control msgs, extension fields, reference clock types |
| `ntp_msg.c` | `ntp::msg` | ~20% | Only 48/68-byte send/recv; no broadcast, no control msg assembly |
| `util.c` | `util` | ~10% | Clock-filter math, jitter/dispersion computation, poll-interval logic |
| `adjfreq_linux.c` | `io::clock` | ~30% | Frequency conversion only; no `ntp_adjtime()` status read |
| `socket.c` | `io::socket` | ~20% | No privileged bind, no hardware timestamping, no broadcast |
| `ntpd.c` | `daemon` module | ~5% | `-n` config check only; no event loop, clock discipline, drift file |
| `parse.y` | `config::lexer` + `config::parser` | ~60% | Full grammar parsed but DNS/resolution not wired |

### 18. Lexer divergence — deep syntax archaeology

| OpenNTPD behavior | Rust behavior | Impact |
|-------------------|---------------|--------|
| `lgetc(0)` returns `int`; EOF at file boundary | `logical_get()` returns `Option<u8>`; EOF = `None` | Equivalent |
| 8096-byte token buffer includes terminating NUL | 8095-byte limit for unquoted (plus NUL), 8094 for quoted | **Off by one** — acceptable for benign configs |
| `\r\n` treated as newline after `\r` consumed | `\r` returned as Symbol(`\r`); `\r\n` not normalized | **Divergent** — affects CRLF line endings |
| `isspace()` defines number terminators | Explicit set: space, tab, newline, cr, vt, ff + punctuation | Functionally equivalent |
| Comment NUL not special | NUL in comment returns `EmbeddedNul` error | **Intentional hardening** |
| `allowed_in_string` may vary by platform | Fixed exclusion set: `(){}<>!=/#,` | Verified against Debian 7.9p1 |

### 19. Parser divergence — grammar archaeology

| OpenNTPD grammar | Rust parser | Status |
|------------------|-------------|--------|
| `constraint from <url>` | ✓ Requires `from` | ✓ |
| `constraints from <url>` | ✓ Requires `from` | ✓ |
| Constraint URL as one STRING token | ✓ One `take_string_token()` | ✓ |
| `https://` scheme stripping | ✓ Removed before host/path split | ✓ |
| `host("*")` → special wildcard address | ✓ Rejected in semantic check | ✓ |
| `listen on *` → wildcard | ✓ `ListenAddress::Wildcard` | ✓ |
| `server *` rejected by peer creation | ✓ Rejected in parser as `is_wildcard()` | **Pre-emptive** (upstream rejects later) |
| `servers *` rejected | ✓ Same check | Same |
| `sensor *` → wildcard string | ✓ `ConfigString("*")` | ✓ |
| `rtable` validation deferred | ✓ `u32` preserved; target check deferred | ✓ |
| `-12\<newline>3abc` → minus on line 1, `123abc` on line 2 | ⚠ String reported on line 1 | **Line attribution diff** |
| `-\<newline>123` → minus on line 1, `123` on line 2 | ⚠ `Symbol('-')` on line 1, `String("123")` on line 2 | Same result, different token type |
| Valid config prints nothing to stdout | ⚠ Prints `configuration OK` to stderr | **Divergent** but harmless |

### 20. NTP protocol gap — detailed surface audit

| Protocol element | RFC | Status | Tests |
|------------------|-----|--------|-------|
| NTP timestamp format (64-bit fixed-point) | 5905 §6 | ✓ | 3 |
| Leap indicator (LI) encode/decode | 5905 §7.3 | ✓ | 2 |
| Version number (VN) encode/decode | 5905 §7.3 | ✓ | 2 |
| Mode field encode/decode (0-7) | 5905 §7.3 | ✓ | 2 |
| Stratum field encode/decode | 5905 §7.3 | ✓ | 2 |
| Poll interval encode/decode | 5905 §7.3 | ✓ | 2 |
| Precision (signed log2) encode/decode | 5905 §7.3 | ✓ | 2 |
| Root delay (32-bit NTP short) | 5905 §7.3 | ✓ | 2 |
| Root dispersion (32-bit NTP short) | 5905 §7.3 | ✓ | 2 |
| Reference ID (32-bit) | 5905 §7.3 | ✓ | 2 |
| Reference timestamp (NTP timestamp) | 5905 §7.3 | ✓ | 2 |
| Origin timestamp (NTP timestamp) | 5905 §7.3 | ✓ | 2 |
| Receive timestamp (NTP timestamp) | 5905 §7.3 | ✓ | 2 |
| Transmit timestamp (NTP timestamp) | 5905 §7.3 | ✓ | 2 |
| Extension field 1 (variable length) | 5905 §7.4 | ✗ | 0 |
| Extension field 2 (variable length) | 5905 §7.5 | ✗ | 0 |
| MAC (MD5/SHA-1 keyed digest) | 5905 §7.5 | ✓ | 2 |
| MAC key ID | 5905 §7.5 | ✓ | 1 |
| MAC digest (16/20 bytes) | 5905 §7.5 | ✓ | 1 |
| Mode 6 control (READSTAT, READVAR, etc.) | 9327 | ✗ | 0 |
| Mode 6 error response | 9327 | ✗ | 0 |
| Mode 7 private protocol | ntpq-private | ✗ | 0 |
| Broadcast / multicast | 5905 §9 | ✗ | 0 |
| Symmetric active / passive | 5905 §8 | ✗ | 0 |
| Kiss-o'-Death (KoD) packet | 5905 §13 | ✗ | 0 |

### 21. Platform support matrix — Docker VM archaeology

| Distribution | `adjtimex` | `adjfreq(2)` | Socket API | Signal API | Status |
|-------------|------------|---------------|------------|------------|--------|
| Linux (Debian/Ubuntu/Alpine/Fedora) | ✓ | N/A | ✓ | ⚠ Not wired | **Primary target** |
| FreeBSD | ✗ | ✗ Stub | ⚠ Untested | ⚠ Not wired | **Not tested** |
| OpenBSD | ✗ | ✗ Stub | ⚠ Untested | ⚠ Not wired | **Not tested** |
| macOS | ✗ | ✗ Stub | ⚠ Untested | ⚠ Not wired | **Not tested** |
| NetBSD | ✗ | ✗ | ⚠ Untested | ⚠ Not wired | **Not present** |

The Docker VM matrix (Debian, Ubuntu, Alpine, Fedora, FreeBSD) has been designed but **no cross-distro oracle tests have been executed**.

### 22. `cargo xtask parity` — oracle harness state

| Capability | Status | Notes |
|------------|--------|-------|
| Rust self-test (30 corpus cases) | ✓ 30/30 pass | SHA-256 evidence committed |
| `--oracle /path/to/ntpd` | ✓ Wired | Builds Rust binary, compares |
| `--oracle-sha256 <expected>` | ✓ Enforced | Mismatch aborts |
| `--oracle-manifest <path>` | ✓ Enforced | JSON manifest verification |
| `--skip-oracle` | ✓ Self-test | 30 cases against expected values |
| Self-comparison guard | ✓ SHA-256 equality rejected | Canonical path + hash |
| `oracle_parity` 3-state | ✓ null/true/false | No oracle / agrees / disagrees |
| JSON receipt with `mode` | ✓ `self-test` or `oracle-parity` | Clear provenance |
| Raw stderr preserved | ✓ Per-case files | Independent category audit |
| `oracle_binary: null` vs `Some(...)` | ✓ Correct for mode | |
| Oracle pinning MANDATORY | ⚠ Pending | Currently optional; must be required |
| Parallel-run isolation | ⚠ Pending | Shared temp dir; no PID-based run dir |
| Receipt collision prevention | ⚠ Pending | 1-second resolution; nanosecond preferred |
| Legacy receipts quarantined | ⚠ Pending | schema_version must become 2 |
| Docker container support | ⚠ Not implemented | `--oracle-image` documented but absent |

### 23. `getopt` CLI parity — complete gap table

| `getopt` feature | OpenNTPD | Rust | Tested |
|------------------|----------|------|--------|
| `-d` | ✓ | ✓ | ✓ |
| `-f <arg>` | ✓ | ✓ | ✓ |
| `-f<arg>` (attached) | ✓ | ✗ | ✗ |
| `-n` | ✓ | ✓ | ✓ |
| `-P <arg>` | ✓ | ✓ | ✓ |
| `-P<arg>` (attached) | ✓ | ✗ | ✗ |
| `-p <arg>` | ✓ | ✓ | ✓ |
| `-p<arg>` (attached) | ✓ | ✗ | ✗ |
| `-s` (deprecated) | ✓ | ✓ | ✓ |
| `-S` (deprecated) | ✓ | ✓ | ✓ |
| `-v` (verbosity) | ✓ | ✓ | ✓ |
| `-vv` | ✓ | ✓ | ✓ |
| `-dn` (grouped) | ✓ | ✓ | ✓ |
| `-dnv` (grouped) | ✓ | ✓ | ✓ |
| `-sn` (grouped with deprecated) | ✓ | ✗ | ✗ |
| `-Sv` (grouped with deprecated) | ✓ | ✗ | ✗ |
| `--` (option terminator) | ✓ | ✗ | ✗ |
| Single `-` (stdin) | ⚠ Partial | ✗ | ✗ |
| Unknown flag → exit 1 | ✓ | ✓ | ✓ |
| Missing argument → exit 1 | ✓ | ✓ | ✓ |

### 24. Config file behavior — detailed protocol

| Behavior | OpenNTPD | Rust | Divergence |
|----------|----------|------|------------|
| Default config path | `SYSCONFDIR/ntpd.conf` | `/etc/ntpd.conf` | Same on most systems |
| `-f /path` | Reads file | Reads file | ✓ |
| `-n` with valid config | Exit 0, print nothing | Exit 0, print `configuration OK` | **Output diff** |
| `-n` with invalid config | Exit 1, print errors to stderr | Exit 1, print errors to stderr + span prefix | ✓ (value) |
| `-n` with unreadable file | Exit 1, print file error | Exit 1, print `cannot read 'path': err` | ✓ |
| Multiple `-f` flags | Last wins | Last wins | ✓ |
| Argument parsing failure | Exit 1 | Exit 1 | ✓ |
| Daemon mode (no `-n`) | Daemonize, run | Exit 78 (unimplemented) | Scaffold |
| Error message format | `ntpd: <file>:<line>: <msg>` | `<start>:<end>: <msg>` (byte spans) | **Span vs line:column** |

### 25. Security architecture gap — detailed

| Control | OpenNTPD | Rust | Risk |
|---------|----------|------|------|
| `setresuid()` / `setresgid()` | After startup | Written, untested | Medium |
| `getresuid()` verification | After drop | Not implemented | Low |
| `chroot()` | Optional jail | Not implemented | Medium |
| `pledge()` (OpenBSD) | System call filter | N/A (not on OpenBSD) | Low |
| `capability` dropping (Linux) | `capng` | Not implemented | Medium |
| `seccomp` BPF (Linux) | Not in 7.9p1 | Not implemented | Low |
| `setproctitle()` | Process title | Not implemented | Low |
| `fork()` + `setsid()` | Daemonization | Not implemented | High |
| PID file | `/var/run/ntpd.pid` | Not implemented | Low |
| Drift file write | `ntp.drift` via `mkstemp` + rename | ⚠ `path.tmp` + `File::create` | **Medium** — symlink race |
| `SOCK_CLOEXEC` | Applied | ✓ | ✓ |
| `O_EXCL` / `O_NOFOLLOW` | Drift file | Not implemented | Medium |

### 26. Evidence artifact status

| Receipt | Location | Schema | Content |
|---------|----------|--------|---------|
| Self-test v1 (old format) | `research/oracle/receipts/parity_2026-07-19T04_51_03Z.json` | 1 (incompatible) | `oracle_parity: true` with null oracle |
| Self-test v1 (old format) | `research/oracle/receipts/parity_2026-07-19T04_51_32Z.json` | 1 (incompatible) | Same defect |
| Self-test v2 (corrected) | `research/oracle/receipts/self-test/parity_2026-07-19T05_10_33Z.json` | 1 (ambiguous) | `oracle_parity: null`, `mode: self-test` |
| Oracle test | Not yet run | — | — |

**Schema version 1 currently describes two incompatible receipt formats.** The old receipts should be quarantined and schema bumped to 2.

### 27. Summary — total uncovered surface

| Category | Estimated coverage | Estimated remaining |
|----------|-------------------|---------------------|
| NTP wire format | 15% | 85% |
| NTP modes (3, 4, 5, 6, 7, 1/2) | 2% | 98% |
| Config parsing | 60% | 40% |
| Client state machine | 0% | 100% |
| Server responder | 0% | 100% |
| Control protocol | 0% | 100% |
| Constraint validation | 0% | 100% |
| Sensor framework | 0% | 100% |
| DNS resolution | 0% | 100% |
| Privilege separation | 0% | 100% |
| Clock discipline | 0% | 100% |
| Event loop | 5% | 95% |
| CLI flags | 75% | 25% |
| Cross-platform support | 5% (Linux only) | 95% |
| **Overall** | **~12%** | **~88%** |
