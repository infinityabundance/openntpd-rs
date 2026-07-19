# OpenNTPD-rs: complete implementation plan

## Dependency graph (bottom-up)

```
Phase 0: Core infrastructure (existing)
├── ntp.h / ntp_msg.c        → ntp + ntp::msg        ✓ 17 tests
├── util.c                   → util                   ✓ 12 tests
├── parse.y                  → config::lexer+parser   ✓ 153 tests
├── adjfreq_linux.c          → io::clock              ✓ 3 tests
├── socket.c                 → io::socket             ✓ 6 tests
└── diagnostic               → config::diagnostic     ✓ 3 tests

Phase 1: Runtime foundation (NEW)
├── imsg protocol            → imsg wire format + framing
├── log subsystem            → syslog / stderr logging
├── privsep / process        → parent/child fork + privilege drop
├── pidfile                  → /var/run/ntpd.pid
├── drift file               → atomic read/write of ntp.drift
└── signal handlers          → SIGHUP/SIGINT/SIGTERM/SIGALRM

Phase 2: Network (NEW)
├── privileged socket bind   → port 123 bind + capabilities
├── ntp client query engine  → mode 3 query/response cycle
├── ntp server responder     → mode 4 server (socket + dispatch)
├── control socket           → /var/run/ntpd.sock imsg
├── broadcast / multicast    → mode 5 discovery
└── constraint TLS           → HTTPS Date header validation

Phase 3: State machines (NEW)
├── peer struct              → full peer state (8-sample filter, reach, flash)
├── client state machine     → poll interval management, query cycle
├── clock filter algorithm   → 8-sample ring, lowest-delay selection
├── clock selection          → intersection/clustering/combining
├── clock discipline         → PLL/FLL via adjtimex/adjfreq
└── system peer election     → best source selection

Phase 4: Daemon (NEW)
├── config.c lowering        → DNS resolution → peer creation
├── event loop               → poll(2) over all fds
├── ntpctl protocol          → imsg control request/response
├── constraint validation    → TLS connection pool + Date parsing
├── sensor framework         → timedelta device polling
├── DNS child process        → async resolution via imsg
├── boot-time correction     → 15-second window + step
└── ntpd full daemon         → -d foreground + background modes

Phase 5: Hardening & oracle (NEW)
├── full getopt CLI parity   → all flag forms, --, grouped deprecated
├── adjtimex behavioral tests → oracle comparison
├── credential verification  → getresuid/getresgid testing
├── socket timestamp tests   → ancillary data parsing
├── ntpctl protocol tests   → imsg send/recv roundtrip
├── Docker VM matrix         → 5-distro oracle comparison
├── corpus expansion         → 30→300+ oracle cases
└── cargo xtask parity seal  → all surfaces ported with evidence

Estimated: ~25,000-35,000 lines of new Rust code across all phases.
