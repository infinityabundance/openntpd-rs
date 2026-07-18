# Source archaeology: OpenNTPD 7.9p1

## Repository structure

The openntpd-portable repository at
<https://github.com/openntpd-portable/openntpd-portable> contains:

### Top-level

| File | Purpose |
|------|---------|
| `configure.ac` | Autoconf configuration |
| `Makefile.am` | Build definition |
| `compat/` | Platform-specific compat layer |
| `include/` | Replacement headers for non-OpenBSD systems |
| `m4/` | Autoconf macros |
| `patches/` | Patches applied to the OpenBSD source |
| `src/` | Build integration for portable sources |

### Source files (from OpenBSD CVS)

The core NTP daemon source comes from the OpenBSD CVS:
`cvs.openbsd.org/src/usr.sbin/ntpd/`

| File | Lines | CVS ID | Purpose |
|------|-------|--------|---------|
| `ntpd.c` | ~1450 | `$OpenBSD: ntpd.c,v 1.145 2026/04/22` | Main daemon, CLI, privilege separation, event loop |
| `ntpd.h` | ~1550 | `$OpenBSD: ntpd.h,v 1.155 2025/08/20` | Main header: structs, enums, prototypes |
| `ntp.c` | ~1820 | `$OpenBSD: ntp.c,v 1.182 2026/04/21` | Core NTP engine: poll, peer management, clock discipline |
| `ntp.h` | ~150 | `$OpenBSD: ntp.h,v 1.15 2023/11/15` | NTP protocol constants and types |
| `ntp_msg.c` | ~220 | `$OpenBSD: ntp_msg.c,v 1.22 2016/09/03` | NTP packet send/receive |
| `ntp_dns.c` | ~370 | `$OpenBSD: ntp_dns.c,v 1.37 2026/04/21` | DNS resolution child process |
| `config.c` | ~330 | `$OpenBSD: config.c,v 1.33 2020/04/12` | Config helpers, peer/sensor/constraint constructors |
| `parse.y` | ~780 | `$OpenBSD: parse.y,v 1.78 2021/10/15` | Bison grammar for ntpd.conf |
| `client.c` | ~1180 | `$OpenBSD: client.c,v 1.118 2023/12/20` | NTP client: peer init, query, validation, clock filter |
| `server.c` | ~440 | `$OpenBSD: server.c,v 1.44 2016/09/03` | NTP server: listener, bind, respond |
| `control.c` | ~280 | `$OpenBSD: control.c,v 1.28 2026/04/21` | Control socket: ntpctl communication |
| `log.c` | ~190 | `$OpenBSD: log.c,v 1.19 2019/07/03` | Logging subsystem |
| `log.h` | ~60 | `$OpenBSD: log.h,v 1.6 2021/12/13` | Logging declarations |
| `util.c` | ~300 | `$OpenBSD: util.c,v 1.30 2026/04/22` | Utilities: time conversions, formatting |
| `constraint.c` | ~600 | `$OpenBSD: constraint.c,v 1.60 2024/11/21` | HTTPS constraint validation |
| `sensors.c` | ~540 | `$OpenBSD: sensors.c,v 1.54 2019/11/11` | Hardware sensor support |

### Portable compat layer

| File | Purpose |
|------|---------|
| `compat/adjfreq_linux.c` | Linux adjfreq via adjtimex(2) |
| `compat/adjfreq_freebsd.c` | FreeBSD adjfreq via ntp_adjtime(2) |
| `compat/adjfreq_netbsd.c` | NetBSD adjfreq via ntp_adjtime(2) |
| `compat/adjfreq_osx.c` | macOS adjfreq via mach absolute time |
| `compat/adjfreq_solaris.c` | Solaris adjfreq via adjtime(2) |
| `compat/adjtime_adjtimex.c` | Linux adjtime via adjtimex(2) |
| `compat/bsd-setresuid.c` | setresuid compat for non-BSD systems |
| `compat/bsd-setresgid.c` | setresgid compat for non-BSD systems |
| `compat/clock_gettime_osx.c` | macOS clock_gettime compat |
| `compat/closefrom.c` | closefrom(3) compat |
| `compat/arc4random.h` | arc4random compat header |
| `compat/progname.c` | getprogname/setprogname compat |
| `compat/setproctitle.c` | setproctitle compat |
| `compat/socket.c` | socket option compat |
| `compat/daemon_solaris.c` | Solaris daemon(3) compat |
| `compat/getifaddrs_solaris.c` | Solaris getifaddrs compat |
| `compat/freezero.c` | freezero(3) compat |
| `compat/clock_getres.c` | clock_getres compat |

## Portable patches

26 patches are applied to the OpenBSD source for portability:

1. IPv6 DNS record handling
2. EAI_NODATA compatibility
3. sin_len/sin6_len conditional
4. rdomain support
5. ntpd.conf OS-dependent options
6. User/file location overrides
7. PID file (-P flag)
8. setproctitle initialization
9. Constraint support disabled notification
10. RTC update on sync
11. SO_TIMESTAMP handling
12. ftello/ftruncate check
13. IPV6_V6ONLY setting
14. DNS retry disable
15. KERN_SECURELVL handling
16. Solaris mode cast
17. peercount initialization
18. Constraint path override
19. File path templates
20. getmonotime fast boot fix
21. time_t overflow in constraint
22. Kernel sync status update
23. Peer/sensor offset invalidation on step
24. recvmsg/connect error retry
25. Pool trust propagation
26. Constraint wait without constraints

## Architecture

```
┌─────────────────────────────────────────────────────┐
│                   ntpd (main process)                │
│  ┌─────────┐  ┌──────────┐  ┌───────────────────┐   │
│  │ Config  │  │  Parse   │  │  DNS Child Proc   │   │
│  │ Loader  │  │  .conf   │  │  (ntp_dns.c)      │   │
│  └─────────┘  └──────────┘  └───────────────────┘   │
│                                                       │
│  ┌─────────────────────────────────────────────┐    │
│  │           Event Loop (poll/select)          │    │
│  │  ┌──────┐ ┌──────┐ ┌──────┐ ┌───────────┐  │    │
│  │  │ NTP  │ │ NTP  │ │ NTP  │ │  Control  │  │    │
│  │  │Client│ │Server│ │Sensors│ │  Socket   │  │    │
│  │  └──────┘ └──────┘ └──────┘ └───────────┘  │    │
│  └─────────────────────────────────────────────┘    │
│                                                       │
│  ┌─────────────────────────────────────────────┐    │
│  │         Clock Discipline                      │    │
│  │  adjtime() / adjfreq() / settimeofday()     │    │
│  │  Drift file: /var/db/ntpd.drift             │    │
│  └─────────────────────────────────────────────┘    │
└─────────────────────────────────────────────────────┘
```

## Key data structures (from ntpd.h)

### `struct ntp_peer`
Represents an NTP server peer:
- `addr`: socket address of the server
- `next`: linked list pointer
- `state`: client state machine
- Various statistics (offset, delay, dispersion)
- Trusted/untrusted flag
- Poll interval, countdown

### `struct ntp_sensor`
Represents a hardware sensor:
- `sensor_id`, `type`, `status`
- `device` path
- Clock offset value

### `struct constraint`
Represents an HTTPS time constraint:
- `addr` / `name` / `port`
- TLS connection state
- Median offset calculation
- Certificate validation

### `imsg` (inter-process message)
Used for communication between ntpd and the DNS child process.
- `imsg_type`: `IMSG_QUERY`, `IMSG_QUERY_RESPONSE`,
  `IMSG_QUERY_END`, `IMSG_QUERY_ERR`
- `imsg_hdr`: standard imsg header from OpenBSD
