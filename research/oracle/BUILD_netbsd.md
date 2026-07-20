# Building OpenNTPD 7.9p1 on NetBSD

These instructions cover building `ntpd` from the OpenNTPD 7.9p1 tarball
on a stock NetBSD system.

## Prerequisites

- NetBSD 10.0 or later
- `gcc` (in base system, or `pkg_add gcc12`)
- `bmake` or `gmake` — the base `make` may work; install `gmake` if needed
- `bison` and `flex` (in base system)
- `wget` or `ftp` (in base system)
- `libtls` / `libressl` — install the package: `pkg_add libtls` or `pkg_add libressl`
- `ca-certificates` package

## Build Steps

```sh
# Install required packages
pkgin install ca-certificates libtls

# Download and verify the tarball
ftp https://ftp.openbsd.org/pub/OpenBSD/OpenNTPD/openntpd-7.9p1.tar.gz
cksum -a sha256 openntpd-7.9p1.tar.gz
# Expected: 091eeb3f4e358e28c3ab2ea58f93d7a0b5758a20d7c8a0418e162e9b2c27addc

tar xzf openntpd-7.9p1.tar.gz
cd openntpd-7.9p1

# Configure, build, install
./configure
gmake
doas gmake install

# Verify the binary runs (dry-run config check)
/usr/local/sbin/ntpd -n -f /dev/null
echo "Oracle built OK: $?"
```

## Notes

- NetBSD's base `make` is BSD make; if `./configure` generates a Makefile
  expecting GNU make, use `gmake` instead.
- `libtls` on NetBSD is provided by `libressl` — either `pkg_add libressl`
  or build from pkgsrc (`security/libressl`).
- If `configure` fails to find `libtls`, try:
  `LDFLAGS="-L/usr/pkg/lib" CPPFLAGS="-I/usr/pkg/include" ./configure`
- The resulting binary is at `/usr/local/sbin/ntpd`.
- To strip debug symbols: `doas strip /usr/local/sbin/ntpd`.
