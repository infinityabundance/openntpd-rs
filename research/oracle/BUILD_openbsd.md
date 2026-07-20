# Building OpenNTPD 7.9p1 on OpenBSD

These instructions cover building `ntpd` from the OpenNTPD 7.9p1 tarball
on a stock OpenBSD system.

## Prerequisites

- OpenBSD 7.5 or later (for `libtls` / `libressl` compatibility)
- `gcc` (base system, or `pkg_add gcc` if you need a newer one)
- `bison` and `flex` (in base system)
- `wget` or `ftp` (in base system)
- `ca-certificates` package

## Build Steps

```sh
# Install required packages (if not already present)
doas pkg_add ca-certificates

# Download and verify the tarball
ftp https://ftp.openbsd.org/pub/OpenBSD/OpenNTPD/openntpd-7.9p1.tar.gz
sha256 openntpd-7.9p1.tar.gz
# Expected: 091eeb3f4e358e28c3ab2ea58f93d7a0b5758a20d7c8a0418e162e9b2c27addc

tar xzf openntpd-7.9p1.tar.gz
cd openntpd-7.9p1

# Configure, build, install
./configure
make
doas make install

# Verify the binary runs (dry-run config check)
ntpd -n -f /dev/null
echo "Oracle built OK: $?"
```

## Notes

- OpenBSD ships with `libressl` which provides `libtls` natively — no extra
  -dev packages needed.
- The resulting binary is at `/usr/local/sbin/ntpd`.
- To strip debug symbols: `doas strip /usr/local/sbin/ntpd`.
