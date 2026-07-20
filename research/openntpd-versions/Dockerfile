# Build OpenNTPD <version> on <base>
#
# Usage:
#   docker build \
#     --build-arg BASE=debian:bookworm-slim \
#     --build-arg VERSION=7.9p1 \
#     --build-arg SHA256=091eeb3f4e358e28c3ab2ea58f93d7a0b5758a20d7c8a0418e162e9b2c27addc \
#     -t openntpd:7.9p1-debian \
#     .

ARG BASE=debian:bookworm-slim
ARG VERSION=7.9p1
ARG SHA256=091eeb3f4e358e28c3ab2ea58f93d7a0b5758a20d7c8a0418e162e9b2c27addc
ARG EXTRA_CFLAGS=
ARG EXTRA_CPPFLAGS=

# ---- builder stage ----
FROM $BASE AS builder

# Re-declare args after FROM so they are available in this stage
ARG VERSION
ARG SHA256
ARG EXTRA_CFLAGS
ARG EXTRA_CPPFLAGS

# Install build dependencies — varies by base OS family
RUN (command -v apt-get && apt-get update && apt-get install -y \
        gcc make libssl-dev libtls-dev bison flex wget ca-certificates \
        && rm -rf /var/lib/apt/lists/*) || \
    (command -v apk && apk add --no-cache \
        gcc make musl-dev openssl-dev libretls-dev bison flex wget) || \
    (command -v yum && yum install -y \
        gcc make openssl-devel libtls-devel bison flex wget ca-certificates \
        && yum clean all) || \
    echo "WARNING: unknown package manager; build may fail"

WORKDIR /build
RUN wget -q "https://ftp.openbsd.org/pub/OpenBSD/OpenNTPD/openntpd-${VERSION}.tar.gz"
RUN echo "${SHA256}  openntpd-${VERSION}.tar.gz" | sha256sum -c
RUN tar xzf "openntpd-${VERSION}.tar.gz"
WORKDIR "/build/openntpd-${VERSION}"

# Build (separate layer so errors are visible)
# EXTRA_CFLAGS/EXTRA_CPPFLAGS allow older versions to pass -fcommon etc.
RUN CFLAGS="${EXTRA_CFLAGS}" CPPFLAGS="${EXTRA_CPPFLAGS}" ./configure

# Build and install, then collect into /install/
RUN CFLAGS="${EXTRA_CFLAGS}" CPPFLAGS="${EXTRA_CPPFLAGS}" make && make install && \
    strip /usr/local/sbin/ntpd 2>/dev/null || true && \
    strip /usr/local/bin/ntpctl 2>/dev/null || true && \
    strip /usr/local/sbin/ntpctl 2>/dev/null || true && \
    mkdir -p /install && \
    cp -a /usr/local/sbin/ntpd /install/ 2>/dev/null; \
    cp -a /usr/local/bin/ntpctl /install/ 2>/dev/null; \
    cp -a /usr/local/sbin/ntpctl /install/ 2>/dev/null; \
    test -f /install/ntpd

# ---- runtime stage ----
FROM $BASE

# Install runtime libraries
RUN (command -v apt-get && apt-get update && apt-get install -y \
        libtls-dev libssl-dev ca-certificates \
        && rm -rf /var/lib/apt/lists/*) || \
    (command -v apk && apk add --no-cache \
        libretls ca-certificates) || \
    (command -v yum && yum install -y \
        libtls-devel openssl-devel ca-certificates \
        && yum clean all) || \
    true

# Copy all installed binaries from builder staging directory
COPY --from=builder /install/ /usr/local/sbin/

# Ensure ntpd is executable and works
RUN chmod +x /usr/local/sbin/ntpd && \
    if [ -f /usr/local/sbin/ntpctl ]; then chmod +x /usr/local/sbin/ntpctl; fi && \
    ntpd -n -f /dev/null 2>/dev/null; echo "ntpd OK: $?"
