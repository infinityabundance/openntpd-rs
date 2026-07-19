# Build OpenNTPD 7.9p1 oracle from source
FROM debian:bookworm-slim AS builder

RUN apt-get update && apt-get install -y \
    gcc make libssl-dev libtls-dev bison flex wget \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /build
RUN wget https://ftp.openbsd.org/pub/OpenBSD/OpenNTPD/openntpd-7.9p1.tar.gz
# RUN echo "<expected-sha256>  openntpd-7.9p1.tar.gz" | sha256sum -c
RUN tar xzf openntpd-7.9p1.tar.gz
WORKDIR /build/openntpd-7.9p1
RUN ./configure && make && make install
RUN strip /usr/local/sbin/ntpd

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y \
    libtls-dev libssl-dev ca-certificates \
    && rm -rf /var/lib/apt/lists/*
COPY --from=builder /usr/local/sbin/ntpd /usr/local/sbin/ntpd
RUN ntpd -n -f /dev/null 2>/dev/null; echo "Oracle built: $?"
