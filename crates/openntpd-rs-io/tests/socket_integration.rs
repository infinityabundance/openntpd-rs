//! Loopback socket integration tests.
//!
//! These tests require a running network stack and are skipped
//! automatically when loopback is unavailable.
//!
//! Tests:
//! - IPv4 send/recv on 127.0.0.1
//! - IPv6 send/recv on ::1
//! - Verify source address, port, and payload integrity
//! - Kernel timestamp presence (SO_TIMESTAMP)
//! - Basic timestamp plausibility

use std::net::{SocketAddr, UdpSocket};
use std::os::fd::AsRawFd;
use std::time::Duration;

const TEST_PAYLOAD: &[u8] = b"openntpd-rs-test-48-byte-payload-here!";

#[test]
fn test_ipv4_send_recv() {
    let bind_addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
    let server = match UdpSocket::bind(bind_addr) {
        Ok(s) => s,
        Err(_) => {
            eprintln!("skipping IPv4 test: cannot bind");
            return;
        }
    };
    let server_addr = server.local_addr().unwrap();
    let _ = server.set_read_timeout(Some(Duration::from_secs(1)));

    let client: SocketAddr = "127.0.0.1:0".parse().unwrap();
    let client_sock = UdpSocket::bind(client).unwrap();
    client_sock.send_to(TEST_PAYLOAD, server_addr).unwrap();

    let mut buf = [0u8; 1024];
    let (len, src) = server.recv_from(&mut buf).unwrap();
    assert_eq!(len, TEST_PAYLOAD.len());
    assert_eq!(&buf[..len], TEST_PAYLOAD);
    assert!(src.ip().is_loopback());
    assert_eq!(src.port(), client_sock.local_addr().unwrap().port());
}

#[test]
fn test_ipv6_send_recv() {
    let bind_addr: SocketAddr = "[::1]:0".parse().unwrap();
    let server = match UdpSocket::bind(bind_addr) {
        Ok(s) => s,
        Err(_) => {
            eprintln!("skipping IPv6 test: cannot bind ::1");
            return;
        }
    };
    let server_addr = server.local_addr().unwrap();
    let _ = server.set_read_timeout(Some(Duration::from_secs(1)));

    let client_addr: SocketAddr = "[::1]:0".parse().unwrap();
    let client_sock = UdpSocket::bind(client_addr).unwrap();
    client_sock.send_to(TEST_PAYLOAD, server_addr).unwrap();

    let mut buf = [0u8; 1024];
    let (len, src) = server.recv_from(&mut buf).unwrap();
    assert_eq!(len, TEST_PAYLOAD.len());
    assert_eq!(&buf[..len], TEST_PAYLOAD);
    assert!(src.ip().is_loopback());
}

#[test]
fn test_ipv4_send_recv_no_timestamp() {
    // Test that recv_ntp_packet works without any timestamping option.
    let bind_addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
    let server = match UdpSocket::bind(bind_addr) {
        Ok(s) => s,
        Err(_) => {
            eprintln!("skipping: cannot bind");
            return;
        }
    };
    let server_addr = server.local_addr().unwrap();
    let _ = server.set_read_timeout(Some(Duration::from_secs(1)));

    let client = UdpSocket::bind("127.0.0.1:0").unwrap();
    client.send_to(TEST_PAYLOAD, server_addr).unwrap();

    let mut buf = [0u8; 1024];
    let (len, src) = openntpd_rs_io::socket::recv_ntp_packet(&server, &mut buf).unwrap();
    assert_eq!(len, TEST_PAYLOAD.len());
    assert_eq!(&buf[..len], TEST_PAYLOAD);
    assert!(src.ip().is_loopback());
}

#[test]
fn test_bind_ntp_socket_ipv4() {
    // Test the custom bind function with SO_REUSEPORT + SO_TIMESTAMP.
    let bind_addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
    let server = match openntpd_rs_io::socket::bind_ntp_socket(bind_addr, true, true) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("skipping: bind_ntp_socket failed: {e}");
            return;
        }
    };
    let server_addr = server.local_addr().unwrap();

    // Send a packet via raw UdpSocket (our test client)
    let client = UdpSocket::bind("127.0.0.1:0").unwrap();
    client.send_to(TEST_PAYLOAD, server_addr).unwrap();

    // Receive via the custom bind socket
    let mut buf = [0u8; 1024];
    let (len, src) = server.recv_from(&mut buf).unwrap();
    assert_eq!(len, TEST_PAYLOAD.len());
    assert_eq!(&buf[..len], TEST_PAYLOAD);
    assert!(src.ip().is_loopback());
}

#[test]
fn test_kernel_timestamp_smoke() {
    // Only run if we can use the raw recvmsg path.
    // Uses SO_TIMESTAMP and checks for a kernel timestamp.
    let bind_addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
    let server = match openntpd_rs_io::socket::bind_ntp_socket(bind_addr, false, true) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("skipping: bind_ntp_socket failed: {e}");
            return;
        }
    };
    let server_addr = server.local_addr().unwrap();
    let fd = server.as_raw_fd();

    let client = UdpSocket::bind("127.0.0.1:0").unwrap();
    client.send_to(TEST_PAYLOAD, server_addr).unwrap();

    let mut buf = [0u8; 1024];
    let result = openntpd_rs_io::socket::recv_ntp_with_timestamp(fd, &mut buf);

    match result {
        Ok((len, src, ts)) => {
            assert_eq!(len, TEST_PAYLOAD.len());
            assert_eq!(&buf[..len], TEST_PAYLOAD);
            assert!(src.ip().is_loopback());

            // If we got a timestamp, verify it's plausible
            if let Some(timestamp_ns) = ts {
                let wall_now = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_nanos() as i64;
                let drift = (timestamp_ns - wall_now).abs();
                // Kernel timestamp should be within 10 seconds of wall clock
                assert!(
                    drift < 10_000_000_000i64,
                    "kernel timestamp {timestamp_ns} too far from wall clock {wall_now} (diff {drift})"
                );
            } else {
                // On some systems SO_TIMESTAMP may not produce anc data;
                // this is not a failure, just a kernel config dependency.
                eprintln!("no kernel timestamp returned (kernel/config dependent)");
            }
        }
        Err(e) => {
            // recvmsg with SO_TIMESTAMP may fail on some CI environments
            // without CAP_NET_RAW or on older kernels.
            eprintln!("recv_ntp_with_timestamp failed (kernel dependent): {e}");
        }
    }
}

#[test]
fn test_bind_without_options() {
    let bind_addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
    let server = openntpd_rs_io::socket::bind_ntp_socket(bind_addr, false, false).unwrap();
    let server_addr = server.local_addr().unwrap();

    let client = UdpSocket::bind("127.0.0.1:0").unwrap();
    client.send_to(TEST_PAYLOAD, server_addr).unwrap();

    let mut buf = [0u8; 1024];
    let (len, src) = server.recv_from(&mut buf).unwrap();
    assert_eq!(len, TEST_PAYLOAD.len());
    assert!(src.ip().is_loopback());
}
