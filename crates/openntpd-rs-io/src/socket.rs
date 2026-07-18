//! Network socket operations — NTP UDP send/recv, control socket.
//!
//! Corresponds to OpenNTPD's `ntp_msg.c` (network send/receive) and
//! `server.c` (socket setup).
//!
//! ## Important
//!
//! - `SO_REUSEPORT` (and other socket options) MUST be set **before**
//!   binding, not after.
//! - Kernel receive timestamps arrive via `recvmsg()` ancillary
//!   control messages (`cmsghdr`).  A plain `recv_from()` cannot
//!   retrieve them.
//! - The IPv4 `s_addr` field is already in network byte order when
//!   returned by the kernel.  Use `to_ne_bytes()` (not `to_be_bytes()`)
//!   to read it on little-endian hosts.

use std::net::{SocketAddr, UdpSocket};
use std::os::fd::{AsRawFd, FromRawFd, IntoRawFd, OwnedFd};

/// Error type for network operations.
#[derive(Debug)]
pub enum SocketError {
    /// Underlying I/O error.
    Io(std::io::Error),
    /// Invalid address.
    Addr(&'static str),
    /// Socket option configuration failed.
    Opt(&'static str),
    /// Send length mismatch.
    Length { expected: usize, actual: usize },
    /// Control message truncated.
    CmsgTrunc,
    /// Datagram truncated.
    DgramTrunc,
}

impl std::fmt::Display for SocketError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(e) => write!(f, "socket I/O: {e}"),
            Self::Addr(a) => write!(f, "address error: {a}"),
            Self::Opt(o) => write!(f, "option error: {o}"),
            Self::Length { expected, actual } => {
                write!(f, "send length mismatch: expected {expected}, got {actual}")
            }
            Self::CmsgTrunc => write!(f, "control message truncated"),
            Self::DgramTrunc => write!(f, "datagram truncated"),
        }
    }
}

impl std::error::Error for SocketError {}

/// Result for socket operations.
pub type SocketResult<T> = Result<T, SocketError>;

/// Set a boolean socket option via `setsockopt`.
///
/// # Safety
///
/// `level`, `optname`, and `fd` must be valid.
unsafe fn set_sock_opt(
    fd: std::os::unix::io::RawFd,
    level: libc::c_int,
    optname: libc::c_int,
    enabled: bool,
) -> SocketResult<()> {
    let val: libc::c_int = if enabled { 1 } else { 0 };
    // SAFETY: caller ensures fd/level/optname are valid.
    let ret = unsafe {
        libc::setsockopt(
            fd,
            level,
            optname,
            &val as *const _ as *const libc::c_void,
            std::mem::size_of_val(&val) as libc::socklen_t,
        )
    };
    if ret != 0 {
        return Err(SocketError::Io(std::io::Error::last_os_error()));
    }
    Ok(())
}

/// Bind an NTP UDP socket, applying pre-bind options.
///
/// Options are configured **before** binding.  The raw fd is wrapped
/// in `OwnedFd` immediately after creation so all error paths close
/// it automatically via RAII.
///
/// - `reuse_port`: set `SO_REUSEPORT` (Linux 3.9+).
/// - `timestamping`: set `SO_TIMESTAMP` for kernel RX timestamps.
pub fn bind_ntp_socket(
    addr: SocketAddr,
    reuse_port: bool,
    timestamping: bool,
) -> SocketResult<UdpSocket> {
    let domain = match addr {
        SocketAddr::V4(_) => libc::AF_INET,
        SocketAddr::V6(_) => libc::AF_INET6,
    };
    // SAFETY: socket with valid domain, SOCK_DGRAM | SOCK_CLOEXEC, UDP.
    let fd = unsafe {
        libc::socket(
            domain,
            libc::SOCK_DGRAM | libc::SOCK_CLOEXEC,
            libc::IPPROTO_UDP,
        )
    };
    if fd < 0 {
        return Err(SocketError::Io(std::io::Error::last_os_error()));
    }

    // Wrap immediately for RAII cleanup on all error paths.
    // SAFETY: fd is a valid, newly-created socket.
    let owned_fd = unsafe { OwnedFd::from_raw_fd(fd) };

    if reuse_port {
        #[cfg(target_os = "linux")]
        // SAFETY: owned_fd is a valid socket.
        unsafe {
            set_sock_opt(
                owned_fd.as_raw_fd(),
                libc::SOL_SOCKET,
                libc::SO_REUSEPORT,
                true,
            )?;
        }
    }

    if timestamping {
        #[cfg(target_os = "linux")]
        // SAFETY: owned_fd is a valid socket.
        unsafe {
            set_sock_opt(
                owned_fd.as_raw_fd(),
                libc::SOL_SOCKET,
                libc::SO_TIMESTAMP,
                true,
            )?;
        }
    }

    // Bind
    let sock_addr: libc::sockaddr_storage = socket_addr_to_storage(addr);
    // SAFETY: bind with valid fd and sockaddr.
    let ret = unsafe {
        libc::bind(
            owned_fd.as_raw_fd(),
            &sock_addr as *const _ as *const libc::sockaddr,
            std::mem::size_of_val(&sock_addr) as libc::socklen_t,
        )
    };
    if ret != 0 {
        return Err(SocketError::Io(std::io::Error::last_os_error()));
    }

    // Convert to UdpSocket.  OwnedFd is consumed so it does not close.
    // SAFETY: fd is valid, owned, bound.  from_raw_fd takes ownership.
    let socket = unsafe { UdpSocket::from_raw_fd(owned_fd.into_raw_fd()) };
    Ok(socket)
}

/// Receive an NTP datagram with optional timestamp ancillary data.
///
/// Uses `recvmsg()` so that `SO_TIMESTAMP` control messages can be
/// retrieved.  Returns the payload, sender address, and optional
/// kernel receive timestamp in nanoseconds.
///
/// Validates `msg_flags` for truncation and verifies ancillary data
/// length before dereferencing.
#[cfg(target_os = "linux")]
pub fn recv_ntp_with_timestamp(
    fd: std::os::unix::io::RawFd,
    buf: &mut [u8],
) -> SocketResult<(usize, SocketAddr, Option<i64>)> {
    let mut iov = libc::iovec {
        iov_base: buf.as_mut_ptr() as *mut libc::c_void,
        iov_len: buf.len(),
    };

    // Ancillary buffer — must be large enough for SO_TIMESTAMP timespec
    // plus alignment headers.  Uses a repr(C) union to guarantee alignment
    // appropriate for `cmsghdr` and `timeval`.
    #[repr(C)]
    union ControlBuf {
        align: libc::cmsghdr,
        bytes: [u8; 64],
    }
    let mut cmsg_union = ControlBuf { bytes: [0u8; 64] };

    let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
    let mut src_storage: libc::sockaddr_storage = unsafe { std::mem::zeroed() };

    msg.msg_name = &mut src_storage as *mut _ as *mut libc::c_void;
    msg.msg_namelen = std::mem::size_of::<libc::sockaddr_storage>() as libc::socklen_t;
    msg.msg_iov = &mut iov;
    msg.msg_iovlen = 1;
    // SAFETY: accessing the bytes field of a union is safe for writing.
    msg.msg_control = unsafe { cmsg_union.bytes.as_mut_ptr() as *mut libc::c_void };
    msg.msg_controllen = 64;

    // SAFETY: recvmsg with valid fd and initialized msghdr.
    let nread = loop {
        let ret = unsafe { libc::recvmsg(fd, &mut msg, 0) };
        if ret < 0 {
            let err = std::io::Error::last_os_error();
            // Retry on EINTR (portable patch 0024).
            if err.kind() == std::io::ErrorKind::Interrupted {
                continue;
            }
            return Err(SocketError::Io(err));
        }
        break ret as usize;
    };

    // Check truncation flags
    if msg.msg_flags & libc::MSG_CTRUNC != 0 {
        return Err(SocketError::CmsgTrunc);
    }
    if msg.msg_flags & libc::MSG_TRUNC != 0 {
        return Err(SocketError::DgramTrunc);
    }

    // Decode sender address
    let src = decode_sockaddr(&src_storage, msg.msg_namelen)?;

    // Parse ancillary data for SO_TIMESTAMP
    let mut rx_timestamp: Option<i64> = None;
    // SAFETY: CMSG_FIRSTHDR/CMSG_NXTHDR macros from libc.
    let mut cmsg: *mut libc::cmsghdr = unsafe { libc::CMSG_FIRSTHDR(&msg) };
    while !cmsg.is_null() {
        // SAFETY: cmsg is valid within the control buffer.
        let cm = unsafe { &*cmsg };
        if cm.cmsg_level == libc::SOL_SOCKET && cm.cmsg_type == libc::SO_TIMESTAMP {
            // Validate ancillary data length: must hold a timeval.
            let required_len =
                unsafe { libc::CMSG_LEN(std::mem::size_of::<libc::timeval>() as _) } as usize;
            if (cm.cmsg_len as usize) < required_len {
                return Err(SocketError::Addr("SO_TIMESTAMP ancillary data too short"));
            }
            // SAFETY: length validated; CMSG_DATA returns pointer to payload.
            let ts: *const libc::timeval = unsafe { libc::CMSG_DATA(cmsg) as *const libc::timeval };
            // SAFETY: ts points to a valid timeval (length checked above).
            let tv = unsafe { *ts };
            rx_timestamp = Some(tv.tv_sec as i64 * 1_000_000_000 + tv.tv_usec as i64 * 1000);
            break;
        }
        // SAFETY: standard CMSG_NXTHDR iteration.
        cmsg = unsafe { libc::CMSG_NXTHDR(&msg, cmsg) };
    }

    Ok((nread, src, rx_timestamp))
}

/// Send an NTP datagram to a remote address.
///
/// Reports `SocketError::Length` if the actual byte count differs
/// from the expected NTP packet size.
pub fn send_ntp_packet(socket: &UdpSocket, buf: &[u8], dest: SocketAddr) -> SocketResult<usize> {
    let sent = socket.send_to(buf, dest).map_err(SocketError::Io)?;
    if sent != buf.len() {
        return Err(SocketError::Length {
            expected: buf.len(),
            actual: sent,
        });
    }
    Ok(sent)
}

/// Receive an NTP packet (basic, without timestamping).
pub fn recv_ntp_packet(socket: &UdpSocket, buf: &mut [u8]) -> SocketResult<(usize, SocketAddr)> {
    let (len, addr) = socket.recv_from(buf).map_err(SocketError::Io)?;
    Ok((len, addr))
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

/// Decode a `SocketAddr` from `sockaddr_storage` and `namelen`.
///
/// On Linux the kernel returns `s_addr` in network byte order already
/// embedded in the `in_addr` struct.  Reading it as a native u32 and
/// calling `to_be_bytes()` on a little-endian host would reverse the
/// bytes.  Use `to_ne_bytes()` to extract the raw network-order bytes.
fn decode_sockaddr(
    storage: &libc::sockaddr_storage,
    namelen: libc::socklen_t,
) -> SocketResult<SocketAddr> {
    match storage.ss_family as i32 {
        libc::AF_INET => {
            if (namelen as usize) < std::mem::size_of::<libc::sockaddr_in>() {
                return Err(SocketError::Addr("truncated IPv4 address"));
            }
            // SAFETY: sockaddr_in is at the start of sockaddr_storage for AF_INET,
            // and we validated the length.  Uses `ptr::from_ref` to get a pointer
            // to the actual underlying `sockaddr_storage`, not to the stack slot
            // holding the reference.
            let sin = unsafe { *std::ptr::from_ref(storage).cast::<libc::sockaddr_in>() };
            // s_addr is network byte order; read the raw bytes directly.
            let ip = sin.sin_addr.s_addr.to_ne_bytes();
            Ok(SocketAddr::V4(std::net::SocketAddrV4::new(
                std::net::Ipv4Addr::new(ip[0], ip[1], ip[2], ip[3]),
                u16::from_be(sin.sin_port),
            )))
        }
        libc::AF_INET6 => {
            if (namelen as usize) < std::mem::size_of::<libc::sockaddr_in6>() {
                return Err(SocketError::Addr("truncated IPv6 address"));
            }
            // SAFETY: sockaddr_in6 is at the start for AF_INET6, length validated.
            let sin6 = unsafe { *std::ptr::from_ref(storage).cast::<libc::sockaddr_in6>() };
            Ok(SocketAddr::V6(std::net::SocketAddrV6::new(
                std::net::Ipv6Addr::from(sin6.sin6_addr.s6_addr),
                u16::from_be(sin6.sin6_port),
                sin6.sin6_flowinfo,
                sin6.sin6_scope_id,
            )))
        }
        _ => Err(SocketError::Addr("unknown address family")),
    }
}

/// Convert a Rust `SocketAddr` to a libc `sockaddr_storage`.
fn socket_addr_to_storage(addr: SocketAddr) -> libc::sockaddr_storage {
    let mut storage: libc::sockaddr_storage = unsafe { std::mem::zeroed() };
    match addr {
        SocketAddr::V4(v4) => {
            // ntohl/htonm: write s_addr in network byte order
            let sin = libc::sockaddr_in {
                sin_family: libc::AF_INET as libc::sa_family_t,
                sin_port: v4.port().to_be(),
                sin_addr: libc::in_addr {
                    s_addr: u32::from_ne_bytes(v4.ip().octets()),
                },
                sin_zero: [0u8; 8],
            };
            // SAFETY: sockaddr_in fits in sockaddr_storage.
            unsafe {
                std::ptr::write(&mut storage as *mut _ as *mut libc::sockaddr_in, sin);
            }
        }
        SocketAddr::V6(v6) => {
            let sin6 = libc::sockaddr_in6 {
                sin6_family: libc::AF_INET6 as libc::sa_family_t,
                sin6_port: v6.port().to_be(),
                sin6_flowinfo: v6.flowinfo(),
                sin6_addr: libc::in6_addr {
                    s6_addr: v6.ip().octets(),
                },
                sin6_scope_id: v6.scope_id(),
            };
            // SAFETY: sockaddr_in6 fits in sockaddr_storage.
            unsafe {
                std::ptr::write(&mut storage as *mut _ as *mut libc::sockaddr_in6, sin6);
            }
        }
    }
    storage
}
