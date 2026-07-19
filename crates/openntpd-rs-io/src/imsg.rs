//! # imsg — inter-process message protocol
//!
//! OpenNTPD's privilege separation is built on OpenBSD's `imsg` framework:
//! a binary message-passing protocol over Unix domain sockets.  This module
//! provides a pure-Rust implementation.
//!
//! ## Wire format
//!
//! Each message consists of a fixed 12-byte header followed by a
//! variable-length payload:
//!
//! ```text
//! 0                   1                   2                   3
//! 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |                          type (32)                            |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |                         peer id (32)                          |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |                        length (32)                            |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |                            payload                            |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! ```

use std::io::{Read, Write};
use std::os::unix::io::{AsRawFd, RawFd};
use std::os::unix::net::UnixStream;

// ---------------------------------------------------------------------------
// Message types — matching OpenNTPD's imsg.h
// ---------------------------------------------------------------------------

pub const IMSG_PARENT_REQ_DNS: u32 = 0x01;
pub const IMSG_PARENT_DNS_RESP: u32 = 0x02;
pub const IMSG_CHILD_REQ_TIME: u32 = 0x03;
pub const IMSG_CHILD_TIME_RESP: u32 = 0x04;
pub const IMSG_PARENT_ADJUST: u32 = 0x05;
pub const IMSG_CHILD_ADJUST_ACK: u32 = 0x06;
pub const IMSG_PARENT_SETTIME: u32 = 0x07;
pub const IMSG_PARENT_DRIFT: u32 = 0x08;
pub const IMSG_CHILD_DRIFT_RESP: u32 = 0x09;
pub const IMSG_PARENT_SENSOR: u32 = 0x0a;
pub const IMSG_PARENT_CONSTRAINT: u32 = 0x0b;
pub const IMSG_CTL_REQ: u32 = 0x0c;
pub const IMSG_CTL_RESP: u32 = 0x0d;
pub const IMSG_PARENT_SHUTDOWN: u32 = 0x0e;
pub const IMSG_CHILD_SHUTDOWN_ACK: u32 = 0x0f;

/// Maximum imsg payload size (matching OpenNTPD's 8KB limit).
pub const IMSG_MAX_PAYLOAD: usize = 8192;

// ---------------------------------------------------------------------------
// Header
// ---------------------------------------------------------------------------

/// Fixed imsg header: 12 bytes on the wire.
#[repr(C, packed)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ImsgHeader {
    pub type_: u32,
    pub peer_id: u32,
    pub length: u32,
}

impl ImsgHeader {
    pub fn new(type_: u32, payload_len: usize) -> Self {
        Self {
            type_,
            peer_id: 0,
            length: payload_len as u32,
        }
    }

    pub fn to_bytes(&self) -> [u8; 12] {
        let mut buf = [0u8; 12];
        buf[0..4].copy_from_slice(&self.type_.to_be_bytes());
        buf[4..8].copy_from_slice(&self.peer_id.to_be_bytes());
        buf[8..12].copy_from_slice(&self.length.to_be_bytes());
        buf
    }

    pub fn from_bytes(bytes: &[u8; 12]) -> Self {
        Self {
            type_: u32::from_be_bytes(bytes[0..4].try_into().unwrap()),
            peer_id: u32::from_be_bytes(bytes[4..8].try_into().unwrap()),
            length: u32::from_be_bytes(bytes[8..12].try_into().unwrap()),
        }
    }

    pub fn validate(&self) -> Result<(), ImsgError> {
        if self.length as usize > IMSG_MAX_PAYLOAD {
            return Err(ImsgError::PayloadTooLarge(self.length as usize));
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Message
// ---------------------------------------------------------------------------

/// A complete imsg message (header + payload).
#[derive(Debug, Clone)]
pub struct Imsg {
    pub header: ImsgHeader,
    pub payload: Vec<u8>,
}

impl Imsg {
    pub fn new(type_: u32, payload: Vec<u8>) -> Self {
        Self {
            header: ImsgHeader::new(type_, payload.len()),
            payload,
        }
    }

    /// Serialize to wire format (header + payload).
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf = self.header.to_bytes().to_vec();
        buf.extend_from_slice(&self.payload);
        buf
    }

    /// Deserialize from wire format bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<(Self, usize), ImsgError> {
        if bytes.len() < 12 {
            return Err(ImsgError::Truncated);
        }
        let header_bytes: [u8; 12] = bytes[..12].try_into().unwrap();
        let header = ImsgHeader::from_bytes(&header_bytes);
        header.validate()?;

        let total = 12 + header.length as usize;
        if bytes.len() < total {
            return Err(ImsgError::Truncated);
        }

        let payload = bytes[12..total].to_vec();
        Ok((Self { header, payload }, total))
    }
}

// ---------------------------------------------------------------------------
// ImsgSocket — wrapper around UnixStream with imsg framing
// ---------------------------------------------------------------------------

/// An imsg socket wraps a `UnixStream` and provides framed send/recv.
pub struct ImsgSocket {
    stream: UnixStream,
    read_buf: Vec<u8>,
    read_offset: usize,
}

impl ImsgSocket {
    /// Create a new imsg socket pair (like `socketpair(AF_UNIX)`).
    pub fn pair() -> std::io::Result<(Self, Self)> {
        let (a, b) = UnixStream::pair()?;
        Ok((Self::new(a), Self::new(b)))
    }

    pub fn new(stream: UnixStream) -> Self {
        Self {
            stream,
            read_buf: vec![0u8; IMSG_MAX_PAYLOAD + 12],
            read_offset: 0,
        }
    }

    pub fn as_raw_fd(&self) -> RawFd {
        self.stream.as_raw_fd()
    }

    /// Send an imsg (header + payload).
    pub fn send(&mut self, msg: &Imsg) -> Result<(), ImsgError> {
        let bytes = msg.to_bytes();
        self.stream
            .write_all(&bytes)
            .map_err(|e| ImsgError::Io(e))?;
        self.stream.flush().map_err(|e| ImsgError::Io(e))?;
        Ok(())
    }

    /// Receive one imsg.  Reads from the stream until a complete message
    /// is available, using the length field to determine framing.
    pub fn recv(&mut self) -> Result<Imsg, ImsgError> {
        // Read at least the header (12 bytes)
        while self.read_offset < 12 {
            let n = self
                .stream
                .read(&mut self.read_buf[self.read_offset..])
                .map_err(|e| ImsgError::Io(e))?;
            if n == 0 {
                return Err(ImsgError::ConnectionClosed);
            }
            self.read_offset += n;
        }

        // Parse header to get payload length
        let header_bytes: [u8; 12] = self.read_buf[..12].try_into().unwrap();
        let header = ImsgHeader::from_bytes(&header_bytes);
        header.validate()?;

        let total = 12 + header.length as usize;

        // Read remaining payload
        while (self.read_offset as u32) < total as u32 {
            let n = self
                .stream
                .read(&mut self.read_buf[self.read_offset..])
                .map_err(|e| ImsgError::Io(e))?;
            if n == 0 {
                return Err(ImsgError::ConnectionClosed);
            }
            self.read_offset += n;
        }

        let payload = self.read_buf[12..total].to_vec();

        // Compact buffer: move remaining data to front
        if self.read_offset > total {
            let remaining = self.read_offset - total;
            self.read_buf.copy_within(total..self.read_offset, 0);
            self.read_offset = remaining;
        } else {
            self.read_offset = 0;
        }

        Ok(Imsg { header, payload })
    }

    /// Send a file descriptor via SCM_RIGHTS alongside an imsg.
    /// Note: This requires using sendmsg/recvmsg for ancillary data.
    /// For simplicity, the current implementation sends the imsg only.
    /// SCM_RIGHTS support will be added in a future phase.
    pub fn send_with_fd(&mut self, msg: &Imsg, _fd: RawFd) -> Result<(), ImsgError> {
        // Placeholder — SCM_RIGHTS requires sendmsg with ancillary data.
        // For now, fall back to regular send.
        self.send(msg)
    }
}

impl Clone for ImsgSocket {
    fn clone(&self) -> Self {
        // UnixStream doesn't support Clone directly, but we can duplicate the fd.
        let fd = self.stream.as_raw_fd();
        let duplicated = unsafe { std::os::unix::io::FromRawFd::from_raw_fd(libc::dup(fd)) };
        Self {
            stream: duplicated,
            read_buf: self.read_buf.clone(),
            read_offset: 0,
        }
    }
}

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

#[derive(Debug)]
pub enum ImsgError {
    Truncated,
    PayloadTooLarge(usize),
    ConnectionClosed,
    Io(std::io::Error),
}

impl std::fmt::Display for ImsgError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ImsgError::Truncated => write!(f, "truncated imsg"),
            ImsgError::PayloadTooLarge(sz) => write!(f, "imsg payload too large: {sz}"),
            ImsgError::ConnectionClosed => write!(f, "imsg connection closed"),
            ImsgError::Io(e) => write!(f, "imsg I/O error: {e}"),
        }
    }
}

impl std::error::Error for ImsgError {}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn imsg_header_roundtrip() {
        let h = ImsgHeader::new(0x01, 64);
        let bytes = h.to_bytes();
        let h2 = ImsgHeader::from_bytes(&bytes);
        assert_eq!(h, h2);
    }

    #[test]
    fn imsg_roundtrip() {
        let payload = b"hello imsg".to_vec();
        let msg = Imsg::new(IMSG_PARENT_REQ_DNS, payload.clone());

        let bytes = msg.to_bytes();
        let (decoded, consumed) = Imsg::from_bytes(&bytes).unwrap();

        assert_eq!(decoded.header.type_, IMSG_PARENT_REQ_DNS);
        assert_eq!(decoded.payload, payload);
        assert_eq!(consumed, 12 + payload.len());
    }

    #[test]
    fn imsg_socket_pair_roundtrip() {
        let (mut a, mut b) = ImsgSocket::pair().unwrap();

        let sent = Imsg::new(IMSG_CHILD_REQ_TIME, b"time query".to_vec());
        a.send(&sent).unwrap();

        let received = b.recv().unwrap();
        assert_eq!(received.header.type_, IMSG_CHILD_REQ_TIME);
        assert_eq!(received.payload, b"time query");
    }

    #[test]
    fn imsg_multiple_messages() {
        let (mut a, mut b) = ImsgSocket::pair().unwrap();

        a.send(&Imsg::new(1, b"msg1".to_vec())).unwrap();
        a.send(&Imsg::new(2, b"msg2".to_vec())).unwrap();

        let r1 = b.recv().unwrap();
        let r2 = b.recv().unwrap();
        assert_eq!(r1.payload, b"msg1");
        assert_eq!(r2.payload, b"msg2");
    }

    #[test]
    fn imsg_payload_too_large() {
        let h = ImsgHeader::new(1, IMSG_MAX_PAYLOAD + 1);
        assert!(h.validate().is_err());
    }

    #[test]
    fn imsg_truncated() {
        let result = Imsg::from_bytes(b"short");
        assert!(result.is_err());
    }

    #[test]
    fn imsg_zero_length_payload() {
        let msg = Imsg::new(1, vec![]);
        let bytes = msg.to_bytes();
        let (decoded, _) = Imsg::from_bytes(&bytes).unwrap();
        assert_eq!(decoded.payload.len(), 0);
    }
}
