//! NTP message I/O — corresponding to OpenNTPD's `ntp_msg.c`.
//!
//! Provides `ntp_getmsg()` and `ntp_sendmsg()` equivalent functions
//! for reading/writing NTP datagrams over UDP sockets.
//!
//! OpenNTPD accepts exactly two packet lengths:
//! - **48 bytes** (unauthenticated)
//! - **68 bytes** (authenticated: 48 + 4-byte key ID + 16-byte digest)

use crate::ntp::{NtpDatagram, NtpPacket, NTP_PACKET_MIN_SIZE};

/// Result of receiving an NTP message.
#[derive(Debug)]
pub struct RecvResult {
    /// The decoded NTP datagram (48 or 68 bytes).
    pub datagram: NtpDatagram,
    /// Total bytes received.
    pub length: usize,
}

/// Receive and decode an NTP datagram from a byte buffer.
///
/// Corresponds to OpenNTPD's `ntp_getmsg()`.
///
/// Returns `None` if the buffer length is not 48 or 68 bytes,
/// or if the header is malformed.
pub fn ntp_getmsg(buf: &[u8]) -> Option<RecvResult> {
    let length = buf.len();
    let datagram = NtpDatagram::decode(buf)?;
    Some(RecvResult { datagram, length })
}

/// Build an NTP transmit buffer from a packet (48 bytes, unauthenticated).
///
/// Corresponds to OpenNTPD's `ntp_sendmsg()`.
#[must_use]
pub fn ntp_sendmsg(packet: &NtpPacket) -> [u8; NTP_PACKET_MIN_SIZE] {
    packet.encode()
}

/// Build an NTP transmit buffer from a datagram (may be authenticated).
#[must_use]
pub fn ntp_send_datagram(datagram: &NtpDatagram) -> alloc::vec::Vec<u8> {
    datagram.encode()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ntp::{li, mode, NtpTimestamp, NTP_PACKET_AUTH_SIZE, NTP_VERSION};

    #[test]
    fn test_ntp_getmsg_valid_48() {
        let mut pkt = NtpPacket::zero();
        pkt.set_li_vn_mode(li::NO_WARNING, NTP_VERSION, mode::SERVER);
        pkt.stratum = 2;
        pkt.transmit_ts = NtpTimestamp::new(1000, 0);

        let encoded = pkt.encode();
        let result = ntp_getmsg(&encoded).unwrap();
        assert_eq!(result.length, 48);
        assert_eq!(result.datagram, NtpDatagram::Unauthenticated(pkt));
    }

    #[test]
    fn test_ntp_getmsg_rejects_bad_lengths() {
        assert!(ntp_getmsg(&[0u8; 10]).is_none());
        assert!(ntp_getmsg(&[0u8; 49]).is_none());
        assert!(ntp_getmsg(&[0u8; 67]).is_none());
        assert!(ntp_getmsg(&[0u8; 69]).is_none());
    }

    #[test]
    fn test_ntp_sendmsg_roundtrip() {
        let pkt = NtpPacket::zero();
        let buf = ntp_sendmsg(&pkt);
        assert_eq!(buf.len(), NTP_PACKET_MIN_SIZE);
        let result = ntp_getmsg(&buf).unwrap();
        match result.datagram {
            NtpDatagram::Unauthenticated(d) => assert_eq!(pkt, d),
            _ => panic!("expected unauthenticated"),
        }
    }

    #[test]
    fn test_authenticated_roundtrip() {
        let pkt = NtpPacket::zero();
        let dgram = NtpDatagram::Authenticated {
            packet: pkt,
            key_id: 0xDEAD_BEEF,
            digest: [0x42; 16],
        };
        let buf = ntp_send_datagram(&dgram);
        assert_eq!(buf.len(), NTP_PACKET_AUTH_SIZE);
        let result = ntp_getmsg(&buf).unwrap();
        assert_eq!(result.datagram, dgram);
    }
}
