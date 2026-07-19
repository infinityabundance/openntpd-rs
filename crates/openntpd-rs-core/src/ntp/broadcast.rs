//! Broadcast (mode 5) and Symmetric (modes 1/2) packet support.
//!
//! These modes extend the basic NTP client/server model:
//!
//! - **Broadcast** (mode 5): server-to-client one-way time distribution.
//!   The server periodically sends unsolicited packets containing its
//!   current timestamp.  The client estimates offset using the known
//!   propagation delay or pairwise calibrations.
//!
//! - **Symmetric** (modes 1/2): peer-to-peer time exchange.
//!   Two peers operate as both client and server simultaneously.
//!   Mode 1 (SYMMETRIC_ACTIVE) initiates; mode 2 (SYMMETRIC_PASSIVE)
//!   responds.

use crate::ntp::*;

// ---------------------------------------------------------------------------
// Helpers: f64 ↔ NTP 16.16 fixed-point
// ---------------------------------------------------------------------------

/// Convert an `f64` to a signed 16.16 `NtpShortSigned`.
fn f64_to_short_signed(val: f64) -> NtpShortSigned {
    let bits = (val * 65_536.0) as i32;
    NtpShortSigned::new((bits >> 16) as i16, bits as u16)
}

/// Convert an `f64` to an unsigned 16.16 `NtpShortUnsigned`.
/// Clamps negative values to zero.
fn f64_to_short_unsigned(val: f64) -> NtpShortUnsigned {
    let clamped = if val < 0.0 { 0.0 } else { val };
    let bits = (clamped * 65_536.0) as u32;
    NtpShortUnsigned::new((bits >> 16) as u16, bits as u16)
}

// ---------------------------------------------------------------------------
// BroadcastPacket (mode 5)
// ---------------------------------------------------------------------------

/// A broadcast mode 5 NTP packet sent by a time server.
///
/// In broadcast mode the server fills all three timestamp fields
/// (origin, receive, transmit) with the same transmit timestamp, or
/// sets origin = receive = transmit.  The client captures its arrival
/// time (T4) and computes:
///
///   offset = ((T2 - T1) + (T3 - T4)) / 2
///
/// where T1 = origin_ts = T2 = receive_ts = T3 = transmit_ts (server time),
/// and T4 is the client's arrival time.
#[derive(Debug, Clone, PartialEq)]
pub struct BroadcastPacket {
    /// The underlying NTP packet.
    pub packet: NtpPacket,
}

impl BroadcastPacket {
    /// Create a new broadcast packet.
    ///
    /// # Parameters
    ///
    /// * `transmit_time` — the NTP timestamp to place in origin, receive,
    ///   and transmit fields.
    /// * `stratum` — the server's stratum (1 = primary, 2–15 = secondary).
    /// * `precision` — system clock precision in log₂ seconds.
    /// * `root_delay` — total round-trip delay to the reference (seconds).
    /// * `root_dispersion` — maximum error relative to the reference (seconds).
    /// * `refid` — reference clock identifier (4-byte ASCII as `u32`).
    #[must_use]
    pub fn new(
        transmit_time: NtpTimestamp,
        stratum: u8,
        precision: i8,
        root_delay: f64,
        root_dispersion: f64,
        refid: u32,
    ) -> Self {
        let mut pkt = NtpPacket::zero();
        pkt.set_li_vn_mode(li::NO_WARNING, NTP_VERSION, mode::BROADCAST);
        pkt.stratum = stratum;
        pkt.precision = precision;
        pkt.root_delay = f64_to_short_signed(root_delay);
        pkt.root_dispersion = f64_to_short_unsigned(root_dispersion);
        pkt.reference_id = refid.to_be_bytes();
        // In broadcast, all three timestamps carry the server's
        // current time so the client can compute offset.
        pkt.origin_ts = transmit_time;
        pkt.receive_ts = transmit_time;
        pkt.transmit_ts = transmit_time;
        Self { packet: pkt }
    }

    /// Decode a broadcast packet from a byte buffer.
    ///
    /// Returns an error if the data is not a valid NTP datagram or if
    /// the mode field is not 5.
    pub fn decode(data: &[u8]) -> Result<Self, &'static str> {
        let datagram = NtpDatagram::decode(data).ok_or("invalid NTP datagram")?;
        let pkt = match datagram {
            NtpDatagram::Unauthenticated(p) => p,
            NtpDatagram::Authenticated { packet, .. } => packet,
        };
        if pkt.mode() != mode::BROADCAST {
            return Err("not a broadcast packet (mode != 5)");
        }
        Ok(Self { packet: pkt })
    }

    /// Encode to wire format (48-byte unauthenticated NTP packet).
    #[must_use]
    pub fn encode(&self) -> alloc::vec::Vec<u8> {
        NtpDatagram::Unauthenticated(self.packet).encode()
    }
}

// ---------------------------------------------------------------------------
// SymmetricPacket (modes 1/2)
// ---------------------------------------------------------------------------

/// A symmetric-mode NTP packet (mode 1 = active, mode 2 = passive).
///
/// In symmetric mode two peers exchange time information as equals.
/// Each peer maintains both a client and server state for the
/// association.
#[derive(Debug, Clone, PartialEq)]
pub struct SymmetricPacket {
    /// The underlying NTP packet.
    pub packet: NtpPacket,
}

impl SymmetricPacket {
    /// Create a new symmetric-mode packet.
    ///
    /// # Parameters
    ///
    /// * `mode` — `mode::SYMMETRIC_ACTIVE` (1) or `mode::SYMMETRIC_PASSIVE` (2).
    #[must_use]
    pub fn new(mode_val: u8) -> Self {
        let mut pkt = NtpPacket::zero();
        pkt.set_li_vn_mode(li::NO_WARNING, NTP_VERSION, mode_val);
        Self { packet: pkt }
    }

    /// Decode a symmetric-mode packet from a byte buffer.
    ///
    /// Returns an error if the data is not a valid NTP datagram or if
    /// the mode field is not 1 or 2.
    pub fn decode(data: &[u8]) -> Result<Self, &'static str> {
        let datagram = NtpDatagram::decode(data).ok_or("invalid NTP datagram")?;
        let pkt = match datagram {
            NtpDatagram::Unauthenticated(p) => p,
            NtpDatagram::Authenticated { packet, .. } => packet,
        };
        let m = pkt.mode();
        if m != mode::SYMMETRIC_ACTIVE && m != mode::SYMMETRIC_PASSIVE {
            return Err("not a symmetric packet (mode must be 1 or 2)");
        }
        Ok(Self { packet: pkt })
    }

    /// Encode to wire format.
    #[must_use]
    pub fn encode(&self) -> alloc::vec::Vec<u8> {
        NtpDatagram::Unauthenticated(self.packet).encode()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // ── Helpers ───────────────────────────────────────────────────────────

    fn sample_broadcast() -> BroadcastPacket {
        let ts = NtpTimestamp::new(4_000_000_000, 0x8000_0000);
        BroadcastPacket::new(
            ts,         // transmit_time
            2,          // stratum (secondary)
            -10,        // precision
            0.025,      // root_delay (~25 ms)
            0.010,      // root_dispersion (~10 ms)
            0x4E545030, // "NTP0" as u32
        )
    }

    // ── Broadcast ─────────────────────────────────────────────────────────

    #[test]
    fn test_broadcast_new_sets_mode() {
        let b = sample_broadcast();
        assert_eq!(b.packet.mode(), mode::BROADCAST);
        assert_eq!(b.packet.version(), NTP_VERSION);
        assert_eq!(b.packet.leap_indicator(), li::NO_WARNING);
    }

    #[test]
    fn test_broadcast_new_sets_stratum_precision() {
        let b = sample_broadcast();
        assert_eq!(b.packet.stratum, 2);
        assert_eq!(b.packet.precision, -10);
    }

    #[test]
    fn test_broadcast_new_timestamps_equal() {
        let b = sample_broadcast();
        assert_eq!(b.packet.origin_ts, b.packet.transmit_ts);
        assert_eq!(b.packet.receive_ts, b.packet.transmit_ts);
    }

    #[test]
    fn test_broadcast_encode_decode_roundtrip() {
        let b = sample_broadcast();
        let encoded = b.encode();
        let decoded = BroadcastPacket::decode(&encoded).unwrap();
        assert_eq!(b.packet, decoded.packet);
    }

    #[test]
    fn test_broadcast_decode_rejects_wrong_mode() {
        // A client-mode (3) packet should be rejected.
        let mut pkt = NtpPacket::zero();
        pkt.set_li_vn_mode(li::NO_WARNING, NTP_VERSION, mode::CLIENT);
        let encoded = NtpDatagram::Unauthenticated(pkt).encode();
        let result = BroadcastPacket::decode(&encoded);
        assert!(result.is_err());
    }

    #[test]
    fn test_broadcast_decode_rejects_truncated() {
        let result = BroadcastPacket::decode(&[0u8; 10]);
        assert!(result.is_err());
    }

    #[test]
    fn test_broadcast_root_delay_dispersion() {
        let b = sample_broadcast();
        let delay_f64 = b.packet.root_delay.to_f64();
        let disp_f64 = b.packet.root_dispersion.to_f64();
        // Should be approximately 0.025 / 0.010 with some 16.16 rounding.
        assert!((delay_f64 - 0.025).abs() < 0.001, "delay={delay_f64}");
        assert!((disp_f64 - 0.010).abs() < 0.001, "disp={disp_f64}");
    }

    #[test]
    fn test_broadcast_reference_id() {
        let b = sample_broadcast();
        assert_eq!(b.packet.reference_id, [0x4E, 0x54, 0x50, 0x30]); // "NTP0"
    }

    // ── Symmetric ─────────────────────────────────────────────────────────

    fn sample_symmetric(mode_val: u8) -> SymmetricPacket {
        let mut s = SymmetricPacket::new(mode_val);
        s.packet.stratum = 3;
        s.packet.poll = 6;
        s.packet.precision = -12;
        s.packet.transmit_ts = NtpTimestamp::new(4_000_000_100, 0);
        s
    }

    #[test]
    fn test_symmetric_active_mode() {
        let s = sample_symmetric(mode::SYMMETRIC_ACTIVE);
        assert_eq!(s.packet.mode(), mode::SYMMETRIC_ACTIVE);
        assert_eq!(s.packet.version(), NTP_VERSION);
    }

    #[test]
    fn test_symmetric_passive_mode() {
        let s = sample_symmetric(mode::SYMMETRIC_PASSIVE);
        assert_eq!(s.packet.mode(), mode::SYMMETRIC_PASSIVE);
    }

    #[test]
    fn test_symmetric_encode_decode_roundtrip() {
        for mode_val in [mode::SYMMETRIC_ACTIVE, mode::SYMMETRIC_PASSIVE] {
            let s = sample_symmetric(mode_val);
            let encoded = s.encode();
            let decoded = SymmetricPacket::decode(&encoded).unwrap();
            assert_eq!(s.packet, decoded.packet, "mode {mode_val}");
        }
    }

    #[test]
    fn test_symmetric_decode_rejects_client_mode() {
        let mut pkt = NtpPacket::zero();
        pkt.set_li_vn_mode(li::NO_WARNING, NTP_VERSION, mode::CLIENT);
        let encoded = NtpDatagram::Unauthenticated(pkt).encode();
        let result = SymmetricPacket::decode(&encoded);
        assert!(result.is_err());
    }

    #[test]
    fn test_symmetric_decode_rejects_truncated() {
        let result = SymmetricPacket::decode(&[0u8; 10]);
        assert!(result.is_err());
    }

    #[test]
    fn test_symmetric_custom_stratum_poll() {
        let s = sample_symmetric(mode::SYMMETRIC_ACTIVE);
        assert_eq!(s.packet.stratum, 3);
        assert_eq!(s.packet.poll, 6);
        assert_eq!(s.packet.precision, -12);
    }

    #[test]
    fn test_symmetric_new_symmetric_active() {
        let s = SymmetricPacket::new(mode::SYMMETRIC_ACTIVE);
        assert_eq!(s.packet.mode(), mode::SYMMETRIC_ACTIVE);
    }

    #[test]
    fn test_symmetric_new_symmetric_passive() {
        let s = SymmetricPacket::new(mode::SYMMETRIC_PASSIVE);
        assert_eq!(s.packet.mode(), mode::SYMMETRIC_PASSIVE);
    }
}
