//! Control socket protocol — imsg-based request/response types for `ntpctl`.
//!
//! This module provides the wire format for OpenNTPD's control socket
//! (`/var/run/ntpd.sock`).  Clients send a [`ControlRequest`] wrapped in
//! an `IMSG_CTL_REQ` message; the daemon replies with one or more
//! [`ControlResponse`] values in `IMSG_CTL_RESP` messages.
//!
//! ## Wire format
//!
//! ### Request
//!
//! ```text
//! 0                   1                   2                   3
//! 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |                     type (u32, big-endian)                     |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! ```
//!
//! ### Response
//!
//! ```text
//! 0                   1                   2                   3
//! 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |                response type (u32, big-endian)                 |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |                   type-specific payload ...                    |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! ```
//!
//! ### Status payload (type = [`CTL_REQ_STATUS`], 32 bytes)
//!
//! ```text
//! +0:  sync_state (u32 BE)         0=Synced, 1=Unsynchronized, 2=Constrained
//! +4:  stratum (u8)
//! +5:  pad (3 bytes, zero)
//! +8:  offset (f64 BE, IEEE 754)
//! +16: frequency (f64 BE, IEEE 754)
//! +24: uptime (u64 BE)
//! ```
//!
//! ### Peers payload (type = [`CTL_REQ_PEERS`])
//!
//! ```text
//! +0:  count (u32 BE)
//! +4:  peer entry[0]
//!      ...
//!
//! Each peer entry (36 + addr_len bytes):
//!   +0:  reach (u8)
//!   +1:  stratum (u8)
//!   +2:  flash_lo (u8)
//!   +3:  flash_hi (u8)
//!   +4:  poll (i8)
//!   +5:  weight (u8)
//!   +6:  trusted (u8)
//!   +7:  pad (1 byte)
//!   +8:  offset (f64 BE)
//!   +16: delay (f64 BE)
//!   +24: dispersion (f64 BE)
//!   +32: addr_len (u32 BE)
//!   +36: address (addr_len bytes, UTF-8)
//! ```
//!
//! ### Sensors payload (type = [`CTL_REQ_SENSORS`])
//!
//! ```text
//! +0:  count (u32 BE)
//! +4:  sensor entry[0]
//!      ...
//!
//! Each sensor entry (20 + device_len + refid_len bytes):
//!   +0:  status (u8)
//!   +1:  stratum (u8)
//!   +2:  weight (u8)
//!   +3:  pad (1 byte)
//!   +4:  correction (i64 BE)
//!   +12: device_len (u32 BE)
//!   +16: refid_len (u32 BE)
//!   +20: device (device_len bytes, UTF-8)
//!   +20 + device_len: refid (refid_len bytes, UTF-8)
//! ```
//!
//! ### All payload (type = [`CTL_REQ_ALL`])
//!
//! Concatenation of status data (32 bytes), then peers payload, then
//! sensors payload — each without a leading type tag.

use alloc::string::String;
use alloc::vec::Vec;
use core::fmt;

// ---------------------------------------------------------------------------
// Control message types — matching ntpd.h
// ---------------------------------------------------------------------------

/// Request current synchronization status.
pub const CTL_REQ_STATUS: u32 = 0x01;

/// Request list of configured NTP peers.
pub const CTL_REQ_PEERS: u32 = 0x02;

/// Request list of hardware sensors.
pub const CTL_REQ_SENSORS: u32 = 0x03;

/// Request all available data (status + peers + sensors).
pub const CTL_REQ_ALL: u32 = 0x04;

/// Deprecated debug request.
pub const CTL_REQ_D: u32 = 0x05;

/// Deprecated peers request.
pub const CTL_REQ_P: u32 = 0x06;

// ---------------------------------------------------------------------------
// SyncState
// ---------------------------------------------------------------------------

/// Clock synchronization state as reported by the daemon.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SyncState {
    /// Clock is synchronized to a reference source.
    Synced = 0,
    /// Clock is not synchronized.
    Unsynchronized = 1,
    /// Clock is constrained (e.g., waiting for HTTPS constraint).
    Constrained = 2,
}

impl SyncState {
    /// Convert a raw `u32` to a `SyncState`.
    ///
    /// Returns `None` for unknown values.
    #[must_use]
    pub fn from_raw(raw: u32) -> Option<Self> {
        match raw {
            0 => Some(Self::Synced),
            1 => Some(Self::Unsynchronized),
            2 => Some(Self::Constrained),
            _ => None,
        }
    }

    /// Convert to a raw `u32` for wire serialization.
    #[must_use]
    pub fn to_raw(self) -> u32 {
        self as u32
    }
}

// ---------------------------------------------------------------------------
// NtpdStatus
// ---------------------------------------------------------------------------

/// Daemon synchronization status — response to [`CTL_REQ_STATUS`].
#[derive(Debug, Clone)]
pub struct NtpdStatus {
    pub sync_state: SyncState,
    pub stratum: u8,
    pub offset: f64,
    pub frequency: f64,
    pub uptime: u64,
}

impl NtpdStatus {
    /// Deserialize from the 32-byte status payload (without leading type
    /// tag).  Returns `None` if the slice is too short or contains an
    /// invalid sync state.
    #[must_use]
    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        if bytes.len() < 32 {
            return None;
        }
        let sync_state_raw = u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
        let sync_state = SyncState::from_raw(sync_state_raw)?;
        let stratum = bytes[4];
        // bytes[5..8] are padding
        let offset = f64::from_be_bytes([
            bytes[8], bytes[9], bytes[10], bytes[11], bytes[12], bytes[13], bytes[14], bytes[15],
        ]);
        let frequency = f64::from_be_bytes([
            bytes[16], bytes[17], bytes[18], bytes[19], bytes[20], bytes[21], bytes[22], bytes[23],
        ]);
        let uptime = u64::from_be_bytes([
            bytes[24], bytes[25], bytes[26], bytes[27], bytes[28], bytes[29], bytes[30], bytes[31],
        ]);
        Some(Self {
            sync_state,
            stratum,
            offset,
            frequency,
            uptime,
        })
    }

    /// Serialize to 32 bytes (status payload, no leading type tag).
    #[must_use]
    pub fn to_bytes(&self) -> [u8; 32] {
        let mut buf = [0u8; 32];
        buf[0..4].copy_from_slice(&self.sync_state.to_raw().to_be_bytes());
        buf[4] = self.stratum;
        // bytes[5..8] are zero padding
        buf[8..16].copy_from_slice(&self.offset.to_be_bytes());
        buf[16..24].copy_from_slice(&self.frequency.to_be_bytes());
        buf[24..32].copy_from_slice(&self.uptime.to_be_bytes());
        buf
    }
}

// ---------------------------------------------------------------------------
// PeerInfo
// ---------------------------------------------------------------------------

/// Information about a single NTP peer — part of the [`CTL_REQ_PEERS`]
/// response.
#[derive(Debug, Clone)]
pub struct PeerInfo {
    /// Peer address (IP:port or hostname).
    pub address: String,
    /// Reachability register (8-bit shift register).
    pub reach: u8,
    /// Clock offset in seconds.
    pub offset: f64,
    /// Round-trip delay in seconds.
    pub delay: f64,
    /// Dispersion in seconds.
    pub dispersion: f64,
    /// Remote stratum.
    pub stratum: u8,
    /// Flash status bits (PFLASH_* flags).
    pub flash: u16,
    /// Polling interval exponent (seconds = 2^poll).
    pub poll: i8,
    /// Selection weight.
    pub weight: u8,
    /// Whether this peer is a trusted source.
    pub trusted: bool,
}

impl PeerInfo {
    /// Serialize a single peer entry.
    #[must_use]
    fn to_entry_bytes(&self) -> Vec<u8> {
        let addr_bytes = self.address.as_bytes();
        let addr_len = addr_bytes.len();
        let mut buf = Vec::with_capacity(36 + addr_len);

        buf.push(self.reach);
        buf.push(self.stratum);
        buf.push((self.flash & 0xff) as u8);
        buf.push((self.flash >> 8) as u8);
        buf.push(self.poll as u8);
        buf.push(self.weight);
        buf.push(if self.trusted { 1 } else { 0 });
        buf.push(0); // pad

        buf.extend_from_slice(&self.offset.to_be_bytes());
        buf.extend_from_slice(&self.delay.to_be_bytes());
        buf.extend_from_slice(&self.dispersion.to_be_bytes());
        buf.extend_from_slice(&(addr_len as u32).to_be_bytes());
        buf.extend_from_slice(addr_bytes);
        buf
    }

    /// Deserialize a single peer entry from bytes.
    ///
    /// Returns `(peer, bytes_consumed)` or `None` if the slice is too
    /// short.
    #[must_use]
    pub fn from_entry_bytes(bytes: &[u8]) -> Option<(Self, usize)> {
        if bytes.len() < 36 {
            return None;
        }
        let reach = bytes[0];
        let stratum = bytes[1];
        let flash_lo = bytes[2] as u16;
        let flash_hi = bytes[3] as u16;
        let flash = flash_lo | (flash_hi << 8);
        let poll = bytes[4] as i8;
        let weight = bytes[5];
        let trusted = bytes[6] != 0;
        // bytes[7] is padding
        let offset = f64::from_be_bytes([
            bytes[8], bytes[9], bytes[10], bytes[11], bytes[12], bytes[13], bytes[14], bytes[15],
        ]);
        let delay = f64::from_be_bytes([
            bytes[16], bytes[17], bytes[18], bytes[19], bytes[20], bytes[21], bytes[22], bytes[23],
        ]);
        let dispersion = f64::from_be_bytes([
            bytes[24], bytes[25], bytes[26], bytes[27], bytes[28], bytes[29], bytes[30], bytes[31],
        ]);
        let addr_len = u32::from_be_bytes([bytes[32], bytes[33], bytes[34], bytes[35]]) as usize;

        let total = 36 + addr_len;
        if bytes.len() < total {
            return None;
        }

        let address = core::str::from_utf8(&bytes[36..total])
            .map(String::from)
            .unwrap_or_else(|_| {
                // Fall back to hex encoding for non-UTF-8 addresses.
                let hex: String = bytes[36..total].iter().fold(String::new(), |mut acc, b| {
                    use core::fmt::Write;
                    write!(acc, "{b:02x}").ok();
                    acc
                });
                hex
            });

        Some((
            Self {
                address,
                reach,
                offset,
                delay,
                dispersion,
                stratum,
                flash,
                poll,
                weight,
                trusted,
            },
            total,
        ))
    }
}

// ---------------------------------------------------------------------------
// SensorInfo
// ---------------------------------------------------------------------------

/// Information about a single hardware sensor — part of the
/// [`CTL_REQ_SENSORS`] response.
#[derive(Debug, Clone)]
pub struct SensorInfo {
    /// Sensor device path (e.g., `/dev/pps0`).
    pub device: String,
    /// Sensor status byte.
    pub status: u8,
    /// Correction value in microseconds (OpenNTPD `int64_t`).
    pub correction: i64,
    /// Overridden stratum (0 = use default).
    pub stratum: u8,
    /// Selection weight.
    pub weight: u8,
    /// Reference identifier (4-character string or descriptive name).
    pub refid: String,
}

impl SensorInfo {
    /// Serialize a single sensor entry.
    #[must_use]
    fn to_entry_bytes(&self) -> Vec<u8> {
        let device_bytes = self.device.as_bytes();
        let refid_bytes = self.refid.as_bytes();
        let device_len = device_bytes.len();
        let refid_len = refid_bytes.len();

        let mut buf = Vec::with_capacity(20 + device_len + refid_len);
        buf.push(self.status);
        buf.push(self.stratum);
        buf.push(self.weight);
        buf.push(0); // pad
        buf.extend_from_slice(&self.correction.to_be_bytes());
        buf.extend_from_slice(&(device_len as u32).to_be_bytes());
        buf.extend_from_slice(&(refid_len as u32).to_be_bytes());
        buf.extend_from_slice(device_bytes);
        buf.extend_from_slice(refid_bytes);
        buf
    }

    /// Deserialize a single sensor entry from bytes.
    ///
    /// Returns `(sensor, bytes_consumed)` or `None` if the slice is too
    /// short.
    #[must_use]
    pub fn from_entry_bytes(bytes: &[u8]) -> Option<(Self, usize)> {
        if bytes.len() < 20 {
            return None;
        }
        let status = bytes[0];
        let stratum = bytes[1];
        let weight = bytes[2];
        // bytes[3] is padding
        let correction = i64::from_be_bytes([
            bytes[4], bytes[5], bytes[6], bytes[7], bytes[8], bytes[9], bytes[10], bytes[11],
        ]);
        let device_len = u32::from_be_bytes([bytes[12], bytes[13], bytes[14], bytes[15]]) as usize;
        let refid_len = u32::from_be_bytes([bytes[16], bytes[17], bytes[18], bytes[19]]) as usize;

        let total = 20 + device_len + refid_len;
        if bytes.len() < total {
            return None;
        }

        let device_str = core::str::from_utf8(&bytes[20..20 + device_len])
            .map(String::from)
            .unwrap_or_else(|_| {
                let hex: String =
                    bytes[20..20 + device_len]
                        .iter()
                        .fold(String::new(), |mut acc, b| {
                            use core::fmt::Write;
                            write!(acc, "{b:02x}").ok();
                            acc
                        });
                hex
            });

        let refid_str = core::str::from_utf8(&bytes[20 + device_len..total])
            .map(String::from)
            .unwrap_or_else(|_| {
                let hex: String =
                    bytes[20 + device_len..total]
                        .iter()
                        .fold(String::new(), |mut acc, b| {
                            use core::fmt::Write;
                            write!(acc, "{b:02x}").ok();
                            acc
                        });
                hex
            });

        Some((
            Self {
                device: device_str,
                status,
                correction,
                stratum,
                weight,
                refid: refid_str,
            },
            total,
        ))
    }
}

// ---------------------------------------------------------------------------
// ControlRequest
// ---------------------------------------------------------------------------

/// A control request sent by `ntpctl` to the daemon.
///
/// The payload is the request type as a big-endian `u32`.
#[derive(Debug, Clone)]
pub struct ControlRequest {
    /// One of the `CTL_REQ_*` constants.
    pub type_: u32,
}

impl ControlRequest {
    /// Create a new control request.
    #[must_use]
    pub fn new(type_: u32) -> Self {
        Self { type_ }
    }

    /// Encode to wire format: 4 bytes (big-endian `u32`).
    #[must_use]
    pub fn encode(&self) -> [u8; 4] {
        self.type_.to_be_bytes()
    }

    /// Decode from wire format (4 bytes).
    ///
    /// Returns the request type, or `None` if the slice is too short.
    #[must_use]
    pub fn decode(bytes: &[u8]) -> Option<u32> {
        if bytes.len() < 4 {
            return None;
        }
        Some(u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
    }
}

// ---------------------------------------------------------------------------
// ControlResponse
// ---------------------------------------------------------------------------

/// A control response sent by the daemon to `ntpctl`.
///
/// The response wire format is:
///
/// ```text
/// response_type (u32, big-endian) | payload (variable)
/// ```
///
/// The `type_` field identifies which `CTL_REQ_*` this data corresponds
/// to.  The `payload` field contains the type-specific serialized data
/// *without* the leading type tag.
#[derive(Debug, Clone)]
pub struct ControlResponse {
    /// One of the `CTL_REQ_*` constants identifying the response kind.
    pub type_: u32,
    /// Type-specific payload bytes (without the leading type tag).
    pub payload: Vec<u8>,
}

impl ControlResponse {
    /// Create a status response from [`NtpdStatus`].
    ///
    /// The payload contains the 32-byte status block.
    #[must_use]
    pub fn new_status(status: &NtpdStatus) -> Self {
        Self {
            type_: CTL_REQ_STATUS,
            payload: status.to_bytes().to_vec(),
        }
    }

    /// Create a peers response from a slice of [`PeerInfo`].
    ///
    /// The payload contains a count prefix followed by peer entries.
    #[must_use]
    pub fn new_peers(peers: &[PeerInfo]) -> Self {
        let count = peers.len() as u32;
        let mut payload = count.to_be_bytes().to_vec();
        for peer in peers {
            payload.extend_from_slice(&peer.to_entry_bytes());
        }
        Self {
            type_: CTL_REQ_PEERS,
            payload,
        }
    }

    /// Create a sensors response from a slice of [`SensorInfo`].
    #[must_use]
    pub fn new_sensors(sensors: &[SensorInfo]) -> Self {
        let count = sensors.len() as u32;
        let mut payload = count.to_be_bytes().to_vec();
        for sensor in sensors {
            payload.extend_from_slice(&sensor.to_entry_bytes());
        }
        Self {
            type_: CTL_REQ_SENSORS,
            payload,
        }
    }

    /// Create a combined "all" response from status, peers, and sensors.
    ///
    /// The payload is a concatenation of:
    /// - 32-byte status block
    /// - peers payload (count + entries)
    /// - sensors payload (count + entries)
    #[must_use]
    pub fn new_all(status: &NtpdStatus, peers: &[PeerInfo], sensors: &[SensorInfo]) -> Self {
        let mut payload = status.to_bytes().to_vec();
        payload.extend_from_slice(&Self::new_peers(peers).payload);
        payload.extend_from_slice(&Self::new_sensors(sensors).payload);
        Self {
            type_: CTL_REQ_ALL,
            payload,
        }
    }

    /// Encode the full response to wire format:
    ///
    /// ```text
    /// type_ (u32, big-endian) | payload
    /// ```
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(4 + self.payload.len());
        buf.extend_from_slice(&self.type_.to_be_bytes());
        buf.extend_from_slice(&self.payload);
        buf
    }

    /// Peek at the first 4 bytes of an encoded response to determine
    /// its type.
    ///
    /// Returns `None` if the slice is shorter than 4 bytes.
    #[must_use]
    pub fn decode_type(bytes: &[u8]) -> Option<u32> {
        if bytes.len() < 4 {
            return None;
        }
        Some(u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
    }

    /// Decode the payload portion of the response (after the leading
    /// type tag has been stripped).
    ///
    /// For status responses, returns the leading [`NtpdStatus`] and the
    /// remaining bytes.
    /// For peers responses, returns the list of [`PeerInfo`] and remaining
    /// bytes.
    /// For sensors responses, returns the list of [`SensorInfo`] and
    /// remaining bytes.
    /// For "all" responses, returns a `DecodedAll` containing all three.
    ///
    /// Returns `None` if the payload is malformed.
    #[must_use]
    pub fn decode_payload(&self) -> Option<DecodedResponse> {
        match self.type_ {
            CTL_REQ_STATUS => {
                let status = NtpdStatus::from_bytes(&self.payload)?;
                Some(DecodedResponse::Status(status))
            }
            CTL_REQ_PEERS => {
                let (peers, _) = decode_peers_payload(&self.payload)?;
                Some(DecodedResponse::Peers(peers))
            }
            CTL_REQ_SENSORS => {
                let (sensors, _) = decode_sensors_payload(&self.payload)?;
                Some(DecodedResponse::Sensors(sensors))
            }
            CTL_REQ_ALL => {
                let (status, remaining) = decode_status_payload(&self.payload)?;
                let (peers, remaining) = decode_peers_payload(remaining)?;
                let (sensors, _) = decode_sensors_payload(remaining)?;
                Some(DecodedResponse::All {
                    status,
                    peers,
                    sensors,
                })
            }
            _ => {
                // Unknown type — return raw payload.
                Some(DecodedResponse::Raw(self.payload.clone()))
            }
        }
    }
}

// ---------------------------------------------------------------------------
// DecodedResponse
// ---------------------------------------------------------------------------

/// The result of decoding a [`ControlResponse`] payload.
#[derive(Debug, Clone)]
pub enum DecodedResponse {
    /// Status response.
    Status(NtpdStatus),
    /// Peers response.
    Peers(Vec<PeerInfo>),
    /// Sensors response.
    Sensors(Vec<SensorInfo>),
    /// Combined "all" response.
    All {
        status: NtpdStatus,
        peers: Vec<PeerInfo>,
        sensors: Vec<SensorInfo>,
    },
    /// Unknown or raw response.
    Raw(Vec<u8>),
}

// ---------------------------------------------------------------------------
// Internal decode helpers
// ---------------------------------------------------------------------------

/// Decode a status payload (32 bytes) from the front of `bytes`.
///
/// Returns `(status, remaining)` or `None`.
#[must_use]
fn decode_status_payload(bytes: &[u8]) -> Option<(NtpdStatus, &[u8])> {
    if bytes.len() < 32 {
        return None;
    }
    let status = NtpdStatus::from_bytes(&bytes[..32])?;
    Some((status, &bytes[32..]))
}

/// Decode a peers payload from the front of `bytes`.
///
/// Returns `(peers, remaining)` or `None`.
#[must_use]
fn decode_peers_payload(bytes: &[u8]) -> Option<(Vec<PeerInfo>, &[u8])> {
    if bytes.len() < 4 {
        return None;
    }
    let count = u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]) as usize;
    let mut remaining = &bytes[4..];
    let mut peers = Vec::with_capacity(count);
    for _ in 0..count {
        let (peer, consumed) = PeerInfo::from_entry_bytes(remaining)?;
        peers.push(peer);
        remaining = &remaining[consumed..];
    }
    Some((peers, remaining))
}

/// Decode a sensors payload from the front of `bytes`.
///
/// Returns `(sensors, remaining)` or `None`.
#[must_use]
fn decode_sensors_payload(bytes: &[u8]) -> Option<(Vec<SensorInfo>, &[u8])> {
    if bytes.len() < 4 {
        return None;
    }
    let count = u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]) as usize;
    let mut remaining = &bytes[4..];
    let mut sensors = Vec::with_capacity(count);
    for _ in 0..count {
        let (sensor, consumed) = SensorInfo::from_entry_bytes(remaining)?;
        sensors.push(sensor);
        remaining = &remaining[consumed..];
    }
    Some((sensors, remaining))
}

// ---------------------------------------------------------------------------
// Display impls
// ---------------------------------------------------------------------------

impl fmt::Display for SyncState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Synced => write!(f, "synced"),
            Self::Unsynchronized => write!(f, "unsynchronized"),
            Self::Constrained => write!(f, "constrained"),
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    // -------------------------------------------------------------------
    // Request encode / decode
    // -------------------------------------------------------------------

    #[test]
    fn test_request_encode_decode_status() {
        let req = ControlRequest::new(CTL_REQ_STATUS);
        let encoded = req.encode();
        let decoded = ControlRequest::decode(&encoded).unwrap();
        assert_eq!(decoded, CTL_REQ_STATUS);
    }

    #[test]
    fn test_request_encode_decode_peers() {
        let req = ControlRequest::new(CTL_REQ_PEERS);
        let encoded = req.encode();
        let decoded = ControlRequest::decode(&encoded).unwrap();
        assert_eq!(decoded, CTL_REQ_PEERS);
    }

    #[test]
    fn test_request_encode_decode_sensors() {
        let req = ControlRequest::new(CTL_REQ_SENSORS);
        let encoded = req.encode();
        let decoded = ControlRequest::decode(&encoded).unwrap();
        assert_eq!(decoded, CTL_REQ_SENSORS);
    }

    #[test]
    fn test_request_encode_decode_all() {
        let req = ControlRequest::new(CTL_REQ_ALL);
        let encoded = req.encode();
        let decoded = ControlRequest::decode(&encoded).unwrap();
        assert_eq!(decoded, CTL_REQ_ALL);
    }

    #[test]
    fn test_request_decode_too_short() {
        assert!(ControlRequest::decode(b"").is_none());
        assert!(ControlRequest::decode(b"\x00\x01").is_none());
    }

    // -------------------------------------------------------------------
    // Status response
    // -------------------------------------------------------------------

    #[test]
    fn test_status_serialization() {
        let status = NtpdStatus {
            sync_state: SyncState::Synced,
            stratum: 2,
            offset: 0.0015,
            frequency: 42.0,
            uptime: 3600,
        };

        let resp = ControlResponse::new_status(&status);
        assert_eq!(resp.type_, CTL_REQ_STATUS);
        assert_eq!(resp.payload.len(), 32);

        // Encode full wire format and decode type
        let encoded = resp.encode();
        assert_eq!(
            ControlResponse::decode_type(&encoded).unwrap(),
            CTL_REQ_STATUS
        );

        // Decode payload
        let decoded = resp.decode_payload().unwrap();
        match decoded {
            DecodedResponse::Status(s) => {
                assert_eq!(s.sync_state, SyncState::Synced);
                assert_eq!(s.stratum, 2);
                assert!((s.offset - 0.0015).abs() < 1e-15);
                assert!((s.frequency - 42.0).abs() < 1e-15);
                assert_eq!(s.uptime, 3600);
            }
            _ => panic!("expected Status variant"),
        }
    }

    #[test]
    fn test_status_roundtrip() {
        let status = NtpdStatus {
            sync_state: SyncState::Unsynchronized,
            stratum: 0,
            offset: -0.005,
            frequency: 0.0,
            uptime: 0,
        };

        let bytes = status.to_bytes();
        let decoded = NtpdStatus::from_bytes(&bytes).unwrap();
        assert_eq!(decoded.sync_state, SyncState::Unsynchronized);
        assert_eq!(decoded.stratum, 0);
        assert!((decoded.offset - (-0.005)).abs() < 1e-15);
        assert!((decoded.frequency - 0.0).abs() < f64::EPSILON);
        assert_eq!(decoded.uptime, 0);
    }

    #[test]
    fn test_status_zero_values() {
        let status = NtpdStatus {
            sync_state: SyncState::Synced,
            stratum: 0,
            offset: 0.0,
            frequency: 0.0,
            uptime: 0,
        };

        let bytes = status.to_bytes();
        let decoded = NtpdStatus::from_bytes(&bytes).unwrap();
        assert_eq!(decoded.sync_state, SyncState::Synced);
        assert_eq!(decoded.offset, 0.0);
        assert_eq!(decoded.frequency, 0.0);
        assert_eq!(decoded.uptime, 0);
    }

    #[test]
    fn test_status_constrained() {
        let status = NtpdStatus {
            sync_state: SyncState::Constrained,
            stratum: 16,
            offset: 0.0,
            frequency: 0.0,
            uptime: 120,
        };

        let resp = ControlResponse::new_status(&status);
        let encoded = resp.encode();
        assert_eq!(
            ControlResponse::decode_type(&encoded).unwrap(),
            CTL_REQ_STATUS
        );

        let decoded = resp.decode_payload().unwrap();
        match decoded {
            DecodedResponse::Status(s) => {
                assert_eq!(s.sync_state, SyncState::Constrained);
                assert_eq!(s.stratum, 16);
                assert_eq!(s.uptime, 120);
            }
            _ => panic!("expected Status variant"),
        }
    }

    // -------------------------------------------------------------------
    // Peer info serialization
    // -------------------------------------------------------------------

    #[test]
    fn test_peers_serialization() {
        let peers = vec![
            PeerInfo {
                address: "192.0.2.1:123".into(),
                reach: 0xff,
                offset: 0.002,
                delay: 0.050,
                dispersion: 0.010,
                stratum: 2,
                flash: 0,
                poll: 6,
                weight: 1,
                trusted: true,
            },
            PeerInfo {
                address: "2001:db8::1:123".into(),
                reach: 0xaa,
                offset: -0.001,
                delay: 0.100,
                dispersion: 0.020,
                stratum: 3,
                flash: 0x01,
                poll: 7,
                weight: 2,
                trusted: false,
            },
        ];

        let resp = ControlResponse::new_peers(&peers);
        assert_eq!(resp.type_, CTL_REQ_PEERS);

        // Encode and check type
        let encoded = resp.encode();
        assert_eq!(
            ControlResponse::decode_type(&encoded).unwrap(),
            CTL_REQ_PEERS
        );

        // Decode payload
        let decoded = resp.decode_payload().unwrap();
        match decoded {
            DecodedResponse::Peers(decoded_peers) => {
                assert_eq!(decoded_peers.len(), 2);

                assert_eq!(decoded_peers[0].address, "192.0.2.1:123");
                assert_eq!(decoded_peers[0].reach, 0xff);
                assert!((decoded_peers[0].offset - 0.002).abs() < 1e-15);
                assert!((decoded_peers[0].delay - 0.050).abs() < 1e-15);
                assert!((decoded_peers[0].dispersion - 0.010).abs() < 1e-15);
                assert_eq!(decoded_peers[0].stratum, 2);
                assert_eq!(decoded_peers[0].flash, 0);
                assert_eq!(decoded_peers[0].poll, 6);
                assert_eq!(decoded_peers[0].weight, 1);
                assert!(decoded_peers[0].trusted);

                assert_eq!(decoded_peers[1].address, "2001:db8::1:123");
                assert_eq!(decoded_peers[1].reach, 0xaa);
                assert!((decoded_peers[1].offset - (-0.001)).abs() < 1e-15);
                assert_eq!(decoded_peers[1].flash, 0x01);
                assert_eq!(decoded_peers[1].poll, 7);
                assert_eq!(decoded_peers[1].weight, 2);
                assert!(!decoded_peers[1].trusted);
            }
            _ => panic!("expected Peers variant"),
        }
    }

    #[test]
    fn test_peers_empty_list() {
        let peers: Vec<PeerInfo> = vec![];
        let resp = ControlResponse::new_peers(&peers);

        let decoded = resp.decode_payload().unwrap();
        match decoded {
            DecodedResponse::Peers(p) => {
                assert!(p.is_empty());
            }
            _ => panic!("expected Peers variant"),
        }
    }

    #[test]
    fn test_peers_very_long_name() {
        let long_name = "a".repeat(512);
        let peer = PeerInfo {
            address: long_name.clone(),
            reach: 0,
            offset: 0.0,
            delay: 0.0,
            dispersion: 0.0,
            stratum: 0,
            flash: 0,
            poll: 0,
            weight: 0,
            trusted: false,
        };

        let resp = ControlResponse::new_peers(&[peer]);
        let decoded = resp.decode_payload().unwrap();
        match decoded {
            DecodedResponse::Peers(p) => {
                assert_eq!(p[0].address.len(), 512);
                assert_eq!(p[0].address, long_name);
            }
            _ => panic!("expected Peers variant"),
        }
    }

    // -------------------------------------------------------------------
    // Sensor info serialization
    // -------------------------------------------------------------------

    #[test]
    fn test_sensors_serialization() {
        let sensors = vec![
            SensorInfo {
                device: "/dev/pps0".into(),
                status: 1,
                correction: 500,
                stratum: 0,
                weight: 1,
                refid: "PPS\0".into(),
            },
            SensorInfo {
                device: "/dev/pps1".into(),
                status: 0,
                correction: -200,
                stratum: 3,
                weight: 2,
                refid: "NMEA".into(),
            },
        ];

        let resp = ControlResponse::new_sensors(&sensors);
        assert_eq!(resp.type_, CTL_REQ_SENSORS);

        // Encode and check type
        let encoded = resp.encode();
        assert_eq!(
            ControlResponse::decode_type(&encoded).unwrap(),
            CTL_REQ_SENSORS
        );

        // Decode payload
        let decoded = resp.decode_payload().unwrap();
        match decoded {
            DecodedResponse::Sensors(ds) => {
                assert_eq!(ds.len(), 2);

                assert_eq!(ds[0].device, "/dev/pps0");
                assert_eq!(ds[0].status, 1);
                assert_eq!(ds[0].correction, 500);
                assert_eq!(ds[0].stratum, 0);
                assert_eq!(ds[0].weight, 1);
                assert_eq!(ds[0].refid, "PPS\0");

                assert_eq!(ds[1].device, "/dev/pps1");
                assert_eq!(ds[1].status, 0);
                assert_eq!(ds[1].correction, -200);
                assert_eq!(ds[1].stratum, 3);
                assert_eq!(ds[1].weight, 2);
                assert_eq!(ds[1].refid, "NMEA");
            }
            _ => panic!("expected Sensors variant"),
        }
    }

    #[test]
    fn test_sensors_empty_list() {
        let sensors: Vec<SensorInfo> = vec![];
        let resp = ControlResponse::new_sensors(&sensors);

        let decoded = resp.decode_payload().unwrap();
        match decoded {
            DecodedResponse::Sensors(s) => {
                assert!(s.is_empty());
            }
            _ => panic!("expected Sensors variant"),
        }
    }

    // -------------------------------------------------------------------
    // All response composition
    // -------------------------------------------------------------------

    #[test]
    fn test_all_response_composition() {
        let status = NtpdStatus {
            sync_state: SyncState::Synced,
            stratum: 3,
            offset: 0.001,
            frequency: 10.0,
            uptime: 7200,
        };

        let peers = vec![PeerInfo {
            address: "10.0.0.1:123".into(),
            reach: 0xfe,
            offset: 0.002,
            delay: 0.030,
            dispersion: 0.005,
            stratum: 2,
            flash: 0,
            poll: 6,
            weight: 1,
            trusted: true,
        }];

        let sensors = vec![SensorInfo {
            device: "/dev/pps0".into(),
            status: 1,
            correction: 100,
            stratum: 0,
            weight: 1,
            refid: "PPS".into(),
        }];

        let resp = ControlResponse::new_all(&status, &peers, &sensors);
        assert_eq!(resp.type_, CTL_REQ_ALL);

        // Encode and check type
        let encoded = resp.encode();
        assert_eq!(ControlResponse::decode_type(&encoded).unwrap(), CTL_REQ_ALL);

        // Decode payload
        let decoded = resp.decode_payload().unwrap();
        match decoded {
            DecodedResponse::All {
                status: s,
                peers: p,
                sensors: sen,
            } => {
                assert_eq!(s.sync_state, SyncState::Synced);
                assert_eq!(s.stratum, 3);
                assert!((s.offset - 0.001).abs() < 1e-15);
                assert_eq!(p.len(), 1);
                assert_eq!(p[0].address, "10.0.0.1:123");
                assert_eq!(sen.len(), 1);
                assert_eq!(sen[0].device, "/dev/pps0");
            }
            _ => panic!("expected All variant"),
        }
    }

    // -------------------------------------------------------------------
    // Edge cases
    // -------------------------------------------------------------------

    #[test]
    fn test_decode_type_too_short() {
        assert!(ControlResponse::decode_type(b"").is_none());
        assert!(ControlResponse::decode_type(b"\x00").is_none());
        assert!(ControlResponse::decode_type(b"\x00\x01").is_none());
        assert!(ControlResponse::decode_type(b"\x00\x01\x02").is_none());
    }

    #[test]
    fn test_decode_type_valid() {
        let resp = ControlResponse::new_status(&NtpdStatus {
            sync_state: SyncState::Synced,
            stratum: 0,
            offset: 0.0,
            frequency: 0.0,
            uptime: 0,
        });
        let encoded = resp.encode();
        assert_eq!(
            ControlResponse::decode_type(&encoded).unwrap(),
            CTL_REQ_STATUS
        );
    }

    #[test]
    fn test_decode_payload_truncated_status() {
        let resp = ControlResponse {
            type_: CTL_REQ_STATUS,
            payload: vec![0u8; 10], // too short
        };
        assert!(resp.decode_payload().is_none());
    }

    #[test]
    fn test_decode_payload_truncated_peers() {
        // Valid count but truncated entries
        let resp = ControlResponse {
            type_: CTL_REQ_PEERS,
            payload: vec![0, 0, 0, 1, 0, 0], // count=1 but no entries
        };
        assert!(resp.decode_payload().is_none());
    }

    #[test]
    fn test_decode_payload_truncated_sensors() {
        let resp = ControlResponse {
            type_: CTL_REQ_SENSORS,
            payload: vec![0, 0, 0, 1, 0], // count=1 but truncated
        };
        assert!(resp.decode_payload().is_none());
    }

    #[test]
    fn test_invalid_sync_state_rejected() {
        let mut bytes = [0u8; 32];
        bytes[0..4].copy_from_slice(&99u32.to_be_bytes()); // invalid state
        assert!(NtpdStatus::from_bytes(&bytes).is_none());
    }

    #[test]
    fn test_peers_multiple_roundtrip() {
        let mut peers = vec![];
        for i in 0..5 {
            peers.push(PeerInfo {
                address: alloc::format!("192.0.2.{}:123", i + 1),
                reach: (0x01 << i) as u8,
                offset: (i as f64) * 0.001,
                delay: (i as f64) * 0.010 + 0.020,
                dispersion: 0.005,
                stratum: (i % 16) as u8,
                flash: (i as u16) * 0x0101,
                poll: 6,
                weight: 1,
                trusted: i % 2 == 0,
            });
        }

        let resp = ControlResponse::new_peers(&peers);
        let decoded = resp.decode_payload().unwrap();
        match decoded {
            DecodedResponse::Peers(dp) => {
                assert_eq!(dp.len(), 5);
                for (a, b) in peers.iter().zip(dp.iter()) {
                    assert_eq!(a.address, b.address);
                    assert_eq!(a.reach, b.reach);
                    assert!((a.offset - b.offset).abs() < 1e-15);
                    assert!((a.delay - b.delay).abs() < 1e-15);
                    assert!((a.dispersion - b.dispersion).abs() < 1e-15);
                    assert_eq!(a.stratum, b.stratum);
                    assert_eq!(a.flash, b.flash);
                    assert_eq!(a.poll, b.poll);
                    assert_eq!(a.weight, b.weight);
                    assert_eq!(a.trusted, b.trusted);
                }
            }
            _ => panic!("expected Peers variant"),
        }
    }

    #[test]
    fn test_sensors_roundtrip() {
        let sensors = vec![
            SensorInfo {
                device: "/dev/pps0".into(),
                status: 0x01,
                correction: 0,
                stratum: 0,
                weight: 10,
                refid: "PPS\0".into(),
            },
            SensorInfo {
                device: "/dev/pps1".into(),
                status: 0x80,
                correction: -999999,
                stratum: 4,
                weight: 5,
                refid: "NMEA".into(),
            },
        ];

        let resp = ControlResponse::new_sensors(&sensors);
        let decoded = resp.decode_payload().unwrap();
        match decoded {
            DecodedResponse::Sensors(ds) => {
                assert_eq!(ds.len(), 2);
                assert_eq!(ds[0].device, "/dev/pps0");
                assert_eq!(ds[0].status, 0x01);
                assert_eq!(ds[0].correction, 0);
                assert_eq!(ds[0].weight, 10);

                assert_eq!(ds[1].device, "/dev/pps1");
                assert_eq!(ds[1].status, 0x80);
                assert_eq!(ds[1].correction, -999999);
                assert_eq!(ds[1].stratum, 4);
                assert_eq!(ds[1].weight, 5);
                assert_eq!(ds[1].refid, "NMEA");
            }
            _ => panic!("expected Sensors variant"),
        }
    }

    #[test]
    fn test_sync_state_display() {
        assert_eq!(alloc::format!("{}", SyncState::Synced), "synced");
        assert_eq!(
            alloc::format!("{}", SyncState::Unsynchronized),
            "unsynchronized"
        );
        assert_eq!(alloc::format!("{}", SyncState::Constrained), "constrained");
    }

    #[test]
    fn test_status_from_bytes_too_short() {
        assert!(NtpdStatus::from_bytes(&[0u8; 0]).is_none());
        assert!(NtpdStatus::from_bytes(&[0u8; 31]).is_none());
    }

    #[test]
    fn test_negative_offset_roundtrip() {
        let status = NtpdStatus {
            sync_state: SyncState::Synced,
            stratum: 1,
            offset: -0.123456789,
            frequency: -0.5,
            uptime: 99_999,
        };
        let bytes = status.to_bytes();
        let decoded = NtpdStatus::from_bytes(&bytes).unwrap();
        assert!((decoded.offset - (-0.123456789)).abs() < 1e-15);
        assert!((decoded.frequency - (-0.5)).abs() < 1e-15);
        assert_eq!(decoded.uptime, 99_999);
    }
}
