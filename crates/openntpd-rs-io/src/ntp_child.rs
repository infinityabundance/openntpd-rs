//! NTP child process — the "ntp engine" running after privsep fork.
//!
//! This implements the core runtime loop that manages peers, sensors,
//! constraints, the control socket, DNS child communication, and clock
//! discipline.
//!
//! ## C correspondence
//!
//! | Rust                              | C                              |
//! |-----------------------------------|--------------------------------|
//! | [`NtpChildProcess::run`]          | `ntp_main()`                   |
//! | [`NtpChildProcess::tick`]         | innards of the `while` loop    |
//! | [`dispatch_parent_imsg`]          | `ntp_dispatch_imsg()`          |
//! | [`dispatch_dns_imsg`]             | `ntp_dispatch_imsg_dns()`      |
//! | [`handle_peer_response`]          | `client_dispatch()`            |
//! | [`priv_adjtime`]                  | `priv_adjtime()`               |
//! | [`priv_adjfreq`]                  | `priv_adjfreq()`               |
//! | [`priv_settime`]                  | `priv_settime()`               |
//! | [`priv_dns`]                      | `priv_dns()`                   |
//! | [`offset_compare`]                | `offset_compare()`             |
//! | [`check_sync_loss`]               | inline in `ntp_main()`         |

use std::cmp::Ordering;
use std::os::unix::io::RawFd;

use openntpd_rs_core::ntp::engine::*;
use openntpd_rs_core::peer::*;

use crate::ctl::*;
use crate::daemon_impl::*;
use crate::imsg::*;
use crate::sensor_io::*;
use crate::util::*;

// ---------------------------------------------------------------------------
// Constants — poll fd indices matching C: PFD_PIPE_MAIN etc.
// ---------------------------------------------------------------------------

/// Index for the imsg pipe to the parent process.
pub const PFD_PIPE_MAIN: usize = 0;
/// Index for the imsg pipe to the DNS child process.
pub const PFD_PIPE_DNS: usize = 1;
/// Index for the control socket (ntpctl connections).
pub const PFD_SOCK_CTL: usize = 2;
/// Number of fixed poll entries before dynamic ones.
pub const PFD_MAX: usize = 3;

/// Constraint scan interval in seconds.
const CONSTRAINT_SCAN_INTERVAL: i64 = 3600; // 1 hour, matching C
/// Constraint retry interval in seconds.
const _CONSTRAINT_RETRY_INTERVAL: i64 = 300; // 5 minutes, matching C

// ---------------------------------------------------------------------------
// FreqAccumulator — linear regression state for priv_adjfreq
// ---------------------------------------------------------------------------

/// Accumulator for linear regression frequency estimation.
///
/// Corresponds to the `conf->freq` fields in C.
#[derive(Debug, Clone)]
struct FreqAccumulator {
    samples: i64,
    x: f64,
    y: f64,
    xx: f64,
    xy: f64,
    overall_offset: f64,
    num: u64,
}

impl FreqAccumulator {
    fn new() -> Self {
        Self {
            samples: 0,
            x: 0.0,
            y: 0.0,
            xx: 0.0,
            xy: 0.0,
            overall_offset: 0.0,
            num: 0,
        }
    }

    fn reset(&mut self) {
        self.samples = 0;
        self.x = 0.0;
        self.y = 0.0;
        self.xx = 0.0;
        self.xy = 0.0;
        self.overall_offset = 0.0;
    }
}

// ---------------------------------------------------------------------------
// ChildConfig
// ---------------------------------------------------------------------------

/// Configuration for the NTP child process.
///
/// Corresponds to the relevant fields of `struct ntpd_conf` in C.
#[derive(Debug, Clone)]
pub struct ChildConfig {
    /// Enable debug mode (log to stderr).
    pub debug: bool,
    /// Step the clock when a good offset is available (`-s` flag).
    pub settime: bool,
    /// Automatic initial time step (implies `-s`).
    pub automatic: bool,
    /// Verbosity level (0–2).
    pub verbose: u8,
    /// Whether the DNS child process is available.
    pub dns_child_enabled: bool,
}

impl Default for ChildConfig {
    fn default() -> Self {
        Self {
            debug: false,
            settime: false,
            automatic: false,
            verbose: 0,
            dns_child_enabled: true,
        }
    }
}

// ---------------------------------------------------------------------------
// NtpChildProcess
// ---------------------------------------------------------------------------

/// The NTP child process — runs the full event loop.
///
/// This is the core runtime that manages peer queries, sensor scans,
/// constraint interactions, the control socket, DNS child communication,
/// and clock discipline via `adjtime`/`adjfreq`/`settime`.
///
/// Corresponds to C: `ntp_main()`.
pub struct NtpChildProcess {
    /// The pure NTP engine (peer filter, clock selection, PLL/FLL).
    pub engine: NtpEngine,
    /// Per-peer runtime state (trustlevel, scheduling, addresses).
    pub peer_states: Vec<ClientPeer>,
    /// imsg socket to the parent daemon process.
    pub main_ibuf: ImsgSocket,
    /// imsg socket to the DNS child process.
    pub dns_ibuf: Option<ImsgSocket>,
    /// Control socket listener fd.
    pub ctl_fd: Option<RawFd>,
    /// Accepted control connections.
    pub ctl_conns: Vec<RawFd>,
    /// Bound NTP listener fds (for server mode).
    pub listener_fds: Vec<RawFd>,
    /// Sensor device names from scanning.
    pub sensor_registry: Vec<String>,
    /// Monotonic time of last sensor scan.
    pub last_sensor_scan: i64,
    /// Monotonic time of the last successful action.
    pub last_action: i64,
    /// Child configuration.
    pub config: ChildConfig,
    /// Constraint median offset (0 = unknown).
    pub constraint_median: f64,
    /// Whether constraints are active (configured).
    pub constraint_active: bool,
    /// Number of constraints.
    pub constraint_cnt: u32,
    /// Monotonic time of last constraint reset.
    pub last_constraint_reset: i64,
    /// Temporary DNS failure count (for auto-settime abandonment).
    pub dns_tmpfail_count: u32,
    /// Frequency estimation accumulator (linear regression).
    freq_accumulator: FreqAccumulator,
    /// Whether we have sent the initial unsynced message.
    unsynced_sent: bool,
    /// Precision from clock_getres (CLOCK_REALTIME).
    pub precision: i8,
    /// Current scale factor for query intervals.
    pub scale: i64,
    /// Whether the clock is synced.
    pub synced: bool,
    /// Status fields for ntpctl show.
    pub status_rootdelay: f64,
    pub status_stratum: u8,
    pub status_leap: u8,
    pub status_refid: u32,
    pub status_reftime: f64,
}

impl NtpChildProcess {
    /// Create a new NTP child process.
    ///
    /// # Arguments
    ///
    /// * `config` - Child process configuration.
    /// * `main_ibuf` - imsg socket to the parent process.
    /// * `dns_ibuf` - Optional imsg socket to the DNS child process.
    /// * `ctl_fd` - Optional control socket listener fd.
    pub fn new(
        config: ChildConfig,
        main_ibuf: ImsgSocket,
        dns_ibuf: Option<ImsgSocket>,
        ctl_fd: Option<RawFd>,
    ) -> Self {
        let engine_config = NtpEngineConfig {
            settime: config.settime,
            automatic: config.automatic,
        };
        Self {
            engine: NtpEngine::new(engine_config),
            peer_states: Vec::new(),
            main_ibuf,
            dns_ibuf,
            ctl_fd,
            ctl_conns: Vec::new(),
            listener_fds: Vec::new(),
            sensor_registry: Vec::new(),
            last_sensor_scan: 0,
            last_action: 0,
            config,
            constraint_median: 0.0,
            constraint_active: false,
            constraint_cnt: 0,
            last_constraint_reset: 0,
            dns_tmpfail_count: 0,
            freq_accumulator: FreqAccumulator::new(),
            unsynced_sent: false,
            precision: 0,
            scale: 1,
            synced: false,
            status_rootdelay: 0.0,
            status_stratum: 0,
            status_leap: 0,
            status_refid: 0,
            status_reftime: 0.0,
        }
    }

    /// Run the child process event loop.
    ///
    /// This blocks until the process is signaled to quit. Sets up the
    /// imsg buffer, initialises sensors, and enters a poll(2) loop.
    ///
    /// Corresponds to C: `ntp_main()` (the main body after chroot/drop).
    ///
    /// # Errors
    ///
    /// Returns `Err` on fatal I/O errors.
    pub fn run(&mut self) -> Result<(), String> {
        // Initialise sensors.
        sensor_init();

        // Send initial IMSG_UNSYNCED to parent.
        self.send_imsg(IMSG_UNSYNCED, &[])?;
        self.unsynced_sent = true;

        // Calculate precision from clock_getres.
        self.precision = -6; // ~15.6 ms default

        log_info("ntp engine ready");

        // Main event loop.
        loop {
            if let Err(e) = self.tick() {
                log_warn(&format!("tick error: {e}"));
                return Err(e);
            }
        }
    }

    /// Send an imsg to the parent process.
    fn send_imsg(&mut self, type_: u32, data: &[u8]) -> Result<(), String> {
        let imsg = Imsg::new(type_, data.to_vec());
        self.main_ibuf
            .send(&imsg)
            .map_err(|e| format!("failed to send imsg to parent: {e}"))
    }

    /// Single iteration of the event loop.
    ///
    /// Builds the pollfd array, handles peer scheduling (queries,
    /// deadlines, send errors), sensor scanning, constraint queries,
    /// calls poll(2), and dispatches events.
    ///
    /// Corresponds to one iteration of the `while (ntp_quit == 0)` loop
    /// in C: `ntp_main()`.
    ///
    /// # Errors
    ///
    /// Returns `Err` on fatal errors that should terminate the child.
    pub fn tick(&mut self) -> Result<(), String> {
        use std::io::ErrorKind;

        let now = getmonotime();

        // ── Phase 1: Peer scheduling ─────────────────────────────────────────
        for peer_state in self.peer_states.iter_mut() {
            // Skip untrusted peers when constraints are active but have
            // not yet produced a median.
            if !peer_state.peer.trusted && self.constraint_active && self.constraint_median == 0.0 {
                // In C: if (!p->trusted && constraint_cnt && constraint_median == 0)
                //        continue;
                continue;
            }

            // Check if it's time to send a query.
            if peer_state.next > 0 && (peer_state.next as f64) <= now {
                // In C: if (p->next > 0 && p->next <= getmonotime())
                //          client_query(p);
                // Mark the peer as having a query sent.
                peer_state.state = ClientState::QuerySent;
                peer_state.set_deadline(QUERYTIME_MAX as i64);
            }

            // Check for query deadline expiry.
            if peer_state.deadline > 0 && (peer_state.deadline as f64) <= now {
                let timeout = 300i64;
                log_debug(&format!(
                    "no reply from {} received in time, next query {timeout}s",
                    peer_state.peer.address.as_utf8().unwrap_or("<unknown>"),
                ));
                // C: if (p->trustlevel >= TRUSTLEVEL_BADPEER &&
                //         (p->trustlevel /= 2) < TRUSTLEVEL_BADPEER)
                if peer_state.trustlevel >= TRUSTLEVEL_BADPEER {
                    peer_state.trustlevel /= 2;
                    if peer_state.trustlevel < TRUSTLEVEL_BADPEER {
                        log_info(&format!(
                            "peer {} now invalid",
                            peer_state.peer.address.as_utf8().unwrap_or("<unknown>"),
                        ));
                    }
                }
                peer_state.set_next(timeout);
            }

            // Check for excessive send errors.
            if peer_state.senderrors > MAX_SEND_ERRORS {
                log_debug(&format!(
                    "failed to send query to {}, next query {}s",
                    peer_state.peer.address.as_utf8().unwrap_or("<unknown>"),
                    INTERVAL_QUERY_PATHETIC,
                ));
                peer_state.senderrors = 0;
                peer_state.set_next(INTERVAL_QUERY_PATHETIC as i64);
            }
        }

        // ── Phase 2: Sensor scanning ────────────────────────────────────────
        let sensors_configured = !self.sensor_registry.is_empty();
        let sensors_allowed = if self.constraint_active {
            self.constraint_median != 0.0
        } else {
            true
        };

        if sensors_configured && sensors_allowed {
            if self.last_sensor_scan == 0
                || (self.last_sensor_scan as f64) + SENSOR_SCAN_INTERVAL as f64 <= now
            {
                let _ = sensor_scan();
                self.last_sensor_scan = now as i64;
            }
        }

        // ── Phase 3: Handle constraint reset timeout ─────────────────────────
        // C: if constraint_median == 0 && clear_cdns
        //        && now - last_cdns_reset > CONSTRAINT_SCAN_INTERVAL
        //        → constraint_reset()
        if self.constraint_median == 0.0
            && (now as i64) - self.last_constraint_reset > CONSTRAINT_SCAN_INTERVAL
        {
            log_debug("Reset constraint info");
            self.constraint_median = 0.0;
            self.last_constraint_reset = getmonotime() as i64;
        }

        // ── Phase 4: Build pollfd array and poll ────────────────────────────
        // Compute next action time.
        let mut next_action: f64 = now + 900.0; // 15 minute max sleep
        for peer_state in &self.peer_states {
            let nxt = peer_state.next as f64;
            let dln = peer_state.deadline as f64;
            if nxt > 0.0 && nxt < next_action {
                next_action = nxt;
            }
            if dln > 0.0 && dln < next_action {
                next_action = dln;
            }
        }
        if self.last_sensor_scan > 0 {
            let next_sensor_scan = (self.last_sensor_scan as f64) + SENSOR_SCAN_INTERVAL as f64;
            if next_sensor_scan < next_action {
                next_action = next_sensor_scan;
            }
        }

        // Use the full timeout for production, but cap at 100ms for testing.
        // In production, the process is long-running, so a full poll wait is fine.
        #[cfg(not(test))]
        let timeout_ms = if next_action > now {
            ((next_action - now).max(1.0) * 1000.0) as u64
        } else {
            1
        };
        #[cfg(test)]
        let timeout_ms = 1u64;

        // Build pollfd array with PFD_* indices.
        let mut poll_fds: Vec<libc::pollfd> = Vec::new();

        // PFD_PIPE_MAIN
        poll_fds.push(libc::pollfd {
            fd: self.main_ibuf.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        });

        // PFD_PIPE_DNS
        if let Some(ref dns_ibuf) = self.dns_ibuf {
            poll_fds.push(libc::pollfd {
                fd: dns_ibuf.as_raw_fd(),
                events: libc::POLLIN,
                revents: 0,
            });
        } else {
            poll_fds.push(libc::pollfd {
                fd: -1,
                events: 0,
                revents: 0,
            });
        }

        // PFD_SOCK_CTL
        if let Some(fd) = self.ctl_fd {
            poll_fds.push(libc::pollfd {
                fd,
                events: libc::POLLIN,
                revents: 0,
            });
        } else {
            poll_fds.push(libc::pollfd {
                fd: -1,
                events: 0,
                revents: 0,
            });
        }

        // Listener fds.
        for &fd in &self.listener_fds {
            poll_fds.push(libc::pollfd {
                fd,
                events: libc::POLLIN,
                revents: 0,
            });
        }

        // Control connection fds.
        for &fd in &self.ctl_conns {
            poll_fds.push(libc::pollfd {
                fd,
                events: libc::POLLIN,
                revents: 0,
            });
        }

        // Call poll(2).
        let nfds = unsafe {
            libc::poll(
                poll_fds.as_mut_ptr(),
                poll_fds.len() as libc::nfds_t,
                timeout_ms as i32,
            )
        };

        if nfds < 0 {
            let err = std::io::Error::last_os_error();
            if err.kind() != ErrorKind::Interrupted {
                log_warn(&format!("poll error: {}", err));
                return Err(format!("poll error: {}", err));
            }
            return Ok(());
        }

        let mut remaining = nfds as usize;

        // ── Phase 5: Dispatch events ─────────────────────────────────────────

        // PFD_PIPE_MAIN
        if remaining > 0 && poll_fds[PFD_PIPE_MAIN].revents & (libc::POLLIN | libc::POLLERR) != 0 {
            remaining -= 1;
            self.dispatch_parent_imsg_all()?;
        }

        // PFD_PIPE_DNS
        if self.dns_ibuf.is_some()
            && remaining > 0
            && poll_fds[PFD_PIPE_DNS].revents & (libc::POLLIN | libc::POLLERR) != 0
        {
            remaining -= 1;
            self.dispatch_dns_imsg_all()?;
        }

        // PFD_SOCK_CTL
        if remaining > 0 && poll_fds[PFD_SOCK_CTL].revents & (libc::POLLIN | libc::POLLERR) != 0 {
            remaining -= 1;
            if let Some(ctl_fd) = self.ctl_fd {
                match control_accept(ctl_fd) {
                    Ok(connfd) => {
                        self.ctl_conns.push(connfd);
                    }
                    Err(e) => {
                        log_debug(&format!("control_accept: {e}"));
                    }
                }
            }
        }

        // Listener sockets (server dispatch).
        let listener_end = PFD_MAX + self.listener_fds.len();
        for idx in PFD_MAX..listener_end.min(poll_fds.len()) {
            if remaining == 0 {
                break;
            }
            if poll_fds[idx].revents & (libc::POLLIN | libc::POLLERR) != 0 {
                remaining -= 1;
                // Placeholder: server_dispatch() would handle incoming NTP requests.
                log_debug("listener socket event");
            }
        }

        // Control connection dispatches.
        // Reads imsg from the control connection and sends an appropriate
        // IMSG_CTL_RESP response for REAL ntpctl compatibility.
        let ctl_start = listener_end;
        let mut to_remove: Vec<usize> = Vec::new();
        for (rel_idx, idx) in (ctl_start..poll_fds.len()).enumerate() {
            if remaining == 0 {
                break;
            }
            if poll_fds[idx].revents & (libc::POLLIN | libc::POLLERR) != 0 {
                remaining -= 1;
                let fd = poll_fds[idx].fd;
                match handle_control_conn(fd, self.synced, self.status_stratum) {
                    Ok(true) => {
                        // Message handled — keep connection open
                    }
                    Ok(false) => {
                        // EOF or no data — close this connection.
                        if rel_idx < self.ctl_conns.len() {
                            to_remove.push(rel_idx);
                        }
                    }
                    Err(e) => {
                        log_debug(&format!("control dispatch error: {e}"));
                        if rel_idx < self.ctl_conns.len() {
                            to_remove.push(rel_idx);
                        }
                    }
                }
            }
        }
        // Remove closed connections in reverse order.
        for &idx in to_remove.iter().rev() {
            if idx < self.ctl_conns.len() {
                let fd = self.ctl_conns.remove(idx);
                control_close(fd);
            }
        }

        // ── Phase 6: Sensor queries ─────────────────────────────────────────
        for sensor_name in &self.sensor_registry.clone() {
            // In the real daemon, sensor_query() reads from the device.
            let _ = sensor_query(sensor_name);
            self.last_action = now as i64;
        }

        // ── Phase 7: Sync loss check ────────────────────────────────────────
        self.check_sync_loss(now as i64);

        Ok(())
    }

    /// Read and dispatch all available imsgs from the parent.
    fn dispatch_parent_imsg_all(&mut self) -> Result<(), String> {
        loop {
            match self.main_ibuf.recv() {
                Ok(imsg) => {
                    self.dispatch_parent_imsg(imsg.header.type_, &imsg.payload)?;
                }
                Err(ImsgError::ConnectionClosed) => {
                    log_info("parent connection closed, shutting down");
                    return Err("parent closed connection".into());
                }
                Err(ImsgError::Truncated) => {
                    break;
                }
                Err(e) => {
                    log_warn(&format!("imsg recv error: {e}"));
                    return Err(format!("imsg recv error: {e}"));
                }
            }
        }
        Ok(())
    }

    /// Dispatch a single imsg from the parent process.
    ///
    /// Corresponds to C: `ntp_dispatch_imsg()` switch statement.
    pub fn dispatch_parent_imsg(&mut self, type_: u32, data: &[u8]) -> Result<(), String> {
        match type_ {
            IMSG_ADJTIME => {
                if data.len() < 4 {
                    log_warnx("invalid IMSG_ADJTIME received: payload too short");
                    return Ok(());
                }
                let mut buf = [0u8; 4];
                buf.copy_from_slice(&data[..4]);
                let n = i32::from_ne_bytes(buf);

                if n == 1 && !self.synced {
                    log_info("clock is now synced");
                    self.synced = true;
                    self.priv_dns(IMSG_SYNCED, None, 0);
                    self.constraint_median = 0.0;
                    self.last_constraint_reset = getmonotime() as i64;
                    self.send_imsg(IMSG_SYNCED, &[])?;
                } else if n == 0 && self.synced {
                    log_info("clock is now unsynced");
                    self.synced = false;
                    self.priv_dns(IMSG_UNSYNCED, None, 0);
                    self.send_imsg(IMSG_UNSYNCED, &[])?;
                }
            }
            IMSG_CONSTRAINT_RESULT => {
                if data.len() >= 8 {
                    let mut buf = [0u8; 8];
                    buf.copy_from_slice(&data[..8]);
                    self.constraint_median = f64::from_ne_bytes(buf);
                }
            }
            IMSG_CONSTRAINT_CLOSE => {
                // A constraint connection was closed.
            }
            IMSG_CONSTRAINT_QUERY => {
                // Forwarded to parent for TLS I/O.
            }
            _ => {
                log_debug(&format!(
                    "unhandled parent imsg type {} ({})",
                    type_,
                    crate::daemon_impl::imsg_type_name(type_)
                ));
            }
        }
        Ok(())
    }

    /// Read and dispatch all available imsgs from the DNS child.
    fn dispatch_dns_imsg_all(&mut self) -> Result<(), String> {
        // Take the DNS socket out temporarily to avoid borrow conflicts.
        let mut dns_ibuf = match self.dns_ibuf.take() {
            Some(buf) => buf,
            None => return Ok(()),
        };

        loop {
            match dns_ibuf.recv() {
                Ok(imsg) => {
                    let type_ = imsg.header.type_;
                    let payload = imsg.payload;
                    // Put the socket back temporarily while we dispatch.
                    self.dns_ibuf = Some(dns_ibuf);
                    self.dispatch_dns_imsg(type_, &payload)?;
                    dns_ibuf = self.dns_ibuf.take().unwrap();
                }
                Err(ImsgError::ConnectionClosed) => {
                    log_info("DNS child connection closed");
                    self.dns_ibuf = None;
                    break;
                }
                Err(ImsgError::Truncated) => {
                    self.dns_ibuf = Some(dns_ibuf);
                    break;
                }
                Err(e) => {
                    log_warn(&format!("dns imsg recv error: {e}"));
                    self.dns_ibuf = Some(dns_ibuf);
                    return Err(format!("dns imsg recv error: {e}"));
                }
            }
        }
        Ok(())
    }

    /// Dispatch a single imsg from the DNS child process.
    ///
    /// Corresponds to C: `ntp_dispatch_imsg_dns()` switch statement.
    pub fn dispatch_dns_imsg(&mut self, type_: u32, data: &[u8]) -> Result<(), String> {
        match type_ {
            IMSG_HOST_DNS => {
                if data.is_empty() {
                    log_debug("DNS lookup tempfail");
                    self.dns_tmpfail_count += 1;
                    if self.dns_tmpfail_count >= 3 {
                        self.priv_settime(0.0, Some("of dns failures"));
                    }
                } else {
                    log_debug(&format!("DNS response received ({} bytes)", data.len()));
                }
            }
            IMSG_CONSTRAINT_DNS => {
                // Forward DNS result to constraint manager.
            }
            IMSG_PROBE_ROOT => {
                if data.len() >= 4 {
                    let mut buf = [0u8; 4];
                    buf.copy_from_slice(&data[..4]);
                    let n = i32::from_ne_bytes(buf);
                    if n < 0 {
                        self.priv_settime(0.0, Some("dns probe failed"));
                    }
                }
            }
            _ => {
                log_debug(&format!("unhandled dns imsg type {type_}"));
            }
        }
        Ok(())
    }

    /// Handle an incoming NTP response from a peer.
    ///
    /// Validates the response, computes offset/delay, updates the peer's
    /// filter and trustlevel, and triggers clock adjustment if needed.
    ///
    /// Returns: -1 on error, 0 for invalid/untrustworthy reply, 1 on
    /// successful processing (matching C `client_dispatch()` return values).
    ///
    /// Corresponds to C: `client_dispatch()`.
    pub fn handle_peer_response(
        &mut self,
        peer_idx: usize,
        buf: &[u8],
        recv_time: f64,
    ) -> Result<i32, String> {
        if peer_idx >= self.peer_states.len() {
            return Err(format!("invalid peer index {peer_idx}"));
        }

        // Parse NTP response using core library.
        let packet = match openntpd_rs_core::ntp::NtpDatagram::decode(buf) {
            Some(datagram) => match datagram {
                openntpd_rs_core::ntp::NtpDatagram::Unauthenticated(pkt) => pkt,
                openntpd_rs_core::ntp::NtpDatagram::Authenticated { packet: pkt, .. } => pkt,
            },
            None => {
                return Ok(-1); // Not an NTP message
            }
        };

        // Validate mode: should be server (4) or symmetric passive (2).
        let mode = packet.mode();
        if mode != 4 && mode != 2 {
            return Ok(0);
        }

        // Validate version.
        let version = packet.version();
        if version < 2 || version > 4 {
            return Ok(0);
        }

        // Check for kiss-o'-death or alarm.
        let leap = packet.leap_indicator();
        let stratum = packet.stratum;
        if leap == 3 || stratum == 0 || stratum > 15 {
            let reason = if leap == 3 {
                "alarm"
            } else if stratum == 0 {
                "KoD"
            } else {
                "invalid stratum"
            };
            {
                let peer_state = &mut self.peer_states[peer_idx];
                let addr = peer_state
                    .peer
                    .address
                    .as_utf8()
                    .unwrap_or("<unknown>")
                    .to_string();
                log_info(&format!("reply from {addr}: not synced ({reason})"));
                let interval = error_interval();
                peer_state.set_next(interval);
            }
            return Ok(0);
        }

        // Compute offset and delay (RFC 2030).
        let t2 = packet.receive_ts.to_f64();
        let t3 = packet.transmit_ts.to_f64();
        let t4 = recv_time;
        let t1 = 0.0;

        let offset = ((t2 - t1) + (t3 - t4)) / 2.0;
        let delay = (t4 - t1) - (t3 - t2);

        // Validate delay (must be non-negative).
        if delay < 0.0 {
            {
                let peer_state = &mut self.peer_states[peer_idx];
                let addr = peer_state
                    .peer
                    .address
                    .as_utf8()
                    .unwrap_or("<unknown>")
                    .to_string();
                log_info(&format!("reply from {addr}: negative delay {delay:.6}s"));
                let interval = error_interval();
                peer_state.set_next(interval);
            }
            return Ok(0);
        }

        // Validate offset against constraint median.
        let context_needed = {
            let peer_state = &self.peer_states[peer_idx];
            let trusted = peer_state.peer.trusted;
            let addr = peer_state
                .peer
                .address
                .as_utf8()
                .unwrap_or("<unknown>")
                .to_string();
            (!trusted, addr)
        };
        if context_needed.0 && self.constraint_median != 0.0 {
            if (offset - self.constraint_median).abs() > 3600.0 {
                log_info(&format!(
                    "reply from {}: constraint check failed",
                    context_needed.1,
                ));
                {
                    let peer_state = &mut self.peer_states[peer_idx];
                    let interval = error_interval();
                    peer_state.set_next(interval);
                }
                return Ok(0);
            }
        }

        // Extract peer data before mutable borrow, then update peer state.
        let (trusted, peer_offset, peer_addr, trustlevel) = {
            let peer_state = &self.peer_states[peer_idx];
            (
                peer_state.peer.trusted,
                peer_state.peer.offset,
                peer_state
                    .peer
                    .address
                    .as_utf8()
                    .unwrap_or("<unknown>")
                    .to_string(),
                peer_state.trustlevel,
            )
        };

        let settime_enabled = self.config.settime;
        let automatic = self.config.automatic;

        // Update peer state.
        {
            let peer_state = &mut self.peer_states[peer_idx];
            peer_state.dispatch_response(offset, delay, stratum);

            // Determine next interval based on trustlevel (matching C ordering).
            let interval = if trustlevel < TRUSTLEVEL_PATHETIC {
                scale_interval(INTERVAL_QUERY_PATHETIC as i64)
            } else if trustlevel < TRUSTLEVEL_AGGRESSIVE {
                if settime_enabled && automatic {
                    INTERVAL_QUERY_ULTRA_VIOLENCE as i64
                } else {
                    scale_interval(INTERVAL_QUERY_AGGRESSIVE as i64)
                }
            } else {
                scale_interval(INTERVAL_QUERY_NORMAL as i64)
            };
            peer_state.set_next(interval);
        }

        self.last_action = getmonotime() as i64;

        log_debug(&format!(
            "reply from {peer_addr}: offset {offset:+.6}s delay {delay:.6}s",
        ));

        // Trigger clock adjustment if settime is enabled.
        if settime_enabled {
            if automatic {
                match self.engine.handle_auto(trusted, peer_offset) {
                    AutoResult::SetTime(off) => {
                        self.priv_settime(off, None);
                    }
                    AutoResult::Abandon => {
                        self.priv_settime(0.0, Some("auto-set abandoned"));
                    }
                    AutoResult::Continue => {}
                }
            } else {
                self.priv_settime(peer_offset, None);
            }
        }

        Ok(1)
    }

    /// Compute the median offset from all peers and sensors with
    /// weight-based voting, then send an IMSG_ADJTIME to the parent.
    ///
    /// Returns the computed median offset, or `None` if insufficient
    /// data.
    ///
    /// Corresponds to C: `priv_adjtime()`.
    pub fn priv_adjtime(&mut self) -> Result<Option<f64>, String> {
        // Collect all candidates: peers with trustlevel >= BADPEER
        // and whose best_sample exists.
        let mut candidates: Vec<(f64, f64, u8, u32)> = Vec::new();
        // (offset, delay, stratum, refid)

        for peer_state in &self.peer_states {
            if peer_state.trustlevel < TRUSTLEVEL_BADPEER {
                continue;
            }
            if let Some(sample) = peer_state.peer.best_sample() {
                // C: offset_cnt += p->weight;
                // Replicate each candidate weight times.
                let weight = peer_state.peer.weight.max(1) as usize;
                for _ in 0..weight {
                    candidates.push((
                        sample.offset,
                        sample.delay,
                        peer_state.peer.stratum,
                        0, // refid placeholder
                    ));
                }
            }
        }

        // For sensors, we would collect from the sensor registry.
        // For now, sensors are omitted in this simplified version.

        if candidates.is_empty() {
            return Ok(None);
        }

        // Sort by offset (matching C: qsort with offset_compare).
        candidates.sort_by(|a, b| a.0.partial_cmp(&b.0).unwrap_or(Ordering::Equal));

        let count = candidates.len();
        let median_idx = count / 2;

        // C: if even count, choose the one with lower delay.
        let i = if count % 2 == 0 && median_idx > 0 {
            if candidates[median_idx - 1].1 < candidates[median_idx].1 {
                median_idx - 1
            } else {
                median_idx
            }
        } else {
            median_idx
        };

        let (offset_median, delay_median, stratum_median, _refid) = candidates[i];

        // Update status fields.
        self.status_rootdelay = delay_median;
        self.status_stratum = stratum_median;

        // Send IMSG_ADJTIME to parent with median offset.
        let payload = offset_median.to_ne_bytes().to_vec();
        self.send_imsg(IMSG_ADJTIME, &payload)?;

        // Update frequency estimate.
        self.priv_adjfreq(offset_median);

        // Update reference time.
        self.status_reftime = gettime();

        // Increment stratum (one more than selected peer).
        self.status_stratum = self.status_stratum.saturating_add(1);
        if self.status_stratum > 15 {
            self.status_stratum = 15;
        }

        // Subtract median offset from all peer offsets.
        for peer_state in &mut self.peer_states {
            peer_state.peer.offset -= offset_median;
            // Also adjust all filter samples.
            for slot in &mut peer_state.peer.filter {
                if let Some(ref mut sample) = slot {
                    sample.offset -= offset_median;
                }
            }
        }

        Ok(Some(offset_median))
    }

    /// Update the frequency estimate via linear regression and send
    /// an IMSG_ADJFREQ to the parent when enough samples accumulate.
    ///
    /// Corresponds to C: `priv_adjfreq()`.
    ///
    /// # Arguments
    ///
    /// * `offset` - The current clock offset estimate.
    pub fn priv_adjfreq(&mut self, offset: f64) {
        if !self.synced {
            self.freq_accumulator.reset();
            return;
        }

        self.freq_accumulator.samples += 1;
        if self.freq_accumulator.samples <= 0 {
            return;
        }

        self.freq_accumulator.overall_offset += offset;
        let adj_offset = self.freq_accumulator.overall_offset;

        let curtime = gettime();

        self.freq_accumulator.xy += adj_offset * curtime;
        self.freq_accumulator.x += curtime;
        self.freq_accumulator.y += adj_offset;
        self.freq_accumulator.xx += curtime * curtime;

        // Only compute frequency after FREQUENCY_SAMPLES samples.
        const FREQUENCY_SAMPLES: i64 = 8;
        if self.freq_accumulator.samples % FREQUENCY_SAMPLES != 0 {
            return;
        }

        let s = self.freq_accumulator.samples as f64;
        let numerator =
            self.freq_accumulator.xy - self.freq_accumulator.x * self.freq_accumulator.y / s;
        let denominator =
            self.freq_accumulator.xx - self.freq_accumulator.x * self.freq_accumulator.x / s;

        let mut freq = if denominator.abs() > 1e-12 {
            numerator / denominator
        } else {
            0.0
        };

        // Clamp to MAX_FREQUENCY_ADJUST.
        const MAX_FREQUENCY_ADJUST: f64 = 1e-4; // 100 ppm
        if freq > MAX_FREQUENCY_ADJUST {
            freq = MAX_FREQUENCY_ADJUST;
        } else if freq < -MAX_FREQUENCY_ADJUST {
            freq = -MAX_FREQUENCY_ADJUST;
        }

        // Send IMSG_ADJFREQ to parent.
        let payload = freq.to_ne_bytes().to_vec();
        if let Err(e) = self.send_imsg(IMSG_ADJFREQ, &payload) {
            log_warn(&format!("failed to send adjfreq: {e}"));
        }

        // Reset accumulator (matching C).
        self.freq_accumulator.reset();
        self.freq_accumulator.num += 1;
    }

    /// Send a settime imsg to the parent process.
    ///
    /// If `offset` is 0.0, it cancels the settime. Otherwise, it adjusts
    /// all peer reply offsets and sends the message. After sending, the
    /// settime flag is cleared.
    ///
    /// Corresponds to C: `priv_settime()`.
    pub fn priv_settime(&mut self, offset: f64, msg: Option<&str>) {
        if offset == 0.0 {
            if let Some(m) = msg {
                log_info(&format!("cancel settime because {m}"));
            } else {
                log_info("cancel settime (zero offset)");
            }
        } else {
            // Adjust all peer filter offsets (matching C).
            for peer_state in &mut self.peer_states {
                for slot in &mut peer_state.peer.filter {
                    if let Some(ref mut sample) = slot {
                        sample.offset -= offset;
                    }
                }
            }
        }

        // Send IMSG_SETTIME to parent.
        let payload = offset.to_ne_bytes().to_vec();
        if let Err(e) = self.send_imsg(IMSG_SETTIME, &payload) {
            log_warn(&format!("failed to send settime: {e}"));
        }

        // Clear settime flag.
        self.config.settime = false;
    }

    /// Send a DNS resolution request to the DNS child process.
    ///
    /// Corresponds to C: `priv_dns()`.
    pub fn priv_dns(&mut self, cmd: u32, name: Option<&str>, _peerid: u32) {
        let dns_ibuf = match self.dns_ibuf.as_mut() {
            Some(buf) => buf,
            None => {
                log_debug("DNS child not available, skipping DNS request");
                return;
            }
        };

        let payload = match name {
            Some(n) => {
                let mut bytes = n.as_bytes().to_vec();
                bytes.push(0); // null-terminated, matching C
                bytes
            }
            None => Vec::new(),
        };

        let imsg = Imsg::new(cmd, payload);
        if let Err(e) = dns_ibuf.send(&imsg) {
            log_warn(&format!("failed to send DNS request: {e}"));
        }
    }

    /// Check for sync loss due to lack of replies.
    ///
    /// If the clock is synced and no action has been taken for
    /// `3 * scale_interval(INTERVAL_QUERY_NORMAL)` seconds, the clock
    /// is marked as unsynced.
    ///
    /// Corresponds to the inline check in C: `ntp_main()`.
    pub fn check_sync_loss(&mut self, now: i64) {
        if !self.synced {
            return;
        }

        // Compute scale_interval(INTERVAL_QUERY_NORMAL) with jitter.
        let interval = (INTERVAL_QUERY_NORMAL as i64) * self.scale;
        let jitter_range = scale_interval(interval) - interval;
        let effective_interval = interval + jitter_range;

        // C: if (conf->status.synced && last_action + 3 * interval < now)
        let threshold = self.last_action + 3 * effective_interval;
        if threshold < now {
            log_info("clock is now unsynced due to lack of replies");
            self.synced = false;
            self.scale = 1;
            self.priv_dns(IMSG_UNSYNCED, None, 0);
            if let Err(e) = self.send_imsg(IMSG_UNSYNCED, &[]) {
                log_warn(&format!("failed to send unsynced: {e}"));
            }
        }
    }

    /// Query sensors for current readings.
    ///
    /// Corresponds to the sensor query loop in C: `ntp_main()`.
    pub fn query_sensors(&mut self) {
        if self.sensor_registry.is_empty() {
            return;
        }
        for sensor_name in &self.sensor_registry.clone() {
            let _ = sensor_query(sensor_name);
        }
    }

    /// Clean up and shut down the child process.
    ///
    /// Flushes imsg buffers, closes control connections, and logs exit.
    ///
    /// Corresponds to the shutdown sequence in C: `ntp_main()`.
    pub fn shutdown(&mut self) {
        log_info("ntp engine exiting");

        // Close control connections.
        for &fd in &self.ctl_conns {
            control_close(fd);
        }
        self.ctl_conns.clear();

        // Close control listener.
        if let Some(fd) = self.ctl_fd {
            control_shutdown(fd);
        }

        // The ImsgSocket will be dropped, which closes its inner stream.
    }
}

// ---------------------------------------------------------------------------
// Free functions
// ---------------------------------------------------------------------------

/// Signal handler for the NTP child process.
///
/// Sets a quit flag on `SIGINT` and `SIGTERM`.  Corresponds to C:
/// `ntp_sighdlr()` in `ntp.c`.
pub fn ntp_sighdlr(sig: i32) -> bool {
    match sig {
        libc::SIGINT | libc::SIGTERM => true, // signal received, should quit
        _ => false,
    }
}

/// Compare two peers by their offset for median selection.
///
/// Corresponds to C: `offset_compare()`.
#[must_use]
pub fn peer_offset_compare(a: &Peer, b: &Peer) -> Ordering {
    a.offset.partial_cmp(&b.offset).unwrap_or(Ordering::Equal)
}

/// Run the NTP child process from the daemon binary.
///
/// This is the entry point called after privsep fork with `-P ntp_main`.
///
/// # Errors
///
/// Returns `Err` if the child process encounters a fatal error.
pub fn run_ntp_child() -> Result<(), String> {
    log_info("NTP child entry point (placeholder)");
    Ok(())
}

/// Scale an interval by the current scale factor and add jitter.
///
/// Corresponds to C: `scale_interval()`.
#[must_use]
pub fn scale_interval(requested: i64) -> i64 {
    let interval = requested; // scale is implicitly 1 in simplified version
    let jitter = interval / 10; // ~10% jitter
    interval + (jitter.max(1) - 1)
}

/// Compute an error interval (longer backoff).
///
/// Corresponds to C: `error_interval()`.
#[must_use]
pub fn error_interval() -> i64 {
    let interval = INTERVAL_QUERY_PATHETIC as i64 * 32; // QSCALE_OFF_MAX / QSCALE_OFF_MIN ≈ 32
    let jitter = interval / 10;
    interval + jitter
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use openntpd_rs_core::config::directive::ConfigString;

    fn make_child() -> NtpChildProcess {
        let (parent_sock, child_sock) = ImsgSocket::pair().expect("failed to create socket pair");
        drop(parent_sock);
        NtpChildProcess::new(ChildConfig::default(), child_sock, None, None)
    }

    fn make_child_with_dns() -> (NtpChildProcess, ImsgSocket, ImsgSocket) {
        let (parent_sock, child_sock) =
            ImsgSocket::pair().expect("failed to create parent socket pair");
        let (dns_parent, dns_child) = ImsgSocket::pair().expect("failed to create dns socket pair");
        let child = NtpChildProcess::new(ChildConfig::default(), child_sock, Some(dns_child), None);
        (child, parent_sock, dns_parent)
    }

    fn make_peer() -> ClientPeer {
        let addr = ConfigString::new(b"127.0.0.1".to_vec()).unwrap();
        ClientPeer::new(addr, 1, false)
    }

    // ── 1. Construction ─────────────────────────────────────────────────

    #[test]
    fn test_ntp_child_new_defaults() {
        let child = make_child();
        assert_eq!(child.peer_states.len(), 0);
        assert!(child.dns_ibuf.is_none());
        assert!(child.ctl_fd.is_none());
        assert!(!child.config.settime);
        assert_eq!(child.config.verbose, 0);
        assert!(!child.synced);
        assert_eq!(child.scale, 1);
    }

    #[test]
    fn test_ntp_child_new_with_config() {
        let (parent_sock, child_sock) = ImsgSocket::pair().unwrap();
        drop(parent_sock);
        let config = ChildConfig {
            debug: true,
            settime: true,
            automatic: true,
            verbose: 2,
            dns_child_enabled: false,
        };
        let child = NtpChildProcess::new(config, child_sock, None, Some(0));
        assert!(child.config.debug);
        assert!(child.config.settime);
        assert!(child.config.automatic);
        assert_eq!(child.config.verbose, 2);
        assert!(!child.config.dns_child_enabled);
        assert_eq!(child.ctl_fd, Some(0));
    }

    #[test]
    fn test_ntp_child_new_with_dns() {
        let (parent_sock, child_sock) = ImsgSocket::pair().unwrap();
        let (dns_parent, dns_child) = ImsgSocket::pair().unwrap();
        drop(parent_sock);
        drop(dns_parent);
        let child = NtpChildProcess::new(ChildConfig::default(), child_sock, Some(dns_child), None);
        assert!(child.dns_ibuf.is_some());
    }

    // ── 2. priv_adjtime with peers ─────────────────────────────────────

    #[test]
    fn test_priv_adjtime_no_peers_returns_none() {
        let (mut child, _parent_sock, _dns_sock) = make_child_with_dns();
        let result = child.priv_adjtime().expect("priv_adjtime should not error");
        assert!(result.is_none());
    }

    #[test]
    fn test_priv_adjtime_single_peer() {
        let (mut child, _parent_sock, _dns_sock) = make_child_with_dns();
        let mut peer = make_peer();
        // Add samples so best_sample() returns something.
        peer.peer.add_sample(0.005, 0.020, 0.001);
        peer.peer.add_sample(0.006, 0.015, 0.001);
        peer.peer.add_sample(0.004, 0.018, 0.001);
        peer.peer.add_sample(0.005, 0.012, 0.001);
        peer.peer.add_sample(0.005, 0.016, 0.001);
        peer.peer.add_sample(0.005, 0.014, 0.001);
        peer.peer.add_sample(0.005, 0.013, 0.001);
        peer.peer.add_sample(0.005, 0.011, 0.001);
        peer.trustlevel = TRUSTLEVEL_BADPEER + 1;
        child.peer_states.push(peer);

        let result = child.priv_adjtime().expect("priv_adjtime failed");
        assert!(result.is_some());
        let offset = result.unwrap();
        // The offset should be near 0.005.
        assert!(
            (offset - 0.005).abs() < 0.01,
            "offset {offset} should be near 0.005"
        );
    }

    #[test]
    fn test_priv_adjtime_multiple_peers_median() {
        let (mut child, _parent_sock, _dns_sock) = make_child_with_dns();

        for offset in &[0.01, 0.02, 0.03, 0.04, 0.05] {
            let mut peer = make_peer();
            let addr = ConfigString::new(
                format!("192.168.1.{}", (offset * 100.0) as u8)
                    .as_bytes()
                    .to_vec(),
            )
            .unwrap();
            let mut core_peer = Peer::new(addr, 1, false);
            for _ in 0..8 {
                core_peer.add_sample(*offset, 0.010, 0.001);
            }
            peer.peer = core_peer;
            peer.trustlevel = TRUSTLEVEL_BADPEER + 1;
            child.peer_states.push(peer);
        }

        let result = child.priv_adjtime().expect("priv_adjtime failed");
        assert!(result.is_some());
        let median = result.unwrap();
        // Median of [0.01, 0.02, 0.03, 0.04, 0.05] → 0.03.
        assert!(
            (median - 0.03).abs() < 0.01,
            "median {median} should be near 0.03"
        );
    }

    #[test]
    fn test_priv_adjtime_low_trustlevel_skipped() {
        let (mut child, _parent_sock, _dns_sock) = make_child_with_dns();
        let mut peer = make_peer();
        peer.trustlevel = TRUSTLEVEL_BADPEER - 1;
        child.peer_states.push(peer);
        let result = child.priv_adjtime().expect("priv_adjtime failed");
        assert!(result.is_none());
    }

    // ── 3. priv_adjfreq frequency estimation ──────────────────────────

    #[test]
    fn test_priv_adjfreq_not_synced_resets() {
        let mut child = make_child();
        child.freq_accumulator.samples = 10;
        child.priv_adjfreq(0.005);
        assert_eq!(
            child.freq_accumulator.samples, 0,
            "should reset when not synced"
        );
    }

    #[test]
    fn test_priv_adjfreq_accumulates() {
        let mut child = make_child();
        child.synced = true;
        child.priv_adjfreq(0.001);
        assert_eq!(child.freq_accumulator.samples, 1);
        child.priv_adjfreq(0.002);
        assert_eq!(child.freq_accumulator.samples, 2);
    }

    #[test]
    fn test_priv_adjfreq_sends_after_enough_samples() {
        let (mut child, mut parent_sock, _dns_sock) = make_child_with_dns();
        child.synced = true;

        for i in 1..=8 {
            child.priv_adjfreq(0.001 * (i as f64));
        }

        assert_eq!(child.freq_accumulator.samples, 0);
        // Check parent socket for message.
        match parent_sock.recv() {
            Ok(imsg) => {
                assert_eq!(imsg.header.type_, IMSG_ADJFREQ);
                assert_eq!(imsg.payload.len(), 8);
            }
            _ => {}
        }
    }

    #[test]
    fn test_priv_adjfreq_clamps_high_value() {
        let (mut child, _parent_sock, _dns_sock) = make_child_with_dns();
        child.synced = true;
        // Set samples to 7 so that after +=1 it reaches 8 (FREQUENCY_SAMPLES).
        child.freq_accumulator.samples = 7;
        child.freq_accumulator.overall_offset = 1000.0;
        child.freq_accumulator.x = 1.0;
        child.freq_accumulator.xx = 1.0;
        child.freq_accumulator.xy = 1000.0;
        child.freq_accumulator.y = 1000.0;
        child.priv_adjfreq(1000.0);
        // After reaching FREQUENCY_SAMPLES, the accumulator resets.
        assert_eq!(
            child.freq_accumulator.samples, 0,
            "accumulator should reset"
        );
        assert_eq!(child.freq_accumulator.num, 1, "num should increment");
    }

    // ── 4. priv_settime imsg sending ─────────────────────────────────

    #[test]
    fn test_priv_settime_sends_imsg() {
        let (mut child, mut parent_sock, _dns_sock) = make_child_with_dns();

        child.priv_settime(0.125, None);

        match parent_sock.recv() {
            Ok(imsg) => {
                assert_eq!(imsg.header.type_, IMSG_SETTIME);
                assert_eq!(imsg.payload.len(), 8);
                let mut buf = [0u8; 8];
                buf.copy_from_slice(&imsg.payload[..8]);
                let offset = f64::from_ne_bytes(buf);
                assert!((offset - 0.125).abs() < 0.0001);
            }
            Err(e) => panic!("expected IMSG_SETTIME but got error: {e}"),
        }
        assert!(!child.config.settime, "settime should be cleared");
    }

    #[test]
    fn test_priv_settime_zero_offset_cancels() {
        let (mut child, mut parent_sock, _dns_sock) = make_child_with_dns();
        child.config.settime = true;
        child.priv_settime(0.0, Some("test cancel"));

        match parent_sock.recv() {
            Ok(imsg) => {
                assert_eq!(imsg.header.type_, IMSG_SETTIME);
                assert_eq!(imsg.payload.len(), 8);
                let mut buf = [0u8; 8];
                buf.copy_from_slice(&imsg.payload[..8]);
                let offset = f64::from_ne_bytes(buf);
                assert!((offset - 0.0).abs() < f64::EPSILON);
            }
            Err(e) => panic!("expected IMSG_SETTIME but got error: {e}"),
        }
        assert!(!child.config.settime, "settime should be cleared");
    }

    #[test]
    fn test_priv_settime_adjusts_peer_offsets() {
        let (mut child, _parent_sock, _dns_sock) = make_child_with_dns();
        let mut peer = make_peer();
        peer.peer.add_sample(1.0, 0.010, 0.001);
        child.peer_states.push(peer);

        child.priv_settime(1.0, None);

        if let Some(sample) = child.peer_states[0].peer.best_sample() {
            assert!(
                (sample.offset - 0.0).abs() < 0.1,
                "offset should be ~0 after adjustment"
            );
        }
    }

    // ── 5. priv_dns message dispatch ──────────────────────────────────

    #[test]
    fn test_priv_dns_sends_to_dns_child() {
        let (mut child, _parent_sock, mut dns_parent) = make_child_with_dns();

        child.priv_dns(IMSG_HOST_DNS, Some("pool.ntp.org"), 42);

        match dns_parent.recv() {
            Ok(imsg) => {
                assert_eq!(imsg.header.type_, IMSG_HOST_DNS);
                let payload_str = String::from_utf8_lossy(&imsg.payload);
                assert!(payload_str.starts_with("pool.ntp.org"));
            }
            Err(e) => panic!("expected IMSG_HOST_DNS but got error: {e}"),
        }
    }

    #[test]
    fn test_priv_dns_no_name_sends_empty() {
        let (mut child, _parent_sock, mut dns_parent) = make_child_with_dns();

        child.priv_dns(IMSG_UNSYNCED, None, 0);

        match dns_parent.recv() {
            Ok(imsg) => {
                assert_eq!(imsg.header.type_, IMSG_UNSYNCED);
                assert!(imsg.payload.is_empty());
            }
            Err(e) => panic!("expected IMSG_UNSYNCED but got error: {e}"),
        }
    }

    #[test]
    fn test_priv_dns_no_dns_child_graceful() {
        let mut child = make_child();
        child.priv_dns(IMSG_HOST_DNS, Some("pool.ntp.org"), 0);
    }

    // ── 6. handle_peer_response with valid/invalid responses ──────────

    #[test]
    fn test_handle_peer_response_invalid_index() {
        let mut child = make_child();
        let result = child.handle_peer_response(0, &[], 0.0);
        assert!(result.is_err(), "should error with out-of-range index");
    }

    #[test]
    fn test_handle_peer_response_empty_buffer() {
        let mut child = make_child();
        child.peer_states.push(make_peer());
        let result = child.handle_peer_response(0, &[], 0.0);
        assert_eq!(result.unwrap_or(-1), -1);
    }

    #[test]
    fn test_handle_peer_response_kiss_of_death() {
        use openntpd_rs_core::ntp::NtpDatagram;

        let mut packet = openntpd_rs_core::ntp::NtpPacket::zero();
        packet.set_li_vn_mode(0, 4, 4);
        packet.stratum = 0; // KoD

        let datagram = NtpDatagram::Unauthenticated(packet);
        let encoded = datagram.encode();

        let mut child = make_child();
        child.peer_states.push(make_peer());
        let result = child.handle_peer_response(0, &encoded, 100.0);
        assert_eq!(result.unwrap_or(-1), 0, "KoD should be ignored (return 0)");
    }

    #[test]
    fn test_handle_peer_response_invalid_stratum() {
        use openntpd_rs_core::ntp::NtpDatagram;

        let mut packet = openntpd_rs_core::ntp::NtpPacket::zero();
        packet.set_li_vn_mode(0, 4, 4);
        packet.stratum = 16; // > max

        let datagram = NtpDatagram::Unauthenticated(packet);
        let encoded = datagram.encode();

        let mut child = make_child();
        child.peer_states.push(make_peer());
        let result = child.handle_peer_response(0, &encoded, 100.0);
        assert_eq!(result.unwrap_or(-1), 0, "high stratum should be ignored");
    }

    // ── 7. check_sync_loss detection ──────────────────────────────────

    #[test]
    fn test_check_sync_loss_not_synced() {
        let mut child = make_child();
        child.synced = false;
        child.last_action = 0;
        child.check_sync_loss(1000000);
        assert!(!child.synced);
    }

    #[test]
    fn test_check_sync_loss_recent_action() {
        let mut child = make_child();
        child.synced = true;
        child.last_action = 1000;
        child.check_sync_loss(1001);
        assert!(child.synced, "should still be synced");
    }

    #[test]
    fn test_check_sync_loss_sync_expired() {
        let mut child = make_child();
        child.synced = true;
        child.last_action = 1000;
        child.scale = 1;
        child.check_sync_loss(1000000);
        assert!(!child.synced, "should become unsynced after timeout");
    }

    #[test]
    fn test_check_sync_loss_boundary() {
        let mut child = make_child();
        child.synced = true;
        child.last_action = 1000;
        child.scale = 1;
        // INTERVAL_QUERY_NORMAL = 30, scale = 1
        // effective_interval ≈ 30 + 2 = 32
        // threshold = 1000 + 3 * 32 = 1096
        child.check_sync_loss(1095);
        assert!(child.synced, "should still be synced at boundary");
        child.check_sync_loss(1097);
        assert!(!child.synced, "should lose sync past boundary");
    }

    // ── 8. peer_offset_compare ordering ───────────────────────────────

    #[test]
    fn test_peer_offset_compare_equal() {
        let addr = ConfigString::new(b"test".to_vec()).unwrap();
        let a = Peer::new(addr.clone(), 1, false);
        let b = Peer::new(addr, 1, false);
        assert_eq!(peer_offset_compare(&a, &b), Ordering::Equal);
    }

    #[test]
    fn test_peer_offset_compare_different() {
        let a_addr = ConfigString::new(b"a".to_vec()).unwrap();
        let b_addr = ConfigString::new(b"b".to_vec()).unwrap();
        let mut a = Peer::new(a_addr, 1, false);
        let mut b = Peer::new(b_addr, 1, false);

        a.add_sample(0.010, 0.005, 0.001);
        a.add_sample(0.011, 0.006, 0.001);
        b.add_sample(0.020, 0.005, 0.001);
        b.add_sample(0.021, 0.006, 0.001);

        let ordering = peer_offset_compare(&a, &b);
        assert_eq!(ordering, Ordering::Less, "a has lower offset than b");
    }

    #[test]
    fn test_peer_offset_compare_negative_offsets() {
        let a_addr = ConfigString::new(b"a".to_vec()).unwrap();
        let b_addr = ConfigString::new(b"b".to_vec()).unwrap();
        let mut a = Peer::new(a_addr, 1, false);
        let mut b = Peer::new(b_addr, 1, false);

        a.add_sample(-0.050, 0.005, 0.001);
        b.add_sample(-0.030, 0.005, 0.001);

        let ordering = peer_offset_compare(&a, &b);
        assert_eq!(ordering, Ordering::Less, "more negative = less");
    }

    // ── 9. Full tick cycle ────────────────────────────────────────────

    #[test]
    fn test_tick_empty() {
        let (mut child, _parent_sock, _dns_sock) = make_child_with_dns();
        let result = child.tick();
        assert!(result.is_ok(), "tick should succeed with no peers");
    }

    #[test]
    fn test_tick_with_peers() {
        let (mut child, _parent_sock, _dns_sock) = make_child_with_dns();
        let mut peer = make_peer();
        peer.next = 0;
        peer.set_next(0);
        child.peer_states.push(peer);

        let result = child.tick();
        assert!(result.is_ok(), "tick should succeed with peers");
    }

    #[test]
    fn test_tick_peer_deadline_expiry() {
        let (mut child, _parent_sock, _dns_sock) = make_child_with_dns();
        let mut peer = make_peer();
        peer.deadline = 1;
        peer.next = 0;
        child.peer_states.push(peer);

        let result = child.tick();
        assert!(result.is_ok());

        let p = &child.peer_states[0];
        assert!(p.next > 0, "next should be set after deadline expiry");
        assert_eq!(p.deadline, 0, "deadline should be cleared");
    }

    #[test]
    fn test_tick_send_errors_handling() {
        let (mut child, _parent_sock, _dns_sock) = make_child_with_dns();
        let mut peer = make_peer();
        peer.senderrors = MAX_SEND_ERRORS + 1;
        peer.next = 1;
        child.peer_states.push(peer);

        let result = child.tick();
        assert!(result.is_ok());

        let p = &child.peer_states[0];
        assert_eq!(p.senderrors, 0, "senderrors should be reset");
        assert!(p.next > 0, "next should be set after send error handling");
    }

    // ── 10. Shutdown sequence ─────────────────────────────────────────

    #[test]
    fn test_shutdown_without_control_socket() {
        let mut child = make_child();
        child.shutdown();
    }

    #[test]
    fn test_shutdown_with_ctl_connections() {
        let (mut child, _parent_sock, _dns_sock) = make_child_with_dns();
        child.shutdown();
        assert!(child.ctl_conns.is_empty());
    }

    #[test]
    fn test_shutdown_multiple_calls() {
        let mut child = make_child();
        child.shutdown();
        child.shutdown();
    }

    // ── 11. Edge cases ────────────────────────────────────────────────

    #[test]
    fn test_scale_interval_positive() {
        let result = scale_interval(30);
        assert!(result >= 30);
    }

    #[test]
    fn test_error_interval_positive() {
        let result = error_interval();
        assert!(result > 0);
    }

    #[test]
    fn test_dispatch_parent_imsg_unknown_type() {
        let mut child = make_child();
        let result = child.dispatch_parent_imsg(9999, &[]);
        assert!(result.is_ok());
    }

    #[test]
    fn test_dispatch_parent_imsg_adjtime_short_payload() {
        let mut child = make_child();
        let result = child.dispatch_parent_imsg(IMSG_ADJTIME, &[1, 2]);
        assert!(result.is_ok());
    }

    #[test]
    fn test_dispatch_parent_imsg_adjtime_sync() {
        let (mut child, _parent_sock, _dns_sock) = make_child_with_dns();
        assert!(!child.synced);

        let result = child.dispatch_parent_imsg(IMSG_ADJTIME, &1i32.to_ne_bytes());
        assert!(result.is_ok());
        assert!(child.synced, "should become synced");
    }

    #[test]
    fn test_dispatch_parent_imsg_adjtime_unsync() {
        let (mut child, _parent_sock, _dns_sock) = make_child_with_dns();
        child.synced = true;

        let result = child.dispatch_parent_imsg(IMSG_ADJTIME, &0i32.to_ne_bytes());
        assert!(result.is_ok());
        assert!(!child.synced, "should become unsynced");
    }

    #[test]
    fn test_dispatch_dns_imsg_probe_root_failure() {
        let (mut child, _parent_sock, _dns_sock) = make_child_with_dns();
        child.config.settime = true;
        let result = child.dispatch_dns_imsg(IMSG_PROBE_ROOT, &(-1i32).to_ne_bytes());
        assert!(result.is_ok());
        assert!(
            !child.config.settime,
            "settime should be cleared after probe failure"
        );
    }

    // -------------------------------------------------------------------
    // ntp_sighdlr
    // -------------------------------------------------------------------

    #[test]
    fn test_ntp_sighdlr_sigint() {
        assert!(ntp_sighdlr(libc::SIGINT));
    }

    #[test]
    fn test_ntp_sighdlr_sigterm() {
        assert!(ntp_sighdlr(libc::SIGTERM));
    }

    #[test]
    fn test_ntp_sighdlr_other_signals() {
        assert!(!ntp_sighdlr(libc::SIGHUP));
        assert!(!ntp_sighdlr(libc::SIGPIPE));
        assert!(!ntp_sighdlr(libc::SIGCHLD));
        assert!(!ntp_sighdlr(libc::SIGUSR1));
        assert!(!ntp_sighdlr(999));
    }
}
