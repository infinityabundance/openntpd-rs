//! `ntpd` daemon library — OpenNTPD-rs forensic reconstruction.
//!
//! Provides the `-n` (config check) logic, daemon-mode infrastructure,
//! and injectable CLI argument parsing for the `ntpd` binary.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::os::unix::io::RawFd;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use openntpd_rs_core::config::runtime::{ListenConfig, RuntimeConfig};
use openntpd_rs_core::ntp::clock::ClockState;
use openntpd_rs_core::ntp::query::QueryState;
use openntpd_rs_core::ntp::{NtpDatagram, NtpTimestamp};
use openntpd_rs_core::peer::Peer;
use openntpd_rs_io::daemon::{
    create_signal_fd, read_signal, DriftFileManager, EventLoop, EventSource, NtpIo, PeerTarget,
    TimerAction,
};

// ---------------------------------------------------------------------------
// Exit codes
// ---------------------------------------------------------------------------

/// Exit code for runtime errors (EXIT_FAILURE = 1).
pub const EXIT_ERROR: u8 = 1;

/// Exit code for invalid configuration (EX_CONFIG).
pub const EXIT_CONFIG: u8 = 78;

// ---------------------------------------------------------------------------
// Daemon configuration & runner
// ---------------------------------------------------------------------------

/// Configuration for the ntpd daemon process.
#[derive(Debug, Clone)]
pub struct DaemonConfig {
    pub config_path: PathBuf,
    pub debug_mode: bool,
    pub verbose: u8,
    pub parent_proc: Option<String>,
    pub pid_file: Option<String>,
}

/// Result of a daemon run.
#[derive(Debug)]
pub struct DaemonResult {
    pub exit_code: u8,
    pub message: String,
}

/// Run the daemon with the given configuration.
///
/// In `-n` mode, this performs the config check and returns immediately.
/// In daemon mode, this starts the event loop.
pub fn run_daemon(config: &DaemonConfig) -> DaemonResult {
    // Always validate config first.
    let check = check_config_file(&config.config_path);
    if !check.is_valid {
        let mut message = String::new();
        for err in &check.errors {
            message.push_str(err);
            message.push('\n');
        }
        return DaemonResult {
            exit_code: EXIT_CONFIG,
            message,
        };
    }

    if config.debug_mode {
        eprintln!(
            "debug mode, config: {}, verbosity: {}",
            config_path_display(&config.config_path),
            config.verbose
        );
    }

    // Read and parse config bytes for runtime lowering.
    let bytes = match std::fs::read(&config.config_path) {
        Ok(b) => b,
        Err(e) => {
            return DaemonResult {
                exit_code: EXIT_ERROR,
                message: format!("cannot read config: {e}"),
            };
        }
    };

    let mut ctx = match DaemonContext::new(&bytes) {
        Ok(ctx) => ctx,
        Err(e) => {
            return DaemonResult {
                exit_code: EXIT_CONFIG,
                message: e,
            };
        }
    };

    match ctx.run(config.debug_mode) {
        Ok(()) => DaemonResult {
            exit_code: 0,
            message: "ntpd exited normally".into(),
        },
        Err(e) => DaemonResult {
            exit_code: EXIT_ERROR,
            message: e,
        },
    }
}

fn config_path_display(path: &PathBuf) -> &str {
    path.to_str().unwrap_or("<invalid path>")
}

// ---------------------------------------------------------------------------
// DaemonContext — ties all subsystems together
// ---------------------------------------------------------------------------

/// Runtime daemon context — ties all subsystems together.
pub struct DaemonContext {
    pub runtime_config: RuntimeConfig,
    pub peers: Vec<Peer>,
    pub query_states: Vec<QueryState>,
    pub clock: ClockState,
    pub event_loop: EventLoop,
    pub ntp_io: NtpIo,
    pub drift_file: Option<DriftFileManager>,
    pub start_time: Instant,
    /// Set of bound socket file descriptors.
    pub bound_fds: Vec<RawFd>,
    /// Signal fd for catching SIGALRM/SIGHUP/SIGINT/SIGTERM.
    pub signal_fd: Option<RawFd>,
}

impl DaemonContext {
    /// Create a new `DaemonContext` from configuration bytes.
    ///
    /// Parses the config, lowers it to runtime objects, creates peers
    /// and initializes all subsystems.
    ///
    /// # Errors
    ///
    /// Returns a string describing parse/lower errors.
    pub fn new(config_bytes: &[u8]) -> Result<Self, String> {
        // Parse the config.
        let parse_result = openntpd_rs_core::config::parser::parse_config(config_bytes);
        if !parse_result.is_valid() {
            let mut msg = String::new();
            for d in &parse_result.diagnostics {
                if d.severity == openntpd_rs_core::config::diagnostic::Severity::Error {
                    let span = match d.span {
                        Some(s) => format!("{}:{}: ", s.start, s.end),
                        None => String::new(),
                    };
                    msg.push_str(&format!("{span}{}\n", d.message));
                }
            }
            return Err(msg);
        }

        let config = parse_result.config;

        // Lower to runtime config.
        let (runtime, _dns_requests) = RuntimeConfig::lower(&config);

        // Create peers from server configs.
        let mut peers: Vec<Peer> = Vec::new();
        let mut query_states: Vec<QueryState> = Vec::new();
        for server in &runtime.servers {
            let address_bytes = format!("{}", server.address).into_bytes();
            // ConfigString::new rejects NUL bytes; IP strings never contain NUL.
            let addr_str = openntpd_rs_core::config::directive::ConfigString::new(address_bytes)
                .expect("IP address bytes should never contain NUL");
            let peer = Peer::new(addr_str, server.weight, server.trusted);
            peers.push(peer);
            query_states.push(QueryState::new());
        }

        Ok(Self {
            runtime_config: runtime,
            peers,
            query_states,
            clock: ClockState::new(),
            event_loop: EventLoop::new(),
            ntp_io: NtpIo::new(),
            drift_file: None,
            start_time: Instant::now(),
            bound_fds: Vec::new(),
            signal_fd: None,
        })
    }

    /// Run the full daemon: bind sockets, start event loop, dispatch.
    ///
    /// # Errors
    ///
    /// Returns a string describing the error on failure.
    pub fn run(&mut self, debug_mode: bool) -> Result<(), String> {
        if self.peers.is_empty() && self.runtime_config.servers.is_empty() {
            return Err("no servers configured".into());
        }

        // Build bind addresses.
        let bind_addrs = build_bind_addresses(&self.runtime_config.listeners);
        let addrs = if bind_addrs.is_empty() {
            // Default: bind wildcard IPv4 on NTP port.
            vec![SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 123)]
        } else {
            bind_addrs
        };

        // Bind NTP sockets.
        let sockets = NtpIo::bind_sockets(&addrs).map_err(|e| format!("bind listeners: {e}"))?;

        // Register peer targets in NtpIo.
        for (_idx, peer) in self.peers.iter().enumerate() {
            let addr_str = core::str::from_utf8(peer.address.as_bytes()).unwrap_or("0.0.0.0");
            if let Ok(ip) = addr_str.parse::<IpAddr>() {
                let target = PeerTarget {
                    id: peer.id,
                    address: SocketAddr::new(ip, 123),
                    query_interval: Duration::from_secs((1u64 << peer.poll.max(0) as u32).max(1)),
                };
                self.ntp_io.peers.push(target);
            }
        }

        // Store bound fds and register with event loop.
        for &(fd, _) in &sockets {
            self.bound_fds.push(fd);
            // Find which peer index this socket maps to.
            let peer_idx = self.ntp_io.peers.len().saturating_sub(1);
            self.event_loop
                .add_source(fd, EventSource::NtpSocket(peer_idx));
        }

        // Initialize drift file (debug mode uses a temp path).
        let drift_path = if debug_mode {
            std::env::temp_dir().join("ntpd.drift")
        } else {
            PathBuf::from("/var/db/ntpd.drift")
        };
        let mut drift = DriftFileManager::new(drift_path);
        drift.write_interval = Duration::from_secs(600); // 10 minutes in debug mode
        if let Ok(freq) = drift.read_drift() {
            // Restore previous frequency estimate.
            self.clock.set_frequency(freq);
            if debug_mode {
                eprintln!("ntpd: restored drift {freq:.3} ppm");
            }
        }
        self.drift_file = Some(drift);

        // Set up signal handling (Linux signalfd).
        #[cfg(target_os = "linux")]
        {
            let sig_fd = create_signal_fd().map_err(|e| format!("create_signal_fd: {e}"))?;
            self.signal_fd = Some(sig_fd);
            self.event_loop.add_source(sig_fd, EventSource::Signal);
        }

        // Register timers.
        self.event_loop.add_timer(
            Duration::from_secs(42), // wait for initial offset
            Duration::from_secs(32), // PollDispatch interval
            TimerAction::PollDispatch,
        );
        self.event_loop.add_timer(
            Duration::from_secs(0),   // fire immediately
            Duration::from_secs(600), // DriftFileWrite interval
            TimerAction::DriftFileWrite,
        );
        // Per-peer query timers.
        for idx in 0..self.peers.len() {
            self.event_loop.add_timer(
                Duration::from_secs(2), // initial delay (staggered)
                Duration::from_secs(2u64 << self.peers[idx].poll.min(10) as u32),
                TimerAction::SendQuery(idx),
            );
        }

        if debug_mode {
            eprintln!("ntpd: starting event loop with {} peers", self.peers.len());
        }

        // Run the event loop manually using poll_once.
        self.event_loop.running = true;
        while self.event_loop.running {
            let (ready, expired) = self
                .event_loop
                .poll_once(1000)
                .map_err(|e| format!("poll error: {e}"))?;

            // Handle ready events (socket readability).
            for event in &ready {
                self.handle_event(*event, self.signal_fd)?;
            }

            // Handle expired timer actions.
            for action in &expired {
                self.handle_timer_action(*action)?;
            }
        }

        Ok(())
    }

    /// Handle a single event dispatched by the event loop.
    ///
    /// # Errors
    ///
    /// Returns a string describing the error on failure.
    pub fn handle_event(
        &mut self,
        event: EventSource,
        signal_fd: Option<RawFd>,
    ) -> Result<(), String> {
        match event {
            EventSource::NtpSocket(peer_idx) => {
                // Try to receive a response.  If nothing is available
                // (non-blocking), that's fine — the timer will retry.
                if let Some(&fd) = self.bound_fds.first() {
                    let mut buf = [0u8; 512];
                    if let Ok((n, _src)) = NtpIo::recv_response(fd, &mut buf) {
                        let recv_time = instant_to_ntp(Instant::now(), self.start_time);
                        self.handle_ntp_response(&buf[..n], peer_idx, recv_time)?;
                    }
                }
                Ok(())
            }
            EventSource::Signal => {
                // Read pending signal from signalfd.
                if let Some(sig_fd) = signal_fd {
                    if let Ok(Some(sig)) = read_signal(sig_fd) {
                        match sig {
                            libc::SIGHUP => self.handle_reload(),
                            libc::SIGINT | libc::SIGTERM => {
                                self.handle_shutdown();
                                Ok(())
                            }
                            _ => Ok(()),
                        }
                    } else {
                        Ok(())
                    }
                } else {
                    Ok(())
                }
            }
            EventSource::Control => {
                // Timer-triggered housekeeping.
                Ok(())
            }
            EventSource::ImsgParent | EventSource::ImsgChild => {
                // Not used in debug mode (no privsep).
                Ok(())
            }
        }
    }

    /// Handle a timer action dispatched by the event loop.
    ///
    /// This is called from the event loop callback when timers expire.
    ///
    /// # Errors
    ///
    /// Returns a string describing the error on failure.
    pub fn handle_timer_action(&mut self, action: TimerAction) -> Result<(), String> {
        match action {
            TimerAction::SendQuery(idx) => {
                if idx < self.peers.len() {
                    self.send_single_query(idx)?;
                }
                Ok(())
            }
            TimerAction::PollDispatch => {
                // Recompute poll intervals and dispatch queries.
                self.dispatch_queries()
            }
            TimerAction::DriftFileWrite => {
                self.write_drift();
                Ok(())
            }
            TimerAction::ConstraintCheck => Ok(()),
        }
    }

    /// Send a single NTP query to a peer.
    ///
    /// # Errors
    ///
    /// Returns a string describing the error on failure.
    pub fn send_single_query(&mut self, peer_idx: usize) -> Result<(), String> {
        let now = instant_to_ntp(Instant::now(), self.start_time);

        if peer_idx >= self.peers.len() || peer_idx >= self.query_states.len() {
            return Err(format!("invalid peer index: {peer_idx}"));
        }

        let qs = &mut self.query_states[peer_idx];
        if qs.outstanding {
            return Ok(()); // Already waiting for a response.
        }

        let pkt = qs.send_query(now);
        let fd = match self.bound_fds.first().copied() {
            Some(fd) => fd,
            None => return Ok(()), // No socket bound — skip.
        };

        // Find the peer target address.
        let dest = self
            .ntp_io
            .peers
            .iter()
            .find(|t| {
                self.peers
                    .get(peer_idx)
                    .map(|p| p.id == t.id)
                    .unwrap_or(false)
            })
            .map(|t| t.address)
            .unwrap_or_else(|| {
                let addr_str = core::str::from_utf8(self.peers[peer_idx].address.as_bytes())
                    .unwrap_or("0.0.0.0");
                let ip = addr_str
                    .parse::<IpAddr>()
                    .unwrap_or(IpAddr::V4(Ipv4Addr::UNSPECIFIED));
                SocketAddr::new(ip, 123)
            });

        NtpIo::send_query(fd, dest, &pkt.encode())
            .map_err(|e| format!("send_query to peer {peer_idx}: {e}"))?;

        Ok(())
    }

    /// Send NTP queries to all peers.
    ///
    /// # Errors
    ///
    /// Returns a string describing the error on failure.
    pub fn dispatch_queries(&mut self) -> Result<(), String> {
        for idx in 0..self.peers.len() {
            self.send_single_query(idx)?;
        }
        Ok(())
    }

    /// Process a received NTP response.
    ///
    /// # Errors
    ///
    /// Returns a string describing the error on failure.
    pub fn handle_ntp_response(
        &mut self,
        buf: &[u8],
        peer_idx: usize,
        recv_time: NtpTimestamp,
    ) -> Result<(), String> {
        if peer_idx >= self.peers.len() || peer_idx >= self.query_states.len() {
            return Err(format!("invalid peer index: {peer_idx}"));
        }

        // Decode the NTP packet.
        let datagram =
            NtpDatagram::decode(buf).ok_or_else(|| "failed to decode NTP datagram".to_string())?;
        let pkt = match datagram {
            NtpDatagram::Unauthenticated(p) => p,
            NtpDatagram::Authenticated { packet, .. } => packet,
        };

        // Process through the query state machine.
        let result = self.query_states[peer_idx].receive_response(
            &mut self.peers[peer_idx],
            &pkt,
            recv_time,
        );

        match result {
            Ok((offset, delay)) => {
                // Update clock discipline.
                let adjustment = self.clock.update(offset, delay, recv_time);
                if adjustment.step {
                    // In a real daemon this would step the system clock.
                    if cfg!(debug_assertions) {
                        eprintln!(
                            "ntpd: step clock by {:.6}s (peer {})",
                            adjustment.offset, peer_idx
                        );
                    }
                }
                Ok(())
            }
            Err(e) => {
                // Log but don't fail — transient errors are normal.
                if cfg!(debug_assertions) {
                    eprintln!("ntpd: response error from peer {peer_idx}: {e}");
                }
                Ok(())
            }
        }
    }

    /// Write drift file periodically.
    pub fn write_drift(&mut self) {
        if let Some(ref mut df) = self.drift_file {
            let freq = self.clock.frequency;
            if let Err(e) = df.write_drift(freq) {
                eprintln!("ntpd: drift file write error: {e}");
            }
        }
    }

    /// Handle SIGHUP — config reload.
    ///
    /// # Errors
    ///
    /// Returns a string describing the error on failure.
    pub fn handle_reload(&mut self) -> Result<(), String> {
        // Placeholder: re-read config would go here.
        eprintln!("ntpd: SIGHUP received, reload not yet implemented");
        Ok(())
    }

    /// Handle SIGINT/SIGTERM — graceful shutdown.
    pub fn handle_shutdown(&mut self) {
        eprintln!("ntpd: shutting down");
        self.event_loop.stop();
    }
}

// ---------------------------------------------------------------------------
// Helper functions
// ---------------------------------------------------------------------------

/// Create a `NtpTimestamp` from an `Instant` (relative to daemon start).
#[must_use]
pub fn instant_to_ntp(instant: Instant, epoch: Instant) -> NtpTimestamp {
    let elapsed = instant.checked_duration_since(epoch).unwrap_or_default();
    let secs = elapsed.as_secs() as u32;
    let subsec_ns = elapsed.subsec_nanos();
    // Convert nanoseconds to NTP fractional part (2^-32 seconds per unit).
    let frac = ((subsec_ns as u64) << 32) / 1_000_000_000;
    NtpTimestamp {
        secs,
        frac: frac as u32,
    }
}

/// Convert `SocketAddr` to raw IP address bytes (16 bytes, IPv4-mapped).
#[must_use]
pub fn socket_addr_to_bytes(addr: &SocketAddr) -> [u8; 16] {
    match addr {
        SocketAddr::V4(v4) => {
            let octets = v4.ip().octets();
            // IPv4-mapped IPv6 address ::ffff:a.b.c.d
            let mut buf = [0u8; 16];
            buf[10] = 0xff;
            buf[11] = 0xff;
            buf[12..16].copy_from_slice(&octets);
            buf
        }
        SocketAddr::V6(v6) => v6.ip().octets(),
    }
}

/// Build bind addresses from `RuntimeConfig` listeners.
#[must_use]
pub fn build_bind_addresses(listeners: &[ListenConfig]) -> Vec<SocketAddr> {
    listeners.iter().map(|l| l.address).collect()
}

// ---------------------------------------------------------------------------
// Config checking
// ---------------------------------------------------------------------------

/// Result of checking an `ntpd.conf` configuration.
#[derive(Debug)]
pub struct CheckResult {
    pub is_valid: bool,
    pub errors: Vec<String>,
}

/// Read and parse an `ntpd.conf` file, returning a `CheckResult`.
pub fn check_config_file(path: impl AsRef<Path>) -> CheckResult {
    let path = path.as_ref();
    match std::fs::read(path) {
        Ok(b) => check_config_bytes(&b),
        Err(e) => CheckResult {
            is_valid: false,
            errors: vec![format!("cannot read '{}': {e}", path.display())],
        },
    }
}

/// Parse configuration bytes and return a `CheckResult`.
pub fn check_config_bytes(bytes: &[u8]) -> CheckResult {
    let result = openntpd_rs_core::config::parser::parse_config(bytes);
    if result.is_valid() {
        CheckResult {
            is_valid: true,
            errors: Vec::new(),
        }
    } else {
        CheckResult {
            is_valid: false,
            errors: result
                .diagnostics
                .iter()
                .filter(|d| d.severity == openntpd_rs_core::config::diagnostic::Severity::Error)
                .map(|d| {
                    let span = match d.span {
                        Some(s) => format!("{}:{}: ", s.start, s.end),
                        None => String::new(),
                    };
                    format!("{span}{}", d.message)
                })
                .collect(),
        }
    }
}

// ---------------------------------------------------------------------------
// CLI argument parsing — injectable and group-flag–aware
// ---------------------------------------------------------------------------

/// Parsed CLI arguments for the `ntpd` binary.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct CliArgs {
    pub config_path: Option<String>,
    pub debug_mode: bool,
    pub config_test: bool,
    pub verbose: u8,
    pub parent_proc: Option<String>,
    pub pid_file: Option<String>,
}

/// Structured CLI parse error.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CliError {
    /// An unknown flag was encountered.
    UnknownFlag(String),
    /// A flag that requires an argument was missing it.
    MissingArgument(String),
}

impl CliError {
    pub fn exit_code(&self) -> u8 {
        EXIT_ERROR
    }
}

/// Parse arguments from an iterator.  Supports grouped short flags
/// (e.g. `-dn`, `-dnv`, `-vv`).
pub fn parse_args_from<I, S>(args: I) -> Result<(CliArgs, Vec<String>), CliError>
where
    I: IntoIterator<Item = S>,
    S: Into<String>,
{
    let mut out = CliArgs::default();
    let mut extra: Vec<String> = Vec::new();
    let args: Vec<String> = args.into_iter().map(|s| s.into()).collect();
    let mut i = 1;

    while i < args.len() {
        let arg = &args[i];
        let mut chars = arg.chars();

        // Must start with '-'
        if !arg.starts_with('-') || arg.len() < 2 {
            return Err(CliError::UnknownFlag(arg.clone()));
        }

        chars.next(); // consume leading '-'
        let mut flag_chars: Vec<char> = chars.collect();

        // Grouped flags: iterate each character after '-'
        // For flags that consume a following argument, only the last
        // character in the group may be the flag.
        while let Some(c) = flag_chars.first().copied() {
            let is_last = flag_chars.len() == 1;
            match c {
                'd' => {
                    out.debug_mode = true;
                    flag_chars.remove(0);
                }
                'n' => {
                    out.config_test = true;
                    flag_chars.remove(0);
                }
                'v' => {
                    out.verbose = out.verbose.saturating_add(1);
                    flag_chars.remove(0);
                }
                'f' if is_last => {
                    i += 1;
                    out.config_path = Some(
                        args.get(i)
                            .ok_or_else(|| CliError::MissingArgument("-f".into()))?
                            .clone(),
                    );
                    flag_chars.remove(0); // consumed
                }
                'P' if is_last => {
                    i += 1;
                    out.parent_proc = Some(
                        args.get(i)
                            .ok_or_else(|| CliError::MissingArgument("-P".into()))?
                            .clone(),
                    );
                    flag_chars.remove(0);
                }
                'p' if is_last => {
                    i += 1;
                    out.pid_file = Some(
                        args.get(i)
                            .ok_or_else(|| CliError::MissingArgument("-p".into()))?
                            .clone(),
                    );
                    flag_chars.remove(0);
                }
                's' | 'S' if is_last => {
                    extra.push(arg.clone());
                    flag_chars.clear();
                }
                _ => {
                    return Err(CliError::UnknownFlag(format!("-{c}")));
                }
            }
        }

        i += 1;
    }

    Ok((out, extra))
}

/// Parse CLI arguments from [`std::env::args`].
pub fn parse_args() -> Result<(CliArgs, Vec<String>), CliError> {
    parse_args_from(std::env::args())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv6Addr;

    // -- Config checking --

    #[test]
    fn valid_config_returns_ok() {
        let result = check_config_bytes(b"listen on *\nserver pool.ntp.org\n");
        assert!(result.is_valid);
        assert!(result.errors.is_empty());
    }

    #[test]
    fn invalid_config_returns_errors() {
        let result = check_config_bytes(b"listen on *\nserver pool.ntp.org weight 100\n");
        assert!(!result.is_valid);
        assert!(!result.errors.is_empty());
    }

    #[test]
    fn empty_config_is_valid() {
        let result = check_config_bytes(b"");
        assert!(result.is_valid);
    }

    #[test]
    fn parser_error_reported() {
        let result = check_config_bytes(b"listen on *\n\0bad\n");
        assert!(!result.is_valid);
    }

    #[test]
    fn multiple_errors_collected() {
        let result = check_config_bytes(
            b"listen on *\nserver pool.ntp.org weight 0\nsensor nmea0 stratum 100\n",
        );
        assert!(result.errors.len() >= 2);
    }

    // -- CLI argument parsing --

    #[test]
    fn cli_defaults() {
        let (args, extra) = parse_args_from(["ntpd"]).unwrap();
        assert_eq!(
            args,
            CliArgs {
                config_path: None,
                debug_mode: false,
                config_test: false,
                verbose: 0,
                parent_proc: None,
                pid_file: None,
            }
        );
        assert!(extra.is_empty());
    }

    #[test]
    fn cli_dash_n() {
        let (args, _) = parse_args_from(["ntpd", "-n"]).unwrap();
        assert!(args.config_test);
    }

    #[test]
    fn cli_dash_f() {
        let (args, _) = parse_args_from(["ntpd", "-f", "/etc/ntpd.conf"]).unwrap();
        assert_eq!(args.config_path, Some("/etc/ntpd.conf".into()));
    }

    #[test]
    fn cli_grouped_dn() {
        let (args, _) = parse_args_from(["ntpd", "-dn"]).unwrap();
        assert!(args.debug_mode);
        assert!(args.config_test);
    }

    #[test]
    fn cli_grouped_dnv() {
        let (args, _) = parse_args_from(["ntpd", "-dnv"]).unwrap();
        assert!(args.debug_mode);
        assert!(args.config_test);
        assert_eq!(args.verbose, 1);
    }

    #[test]
    fn cli_repeated_v() {
        let (args, _) = parse_args_from(["ntpd", "-vv"]).unwrap();
        assert_eq!(args.verbose, 2);
    }

    #[test]
    fn cli_missing_f_argument() {
        let err = parse_args_from(["ntpd", "-f"]).unwrap_err();
        assert!(matches!(err, CliError::MissingArgument(_)));
    }

    #[test]
    fn cli_unknown_option() {
        let err = parse_args_from(["ntpd", "--xyz"]).unwrap_err();
        assert!(matches!(err, CliError::UnknownFlag(_)));
    }

    #[test]
    fn cli_positional_argument_rejected() {
        let err = parse_args_from(["ntpd", "positional"]).unwrap_err();
        assert!(matches!(err, CliError::UnknownFlag(_)));
    }

    // -- DaemonContext --

    #[test]
    fn daemon_context_creation_from_valid_config() {
        let ctx = DaemonContext::new(b"listen on *\nserver 127.0.0.1\n").unwrap();
        assert_eq!(ctx.peers.len(), 1);
        assert_eq!(ctx.query_states.len(), 1);
        assert_eq!(ctx.runtime_config.servers.len(), 1);
    }

    #[test]
    fn daemon_context_creation_from_invalid_config() {
        let err = DaemonContext::new(b"listen on *\nserver pool.ntp.org weight 100\n");
        assert!(err.is_err());
    }

    #[test]
    fn daemon_context_empty_config_has_no_peers() {
        let ctx = DaemonContext::new(b"listen on *\n").unwrap();
        assert!(ctx.peers.is_empty());
        assert!(ctx.query_states.is_empty());
    }

    #[test]
    fn daemon_context_multiple_servers() {
        let ctx = DaemonContext::new(b"listen on *\nserver 127.0.0.1\nserver 127.0.0.2 weight 5\n")
            .unwrap();
        assert_eq!(ctx.peers.len(), 2);
        assert_eq!(ctx.query_states.len(), 2);
        // Check weight is preserved.
        assert_eq!(ctx.peers[0].weight, 1); // default
        assert_eq!(ctx.peers[1].weight, 5);
    }

    #[test]
    fn daemon_context_empty_config_has_no_peers_via_parse() {
        // Empty config is valid per parser but has no servers.
        let ctx = DaemonContext::new(b"").unwrap();
        assert!(ctx.peers.is_empty());
        assert!(ctx.runtime_config.servers.is_empty());
    }

    #[test]
    fn daemon_context_trusted_peer() {
        let ctx = DaemonContext::new(b"listen on *\nserver 127.0.0.1 trusted\n").unwrap();
        assert_eq!(ctx.peers.len(), 1);
        assert!(ctx.peers[0].trusted);
    }

    // -- instant_to_ntp --

    #[test]
    fn instant_to_ntp_zero_elapsed() {
        let epoch = Instant::now();
        let ts = instant_to_ntp(epoch, epoch);
        assert_eq!(ts.secs, 0);
        assert_eq!(ts.frac, 0);
    }

    #[test]
    fn instant_to_ntp_one_second() {
        let epoch = Instant::now();
        let later = epoch + Duration::from_secs(1);
        let ts = instant_to_ntp(later, epoch);
        assert_eq!(ts.secs, 1);
    }

    #[test]
    fn instant_to_ntp_subsecond() {
        let epoch = Instant::now();
        let later = epoch + Duration::from_nanos(500_000_000); // 0.5s
        let ts = instant_to_ntp(later, epoch);
        assert_eq!(ts.secs, 0);
        // frac should be approximately 2^31 (half of 2^32).
        // Allow some tolerance for scheduling jitter.
        let diff = (ts.frac as i64 - 0x8000_0000u32 as i64).abs();
        assert!(
            diff < 0x0002_0000,
            "frac {} not near 0x80000000 (diff={})",
            ts.frac,
            diff
        );
    }

    #[test]
    fn instant_to_ntp_before_epoch_clamps() {
        let epoch = Instant::now();
        let earlier = epoch - Duration::from_secs(1);
        let ts = instant_to_ntp(earlier, epoch);
        assert_eq!(ts.secs, 0);
        assert_eq!(ts.frac, 0);
    }

    // -- socket_addr_to_bytes --

    #[test]
    fn socket_addr_to_bytes_ipv4() {
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)), 123);
        let bytes = socket_addr_to_bytes(&addr);
        // IPv4-mapped: ::ffff:192.168.1.1
        assert_eq!(bytes[10], 0xff);
        assert_eq!(bytes[11], 0xff);
        assert_eq!(bytes[12], 192);
        assert_eq!(bytes[13], 168);
        assert_eq!(bytes[14], 1);
        assert_eq!(bytes[15], 1);
        // Leading bytes should be zero.
        assert_eq!(bytes[0..10], [0u8; 10]);
    }

    #[test]
    fn socket_addr_to_bytes_ipv6() {
        let addr = SocketAddr::new(
            IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1)),
            123,
        );
        let bytes = socket_addr_to_bytes(&addr);
        assert_eq!(bytes[0], 0x20);
        assert_eq!(bytes[1], 0x01);
        assert_eq!(bytes[2], 0x0d);
        assert_eq!(bytes[3], 0xb8);
        assert_eq!(bytes[15], 0x01);
    }

    #[test]
    fn socket_addr_to_bytes_loopback() {
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 123);
        let bytes = socket_addr_to_bytes(&addr);
        assert_eq!(bytes[12], 127);
        assert_eq!(bytes[15], 1);
    }

    // -- build_bind_addresses --

    #[test]
    fn build_bind_addresses_empty() {
        let addrs = build_bind_addresses(&[]);
        assert!(addrs.is_empty());
    }

    #[test]
    fn build_bind_addresses_single() {
        let listeners = vec![ListenConfig {
            address: SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 123),
            rtable: 0,
        }];
        let addrs = build_bind_addresses(&listeners);
        assert_eq!(addrs.len(), 1);
        assert_eq!(addrs[0].port(), 123);
    }

    #[test]
    fn build_bind_addresses_multiple() {
        let listeners = vec![
            ListenConfig {
                address: SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 123),
                rtable: 0,
            },
            ListenConfig {
                address: SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 123),
                rtable: 0,
            },
        ];
        let addrs = build_bind_addresses(&listeners);
        assert_eq!(addrs.len(), 2);
    }

    // -- run_daemon --

    #[test]
    fn run_daemon_with_invalid_config_returns_config_error() {
        let config = DaemonConfig {
            config_path: PathBuf::from("/nonexistent/ntpd.conf"),
            debug_mode: false,
            verbose: 0,
            parent_proc: None,
            pid_file: None,
        };
        let result = run_daemon(&config);
        assert_eq!(result.exit_code, EXIT_CONFIG);
    }

    #[test]
    fn run_daemon_with_valid_config_but_no_servers_has_error() {
        // Write a temp valid config with no servers.
        let dir = std::env::temp_dir();
        let path = dir.join("ntpd_daemon_test_empty.conf");
        std::fs::write(&path, b"listen on *\n").unwrap();

        let config = DaemonConfig {
            config_path: path.clone(),
            debug_mode: false,
            verbose: 0,
            parent_proc: None,
            pid_file: None,
        };
        let result = run_daemon(&config);
        // Should error because no servers are configured.
        assert_eq!(result.exit_code, EXIT_ERROR);
        assert!(
            result.message.contains("no servers configured") || result.message.contains("error")
        );

        std::fs::remove_file(&path).unwrap_or(());
    }

    // -- dispatch_queries integration --

    #[test]
    fn dispatch_queries_no_peers_succeeds() {
        let mut ctx = DaemonContext::new(b"listen on *\n").unwrap();
        // No peers — dispatch is a no-op.
        assert!(ctx.dispatch_queries().is_ok());
    }

    // -- write_drift --

    #[test]
    fn write_drift_without_manager_does_not_panic() {
        let mut ctx = DaemonContext::new(b"listen on *\n").unwrap();
        ctx.drift_file = None;
        // Should not panic.
        ctx.write_drift();
    }

    // -- handle_shutdown --

    #[test]
    fn handle_shutdown_stops_event_loop() {
        let mut ctx = DaemonContext::new(b"listen on *\n").unwrap();
        ctx.event_loop.running = true;
        assert!(ctx.event_loop.running);
        ctx.handle_shutdown();
        assert!(!ctx.event_loop.running);
    }

    #[test]
    fn handle_reload_does_not_error() {
        let mut ctx = DaemonContext::new(b"listen on *\n").unwrap();
        assert!(ctx.handle_reload().is_ok());
    }

    // -- send_single_query --

    #[test]
    fn send_single_query_invalid_index_errors() {
        let mut ctx = DaemonContext::new(b"listen on *\nserver 127.0.0.1\n").unwrap();
        let result = ctx.send_single_query(99);
        assert!(result.is_err());
    }

    // -- handle_ntp_response --

    #[test]
    fn handle_ntp_response_invalid_index_errors() {
        let mut ctx = DaemonContext::new(b"listen on *\n").unwrap();
        let ts = NtpTimestamp::new(0, 0);
        let result = ctx.handle_ntp_response(b"", 99, ts);
        assert!(result.is_err());
    }

    #[test]
    fn handle_ntp_response_bad_packet_does_not_panic() {
        let mut ctx = DaemonContext::new(b"listen on *\nserver 127.0.0.1\n").unwrap();
        let ts = NtpTimestamp::new(0, 0);
        // Empty buffer will fail decode — should not panic.
        let result = ctx.handle_ntp_response(b"", 0, ts);
        assert!(result.is_err());
    }

    // -- handle_timer_action --

    #[test]
    fn handle_timer_action_send_query_bad_index() {
        let mut ctx = DaemonContext::new(b"listen on *\nserver 127.0.0.1\n").unwrap();
        // Index out of range should not panic.
        let result = ctx.handle_timer_action(TimerAction::SendQuery(99));
        assert!(result.is_ok());
    }

    #[test]
    fn handle_timer_action_poll_dispatch() {
        let mut ctx = DaemonContext::new(b"listen on *\nserver 127.0.0.1\n").unwrap();
        assert!(ctx.handle_timer_action(TimerAction::PollDispatch).is_ok());
    }

    #[test]
    fn handle_timer_action_drift_file_write() {
        let mut ctx = DaemonContext::new(b"listen on *\nserver 127.0.0.1\n").unwrap();
        assert!(ctx.handle_timer_action(TimerAction::DriftFileWrite).is_ok());
    }

    #[test]
    fn handle_timer_action_constraint_check() {
        let mut ctx = DaemonContext::new(b"listen on *\nserver 127.0.0.1\n").unwrap();
        assert!(ctx
            .handle_timer_action(TimerAction::ConstraintCheck)
            .is_ok());
    }

    // -- EventLoop integration via handle_event --

    #[test]
    fn handle_event_control_is_ok() {
        let mut ctx = DaemonContext::new(b"listen on *\n").unwrap();
        let result = ctx.handle_event(EventSource::Control, None);
        assert!(result.is_ok());
    }

    #[test]
    fn handle_event_imsg_is_ok() {
        let mut ctx = DaemonContext::new(b"listen on *\n").unwrap();
        assert!(ctx.handle_event(EventSource::ImsgParent, None).is_ok());
        assert!(ctx.handle_event(EventSource::ImsgChild, None).is_ok());
    }

    // -- socket_addr_to_bytes roundtrip --

    #[test]
    fn socket_addr_to_bytes_ipv4_roundtrip() {
        let original = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), 123);
        let bytes = socket_addr_to_bytes(&original);
        // Reconstruct from bytes: IPv4 mapped means bytes 12-15 are the IP.
        let reconstructed = Ipv4Addr::new(bytes[12], bytes[13], bytes[14], bytes[15]);
        assert_eq!(reconstructed, Ipv4Addr::new(10, 0, 0, 1));
    }

    #[test]
    fn socket_addr_to_bytes_ipv6_roundtrip() {
        let original = SocketAddr::new(IpAddr::V6(Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1)), 123);
        let bytes = socket_addr_to_bytes(&original);
        let reconstructed = Ipv6Addr::from(bytes);
        assert_eq!(reconstructed, Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1));
    }

    // -- instant_to_ntp precision --

    #[test]
    fn instant_to_ntp_half_second_precision() {
        let epoch = Instant::now();
        let half_sec = epoch + Duration::from_nanos(500_000_000);
        let ts = instant_to_ntp(half_sec, epoch);
        // frac for 0.5s = 2^31 = 2147483648
        let expected_frac = (0x8000_0000u64) as u32;
        let diff = (ts.frac as i64 - expected_frac as i64).abs();
        assert!(
            diff < 100_000,
            "frac {} not near expected {} (diff={})",
            ts.frac,
            expected_frac,
            diff
        );
    }

    // -- parse_args additional edge cases --

    #[test]
    fn cli_parent_proc() {
        let (args, _) = parse_args_from(["ntpd", "-P", "parent"]).unwrap();
        assert_eq!(args.parent_proc, Some("parent".into()));
    }

    #[test]
    fn cli_pid_file() {
        let (args, _) = parse_args_from(["ntpd", "-p", "/var/run/ntpd.pid"]).unwrap();
        assert_eq!(args.pid_file, Some("/var/run/ntpd.pid".into()));
    }
}
