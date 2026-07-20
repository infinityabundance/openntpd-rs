//! Daemon event loop — poll-based runtime engine for openntpd-rs.
//!
//! This module corresponds to OpenNTPD's `ntpd.c` main loop.  It
//! provides:
//!
//! - A poll(2)-based event loop
//! - Signal handling (SIGALRM, SIGHUP, SIGINT/SIGTERM) via signalfd
//! - NTP socket management (bind, send, recv)
//! - Timer management for poll intervals
//!
//! ## Structure
//!
//! | Component | Role |
//! |-----------|------|
//! | [`EventLoop`] | Poll loop, timer dispatch, shutdown coordination |
//! | [`NtpIo`] | UDP NTP socket lifecycle (mode 3/4 client I/O) |
//! | [`DriftFileManager`] | Atomic drift-file read/write |
//! | [`create_signal_fd`] | signalfd wrapper (Linux only) |

use std::net::SocketAddr;
use std::os::unix::io::{FromRawFd, IntoRawFd, RawFd};
use std::path::PathBuf;
use std::time::{Duration, Instant};

use crate::socket::{SocketError, SocketResult};

// ---------------------------------------------------------------------------
// Event source types
// ---------------------------------------------------------------------------

/// Event types for the poll loop.
///
/// Each variant identifies *which* fd fired.  The index in
/// [`EventSource::NtpSocket`] references a peer slot so the handler
/// can map the event back to a specific query target.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum EventSource {
    /// NTP query/response socket identified by peer index.
    NtpSocket(usize),
    /// imsg from parent process.
    ImsgParent,
    /// imsg from child process.
    ImsgChild,
    /// Signal fd (signalfd on Linux).
    Signal,
    /// Control socket (ntpctl queries).
    Control,
}

/// A pollable event source.
///
/// Stored in [`EventLoop::sources`] and converted to a `pollfd` array
/// on each iteration.
#[derive(Debug)]
pub struct PollSource {
    /// The raw file descriptor.
    pub fd: RawFd,
    /// The logical event kind.
    pub event: EventSource,
}

// ---------------------------------------------------------------------------
// Timer management
// ---------------------------------------------------------------------------

/// Timer event for scheduled actions.
///
/// Timers are stored in [`EventLoop::timers`], sorted by deadline
/// (nearest first).  On each poll iteration the loop pops expired
/// timers and dispatches their actions.
#[derive(Debug, Clone)]
pub struct TimerEvent {
    /// Absolute deadline for the next fire.
    pub deadline: Instant,
    /// Re-arm interval after firing.  Zero means one-shot.
    pub interval: Duration,
    /// The action to perform when this timer fires.
    pub action: TimerAction,
}

/// Kinds of timer-driven actions.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TimerAction {
    /// Send NTP query to the peer at the given index.
    SendQuery(usize),
    /// Dispatch poll-interval updates (recompute query intervals).
    PollDispatch,
    /// Periodic drift-file write.
    DriftFileWrite,
    /// Periodic constraint checking.
    ConstraintCheck,
}

// ---------------------------------------------------------------------------
// Event loop
// ---------------------------------------------------------------------------

/// Daemon event-loop state.
///
/// Manages poll sources and timers.  The typical usage pattern:
///
/// ```ignore
/// let mut el = EventLoop::new();
/// el.add_source(signal_fd, EventSource::Signal);
/// el.add_timer(delay, interval, TimerAction::PollDispatch);
/// el.run(|event, state| {
///     match event {
///         EventSource::Signal => { /* handle signal */ },
///         _ => { /* other events */ },
///     }
///     Ok(())
/// })?;
/// ```
pub struct EventLoop {
    /// Registered poll sources.
    pub sources: Vec<PollSource>,
    /// Registered timers (sorted by deadline, nearest first).
    pub timers: Vec<TimerEvent>,
    /// Whether the loop should keep running.
    pub running: bool,
}

impl EventLoop {
    /// Create a new, empty event loop.
    #[must_use]
    pub fn new() -> Self {
        Self {
            sources: Vec::new(),
            timers: Vec::new(),
            running: false,
        }
    }

    /// Add a poll source.
    pub fn add_source(&mut self, fd: RawFd, event: EventSource) {
        // Avoid duplicate registration (same fd + event).
        if self.sources.iter().any(|s| s.fd == fd && s.event == event) {
            return;
        }
        self.sources.push(PollSource { fd, event });
    }

    /// Remove a poll source by fd.  Returns `true` if found.
    pub fn remove_source(&mut self, fd: RawFd) -> bool {
        let len_before = self.sources.len();
        self.sources.retain(|s| s.fd != fd);
        self.sources.len() < len_before
    }

    /// Add a timer.
    ///
    /// `delay` is the initial offset from now; `interval` is the
    /// repeat interval.  Pass `Duration::ZERO` for a one-shot timer.
    pub fn add_timer(&mut self, delay: Duration, interval: Duration, action: TimerAction) {
        let deadline = Instant::now() + delay;
        let timer = TimerEvent {
            deadline,
            interval,
            action,
        };
        self.timers.push(timer);
        self.timers.sort_by_key(|t| t.deadline);
    }

    /// Remove all timers matching the given action.
    pub fn remove_timers(&mut self, action: TimerAction) {
        self.timers.retain(|t| t.action != action);
    }

    /// Run a single poll iteration.
    ///
    /// Constructs the `pollfd` array from [`Self::sources`], calls
    /// `poll(2)`, then returns the set of ready events and any
    /// expired timers.
    ///
    /// `timeout_ms` is the poll timeout in milliseconds.  Pass `-1`
    /// for infinite wait, `0` for non-blocking.
    pub fn poll_once(
        &mut self,
        timeout_ms: i32,
    ) -> Result<(Vec<EventSource>, Vec<TimerAction>), String> {
        // If there are no sources, we cannot poll indefinitely.
        // Treat -1 (infinite) as 0 in this case.
        let effective_timeout = if self.sources.is_empty() && timeout_ms < 0 {
            0
        } else {
            timeout_ms
        };

        // Build pollfd array.
        let mut poll_fds: Vec<libc::pollfd> = self
            .sources
            .iter()
            .map(|s| libc::pollfd {
                fd: s.fd,
                events: libc::POLLIN,
                revents: 0,
            })
            .collect();

        // SAFETY: poll() with a valid array and count.  When the array
        // is empty, passing NULL and 0 is well-defined (it just sleeps).
        let ret = unsafe {
            libc::poll(
                poll_fds.as_mut_ptr(),
                poll_fds.len() as libc::nfds_t,
                effective_timeout,
            )
        };

        if ret < 0 {
            let err = std::io::Error::last_os_error();
            // EINTR is not an error — caller should retry if needed.
            if err.kind() == std::io::ErrorKind::Interrupted {
                return Ok((Vec::new(), Vec::new()));
            }
            return Err(format!("poll(2) failed: {err}"));
        }

        // Collect ready events.
        let mut ready = Vec::new();
        for (i, pfd) in poll_fds.iter().enumerate() {
            if pfd.revents & libc::POLLIN != 0
                || pfd.revents & libc::POLLHUP != 0
                || pfd.revents & libc::POLLERR != 0
            {
                ready.push(self.sources[i].event);
            }
        }

        // Collect expired timers.
        let now = Instant::now();
        let mut expired = Vec::new();
        let mut keep = Vec::new();

        for mut timer in self.timers.drain(..) {
            if timer.deadline <= now {
                expired.push(timer.action);
                // Re-arm repeating timers.
                if timer.interval > Duration::ZERO {
                    timer.deadline = now + timer.interval;
                    keep.push(timer);
                }
            } else {
                keep.push(timer);
            }
        }

        // Re-sort kept timers (they may have new deadlines).
        keep.sort_by_key(|t| t.deadline);
        self.timers = keep;

        Ok((ready, expired))
    }

    /// Main event loop — runs until stopped.
    ///
    /// Each iteration calls [`Self::poll_once`] with a timeout
    /// derived from the nearest timer deadline (or `-1` if no timers
    /// are present).  The `callback` is invoked for every ready event
    /// and every expired timer action.
    pub fn run<F>(&mut self, mut callback: F) -> Result<(), String>
    where
        F: FnMut(EventSource, &mut Self) -> Result<(), String>,
    {
        self.running = true;

        while self.running {
            // If there are no sources and no timers, there is nothing to
            // wait for — stop immediately.
            if self.sources.is_empty() && self.timers.is_empty() {
                break;
            }

            // Compute timeout until the nearest timer.
            let timeout_ms = self.next_timeout_ms();

            let (ready, expired) = self.poll_once(timeout_ms)?;

            // Process ready events.
            for event in &ready {
                callback(*event, self)?;
            }

            // Process expired timers.  Map to synthetic EventSource values.
            for action in &expired {
                let synthetic = match action {
                    TimerAction::SendQuery(idx) => EventSource::NtpSocket(*idx),
                    TimerAction::PollDispatch
                    | TimerAction::DriftFileWrite
                    | TimerAction::ConstraintCheck => EventSource::Control,
                };
                callback(synthetic, self)?;
            }
        }

        Ok(())
    }

    /// Stop the event loop at the next iteration boundary.
    pub fn stop(&mut self) {
        self.running = false;
    }

    /// Compute the poll timeout (ms) from the nearest timer.
    ///
    /// Returns `-1` (infinite) if there are no timers, or a clamped
    /// non-negative value otherwise.
    fn next_timeout_ms(&self) -> i32 {
        let nearest = match self.timers.first() {
            Some(t) => t.deadline,
            None => return -1,
        };

        let now = Instant::now();
        if nearest <= now {
            return 0;
        }

        let dur = nearest - now;
        let ms = dur.as_millis();
        // Clamp to i32::MAX ms (about 24 days) — poll accepts i32.
        ms.min(i32::MAX as u128) as i32
    }
}

impl Default for EventLoop {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// NTP I/O
// ---------------------------------------------------------------------------

/// NTP query/reply I/O — send mode 3 queries, receive mode 4 responses.
///
/// Manages a set of bound UDP sockets and known peer targets.  Each
/// socket may be shared by multiple peers (common when binding to
/// `0.0.0.0`).
pub struct NtpIo {
    /// Bound NTP sockets: `(fd, local_address)`.
    pub sockets: Vec<(RawFd, SocketAddr)>,
    /// Peers to query.
    pub peers: Vec<PeerTarget>,
}

/// A remote NTP peer that the daemon queries.
#[derive(Debug, Clone)]
pub struct PeerTarget {
    /// Unique peer identifier (matches imsg peer_id).
    pub id: u64,
    /// Remote address (UDP).
    pub address: SocketAddr,
    /// Interval between queries.
    pub query_interval: Duration,
}

impl NtpIo {
    /// Create a new, empty NTP I/O manager.
    #[must_use]
    pub fn new() -> Self {
        Self {
            sockets: Vec::new(),
            peers: Vec::new(),
        }
    }

    /// Create and bind NTP sockets for the given addresses.
    ///
    /// Each address gets a dedicated UDP socket with `SO_REUSEPORT`
    /// and `SO_TIMESTAMP` enabled.  Returns the list of `(fd, addr)`
    /// pairs for use by the event loop.
    ///
    /// ## Errors
    ///
    /// Returns [`SocketError`] if socket creation or bind fails.
    pub fn bind_sockets(
        bind_addrs: &[SocketAddr],
    ) -> Result<Vec<(RawFd, SocketAddr)>, SocketError> {
        let mut result = Vec::with_capacity(bind_addrs.len());

        for addr in bind_addrs {
            let socket = crate::socket::bind_ntp_socket(*addr, true, true)?;
            // Query the kernel for the actual bound address (in case port
            // 0 was requested for an ephemeral port).
            let actual_addr = socket.local_addr().map_err(SocketError::Io)?;
            let fd = socket.into_raw_fd();
            result.push((fd, actual_addr));
        }

        Ok(result)
    }

    /// Send a mode 3 (client) NTP query to a peer.
    ///
    /// `fd` is one of the bound socket fds.  `dest` is the peer's UDP
    /// address.  `packet` is the raw 48-byte (or longer) NTP packet.
    ///
    /// ## Errors
    ///
    /// Returns [`SocketError`] if the send fails or the byte count
    /// does not match.
    pub fn send_query(fd: RawFd, dest: SocketAddr, packet: &[u8]) -> SocketResult<usize> {
        // SAFETY: fd is a valid UDP socket from bind_ntp_socket.
        let socket = unsafe { std::net::UdpSocket::from_raw_fd(fd) };
        let result = crate::socket::send_ntp_packet(&socket, packet, dest);
        // Don't close the fd — we are borrowing it.
        std::mem::forget(socket);
        result
    }

    /// Receive an NTP response.
    ///
    /// Reads a datagram from `fd` into `buf`.  Returns the number of
    /// bytes read and the sender address.
    ///
    /// ## Errors
    ///
    /// Returns [`SocketError`] if the recv fails.
    pub fn recv_response(fd: RawFd, buf: &mut [u8]) -> SocketResult<(usize, SocketAddr)> {
        // SAFETY: fd is a valid UDP socket from bind_ntp_socket.
        let socket = unsafe { std::net::UdpSocket::from_raw_fd(fd) };
        let result = crate::socket::recv_ntp_packet(&socket, buf);
        std::mem::forget(socket);
        result
    }
}

impl Default for NtpIo {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Signal handling (Linux signalfd)
// ---------------------------------------------------------------------------

/// Create a signalfd that catches signals relevant to the daemon.
///
/// The following signals are blocked (they will no longer be delivered
/// via the normal action mechanism) and can instead be read from the
/// returned fd:
///
/// - `SIGALRM` — timer expiry (legacy, kept for compat)
/// - `SIGHUP` — re-read configuration
/// - `SIGINT` — graceful shutdown (Ctrl+C)
/// - `SIGTERM` — graceful shutdown (systemd / kill)
///
/// ## Safety
///
/// This function blocks signals process-wide, which affects all
/// threads.  The caller must ensure this is called before spawning
/// any threads.
#[cfg(target_os = "linux")]
pub fn create_signal_fd() -> std::io::Result<RawFd> {
    // Block the signals we want to catch.
    let mut mask: libc::sigset_t = unsafe { std::mem::zeroed() };
    // SAFETY: sigemptyset is safe with a valid sigset_t pointer.
    unsafe {
        libc::sigemptyset(&mut mask);
    }
    // SAFETY: sigaddset is safe with a valid sigset_t pointer and valid signal numbers.
    unsafe {
        libc::sigaddset(&mut mask, libc::SIGALRM);
        libc::sigaddset(&mut mask, libc::SIGHUP);
        libc::sigaddset(&mut mask, libc::SIGINT);
        libc::sigaddset(&mut mask, libc::SIGTERM);
    }

    // Block these signals so they queue for signalfd.
    // SAFETY: sigprocmask with SIG_BLOCK and a valid mask.
    let ret = unsafe { libc::sigprocmask(libc::SIG_BLOCK, &mask, std::ptr::null_mut()) };
    if ret != 0 {
        return Err(std::io::Error::last_os_error());
    }

    // Create the signalfd.
    // SAFETY: signalfd with a valid mask and SFD_CLOEXEC.
    let fd = unsafe { libc::signalfd(-1, &mask, libc::SFD_CLOEXEC | libc::SFD_NONBLOCK) };
    if fd < 0 {
        return Err(std::io::Error::last_os_error());
    }

    Ok(fd)
}

/// Read a pending signal from a signalfd.
///
/// Returns the signal number, or `None` if no signal is pending
/// (fd is non-blocking and EAGAIN occurred).
#[cfg(target_os = "linux")]
pub fn read_signal(fd: RawFd) -> std::io::Result<Option<libc::c_int>> {
    let mut siginfo: libc::signalfd_siginfo = unsafe { std::mem::zeroed() };
    // SAFETY: read() into a signalfd_siginfo-sized buffer is safe.
    let nread = unsafe {
        libc::read(
            fd,
            &mut siginfo as *mut _ as *mut libc::c_void,
            std::mem::size_of::<libc::signalfd_siginfo>(),
        )
    };
    if nread < 0 {
        let err = std::io::Error::last_os_error();
        if err.kind() == std::io::ErrorKind::WouldBlock {
            return Ok(None);
        }
        return Err(err);
    }
    Ok(Some(siginfo.ssi_signo as libc::c_int))
}

// ---------------------------------------------------------------------------
// Drift file management
// ---------------------------------------------------------------------------

/// Drift-file periodic writer.
///
/// Manages the drift file that persists the clock frequency correction
/// between daemon restarts.  Writes are atomic (write to temp file,
/// rename) to avoid corruption on crash.
pub struct DriftFileManager {
    /// Path to the drift file.
    pub path: PathBuf,
    /// Last write timestamp (for metering write frequency).
    pub last_write: Instant,
    /// Minimum interval between writes.
    pub write_interval: Duration,
}

impl DriftFileManager {
    /// Create a new drift-file manager.
    ///
    /// `path` is the drift file location (e.g. `/var/db/ntpd.drift`).
    /// Initial `last_write` is set far in the past so the first
    /// write is never suppressed by the interval check.
    #[must_use]
    pub fn new(path: PathBuf) -> Self {
        Self {
            path,
            last_write: Instant::now()
                .checked_sub(Duration::from_secs(86400 * 365))
                .unwrap_or(Instant::now()),
            write_interval: Duration::from_secs(3600), // default: 1 hour
        }
    }

    /// Set a custom write interval.
    #[must_use]
    pub fn with_write_interval(mut self, interval: Duration) -> Self {
        self.write_interval = interval;
        self
    }

    /// Write the drift file atomically (tmp + rename).
    ///
    /// `frequency` is the clock frequency offset in ppm.
    /// The write is a no-op if [`Self::write_interval`] has not elapsed
    /// since the last write.
    pub fn write_drift(&mut self, frequency: f64) -> std::io::Result<()> {
        let now = Instant::now();
        if now < self.last_write + self.write_interval {
            return Ok(()); // Too soon — skip.
        }
        self.last_write = now;

        let contents = format!("{frequency:.6}\n");
        let tmp_path = self.path.with_extension("tmp");
        {
            let mut tmp = std::fs::File::create(&tmp_path)?;
            std::io::Write::write_all(&mut tmp, contents.as_bytes())?;
            tmp.sync_all()?;
        }
        std::fs::rename(&tmp_path, &self.path)?;
        Ok(())
    }

    /// Read the drift file at startup.
    ///
    /// Returns the frequency value in ppm, or an error if the file
    /// is missing or malformed.
    pub fn read_drift(&self) -> std::io::Result<f64> {
        let contents = std::fs::read_to_string(&self.path)?;
        let trimmed = contents.trim();
        trimmed
            .parse::<f64>()
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;
    use std::time::Duration;

    // -----------------------------------------------------------------------
    // EventLoop tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_event_loop_new_is_empty() {
        let el = EventLoop::new();
        assert!(el.sources.is_empty());
        assert!(el.timers.is_empty());
        assert!(!el.running);
    }

    #[test]
    fn test_event_loop_add_source() {
        let mut el = EventLoop::new();
        el.add_source(42, EventSource::Signal);
        assert_eq!(el.sources.len(), 1);
        assert_eq!(el.sources[0].fd, 42);
        assert_eq!(el.sources[0].event, EventSource::Signal);
    }

    #[test]
    fn test_event_loop_add_source_dedup() {
        let mut el = EventLoop::new();
        el.add_source(42, EventSource::Signal);
        el.add_source(42, EventSource::Signal); // duplicate
        assert_eq!(el.sources.len(), 1);
    }

    #[test]
    fn test_event_loop_remove_source() {
        let mut el = EventLoop::new();
        el.add_source(42, EventSource::Signal);
        el.add_source(7, EventSource::Control);
        assert!(el.remove_source(42));
        assert_eq!(el.sources.len(), 1);
        assert_eq!(el.sources[0].fd, 7);
        // Removing already-removed returns false.
        assert!(!el.remove_source(42));
    }

    #[test]
    fn test_event_loop_poll_timeout() {
        // Use a pipe so poll has something to wait on.
        let mut fds: [libc::c_int; 2] = [0; 2];
        // SAFETY: pipe() with valid array.
        let ret = unsafe { libc::pipe(fds.as_mut_ptr()) };
        assert_eq!(ret, 0, "pipe creation failed");

        let mut el = EventLoop::new();
        el.add_source(fds[0], EventSource::Control);

        // Poll with 0 timeout — should return immediately.
        let (ready, _expired) = el.poll_once(0).unwrap();
        assert!(ready.is_empty(), "no data written, should be empty");

        // Write to the pipe and poll again.
        let msg = b"x";
        // SAFETY: write to valid pipe fd.
        let written = unsafe { libc::write(fds[1], msg.as_ptr() as *const libc::c_void, 1) };
        assert_eq!(written, 1);

        let (ready, _expired) = el.poll_once(0).unwrap();
        assert_eq!(ready.len(), 1);
        assert_eq!(ready[0], EventSource::Control);

        // Cleanup.
        // SAFETY: close valid fds.
        unsafe {
            libc::close(fds[0]);
            libc::close(fds[1]);
        }
    }

    #[test]
    fn test_event_loop_stop() {
        let mut el = EventLoop::new();
        el.running = true;
        el.stop();
        assert!(!el.running);
    }

    #[test]
    fn test_event_loop_run_stops_immediately() {
        let mut el = EventLoop::new();
        let mut calls = 0;
        let result = el.run(|_event, _state| {
            calls += 1;
            Ok(())
        });
        assert!(result.is_ok());
        // No sources or timers means no events.
        assert_eq!(calls, 0);
    }

    #[test]
    fn test_event_loop_run_with_timer() {
        // Create a pipe so poll has a valid fd.
        let mut fds: [libc::c_int; 2] = [0; 2];
        // SAFETY: pipe() with valid array.
        let ret = unsafe { libc::pipe(fds.as_mut_ptr()) };
        assert_eq!(ret, 0, "pipe creation failed");

        let mut el = EventLoop::new();
        el.add_source(fds[0], EventSource::Control);

        // Add a timer that fires immediately.
        el.add_timer(Duration::ZERO, Duration::ZERO, TimerAction::DriftFileWrite);

        let mut timer_fired = false;
        let result = el.run(|event, state| {
            match event {
                EventSource::Control => {
                    // Timer fired (mapped from DriftFileWrite).
                    timer_fired = true;
                    state.stop();
                }
                _ => {}
            }
            Ok(())
        });
        assert!(result.is_ok(), "event loop run failed: {result:?}");
        assert!(timer_fired, "timer should have fired");

        // SAFETY: close valid fds.
        unsafe {
            libc::close(fds[0]);
            libc::close(fds[1]);
        }
    }

    // -----------------------------------------------------------------------
    // Timer management tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_add_timer() {
        let mut el = EventLoop::new();
        assert!(el.timers.is_empty());

        el.add_timer(
            Duration::from_secs(10),
            Duration::ZERO,
            TimerAction::DriftFileWrite,
        );
        assert_eq!(el.timers.len(), 1);
        assert_eq!(el.timers[0].action, TimerAction::DriftFileWrite);
        assert_eq!(el.timers[0].interval, Duration::ZERO); // one-shot
    }

    #[test]
    fn test_remove_timers() {
        let mut el = EventLoop::new();
        el.add_timer(
            Duration::from_secs(1),
            Duration::ZERO,
            TimerAction::DriftFileWrite,
        );
        el.add_timer(
            Duration::from_secs(2),
            Duration::ZERO,
            TimerAction::SendQuery(0),
        );
        el.add_timer(
            Duration::from_secs(3),
            Duration::ZERO,
            TimerAction::PollDispatch,
        );

        assert_eq!(el.timers.len(), 3);
        el.remove_timers(TimerAction::DriftFileWrite);
        assert_eq!(el.timers.len(), 2);
        assert!(el
            .timers
            .iter()
            .all(|t| t.action != TimerAction::DriftFileWrite));
    }

    #[test]
    fn test_timer_ordering_nearest_deadline_first() {
        let mut el = EventLoop::new();
        // Add timers out of order.
        el.add_timer(
            Duration::from_secs(5),
            Duration::ZERO,
            TimerAction::SendQuery(5),
        );
        el.add_timer(
            Duration::from_secs(1),
            Duration::ZERO,
            TimerAction::SendQuery(1),
        );
        el.add_timer(
            Duration::from_secs(3),
            Duration::ZERO,
            TimerAction::SendQuery(3),
        );

        assert_eq!(el.timers.len(), 3);
        // First timer should be the 1-second one.
        assert_eq!(el.timers[0].action, TimerAction::SendQuery(1));
        assert_eq!(el.timers[1].action, TimerAction::SendQuery(3));
        assert_eq!(el.timers[2].action, TimerAction::SendQuery(5));
    }

    #[test]
    fn test_timer_fire_and_remove() {
        let mut el = EventLoop::new();
        el.add_timer(Duration::ZERO, Duration::ZERO, TimerAction::DriftFileWrite);

        let (ready, expired) = el.poll_once(0).unwrap();
        assert!(ready.is_empty());
        assert_eq!(expired.len(), 1);
        assert_eq!(expired[0], TimerAction::DriftFileWrite);

        // Timer should be gone (one-shot).
        assert!(el.timers.is_empty());
    }

    #[test]
    fn test_timer_repeating() {
        let mut el = EventLoop::new();
        el.add_timer(
            Duration::ZERO,
            Duration::from_secs(60),
            TimerAction::PollDispatch,
        );

        // First fire.
        let (_ready, expired) = el.poll_once(0).unwrap();
        assert_eq!(expired.len(), 1);
        assert_eq!(expired[0], TimerAction::PollDispatch);

        // Timer should be re-armed.
        assert_eq!(el.timers.len(), 1);
        assert_eq!(el.timers[0].action, TimerAction::PollDispatch);
        assert_eq!(el.timers[0].interval, Duration::from_secs(60));
    }

    #[test]
    fn test_next_timeout_no_timers() {
        let el = EventLoop::new();
        assert_eq!(el.next_timeout_ms(), -1);
    }

    #[test]
    fn test_next_timeout_with_timer() {
        let mut el = EventLoop::new();
        el.add_timer(
            Duration::from_secs(10),
            Duration::ZERO,
            TimerAction::PollDispatch,
        );
        let timeout = el.next_timeout_ms();
        assert!(timeout > 0, "expected positive timeout, got {timeout}");
        assert!(timeout <= 10_000, "timeout should be <= 10s in ms");
    }

    // -----------------------------------------------------------------------
    // NtpIo tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_ntp_io_new() {
        let io = NtpIo::new();
        assert!(io.sockets.is_empty());
        assert!(io.peers.is_empty());
    }

    #[test]
    fn test_ntp_io_bind_sockets_ephemeral() {
        // Bind to loopback with port 0 to get an ephemeral port.
        let addrs = ["127.0.0.1:0".parse::<SocketAddr>().unwrap()];
        let sockets = NtpIo::bind_sockets(&addrs);
        assert!(sockets.is_ok(), "bind_sockets failed: {:?}", sockets.err());
        let sockets = sockets.unwrap();
        assert_eq!(sockets.len(), 1);

        let (fd, addr) = &sockets[0];
        assert!(*fd >= 0, "invalid fd");
        assert_ne!(addr.port(), 0, "should have an ephemeral port");

        // Cleanup.
        // SAFETY: fd is a valid socket.
        unsafe {
            libc::close(*fd);
        }
    }

    #[test]
    fn test_ntp_io_bind_sockets_ipv6_ephemeral() {
        let addrs = ["[::1]:0".parse::<SocketAddr>().unwrap()];
        let sockets = NtpIo::bind_sockets(&addrs);
        assert!(
            sockets.is_ok(),
            "bind_sockets (IPv6) failed: {:?}",
            sockets.err()
        );
        let sockets = sockets.unwrap();
        assert_eq!(sockets.len(), 1);

        let (fd, addr) = &sockets[0];
        assert!(*fd >= 0, "invalid fd");
        assert_ne!(addr.port(), 0, "should have an ephemeral port");

        // Cleanup.
        // SAFETY: fd is a valid socket.
        unsafe {
            libc::close(*fd);
        }
    }

    #[test]
    fn test_ntp_io_bind_multiple_sockets() {
        let addrs = [
            "127.0.0.1:0".parse::<SocketAddr>().unwrap(),
            "127.0.0.1:0".parse::<SocketAddr>().unwrap(),
        ];
        let sockets = NtpIo::bind_sockets(&addrs).unwrap();
        assert_eq!(sockets.len(), 2);
        assert_ne!(
            sockets[0].1.port(),
            sockets[1].1.port(),
            "two ephemeral binds should get different ports"
        );

        // Cleanup.
        for (fd, _) in &sockets {
            // SAFETY: fd is a valid socket.
            unsafe {
                libc::close(*fd);
            }
        }
    }

    #[test]
    fn test_ntp_io_send_recv_loopback() {
        use std::net::UdpSocket;

        // Create a bound "server" socket to receive the query.
        let server = UdpSocket::bind("127.0.0.1:0").unwrap();
        let server_addr = server.local_addr().unwrap();

        // Create a "client" socket to send the query.
        let client = UdpSocket::bind("127.0.0.1:0").unwrap();
        let client_addr = client.local_addr().unwrap();
        let client_fd = client.into_raw_fd();

        // Build a minimal NTP mode 3 query packet (48 bytes).
        // li=0, vn=4, mode=3 => 0x23
        let mut query = [0u8; 48];
        query[0] = 0x23; // LI=0, VN=4, Mode=3

        let send_result = NtpIo::send_query(client_fd, server_addr, &query);
        assert!(
            send_result.is_ok(),
            "send_query failed: {:?}",
            send_result.err()
        );
        assert_eq!(send_result.unwrap(), 48);

        // Receive on the server side.
        let mut buf = [0u8; 48];
        let (nread, from) = server.recv_from(&mut buf).unwrap();
        assert_eq!(nread, 48);
        assert_eq!(buf[0], 0x23); // Mode 3 query
        assert_eq!(from, client_addr);

        // Send a mode 4 response back.
        let mut response = [0u8; 48];
        response[0] = 0x24; // LI=0, VN=4, Mode=4
        server.send_to(&response, from).unwrap();

        // Receive on the client side.
        let recv_result = NtpIo::recv_response(client_fd, &mut buf);
        assert!(
            recv_result.is_ok(),
            "recv_response failed: {:?}",
            recv_result.err()
        );
        let (nread, sender) = recv_result.unwrap();
        assert_eq!(nread, 48);
        assert_eq!(buf[0], 0x24);
        assert_eq!(sender, server_addr);

        // Cleanup.
        // SAFETY: client_fd is a valid socket (into_raw_fd consumed the UdpSocket).
        unsafe {
            libc::close(client_fd);
        }
    }

    // -----------------------------------------------------------------------
    // DriftFileManager tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_drift_file_write_read_cycle() {
        let dir = std::env::temp_dir().join(format!("openntpd_drift_test_{}", std::process::id()));
        let _ = std::fs::create_dir_all(&dir);
        let path = dir.join("ntpd.drift");

        let mut manager = DriftFileManager::new(path.clone());
        // Override interval so the write is not suppressed.
        manager.write_interval = Duration::ZERO;
        manager.last_write = Instant::now()
            .checked_sub(Duration::from_secs(3600))
            .unwrap();

        let freq = -10.5;
        manager.write_drift(freq).unwrap();

        let readback = manager.read_drift().unwrap();
        assert!(
            (readback - freq).abs() < 1e-9,
            "expected {freq}, got {readback}"
        );

        // Cleanup.
        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_dir(&dir);
    }

    #[test]
    fn test_drift_file_missing() {
        let dir =
            std::env::temp_dir().join(format!("openntpd_drift_missing_{}", std::process::id()));
        let _ = std::fs::create_dir_all(&dir);
        let path = dir.join("nonexistent.drift");

        let manager = DriftFileManager::new(path);
        let result = manager.read_drift();
        assert!(result.is_err(), "expected error for missing file");

        let _ = std::fs::remove_dir(&dir);
    }

    #[test]
    fn test_drift_file_write_interval_suppression() {
        let dir =
            std::env::temp_dir().join(format!("openntpd_drift_suppress_{}", std::process::id()));
        let _ = std::fs::create_dir_all(&dir);
        let path = dir.join("suppress.drift");

        let mut manager = DriftFileManager::new(path.clone());
        // Set a long interval so the immediate write is suppressed.
        manager.write_interval = Duration::from_secs(3600);
        manager.last_write = Instant::now(); // Just wrote

        // This should be a no-op (interval not elapsed).
        manager.write_drift(42.0).unwrap();

        // The file should not exist (write was suppressed).
        assert!(!path.exists(), "file should not have been written");

        let _ = std::fs::remove_dir(&dir);
    }

    #[test]
    fn test_drift_file_write_atomicity() {
        let dir =
            std::env::temp_dir().join(format!("openntpd_drift_atomic_{}", std::process::id()));
        let _ = std::fs::create_dir_all(&dir);
        let path = dir.join("atomic.drift");

        // Write a known value.
        let mut manager = DriftFileManager::new(path.clone());
        manager.write_interval = Duration::ZERO;
        manager.last_write = Instant::now()
            .checked_sub(Duration::from_secs(3600))
            .unwrap();

        manager.write_drift(1.234).unwrap();
        assert_eq!(manager.read_drift().unwrap(), 1.234);

        // Overwrite with a new value.
        manager.write_drift(5.678).unwrap();
        assert_eq!(manager.read_drift().unwrap(), 5.678);

        // Read the raw file content — it should be plain text.
        let contents = std::fs::read_to_string(&path).unwrap();
        assert!(
            contents.contains("5.678"),
            "expected 5.678 in file, got {contents:?}"
        );

        // Cleanup.
        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_dir(&dir);
    }

    #[test]
    fn test_drift_file_manager_default_interval() {
        let manager = DriftFileManager::new(PathBuf::from("/tmp/test.drift"));
        assert_eq!(manager.write_interval, Duration::from_secs(3600));
        assert_eq!(manager.path, Path::new("/tmp/test.drift"));
    }

    // -----------------------------------------------------------------------
    // Timer action identity
    // -----------------------------------------------------------------------

    #[test]
    fn test_timer_action_send_query_identity() {
        let a = TimerAction::SendQuery(0);
        let b = TimerAction::SendQuery(0);
        let c = TimerAction::SendQuery(1);
        assert_eq!(a, b);
        assert_ne!(a, c);
    }

    #[test]
    fn test_timer_action_variants_distinct() {
        let variants = [
            TimerAction::SendQuery(0),
            TimerAction::PollDispatch,
            TimerAction::DriftFileWrite,
            TimerAction::ConstraintCheck,
        ];
        for (i, a) in variants.iter().enumerate() {
            for (j, b) in variants.iter().enumerate() {
                if i == j {
                    assert_eq!(a, b);
                } else {
                    assert_ne!(a, b);
                }
            }
        }
    }

    #[test]
    fn test_event_source_variants_distinct() {
        let variants = [
            EventSource::NtpSocket(0),
            EventSource::ImsgParent,
            EventSource::ImsgChild,
            EventSource::Signal,
            EventSource::Control,
        ];
        for (i, a) in variants.iter().enumerate() {
            for (j, b) in variants.iter().enumerate() {
                if i == j {
                    assert_eq!(a, b);
                } else {
                    assert_ne!(a, b);
                }
            }
        }
    }

    #[test]
    fn test_event_loop_default() {
        let el: EventLoop = Default::default();
        assert!(el.sources.is_empty());
        assert!(el.timers.is_empty());
        assert!(!el.running);
    }

    // -----------------------------------------------------------------------
    // Multiple timer expiry in single poll
    // -----------------------------------------------------------------------

    #[test]
    fn test_multiple_timers_expire_simultaneously() {
        let mut el = EventLoop::new();
        // Add three timers that all fire immediately.
        el.add_timer(Duration::ZERO, Duration::ZERO, TimerAction::SendQuery(0));
        el.add_timer(Duration::ZERO, Duration::ZERO, TimerAction::SendQuery(1));
        el.add_timer(Duration::ZERO, Duration::ZERO, TimerAction::DriftFileWrite);

        let (_ready, expired) = el.poll_once(0).unwrap();
        assert_eq!(expired.len(), 3);
        assert!(expired.contains(&TimerAction::SendQuery(0)));
        assert!(expired.contains(&TimerAction::SendQuery(1)));
        assert!(expired.contains(&TimerAction::DriftFileWrite));

        // All timers consumed (one-shot).
        assert!(el.timers.is_empty());
    }

    // -----------------------------------------------------------------------
    // PeerTarget test
    // -----------------------------------------------------------------------

    #[test]
    fn test_peer_target_creation() {
        let peer = PeerTarget {
            id: 42,
            address: "192.0.2.1:123".parse::<SocketAddr>().unwrap(),
            query_interval: Duration::from_secs(64),
        };
        assert_eq!(peer.id, 42);
        assert_eq!(peer.address.port(), 123);
        assert_eq!(peer.query_interval, Duration::from_secs(64));
    }
}
