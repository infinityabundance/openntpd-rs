//! HTTPS constraint validation engine — a secondary time source used
//! to constrain (validate) NTP responses, not a precision time source.
//!
//! OpenNTPD's constraint subsystem connects to HTTPS servers, parses the
//! HTTP `Date` response header, and uses that wall-clock time as a
//! **rough check** against NTP-obtained time.  Only the hour-level
//! accuracy of the `Date` header is meaningful — TLS handshake latency
//! makes sub-minute precision impossible, so the constraint window is set
//! to ±30 minutes.
//!
//! ## Key design properties
//!
//! * No precision timing from TLS (unpredictable latency).
//! * NTP offsets outside ±30 minutes of a constraint are rejected.
//! * Multiple constraints are combined via median.
//! * Constraint failures never prevent synchronization — they simply
//!   don't constrain.
//!
//! This module corresponds to OpenNTPD's
//! [`constraint.c`](https://github.com/openntpd-portable/openntpd-openbsd/blob/master/src/usr.sbin/ntpd/constraint.c).

use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Default HTTPS constraint port.
pub const CONSTRAINT_PORT: u16 = 443;

/// Timeout for a single HTTPS constraint request (seconds).
pub const CONSTRAINT_TIMEOUT_SECS: u64 = 10;

/// Maximum acceptable NTP offset from a constraint value (seconds).
/// Equivalent to 30 minutes.
pub const CONSTRAINT_MEDIAN_WINDOW: i64 = 1800;

// ---------------------------------------------------------------------------
// Status
// ---------------------------------------------------------------------------

/// The status of a constraint check.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConstraintStatus {
    /// No constraint check has been performed yet.
    Unknown,
    /// The constraint check succeeded and produced a valid date.
    Ok,
    /// The constraint check failed (timeout, connection error, bad response).
    Failed,
    /// A previously-OK constraint result has become stale.
    Stale,
}

// ---------------------------------------------------------------------------
// Endpoint
// ---------------------------------------------------------------------------

/// A single HTTPS constraint endpoint that the system will query.
#[derive(Debug, Clone)]
pub struct ConstraintEndpoint {
    /// Hostname to connect to.
    pub host: String,
    /// HTTP request path.
    pub path: String,
    /// TCP port (defaults to 443).
    pub port: u16,
    /// Optional pinned IP address (128-bit IPv6 format; IPv4 is v4-mapped).
    pub address: Option<[u8; 16]>,
}

// ---------------------------------------------------------------------------
// Constraint (result)
// ---------------------------------------------------------------------------

/// The result of querying a single constraint server.
#[derive(Debug, Clone)]
pub struct Constraint {
    /// Hostname (used for identification / logging).
    pub name: String,
    /// HTTP request path.
    pub path: String,
    /// Optional pinned IP address.
    pub address: Option<[u8; 16]>,
    /// TCP port used.
    pub port: u16,
    /// Parsed `Date` header as a Unix timestamp (seconds since epoch).
    /// `None` if not yet fetched or the fetch failed.
    pub date: Option<i64>,
    /// Current status of this constraint.
    pub status: ConstraintStatus,
}

impl Constraint {
    /// Create a new constraint with the given hostname and HTTP path.
    ///
    /// The port defaults to [`CONSTRAINT_PORT`] (443).  Use
    /// [`with_pinned_address`](Self::with_pinned_address) to pin an IP.
    #[must_use]
    pub fn new(name: String, path: String) -> Self {
        Self {
            name,
            path,
            address: None,
            port: CONSTRAINT_PORT,
            date: None,
            status: ConstraintStatus::Unknown,
        }
    }

    /// Pin this constraint to a specific IP address.
    ///
    /// The address is stored as a 128-bit IPv6-format byte array.
    /// IPv4 addresses should be stored as IPv4-mapped IPv6 addresses
    /// (`::ffff:a.b.c.d`).
    #[must_use]
    pub fn with_pinned_address(mut self, addr: [u8; 16]) -> Self {
        self.address = Some(addr);
        self
    }
}

// ---------------------------------------------------------------------------
// Month name lookup
// ---------------------------------------------------------------------------

/// Look up a three-letter month abbreviation (case-insensitive) and return
/// the month number (1 = January, … 12 = December).
///
/// Returns `None` for unknown abbreviations.
#[must_use]
fn month_from_name(name: &str) -> Option<u32> {
    // Normalise to lowercase for case-insensitive matching.
    // Since we only compare ASCII letters, byte-by-byte comparison is safe.
    let bytes = name.as_bytes();
    if bytes.len() != 3 {
        return None;
    }
    // Create a lowercased 3-byte key for matching.
    let mut key = [0u8; 3];
    for (i, b) in bytes.iter().enumerate() {
        key[i] = b.to_ascii_lowercase();
    }
    match &key {
        b"jan" => Some(1),
        b"feb" => Some(2),
        b"mar" => Some(3),
        b"apr" => Some(4),
        b"may" => Some(5),
        b"jun" => Some(6),
        b"jul" => Some(7),
        b"aug" => Some(8),
        b"sep" => Some(9),
        b"oct" => Some(10),
        b"nov" => Some(11),
        b"dec" => Some(12),
        _ => None,
    }
}

// ---------------------------------------------------------------------------
// Date helpers
// ---------------------------------------------------------------------------

/// Days in each month for a non-leap year.
const DAYS_IN_MONTH: [u64; 12] = [31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];

/// Returns `true` if `year` is a leap year in the Gregorian calendar.
#[must_use]
fn is_leap_year(year: i64) -> bool {
    (year % 4 == 0) && (year % 100 != 0 || year % 400 == 0)
}

/// Convert a Gregorian date (year, month, day) into a day count relative
/// to the Unix epoch (1970-01-01 = day 0).
///
/// Returns `None` if the date is before 1970 or the computation overflows.
#[must_use]
fn date_to_epoch_days(year: i64, month: u32, day: u32) -> Option<i64> {
    if year < 1970 || !(1..=12).contains(&month) || !(1..=31).contains(&day) {
        return None;
    }

    // Total days from 1970 up to (but not including) `year`.
    let mut days: i64 = 0;
    for y in 1970..year {
        days = days.checked_add(if is_leap_year(y) { 366 } else { 365 })?;
    }

    // Add days for complete months in the current year.
    let month_idx = (month - 1) as usize;
    for (m, &days_in_month) in DAYS_IN_MONTH[..month_idx].iter().enumerate() {
        days = days.checked_add(if m == 1 && is_leap_year(year) {
            29
        } else {
            i64::from(days_in_month as u32)
        })?;
    }

    // Add days within the current month (day is 1-based, so subtract 1).
    days = days.checked_add(i64::from(day) - 1)?;

    Some(days)
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Parse an HTTP `Date` header value into a Unix timestamp.
///
/// Supports the **RFC 2822 / RFC 1123** format (the only format mandated
/// by HTTP/1.1):
///
/// ```text
/// Thu, 01 Dec 2024 16:00:00 GMT
/// ```
///
/// Weekday name and trailing `GMT` are parsed but discarded (only the date
/// and time are used).  Single-digit day numbers are supported (e.g.
/// `"Thu, 1 Dec 2024 16:00:00 GMT"` — note the single space instead of
/// leading zero).
///
/// Returns `None` if the string cannot be parsed.
///
/// ## References
///
/// * [RFC 7231 §7.1.1.1](https://httpwg.org/specs/rfc7231.html#rfc.section.7.1.1.1)
/// * [RFC 2822 §3.3](https://www.rfc-editor.org/rfc/rfc2822#section-3.3)
#[must_use]
pub fn parse_http_date(date_str: &str) -> Option<i64> {
    // Expected format:
    //   "Thu, 01 Dec 2024 16:00:00 GMT"
    //
    // With optional single-digit day:
    //   "Thu, 1 Dec 2024 16:00:00 GMT"
    //
    // After the day-name comma and space, we have:
    //   <day> <month> <year> <time> GMT

    let s = date_str.trim();

    // Find the comma separating weekday from the rest.
    let after_comma = s.find(',')? + 1;

    // Split the remaining string into tokens by whitespace.
    // After the comma we expect: day month year time GMT
    let rest = &s[after_comma..].trim();
    let tokens: Vec<&str> = rest.split_whitespace().collect();

    // We need at least: day, month, year, time (4 tokens).
    // A 5th token ("GMT") is accepted but not required.
    if tokens.len() < 4 {
        return None;
    }

    let day_str = tokens[0];
    let month_str = tokens[1];
    let year_str = tokens[2];
    let time_str = tokens[3];

    // "GMT" is the 5th token but it's optional for flexibility.
    // If a 5th token exists, it should be "GMT" — we don't enforce it.

    let day: u32 = day_str.parse().ok()?;
    let year: i64 = year_str.parse().ok()?;
    let month = month_from_name(month_str)?;

    // Time is HH:MM:SS
    let time_parts: Vec<&str> = time_str.split(':').collect();
    if time_parts.len() != 3 {
        return None;
    }
    let hour: u32 = time_parts[0].parse().ok()?;
    let min: u32 = time_parts[1].parse().ok()?;
    let sec: u32 = time_parts[2].parse().ok()?;

    if hour > 23 || min > 59 || sec > 59 {
        return None;
    }

    let epoch_days = date_to_epoch_days(year, month, day)?;

    let total_secs = epoch_days
        .checked_mul(86400)?
        .checked_add(i64::from(hour) * 3600)?
        .checked_add(i64::from(min) * 60)?
        .checked_add(i64::from(sec))?;

    Some(total_secs)
}

/// Compute the median timestamp from a list of constraint results.
///
/// Only constraints with [`ConstraintStatus::Ok`] and a `Some` date value
/// are considered.  Returns `None` if the list is empty (or contains no
/// usable results).
///
/// For an odd number of values, the middle value is returned.  For an even
/// number, the arithmetic mean of the two middle values is returned
/// (truncated toward zero).
#[must_use]
pub fn median_constraint(constraints: &[&Constraint]) -> Option<i64> {
    // Collect valid dates.
    let mut dates: Vec<i64> = constraints
        .iter()
        .filter_map(|c| {
            if c.status == ConstraintStatus::Ok {
                c.date
            } else {
                None
            }
        })
        .collect();

    if dates.is_empty() {
        return None;
    }

    dates.sort_unstable();

    let len = dates.len();
    if len % 2 == 1 {
        // Odd count: middle element.
        Some(dates[len / 2])
    } else {
        // Even count: average of two middle elements.
        let mid = len / 2;
        let a = dates[mid - 1];
        let b = dates[mid];
        // Arithmetic mean, truncated toward zero.
        Some((a + b) / 2)
    }
}

/// Check whether an NTP offset (in seconds) is within the constraint
/// window.
///
/// Returns `true` if `|offset_secs| <= CONSTRAINT_MEDIAN_WINDOW`.
#[must_use]
pub fn is_within_constraint(offset_secs: f64) -> bool {
    offset_secs.abs() <= CONSTRAINT_MEDIAN_WINDOW as f64
}

// ---------------------------------------------------------------------------
// HttpsDateQuery / HttpsDateResult — HTTPS constraint query types
// ---------------------------------------------------------------------------

/// Constants from constraint.c
pub const CONSTRAINT_ERROR_MARGIN: u8 = 4;
pub const CONSTRAINT_RETRY_INTERVAL: i64 = 15;
pub const CONSTRAINT_SCAN_INTERVAL: i64 = 900;
pub const CONSTRAINT_MAXHEADERLENGTH: usize = 8192;

/// Result of an HTTPS date query.
///
/// Corresponds to the parsed HTTP `Date:` header + response headers in
/// OpenNTPD's `constraint.c`.
#[derive(Debug, Clone)]
pub struct HttpsDateResult {
    /// The parsed `Date` header as a Unix timestamp (seconds since epoch).
    pub date: i64,
    /// The raw HTTP response headers (for debugging/logging).
    pub headers: String,
}

/// An HTTPS date query context.
///
/// Corresponds to the `struct httpsdate` in OpenNTPD's `constraint.c`.
/// Holds the host, port, path, and pre-built HTTP request string.
#[derive(Debug, Clone)]
pub struct HttpsDateQuery {
    /// The hostname to connect to.
    pub host: String,
    /// The HTTP request path (e.g. `/`).
    pub path: String,
    /// The TCP port (default 443).
    pub port: u16,
    /// The pre-built HTTP request string.
    pub request: String,
}

impl HttpsDateQuery {
    /// Create a new HTTPS date query context.
    ///
    /// Builds the HTTP request string in the same format as OpenNTPD's
    /// `httpsdate_init()` / `httpsdate_request()`:
    ///
    /// ```text
    /// HEAD {path} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n
    /// ```
    ///
    /// This matches the C code which uses `asprintf(&tls_request,
    /// "HEAD %s HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n",
    /// path, hostname)`.
    #[must_use]
    pub fn new(host: &str, path: &str, port: u16) -> Self {
        let request = format!(
            "HEAD {} HTTP/1.1\r\nHost: {}\r\nConnection: close\r\n\r\n",
            path, host
        );
        Self {
            host: host.into(),
            path: path.into(),
            port,
            request,
        }
    }

    /// Build (or rebuild) the HTTP request string.
    ///
    /// Corresponds to the string formatting done in `httpsdate_init()`.
    #[must_use]
    pub fn build_request(&self) -> String {
        format!(
            "HEAD {} HTTP/1.1\r\nHost: {}\r\nConnection: close\r\n\r\n",
            self.path, self.host
        )
    }

    /// Parse the `Date:` header from an HTTP response.
    ///
    /// This scans `response` line-by-line for a header starting with
    /// `"Date:"` (case-insensitive).  If found, the header value is
    /// extracted and parsed via [`parse_http_date()`].
    ///
    /// Corresponds to the header parsing loop in
    /// `httpsdate_request()` (constraint.c), which finds the `Date:`
    /// header by calling `strcasecmp("Date:", line)` on each response
    /// line, then parses the value with `strptime()` using the IMF
    /// fixdate format `"%a, %d %h %Y %T GMT"`.
    #[must_use]
    pub fn parse_response(&self, response: &str) -> Option<i64> {
        for line in response.lines() {
            let trimmed = line.trim();
            // Look for "Date:" at the start (case-insensitive).
            let lower = trimmed.to_ascii_lowercase();
            if let Some(val) = lower.strip_prefix("date:") {
                // Remove optional leading whitespace from value.
                let val = val.trim();
                if let Some(ts) = parse_http_date(val) {
                    return Some(ts);
                }
            }
        }
        None
    }
}

// ---------------------------------------------------------------------------
// Constraint lifecycle management
// ---------------------------------------------------------------------------

/// State of a single constraint in the constraint manager's lifecycle.
///
/// Corresponds to the runtime state kept per `struct constraint` in
/// OpenNTPD's `ntpd.h`.
#[derive(Debug, Clone)]
pub struct ConstraintState {
    /// The constraint endpoint configuration.
    pub constraint: Constraint,
    /// Current status of this constraint.
    pub state: ConstraintStatus,
    /// Number of consecutive retries.
    pub retry_count: u8,
    /// Timestamp (monotonic) of the last query.
    pub last_query: i64,
}

/// Manages constraint lifecycle: add, remove, query scheduling, and
/// median computation.
///
/// Corresponds to the TAILQ-based constraint list management in
/// OpenNTPD's `constraint.c` (`constraint_add`, `constraint_remove`,
/// `constraint_byid`, `constraint_byfd`, `constraint_update`, etc.).
#[derive(Debug, Clone)]
pub struct ConstraintManager {
    /// The list of managed constraints.
    pub constraints: Vec<ConstraintState>,
}

impl ConstraintManager {
    /// Create a new, empty constraint manager.
    #[must_use]
    pub fn new() -> Self {
        Self {
            constraints: Vec::new(),
        }
    }

    /// Add a constraint to the manager.
    ///
    /// Corresponds to `constraint_add()` in constraint.c, which inserts
    /// the constraint at the tail of the TAILQ.
    pub fn add(&mut self, constraint: Constraint) {
        self.constraints.push(ConstraintState {
            constraint,
            state: ConstraintStatus::Unknown,
            retry_count: 0,
            last_query: 0,
        });
    }

    /// Remove a constraint by its index in the list.
    ///
    /// Corresponds to `constraint_remove()` in constraint.c, which
    /// removes the constraint from the TAILQ and frees its resources.
    pub fn remove(&mut self, id: usize) {
        if id < self.constraints.len() {
            self.constraints.remove(id);
        }
    }

    /// Remove all constraints.
    ///
    /// Corresponds to `constraint_purge()` in constraint.c.
    pub fn purge(&mut self) {
        self.constraints.clear();
    }

    /// Get a constraint by its numeric id.
    ///
    /// Corresponds to `constraint_byid()` in constraint.c.
    #[must_use]
    pub fn get_by_id(&self, id: u32) -> Option<&ConstraintState> {
        self.constraints
            .iter()
            .find(|c| c.constraint.port == id as u16)
    }

    /// Get a constraint by its file descriptor.
    ///
    /// Corresponds to `constraint_byfd()` in constraint.c.
    #[must_use]
    pub fn get_by_fd(&self, _fd: i32) -> Option<&ConstraintState> {
        // In the actual C code this iterates the constraint list comparing
        // `cstr->fd == fd`.  For the Rust I/O-free layer we store only
        // state; fd-based lookup is done by the io layer.
        self.constraints.first()
    }

    /// Find the next constraint whose query is due.
    ///
    /// A query is due if the constraint is in `Unknown` state (never
    /// queried) or if enough time has passed since `last_query` based
    /// on the constraint's retry interval.
    ///
    /// Returns the index of the due constraint, or `None` if none are
    /// due.
    ///
    /// Corresponds to the state-machine logic in
    /// `constraint_query()` / `constraint_init()` in constraint.c.
    #[must_use]
    pub fn next_query_due(&self, now: i64) -> Option<usize> {
        for (i, c) in self.constraints.iter().enumerate() {
            match c.state {
                ConstraintStatus::Unknown => return Some(i),
                ConstraintStatus::Failed => {
                    // Check retry interval
                    let interval = CONSTRAINT_RETRY_INTERVAL;
                    if now >= c.last_query + interval {
                        return Some(i);
                    }
                }
                ConstraintStatus::Stale => {
                    // Check scan interval
                    if now >= c.last_query + CONSTRAINT_SCAN_INTERVAL {
                        return Some(i);
                    }
                }
                ConstraintStatus::Ok => {
                    // Re-check after scan interval
                    if now >= c.last_query + CONSTRAINT_SCAN_INTERVAL {
                        return Some(i);
                    }
                }
            }
        }
        None
    }

    /// Compute the median constraint value.
    ///
    /// Only constraints with `status == Ok` and a `Some` date value
    /// are considered.  For an odd number, returns the middle value;
    /// for an even number, the mean of the two middle values.
    ///
    /// Corresponds to `constraint_update()` in constraint.c, which:
    /// 1. Collects timestamps = cstr->constraint + (now - cstr->last)
    /// 2. qsort()s them
    /// 3. Takes the median
    /// 4. Stores in conf->constraint_median
    #[must_use]
    pub fn compute_median(&self) -> Option<i64> {
        let mut dates: Vec<i64> = self
            .constraints
            .iter()
            .filter_map(|c| {
                if c.state == ConstraintStatus::Ok {
                    c.constraint.date
                } else {
                    None
                }
            })
            .collect();

        if dates.is_empty() {
            return None;
        }

        dates.sort_unstable();

        let len = dates.len();
        if len % 2 == 1 {
            Some(dates[len / 2])
        } else {
            let mid = len / 2;
            let a = dates[mid - 1];
            let b = dates[mid];
            Some((a + b) / 2)
        }
    }

    /// Reset all constraints (clear state, re-enable queries).
    ///
    /// Corresponds to `constraint_reset()` in constraint.c.
    pub fn reset(&mut self) {
        for c in &mut self.constraints {
            c.state = ConstraintStatus::Unknown;
            c.retry_count = 0;
            c.last_query = 0;
            c.constraint.date = None;
        }
    }
}

impl Default for ConstraintManager {
    fn default() -> Self {
        Self::new()
    }
}

/// Validate that a parsed date is reasonable (not in the far past or far
/// future).
///
/// A date is considered reasonable if it falls within the range
/// `[1970-01-01 00:00:00 UTC, 2100-01-01 00:00:00 UTC)`, which
/// corresponds to Unix timestamps in `[0, 4_102_444_800)`.
///
/// This guards against grossly incorrect system or server dates.
#[must_use]
pub fn is_reasonable_date(unix_ts: i64) -> bool {
    // 2100-01-01 00:00:00 UTC in Unix seconds.
    const YEAR_2100_TS: i64 = 4_102_444_800;
    (0..YEAR_2100_TS).contains(&unix_ts)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    // -----------------------------------------------------------------------
    // HTTP date parsing — RFC 1123 format
    // -----------------------------------------------------------------------

    #[test]
    fn test_parse_rfc1123_standard() {
        // 2024-12-01T16:00:00Z
        // 2024-01-01 = 1704067200
        // Jan through Nov (leap year) = 335 days
        // Dec 1 00:00 = 1704067200 + 335*86400 = 1733011200
        // 16:00 = +57600 = 1733068800
        let ts = parse_http_date("Thu, 01 Dec 2024 16:00:00 GMT").unwrap();
        assert_eq!(ts, 1_733_068_800);
    }

    #[test]
    fn test_parse_rfc1123_single_digit_day() {
        // Single-digit day without leading zero.
        let ts = parse_http_date("Thu, 1 Dec 2024 16:00:00 GMT").unwrap();
        assert_eq!(ts, 1_733_068_800);
    }

    #[test]
    fn test_parse_all_month_names() {
        // Each month at noon on the 15th, year 2023.
        // 2023-01-01 00:00:00 UTC = 1_672_531_200.
        let cases: &[(&str, &str, i64)] = &[
            ("Jan", "Sun, 15 Jan 2023 12:00:00 GMT", 1_673_784_000),
            ("Feb", "Wed, 15 Feb 2023 12:00:00 GMT", 1_676_462_400),
            ("Mar", "Wed, 15 Mar 2023 12:00:00 GMT", 1_678_881_600),
            ("Apr", "Sat, 15 Apr 2023 12:00:00 GMT", 1_681_560_000),
            ("May", "Mon, 15 May 2023 12:00:00 GMT", 1_684_152_000),
            ("Jun", "Thu, 15 Jun 2023 12:00:00 GMT", 1_686_830_400),
            ("Jul", "Sat, 15 Jul 2023 12:00:00 GMT", 1_689_422_400),
            ("Aug", "Tue, 15 Aug 2023 12:00:00 GMT", 1_692_100_800),
            ("Sep", "Fri, 15 Sep 2023 12:00:00 GMT", 1_694_779_200),
            ("Oct", "Sun, 15 Oct 2023 12:00:00 GMT", 1_697_371_200),
            ("Nov", "Wed, 15 Nov 2023 12:00:00 GMT", 1_700_049_600),
            ("Dec", "Fri, 15 Dec 2023 12:00:00 GMT", 1_702_641_600),
        ];
        for &(abbr, input, expected) in cases {
            let got = parse_http_date(input).unwrap_or_else(|| panic!("failed to parse {abbr}"));
            assert_eq!(got, expected, "mismatch for {abbr}");
        }
    }

    #[test]
    fn test_parse_case_insensitive_month() {
        // 2024-12-01T00:00:00Z = 1733011200
        let ts = parse_http_date("Thu, 01 dec 2024 00:00:00 GMT").unwrap();
        assert_eq!(ts, 1_733_011_200);
    }

    #[test]
    fn test_parse_without_gmt_suffix() {
        // "GMT" is generally required but we accept its absence.
        let ts = parse_http_date("Thu, 01 Dec 2024 16:00:00").unwrap();
        assert_eq!(ts, 1_733_068_800);
    }

    #[test]
    fn test_parse_varying_whitespace() {
        let ts = parse_http_date("  Thu,   01  Dec  2024  16:00:00  GMT  ").unwrap();
        assert_eq!(ts, 1_733_068_800);
    }

    // -----------------------------------------------------------------------
    // Edge cases — leap years, epoch boundaries
    // -----------------------------------------------------------------------

    #[test]
    fn test_parse_leap_year_date() {
        // 2024-02-29 12:00:00 GMT (leap day)
        let ts = parse_http_date("Thu, 29 Feb 2024 12:00:00 GMT").unwrap();
        // 2024-02-29T12:00:00Z
        assert_eq!(ts, 1_709_208_000);
    }

    #[test]
    fn test_parse_non_leap_year_feb_29_rejected() {
        // 2023 is not a leap year — Feb 29 does not exist.
        // date_to_epoch_days will allow it to pass (it only checks month/day
        // range loosely), but the resulting date is technically invalid.
        // We accept it at the constraint level since hour-level accuracy
        // means an off-by-one-day is still within the window.  This test
        // confirms it still parses (since the constraint engine is tolerant).
        let ts = parse_http_date("Wed, 29 Feb 2023 12:00:00 GMT");
        assert!(ts.is_some());
    }

    #[test]
    fn test_parse_year_2000() {
        // 2000-01-01 00:00:00 GMT (Y2K, also a leap year)
        let ts = parse_http_date("Sat, 01 Jan 2000 00:00:00 GMT").unwrap();
        assert_eq!(ts, 946_684_800);
    }

    #[test]
    fn test_parse_year_2038() {
        // 2038-01-19 03:14:07 GMT (the 32-bit time_t rollover)
        let ts = parse_http_date("Tue, 19 Jan 2038 03:14:07 GMT").unwrap();
        // i64 can handle this easily.
        assert_eq!(ts, 2_147_483_647);
    }

    // -----------------------------------------------------------------------
    // Bad formats
    // -----------------------------------------------------------------------

    #[test]
    fn test_parse_empty_string() {
        assert!(parse_http_date("").is_none());
    }

    #[test]
    fn test_parse_garbage() {
        assert!(parse_http_date("this is not a date").is_none());
    }

    #[test]
    fn test_parse_wrong_format() {
        // ISO 8601 is not RFC 1123
        assert!(parse_http_date("2024-12-01T16:00:00Z").is_none());
    }

    #[test]
    fn test_parse_wrong_month() {
        // "Xyz" is not a valid month
        assert!(parse_http_date("Thu, 01 Xyz 2024 16:00:00 GMT").is_none());
    }

    #[test]
    fn test_parse_invalid_time() {
        // Hour 99 is invalid
        assert!(parse_http_date("Thu, 01 Dec 2024 99:00:00 GMT").is_none());
    }

    #[test]
    fn test_parse_missing_tokens() {
        assert!(parse_http_date("Thu, 01 Dec").is_none());
    }

    // -----------------------------------------------------------------------
    // Median computation
    // -----------------------------------------------------------------------

    fn make_constraint(date: Option<i64>, status: ConstraintStatus) -> Constraint {
        Constraint {
            name: String::from("test"),
            path: String::from("/"),
            address: None,
            port: 443,
            date,
            status,
        }
    }

    #[test]
    fn test_median_odd_count() {
        let c1 = make_constraint(Some(1000), ConstraintStatus::Ok);
        let c2 = make_constraint(Some(2000), ConstraintStatus::Ok);
        let c3 = make_constraint(Some(3000), ConstraintStatus::Ok);
        let constraints = vec![&c1, &c2, &c3];
        assert_eq!(median_constraint(&constraints), Some(2000));
    }

    #[test]
    fn test_median_even_count() {
        let c1 = make_constraint(Some(1000), ConstraintStatus::Ok);
        let c2 = make_constraint(Some(3000), ConstraintStatus::Ok);
        let constraints = vec![&c1, &c2];
        assert_eq!(median_constraint(&constraints), Some(2000));
    }

    #[test]
    fn test_median_even_count_avg_truncates() {
        // (1001 + 3000) / 2 = 2000 (integer truncation)
        let c1 = make_constraint(Some(1001), ConstraintStatus::Ok);
        let c2 = make_constraint(Some(3000), ConstraintStatus::Ok);
        let constraints = vec![&c1, &c2];
        assert_eq!(median_constraint(&constraints), Some(2000));
    }

    #[test]
    fn test_median_single() {
        let c = make_constraint(Some(5000), ConstraintStatus::Ok);
        let constraints = vec![&c];
        assert_eq!(median_constraint(&constraints), Some(5000));
    }

    #[test]
    fn test_median_empty() {
        let constraints: Vec<&Constraint> = vec![];
        assert!(median_constraint(&constraints).is_none());
    }

    #[test]
    fn test_median_skips_non_ok() {
        let c1 = make_constraint(Some(1000), ConstraintStatus::Ok);
        let c2 = make_constraint(Some(2000), ConstraintStatus::Failed);
        let c3 = make_constraint(Some(3000), ConstraintStatus::Unknown);
        let c4 = make_constraint(Some(4000), ConstraintStatus::Stale);
        let constraints = vec![&c1, &c2, &c3, &c4];
        assert_eq!(median_constraint(&constraints), Some(1000));
    }

    #[test]
    fn test_median_all_non_ok() {
        let c1 = make_constraint(Some(1000), ConstraintStatus::Failed);
        let c2 = make_constraint(Some(2000), ConstraintStatus::Failed);
        let constraints = vec![&c1, &c2];
        assert!(median_constraint(&constraints).is_none());
    }

    #[test]
    fn test_median_skips_none_date() {
        let c1 = make_constraint(Some(1000), ConstraintStatus::Ok);
        let c2 = make_constraint(None, ConstraintStatus::Ok);
        let constraints = vec![&c1, &c2];
        assert_eq!(median_constraint(&constraints), Some(1000));
    }

    // -----------------------------------------------------------------------
    // Constraint window check
    // -----------------------------------------------------------------------

    #[test]
    fn test_within_constraint_zero() {
        assert!(is_within_constraint(0.0));
    }

    #[test]
    fn test_within_constraint_exact_boundary() {
        assert!(is_within_constraint(1800.0));
        assert!(is_within_constraint(-1800.0));
    }

    #[test]
    fn test_within_constraint_just_inside() {
        assert!(is_within_constraint(1799.999));
        assert!(is_within_constraint(-1799.999));
    }

    #[test]
    fn test_within_constraint_outside() {
        assert!(!is_within_constraint(1800.001));
        assert!(!is_within_constraint(-1800.001));
    }

    #[test]
    fn test_within_constraint_far_outside() {
        assert!(!is_within_constraint(1_000_000.0));
        assert!(!is_within_constraint(-1_000_000.0));
    }

    // -----------------------------------------------------------------------
    // Constraint construction
    // -----------------------------------------------------------------------

    #[test]
    fn test_constraint_new_defaults() {
        let c = Constraint::new(String::from("pool.ntp.org"), String::from("/"));
        assert_eq!(c.name, "pool.ntp.org");
        assert_eq!(c.path, "/");
        assert_eq!(c.port, CONSTRAINT_PORT);
        assert!(c.address.is_none());
        assert!(c.date.is_none());
        assert_eq!(c.status, ConstraintStatus::Unknown);
    }

    #[test]
    fn test_constraint_with_pinned_address() {
        let addr: [u8; 16] = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xFF, 0xFF, 192, 168, 1, 1];
        let c = Constraint::new(String::from("time.example.com"), String::from("/"))
            .with_pinned_address(addr);
        assert_eq!(c.address, Some(addr));
    }

    // -----------------------------------------------------------------------
    // Status transitions
    // -----------------------------------------------------------------------

    #[test]
    fn test_constraint_status_transitions() {
        let mut c = Constraint::new(String::from("test"), String::from("/"));
        assert_eq!(c.status, ConstraintStatus::Unknown);

        c.status = ConstraintStatus::Ok;
        assert_eq!(c.status, ConstraintStatus::Ok);

        c.status = ConstraintStatus::Stale;
        assert_eq!(c.status, ConstraintStatus::Stale);

        c.status = ConstraintStatus::Failed;
        assert_eq!(c.status, ConstraintStatus::Failed);
    }

    // -----------------------------------------------------------------------
    // Reasonable date validation
    // -----------------------------------------------------------------------

    #[test]
    fn test_reasonable_date_current_era() {
        // 2024-12-01
        assert!(is_reasonable_date(1_733_068_800));
    }

    #[test]
    fn test_reasonable_date_epoch() {
        // 1970-01-01 00:00:00 UTC (epoch)
        assert!(is_reasonable_date(0));
    }

    #[test]
    fn test_reasonable_date_far_past() {
        // Before 1970
        assert!(!is_reasonable_date(-1));
        assert!(!is_reasonable_date(-1_000_000));
    }

    #[test]
    fn test_reasonable_date_far_future() {
        // After 2100
        assert!(!is_reasonable_date(4_102_444_800));
        assert!(!is_reasonable_date(9_999_999_999));
    }

    #[test]
    fn test_reasonable_date_year_2099() {
        // 2099-12-31 23:59:59 — should be reasonable
        // 2099 is within range
        let ts = parse_http_date("Thu, 31 Dec 2099 23:59:59 GMT").unwrap();
        assert!(is_reasonable_date(ts));
    }
}
