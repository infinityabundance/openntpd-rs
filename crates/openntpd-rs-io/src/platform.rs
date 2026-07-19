//! Platform detection and default paths.
//!
//! Provides compile-time platform detection functions that return
//! human-readable names, capability flags, and default file paths
//! appropriate for the current operating system.
//!
//! ## Default paths by platform
//!
//! | Path | Linux | FreeBSD | macOS |
//! |------|-------|---------|-------|
//! | Config | `/etc/ntpd.conf` | `/etc/ntpd.conf` | `/etc/ntpd.conf` |
//! | Drift | `/var/lib/ntp/ntpd.drift` | `/var/db/ntpd.drift` | `/var/db/ntpd.drift` |
//! | Control socket | `/var/run/ntpd.sock` | `/var/run/ntpd.sock` | `/var/run/ntpd.sock` |
//! | PID file | `/var/run/ntpd.pid` | `/var/run/ntpd.pid` | `/var/run/ntpd.pid` |
//! | NTP user | `ntp` | `_ntp` | `_ntp` |

/// Detect the current platform and return a human-readable name.
///
/// # Examples
///
/// ```
/// use openntpd_rs_io::platform::platform_name;
/// let name = platform_name();
/// assert!(!name.is_empty());
/// ```
#[must_use]
pub fn platform_name() -> &'static str {
    #[cfg(target_os = "linux")]
    {
        "linux"
    }
    #[cfg(target_os = "freebsd")]
    {
        "freebsd"
    }
    #[cfg(target_os = "openbsd")]
    {
        "openbsd"
    }
    #[cfg(target_os = "macos")]
    {
        "macos"
    }
    #[cfg(not(any(
        target_os = "linux",
        target_os = "freebsd",
        target_os = "openbsd",
        target_os = "macos"
    )))]
    {
        "unknown"
    }
}

/// Check if the current platform supports `adjfreq(2)`.
///
/// `adjfreq(2)` is available on OpenBSD and FreeBSD.
#[must_use]
pub fn supports_adjfreq() -> bool {
    #[cfg(any(target_os = "openbsd", target_os = "freebsd"))]
    {
        true
    }
    #[cfg(not(any(target_os = "openbsd", target_os = "freebsd")))]
    {
        false
    }
}

/// Check if the current platform supports `adjtimex(2)`.
///
/// `adjtimex(2)` is Linux-specific.
#[must_use]
pub fn supports_adjtimex() -> bool {
    #[cfg(target_os = "linux")]
    {
        true
    }
    #[cfg(not(target_os = "linux"))]
    {
        false
    }
}

/// Default drift file path for the current platform.
///
/// - Linux: `/var/lib/ntp/ntpd.drift`
/// - FreeBSD / macOS: `/var/db/ntpd.drift`
/// - Fallback: `/var/db/ntpd.drift`
#[must_use]
pub fn default_drift_path() -> &'static str {
    #[cfg(target_os = "linux")]
    {
        "/var/lib/ntp/ntpd.drift"
    }
    #[cfg(not(target_os = "linux"))]
    {
        "/var/db/ntpd.drift"
    }
}

/// Default config file path for the current platform.
///
/// All platforms: `/etc/ntpd.conf`
#[must_use]
pub fn default_config_path() -> &'static str {
    "/etc/ntpd.conf"
}

/// Default control socket path for the current platform.
///
/// All platforms: `/var/run/ntpd.sock`
#[must_use]
pub fn default_ctl_socket_path() -> &'static str {
    "/var/run/ntpd.sock"
}

/// Default PID file path for the current platform.
///
/// All platforms: `/var/run/ntpd.pid`
#[must_use]
pub fn default_pid_file_path() -> &'static str {
    "/var/run/ntpd.pid"
}

/// Default NTP user for the current platform.
///
/// - Linux: `ntp`
/// - FreeBSD / macOS: `_ntp`
/// - Fallback: `_ntp`
#[must_use]
pub fn default_ntp_user() -> &'static str {
    #[cfg(target_os = "linux")]
    {
        "ntp"
    }
    #[cfg(not(target_os = "linux"))]
    {
        "_ntp"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_platform_name_non_empty() {
        let name = platform_name();
        assert!(!name.is_empty(), "platform_name must not be empty");
    }

    #[test]
    fn test_platform_name_known() {
        let name = platform_name();
        assert!(
            ["linux", "freebsd", "openbsd", "macos", "unknown"].contains(&name),
            "unexpected platform name: {name}"
        );
    }

    #[test]
    fn test_supports_adjfreq_platform_consistent() {
        // adjfreq is only supported on OpenBSD and FreeBSD
        #[cfg(any(target_os = "openbsd", target_os = "freebsd"))]
        assert!(supports_adjfreq());
        #[cfg(not(any(target_os = "openbsd", target_os = "freebsd")))]
        assert!(!supports_adjfreq());
    }

    #[test]
    fn test_supports_adjtimex_platform_consistent() {
        // adjtimex is Linux-only
        #[cfg(target_os = "linux")]
        assert!(supports_adjtimex());
        #[cfg(not(target_os = "linux"))]
        assert!(!supports_adjtimex());
    }

    #[test]
    fn test_default_paths_non_empty() {
        assert!(!default_drift_path().is_empty());
        assert!(!default_config_path().is_empty());
        assert!(!default_ctl_socket_path().is_empty());
        assert!(!default_pid_file_path().is_empty());
    }

    #[test]
    fn test_default_paths_absolute() {
        assert!(default_drift_path().starts_with('/'));
        assert!(default_config_path().starts_with('/'));
        assert!(default_ctl_socket_path().starts_with('/'));
        assert!(default_pid_file_path().starts_with('/'));
    }

    #[test]
    fn test_default_ntp_user_non_empty() {
        assert!(!default_ntp_user().is_empty());
    }

    #[test]
    fn test_default_drift_path_linux() {
        #[cfg(target_os = "linux")]
        assert_eq!(default_drift_path(), "/var/lib/ntp/ntpd.drift");
    }

    #[test]
    fn test_default_drift_path_bsd() {
        #[cfg(not(target_os = "linux"))]
        assert_eq!(default_drift_path(), "/var/db/ntpd.drift");
    }

    #[test]
    fn test_default_ntp_user_linux() {
        #[cfg(target_os = "linux")]
        assert_eq!(default_ntp_user(), "ntp");
    }

    #[test]
    fn test_default_ntp_user_bsd() {
        #[cfg(not(target_os = "linux"))]
        assert_eq!(default_ntp_user(), "_ntp");
    }

    #[test]
    fn test_adjfreq_and_adjtimex_mutually_exclusive() {
        // A platform should support adjfreq OR adjtimex, but not both
        if supports_adjfreq() {
            assert!(!supports_adjtimex());
        }
        if supports_adjtimex() {
            assert!(!supports_adjfreq());
        }
    }
}
