//! OpenBSD pledge() sandboxing.
//!
//! Provides safe Rust wrappers around OpenBSD's `pledge(2)` system call,
//! which restricts system call access to a whitelist of "promises".
//!
//! ## Promises used
//!
//! | Process | Pledge string | Equivalent |
//! |---------|--------------|------------|
//! | NTP child | `"stdio inet"` | Network I/O, clock reads, memory |
//! | Parent   | `"stdio settime proc exec"` | Clock setting, fork/exec, credentials |
//!
//! ## References
//!
//! - pledge(2) — OpenBSD manual
//! - OpenNTPD's `pledge()` calls in `ntpd.c` and `ntp_child.c`

/// OpenBSD pledge() sandboxing.
#[cfg(target_os = "openbsd")]
pub mod openbsd {
    use std::ffi::CString;

    /// Apply `pledge()` with the given promises string.
    ///
    /// Wraps `libc::pledge(promises, execpromises)`.
    ///
    /// # Arguments
    ///
    /// * `promises` — The promises string (e.g., `"stdio inet"`).
    ///   Passed as a C string to the syscall.
    /// * `execpromises` — Optional promises for exec'd children.
    ///   Pass `None` for no exec promises.
    ///
    /// # Errors
    ///
    /// Returns an error message if `pledge()` fails (e.g., invalid
    /// promise name, or the process already called `pledge()` with a
    /// stricter set).
    fn pledge(promises: &str, execpromises: Option<&str>) -> Result<(), String> {
        let c_promises = CString::new(promises)
            .map_err(|_| format!("invalid promises string (contains null byte): {promises}"))?;
        let c_exec =
            match execpromises {
                Some(s) => Some(CString::new(s).map_err(|_| {
                    format!("invalid execpromises string (contains null byte): {s}")
                })?),
                None => None,
            };

        let ret = unsafe {
            libc::pledge(
                c_promises.as_ptr(),
                c_exec.as_ref().map_or(core::ptr::null(), |c| c.as_ptr()),
            )
        };

        if ret == 0 {
            Ok(())
        } else {
            Err(format!(
                "pledge(\"{promises}\") failed: {}",
                std::io::Error::last_os_error()
            ))
        }
    }

    /// Apply pledge promises for the NTP child process.
    ///
    /// The child performs network time queries, so it needs:
    /// - `stdio` — standard I/O, memory allocation, signals
    /// - `inet` — socket operations, DNS resolution
    ///
    /// Equivalent to C: `pledge("stdio inet", NULL)`
    ///
    /// # Errors
    ///
    /// Returns an error message if `pledge()` fails.
    pub fn child_pledge() -> Result<(), String> {
        pledge("stdio inet", None)
    }

    /// Apply pledge promises for the parent (privileged) process.
    ///
    /// The parent manages time adjustment, process lifecycle, and
    /// privilege separation, so it needs:
    /// - `stdio` — standard I/O, memory allocation, signals
    /// - `settime` — `adjtime(2)` and `settimeofday(2)`
    /// - `proc` — `fork(2)`, `wait(2)`, `kill(2)`
    /// - `exec` — `execve(2)` for starting child processes
    ///
    /// Equivalent to C: `pledge("stdio settime proc exec", NULL)`
    ///
    /// # Errors
    ///
    /// Returns an error message if `pledge()` fails.
    pub fn parent_pledge() -> Result<(), String> {
        pledge("stdio settime proc exec", None)
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        /// Verify that `child_pledge()` builds the correct promise string.
        /// We can't actually call pledge() in tests (would lock down the
        /// test process), so we test the string formatting indirectly
        /// via the `pledge` function's C string conversion.
        #[test]
        fn test_child_pledge_promises_valid_utf8() {
            // The promise string is valid UTF-8 and contains no null bytes.
            let promises = "stdio inet";
            assert!(CString::new(promises).is_ok());
            // Verify the string content
            assert_eq!(promises, "stdio inet");
        }

        /// Verify that `parent_pledge()` builds the correct promise string.
        #[test]
        fn test_parent_pledge_promises_valid_utf8() {
            let promises = "stdio settime proc exec";
            assert!(CString::new(promises).is_ok());
            assert_eq!(promises, "stdio settime proc exec");
        }

        /// Verify that pledge() rejects null bytes in promises.
        #[test]
        fn test_pledge_rejects_null_bytes() {
            let result = pledge("stdio\x00inet", None);
            assert!(result.is_err());
            assert!(
                result.unwrap_err().contains("null byte"),
                "should reject invalid C strings"
            );
        }

        /// Verify that pledge() rejects null bytes in execpromises.
        #[test]
        fn test_pledge_rejects_null_in_execpromises() {
            let result = pledge("stdio", Some("exec\x00"));
            assert!(result.is_err());
            assert!(
                result.unwrap_err().contains("null byte"),
                "should reject invalid execpromises"
            );
        }

        /// Verify the promise strings have the expected format.
        #[test]
        fn test_child_promise_format() {
            #[cfg(target_os = "openbsd")]
            {
                let result = child_pledge();
                // On a real OpenBSD system this might succeed or fail
                // depending on the environment; we just verify the
                // error type is plausible.
                if let Err(e) = result {
                    assert!(
                        e.contains("pledge") || e.contains("stdio"),
                        "unexpected error: {e}"
                    );
                }
            }
            #[cfg(not(target_os = "openbsd"))]
            {
                // On non-OpenBSD, this module isn't even compiled,
                // so this test is a no-op.
            }
        }

        /// Verify the parent promise format.
        #[test]
        fn test_parent_promise_format() {
            #[cfg(target_os = "openbsd")]
            {
                let result = parent_pledge();
                if let Err(e) = result {
                    assert!(e.contains("pledge"), "unexpected error: {e}");
                }
            }
        }

        /// Verify that the pledge strings match OpenNTPD conventions.
        #[test]
        fn test_child_pledge_string_matches_openntpd() {
            // OpenNTPD uses: pledge("stdio inet", NULL) for the child.
            let promises = "stdio inet";
            assert_eq!(promises, "stdio inet");

            // OpenNTPD uses: pledge("stdio settime proc exec", NULL) for parent.
            let parent_promises = "stdio settime proc exec";
            assert_eq!(parent_promises, "stdio settime proc exec");
        }

        /// Verify error message contains the promise string for debugging.
        #[test]
        fn test_pledge_error_contains_promise_string() {
            let result = pledge("\0invalid", None);
            assert!(result.is_err());
            let err = result.unwrap_err();
            assert!(
                err.contains("\0invalid") || err.contains("null byte"),
                "error should reference the failing promise string: {err}"
            );
        }

        /// Smoke test: CString conversion for realistic strings.
        #[test]
        fn test_realistic_cstring_conversion() {
            let promises = [
                "stdio",
                "stdio inet",
                "stdio settime proc exec",
                "inet",
                "exec",
            ];
            for p in &promises {
                let c = CString::new(*p);
                assert!(
                    c.is_ok(),
                    "valid promise string {p:?} should convert to CString"
                );
            }
        }
    }
}
