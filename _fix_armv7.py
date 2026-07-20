# Fix armv7 32-bit type issues in io crate
files = {
    "crates/openntpd-rs-io/src/clock.rs": [
        ("tx.freq = linux_freq;", "tx.freq = linux_freq as libc::c_long;"),
    ],
    "crates/openntpd-rs-io/src/daemon_impl.rs": [
        ("tx.freq = linux_freq;", "tx.freq = linux_freq as libc::c_long;"),
    ],
    "crates/openntpd-rs-io/src/util.rs": [
        ("tv_sec: secs,", "tv_sec: secs as libc::time_t,"),
        ("tv_usec: usec as i64,", "tv_usec: usec as libc::suseconds_t,"),
        ("let ntp_secs = tv.tv_sec.checked_add(NTP_UNIX_EPOCH_DELTA as i64)?;", "let ntp_secs = (tv.tv_sec as i64).checked_add(NTP_UNIX_EPOCH_DELTA as i64)?;"),
    ],
}

for filepath, replacements in files.items():
    with open(filepath, "r") as f:
        content = f.read()
    for old, new in replacements:
        content = content.replace(old, new)
    with open(filepath, "w") as f:
        f.write(content)
    print(f"Fixed {filepath}")
