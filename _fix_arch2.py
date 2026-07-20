import re

# Fix ctl.rs: b as i8 -> b as libc::c_char (all instances)
with open("crates/openntpd-rs-io/src/ctl.rs", "r") as f:
    content = f.read()
content = content.replace("b as i8", "b as libc::c_char")
with open("crates/openntpd-rs-io/src/ctl.rs", "w") as f:
    f.write(content)

# Fix daemon_impl.rs: as_ptr() issues with strftime
with open("crates/openntpd-rs-io/src/daemon_impl.rs", "r") as f:
    content = f.read()
# Replace CStr::from_ptr with proper cast
content = content.replace(
    "std::ffi::CStr::from_ptr(buf.as_ptr())",
    "std::ffi::CStr::from_ptr(buf.as_ptr() as *const libc::c_char)"
)
content = content.replace(
    "buf.as_mut_ptr()",
    "buf.as_mut_ptr() as *mut libc::c_char"
)
with open("crates/openntpd-rs-io/src/daemon_impl.rs", "w") as f:
    f.write(content)

# Fix util.rs: syslog format string 
with open("crates/openntpd-rs-io/src/util.rs", "r") as f:
    content = f.read()
content = content.replace(
    "b\"%s\\0\".as_ptr() as *const libc::c_char, cmsg.as_ptr()",
    "b\"%s\\0\".as_ptr() as *const libc::c_char, cmsg.as_ptr() as *const libc::c_char"
)
with open("crates/openntpd-rs-io/src/util.rs", "w") as f:
    f.write(content)

print("Done")
