use std::path::Path;

pub fn run() -> anyhow::Result<()> {
    let docs_gen = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .join("docs")
        .join("generated");
    std::fs::create_dir_all(&docs_gen)?;
    generate_port_parity(&docs_gen)?;
    generate_negative_capabilities(&docs_gen)?;
    println!("✓ Documentation regenerated in {}.", docs_gen.display());
    Ok(())
}

pub(crate) fn run_inner(out_dir: &Path) -> anyhow::Result<()> {
    generate_port_parity(out_dir)?;
    generate_negative_capabilities(out_dir)?;
    Ok(())
}

struct Surface {
    c_file: &'static str,
    rs_module: &'static str,
    status: &'static str,
    tests: &'static [&'static str],
}

fn surfaces() -> Vec<Surface> {
    vec![
        Surface {
            c_file: "ntp.h",
            rs_module: "ntp",
            status: "Implemented — internally tested",
            tests: &[
                "test_ntp_timestamp_wire_roundtrip",
                "test_packet_encode_decode_roundtrip",
                "test_datagram_accepts_48_and_68",
                "test_datagram_rejects_bad_lengths",
                "test_authenticated_roundtrip",
                "test_era_resolution_current_era",
                "test_era_resolution_post_2036",
                "test_era_resolution_era_boundary_crossing",
                "test_era_resolution_previous_era",
                "test_era_resolution_era_2",
                "test_ntp_to_unix_known_value",
                "test_roundtrip_unix_ntp_unix",
                "test_unix_to_ntp_epoch",
            ],
        },
        Surface {
            c_file: "ntp_msg.c",
            rs_module: "ntp::msg",
            status: "Implemented — internally tested",
            tests: &[
                "test_ntp_getmsg_valid_48",
                "test_ntp_getmsg_rejects_bad_lengths",
                "test_ntp_sendmsg_roundtrip",
                "test_authenticated_roundtrip",
            ],
        },
        Surface {
            c_file: "util.c",
            rs_module: "util",
            status: "Implemented — internally tested",
            tests: &[
                "test_frequency_ppm_roundtrip",
                "test_frequency_linux_conversion_known_value",
                "test_frequency_linux_roundtrip",
                "test_frequency_linux_overflow_rejection",
                "test_timespec_from_f64",
                "test_timespec_normalize_positive",
                "test_timespec_normalize_negative",
                "test_timespec_roundtrip",
                "test_timespec_nan_inf_rejected",
                "test_timespec_out_of_range_rejected",
                "test_timespec_new_overflow_rejected",
                "test_d_to_timespec_negative",
            ],
        },
        Surface {
            c_file: "config (AST types)",
            rs_module: "config::directive",
            status: "Implemented — internally tested",
            tests: &[
                "weight_zero_rejected",
                "weight_one_accepted",
                "weight_ten_accepted",
                "weight_eleven_rejected",
                "stratum_zero_rejected",
                "stratum_one_accepted",
                "stratum_fifteen_accepted",
                "stratum_sixteen_rejected",
                "correction_min_accepted",
                "correction_max_accepted",
                "correction_below_min_rejected",
                "correction_above_max_rejected",
                "correction_zero_accepted",
                "refid_empty_rejected",
                "refid_one_byte",
                "refid_four_bytes",
                "refid_nul_rejected",
                "refid_five_bytes_rejected",
                "refid_display_ascii",
                "server_options_defaults",
                "sensor_options_defaults",
                "config_empty",
                "span_union",
                "listen_wildcard",
                "listen_hostname",
                "server_directive",
                "server_pool_directive",
                "query_from_ip",
                "constraint_single",
                "constraint_pool",
                "sensor_directive",
            ],
        },
        Surface {
            c_file: "config (diagnostics)",
            rs_module: "config::diagnostic",
            status: "Implemented — internally tested",
            tests: &["test_diag_error", "test_parse_valid", "test_parse_invalid"],
        },
        Surface {
            c_file: "adjfreq_linux.c",
            rs_module: "io::clock",
            status: "Implemented — internally tested",
            tests: &[
                "test_openbsd_to_linux_known",
                "test_linux_roundtrip",
                "test_openbsd_to_linux_overflow_rejected",
            ],
        },
        Surface {
            c_file: "socket (loopback)",
            rs_module: "io::socket",
            status: "Implemented — internally tested",
            tests: &[
                "test_ipv4_send_recv",
                "test_ipv6_send_recv",
                "test_ipv4_send_recv_no_timestamp",
                "test_bind_ntp_socket_ipv4",
                "test_bind_without_options",
                "test_kernel_timestamp_smoke",
            ],
        },
        Surface {
            c_file: "ntpd.h (CLI)",
            rs_module: "daemon (CLI)",
            status: "Implemented — unverified against oracle",
            tests: &[],
        },
        Surface {
            c_file: "ntpctl (CLI)",
            rs_module: "ntpctl (CLI)",
            status: "Implemented — unverified against oracle",
            tests: &[],
        },
        Surface {
            c_file: "adjtime_adjtimex.c",
            rs_module: "io::clock",
            status: "Implemented — unverified against oracle",
            tests: &[],
        },
        Surface {
            c_file: "bsd-setresuid.c",
            rs_module: "io::process",
            status: "Implemented — unverified against oracle",
            tests: &[],
        },
        Surface {
            c_file: "socket (timestamping)",
            rs_module: "io::socket",
            status: "Implemented — unverified against oracle",
            tests: &[],
        },
        Surface {
            c_file: "parse.y (lexer)",
            rs_module: "config::lexer",
            status: "Implemented — internally tested",
            tests: &[
                "cursor_peek_bump",
                "comment_only",
                "comment_at_eof",
                "continuation_extends_comment",
                "all_keywords",
                "keyword_case_sensitive",
                "number_positive",
                "number_negative",
                "number_zero",
                "number_i64_min",
                "number_i64_max",
                "number_overflow_pos",
                "number_overflow_neg",
                "lone_minus_symbol",
                "number_then_slash",
                "number_then_space",
                "number_then_newline",
                "number_continuation",
                "numeric_ipv4_is_string",
                "numeric_ipv6_is_string",
                "digit_prefixed_hostname",
                "digits_followed_by_alpha",
                "digit_hyphen_digit",
                "continuation_between_tokens",
                "continuation_at_start_of_line",
                "recovery_skips_escaped_newline",
                "wildcard_is_string",
                "wildcard_listen",
                "colon_prefixed_string",
                "underscore_prefixed_string",
                "quoted_double",
                "quoted_single",
                "quoted_non_utf8",
                "quoted_empty",
                "unterminated_quote_eof",
                "unterminated_quote_newline",
                "quoted_escaped_quote",
                "quoted_escaped_space",
                "quoted_escaped_tab",
                "quoted_unknown_escape",
                "quoted_escaped_nul_returns_error",
                "quoted_raw_newline_continues",
                "unquoted_continuation_merges",
                "unquoted_backslash_removed",
                "quoted_backslash_newline",
                "nul_unquoted",
                "nul_quoted",
                "nul_comment",
                "newline_tracking",
                "recovery_after_nul",
                "recovery_after_overflow",
                "recovery_after_unterminated_quote",
                "symbols",
                "unquoted_slash_terminates",
                "unquoted_at_sign_permitted",
                "unquoted_question_mark_permitted",
                "unquoted_semicolon_terminates",
                "unquoted_bracket_terminates",
                "unquoted_paren_terminates",
                "unquoted_bang_terminates",
                "unquoted_comma_terminates",
                "quoted_limit_8094",
                "quoted_limit_8095_rejected",
                "unquoted_limit_8095",
                "unquoted_limit_8096_rejected",
                "simple_directive_line",
                "listen_directive_line",
            ],
        },
        Surface {
            c_file: "parse.y (parser)",
            rs_module: "config (planned)",
            status: "Planned",
            tests: &[],
        },
        Surface {
            c_file: "config.c (lowering)",
            rs_module: "config (planned)",
            status: "Planned",
            tests: &[],
        },
        Surface {
            c_file: "ntpd.c",
            rs_module: "daemon",
            status: "Scaffold",
            tests: &[],
        },
        Surface {
            c_file: "client.c",
            rs_module: "peer",
            status: "Planned",
            tests: &[],
        },
        Surface {
            c_file: "server.c",
            rs_module: "server",
            status: "Planned",
            tests: &[],
        },
        Surface {
            c_file: "control.c",
            rs_module: "control",
            status: "Planned",
            tests: &[],
        },
    ]
}

fn generate_port_parity(docs_gen: &Path) -> anyhow::Result<()> {
    let mut md = String::new();
    md.push_str("<!-- DO NOT EDIT BY HAND. Generated by `cargo xtask gen`. Run `cargo xtask check` to verify freshness. -->\n\n");
    md.push_str(
        "# Port parity matrix\n\nOpenNTPD 7.9p1 translation units and their Rust counterparts.\n\n",
    );
    md.push_str("| C source | Rust module | Status | Tests |\n|----------|-------------|--------|-------|\n");
    let total: usize = surfaces().iter().map(|s| s.tests.len()).sum();
    for s in surfaces() {
        let n = if s.tests.is_empty() {
            "—".into()
        } else {
            s.tests.len().to_string()
        };
        md.push_str(&format!(
            "| `{}` | `{}` | {} | {} |\n",
            s.c_file, s.rs_module, s.status, n
        ));
    }
    md.push('\n');
    md.push_str(&format!("**Total project tests: {total}**\n\n"));
    md.push_str("## Status definitions\n\n");
    md.push_str("- **Implemented — internally tested**: Rust code exists, unit tests pass, but no oracle comparison has been run.\n");
    md.push_str("- **Implemented — unverified against oracle**: Rust code exists, has not been tested against the real ntpd.\n");
    md.push_str("- **Scaffold**: type/signature only, no behavioral implementation.\n");
    md.push_str("- **Planned**: not yet started.\n");
    md.push_str("\n**No surface is labelled `Ported` until `cargo xtask parity` produces a verified evidence artifact against the real OpenNTPD 7.9p1 oracle.**\n\n");
    std::fs::write(docs_gen.join("port-parity.md"), &md)?;
    Ok(())
}

fn generate_negative_capabilities(docs_gen: &Path) -> anyhow::Result<()> {
    let mut md = String::new();
    md.push_str("<!-- DO NOT EDIT BY HAND. Generated by `cargo xtask gen`. Run `cargo xtask check` to verify freshness. -->\n\n");
    md.push_str(
        "# Negative capabilities\n\nThings `openntpd-rs` deliberately does **not** do yet.\n\n",
    );

    md.push_str("## Implemented — internally tested\n\n| Module | Tests |\n|--------|-------|\n");
    md.push_str("| NTP wire (`ntp`) | 13: wire format, unsigned dispersion, era 0–2 |\n");
    md.push_str("| NTP msg I/O (`ntp::msg`) | 4: exact-length, auth suffix |\n");
    md.push_str("| Utility (`util`) | 12: frequency, Timespec, NaN/Inf/range/overflow |\n");
    md.push_str("| Config AST (`config::directive`) | 31: all newtypes, directives, bounds |\n");
    md.push_str("| Config diagnostics (`config::diagnostic`) | 3: severity, parse result |\n");
    md.push_str("| Config lexer (`config::lexer`) | 67: cursor, keywords, numbers, quoted strings, NUL rejection, continuation, recovery, char class, length boundaries |\n");
    md.push_str("| Clock adjfreq (`io::clock`) | 3: adjtimex conversion, overflow |\n");
    md.push_str("| Socket loopback (`io::socket`) | 6: IPv4/v6, bind options, timestamp |\n\n");

    md.push_str(
        "## Implemented — unverified against oracle\n\n| Surface | Notes |\n|---------|-------|\n",
    );
    md.push_str("| ntpd CLI | Flags parsed; fail-closed exit 78. No behavioral tests. |\n");
    md.push_str("| ntpctl CLI | Prefix matching; ambiguity rejection. |\n");
    md.push_str("| adjtime_oss (`io::clock`) | No dedicated test. |\n");
    md.push_str("| Process (`io::process`) | No runtime credential test. |\n");
    md.push_str("| Socket timestamping (`io::socket`) | recvmsg SO_TIMESTAMP written; no behavioral tests. |\n\n");

    md.push_str("## Config surfaces\n\n");
    md.push_str("- **parse.y lexer** (`config::lexer`) — Implemented, 67 tests: cursor, keywords, numbers, quoted strings, NUL rejection, backslash-newline, error recovery, char class, token length boundaries\n");
    md.push_str("- **parse.y parser** — **Planned**: directive grammar, semantic validation\n");
    md.push_str("- **config.c runtime lowering** — **Planned**: DNS resolution, peer creation\n\n");

    md.push_str("## Not yet wired\n\n- NTP poll loop, clock discipline, source selection, control socket, constraint validation, sensor framework, DNS, privsep\n\n");

    md.push_str(
        "## Platform gaps\n\n| Platform | adjfreq | Status |\n|----------|---------|--------|\n",
    );
    md.push_str("| Linux | adjtimex | Implemented (internally tested) |\n| FreeBSD | adjfreq(2) | Stub |\n| OpenBSD | adjfreq(2) | Stub |\n");
    md.push_str("| macOS | mach_timebase | Stub |\n| Solaris | adjtime(2) | Stub |\n\n");

    md.push_str("## Unimplemented features\n\n- Symmetric/broadcast/control/private modes, Autokey, NTS, MS-SNTP, kernel PLL, reference clocks, hardware timestamping, privsep imsg\n\n");
    md.push_str("## Highest-risk unsafe module\n\n`io::socket` — recvmsg, CMSG macros, sockaddr casts. Structurally correct; no runtime tests for kernel timestamp ancillary parsing or truncation rejection.\n\n");
    md.push_str("## Deployment boundary\n\nopenntpd-rs does **not**: discipline a real system clock in production, run as a privileged daemon, connect to a running ntpd, or make any production-replacement claim.\n");

    std::fs::write(docs_gen.join("negative-capabilities.md"), &md)?;
    Ok(())
}
