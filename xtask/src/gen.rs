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
            c_file: "parse.y (parser)",
            rs_module: "config::parser",
            status: "Implemented — internally tested",
            tests: &[
                "blank_lines",
                "constraint_from_quoted_https_url",
                "constraint_from_url",
                "constraint_https_url_defaults_path",
                "constraint_invalid_pinned_discards_directive",
                "constraint_requires_from",
                "constraint_wildcard_rejected",
                "constraint_https_wildcard_rejected",
                "constraint_https_wildcard_with_path_rejected",
                "constraint_https_wildcard_prefix_accepted",
                "constraint_with_pinned",
                "constraints_rejects_pinned",
                "constraints_requires_from",
                "directive_span",
                "empty_config",
                "error_skips_to_next_line",
                "invalid_listen_rtable_discards_directive",
                "invalid_sensor_option_discards_directive",
                "invalid_server_weight_discards_directive",
                "lexer_error_passthrough",
                "lexer_error_after_parser_error_preserves_next_directive",
                "lexer_error_in_address_preserves_next_directive",
                "lexer_error_in_server_option_preserves_next_directive",
                "lexer_error_preserves_following_directive",
                "listen_hostname",
                "listen_missing_on",
                "listen_numeric",
                "listen_wildcard",
                "multiple_directives",
                "query_from_hostname_rejected",
                "query_from_ipv4",
                "query_from_ipv6",
                "query_trailing_token_discards_directive",
                "rtable_u32_overflow_rejected",
                "semantic_error_span_pinned_address",
                "semantic_error_span_query_address",
                "semantic_error_span_stratum",
                "semantic_error_span_weight",
                "sensor_adjacent_strings_rejected",
                "sensor_all_options",
                "sensor_invalid_correction",
                "sensor_invalid_stratum",
                "sensor_invalid_weight",
                "sensor_number_rejected",
                "sensor_quoted_path",
                "sensor_single_name",
                "sensor_stratum_257_rejected",
                "sensor_stratum_negative_wrap_rejected",
                "sensor_unquoted_path_rejected",
                "sensor_weight_257_rejected",
                "sensor_wildcard",
                "server_invalid_weight_rejected",
                "server_minimal",
                "server_pool",
                "server_weight_257_rejected",
                "server_weight_negative_wrap_rejected",
                "server_wildcard_rejected",
                "servers_wildcard_rejected",
                "server_with_options",
                "unknown_keyword_at_start",
            ],
        },
        Surface {
            c_file: "parse.y (lexer)",
            rs_module: "config::lexer",
            status: "Implemented — internally tested",
            tests: &[
                "all_keywords",
                "backslash_before_double_quote_opens_quote",
                "backslash_before_single_quote_opens_quote",
                "brackets_inside_unquoted_string",
                "colon_prefixed_string",
                "comment_at_eof",
                "comment_only",
                "continuation_at_start_of_line",
                "continuation_between_tokens",
                "continuation_extends_comment",
                "cursor_peek_after_continuation",
                "cursor_peek_bump",
                "cursor_unread",
                "digit_hyphen_digit",
                "digit_prefixed_hostname",
                "digits_followed_by_alpha",
                "double_backslash_preserves_second",
                "keyword_case_sensitive",
                "leading_backslash_before_keyword",
                "listen_directive_line",
                "lone_minus_symbol",
                "negative_number_8095_total_accepted",
                "negative_number_8096_total_rejected",
                "negative_number_after_minus_dotted",
                "negative_number_after_minus_fallback",
                "newline_tracking",
                "non_punctuation_as_symbol",
                "nul_comment",
                "nul_quoted",
                "nul_unquoted",
                "number_continuation",
                "number_i64_max",
                "number_i64_min",
                "number_negative",
                "number_overflow_neg",
                "number_overflow_pos",
                "number_positive",
                "number_terminator_form_feed",
                "number_terminator_vertical_tab",
                "number_then_newline",
                "number_then_slash",
                "number_then_space",
                "number_zero",
                "numeric_ipv4_is_string",
                "numeric_ipv6_is_string",
                "positive_number_8095_total_accepted",
                "quoted_backslash_before_closing_quote",
                "quoted_backslash_newline",
                "quoted_double",
                "quoted_two_backslashes_before_quote_is_unterminated",
                "quoted_two_backslashes_then_two_quotes",
                "quoted_unknown_escape_reprocesses_target",
                "quoted_empty",
                "quoted_escaped_nul_returns_error",
                "quoted_escaped_quote",
                "quoted_escaped_space",
                "quoted_escaped_tab",
                "quoted_escaped_unknown_escape_preserves_both",
                "quoted_limit_8094",
                "quoted_limit_8095_rejected",
                "quoted_non_utf8",
                "quoted_raw_newline_continues",
                "quoted_single",
                "quoted_unknown_escape",
                "recovery_advances_to_next_line",
                "recovery_after_nul",
                "recovery_after_overflow",
                "recovery_after_unterminated_quote",
                "recovery_skips_escaped_newline",
                "semicolon_inside_unquoted_string",
                "simple_directive_line",
                "span_across_continuation",
                "span_keyword_before_space",
                "span_newline_after_comment",
                "span_number_before_newline",
                "span_slash_between_strings",
                "symbols",
                "underscore_prefixed_string",
                "unquoted_at_sign_permitted",
                "unquoted_backslash_removed",
                "unquoted_bang_terminates",
                "unquoted_comma_terminates",
                "unquoted_continuation_merges",
                "unquoted_limit_8095",
                "unquoted_limit_8096_rejected",
                "unquoted_paren_terminates",
                "unquoted_question_mark_permitted",
                "unquoted_slash_terminates",
                "unterminated_quote_eof",
                "unterminated_quote_newline",
                "whitespace_continuation_with_indentation",
                "wildcard_is_string",
                "wildcard_listen",
            ],
        },
        Surface {
            c_file: "config.c (lowering)",
            rs_module: "config (planned)",
            status: "Planned",
            tests: &[],
        },
        Surface {
            c_file: "ntpd.c (-n)",
            rs_module: "daemon",
            status: "Implemented — internally tested",
            tests: &[
                "valid_config_returns_ok",
                "invalid_config_returns_errors",
                "empty_config_is_valid",
                "parser_error_reported",
                "multiple_errors_collected",
                "cli_defaults",
                "cli_dash_n",
                "cli_dash_f",
                "cli_grouped_dn",
                "cli_grouped_dnv",
                "cli_repeated_v",
                "cli_missing_f_argument",
                "cli_unknown_option",
                "cli_positional_argument_rejected",
                "binary_valid_config_exit_0",
                "binary_valid_config_prints_configuration_ok",
                "binary_invalid_config_exit_1",
                "binary_invalid_config_prints_error",
                "binary_unreadable_file_exit_1",
                "binary_f_option_selects_config",
                "binary_grouped_dn",
            ],
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
    md.push_str(&format!("**Total project tests: {total} (+ 3 xtask harness)**\n\n"));
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

    let lexer_tests = surfaces()
        .iter()
        .find(|surface| surface.rs_module == "config::lexer")
        .expect("lexer surface exists")
        .tests
        .len();
    let parser_tests = surfaces()
        .iter()
        .find(|surface| surface.rs_module == "config::parser")
        .expect("parser surface exists")
        .tests
        .len();

    md.push_str("## Implemented — internally tested\n\n| Module | Tests |\n|--------|-------|\n");
    md.push_str("| NTP wire (`ntp`) | 13: wire format, unsigned dispersion, era 0–2 |\n");
    md.push_str("| NTP msg I/O (`ntp::msg`) | 4: exact-length, auth suffix |\n");
    md.push_str("| Utility (`util`) | 12: frequency, Timespec, NaN/Inf/range/overflow |\n");
    md.push_str("| Config AST (`config::directive`) | 31: all newtypes, directives, bounds |\n");
    md.push_str("| Config diagnostics (`config::diagnostic`) | 3: severity, parse result |\n");
    md.push_str(&format!(
        "| Config lexer (`config::lexer`) | {lexer_tests}: cursor, keywords, numbers, quoted strings, NUL rejection, continuation, recovery, char class, length boundaries, backslash handling, negative number limits, escaped-quote opening, spans |\n"
    ));
    md.push_str(&format!(
        "| Config parser (`config::parser`) | {parser_tests}: directive grammar, option parsing, error recovery, constraint URL splitting, spans |\n"
    ));
    md.push_str("| Clock adjfreq (`io::clock`) | 3: adjtimex conversion, overflow |\n");
    md.push_str("| Socket loopback (`io::socket`) | 6: IPv4/v6, bind options, timestamp |\n\n");

    md.push_str(
        "## Implemented — unverified against oracle\n\n| Surface | Notes |\n|---------|-------|\n",
    );
    md.push_str("| ntpd CLI | Flags parsed; fail-closed exit 78. -n mode implements config check with 6 tests. |\n");
    md.push_str("| ntpctl CLI | Prefix matching; ambiguity rejection. |\n");
    md.push_str("| adjtime_oss (`io::clock`) | No dedicated test. |\n");
    md.push_str("| Process (`io::process`) | No runtime credential test. |\n");
    md.push_str("| Socket timestamping (`io::socket`) | recvmsg SO_TIMESTAMP written; no behavioral tests. |\n\n");

    md.push_str("## Config surfaces\n\n");
    md.push_str(&format!(
        "- **parse.y lexer** (`config::lexer`) — Implemented, {lexer_tests} tests: cursor, keywords, numbers, quoted strings, NUL rejection, backslash-newline, error recovery, char class, token length boundaries, negative number limits, escaped-quote opening, spans\n"
    ));
    md.push_str(&format!(
        "- **parse.y parser** (`config::parser`) — Implemented, {parser_tests} tests: directive grammar, option parsing, end-of-line enforcement, error recovery, spans, constraint URL splitting, semantic validation\n"
    ));
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

    // Append reference to the full forensic archaeology atlas.
    md.push_str("\n---\n\n## Full forensic audit\n\n");
    md.push_str("The complete OpenNTPD code archaeology atlas and openntpd-rs vs oracle ");
    md.push_str("comparison audit is maintained separately at ");
    md.push_str("[`docs/archaeology.md`](../archaeology.md).\n");
    md.push_str("That document contains the full:\n\n");
    md.push_str("- 33-release historical timeline (2004–2026)\n");
    md.push_str("- 17 portable release version matrix\n");
    md.push_str("- 13 deep esoteric architectural surfaces (imsg, privsep, clock filter, etc.)\n");
    md.push_str("- 6-distro Docker VM comparison matrix\n");
    md.push_str("- 10 esoteric version differences\n");
    md.push_str("- C source coverage gap analysis (~9000 LOC uncovered)\n");
    md.push_str("- Lexer, parser, NTP protocol, platform, oracle harness, getopt, ");
    md.push_str("config behavior, security, and evidence status audits\n");

    std::fs::write(docs_gen.join("negative-capabilities.md"), &md)?;
    Ok(())
}
