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
            c_file: "client.c (query engine)",
            rs_module: "ntp::query",
            status: "Implemented — internally tested",
            tests: &[
                "test_build_query_correct_mode_version",
                "test_build_query_all_fields_sane",
                "test_build_query_zero_timestamp",
                "test_process_response_updates_peer",
                "test_process_response_updates_filter",
                "test_process_response_wrong_mode",
                "test_process_response_kiss_of_death",
                "test_process_response_invalid_stratum",
                "test_process_response_invalid_version",
                "test_process_response_replay_attack",
                "test_process_response_bad_timestamp_zero_receive",
                "test_process_response_bad_timestamp_zero_transmit",
                "test_process_response_sets_delay_flash",
                "test_process_response_sets_offset_flash",
                "test_process_response_no_flash_for_good_response",
                "test_query_state_new_is_idle",
                "test_query_state_send_query",
                "test_query_state_send_receive_cycle",
                "test_query_state_rejects_wrong_origin",
                "test_query_state_timeout_not_outstanding",
                "test_query_state_timeout_elapsed",
                "test_query_state_no_timeout_before_deadline",
                "test_query_state_timeout_exact_boundary",
                "test_full_query_lifecycle",
                "test_integration_multiple_queries_fill_filter",
                "test_integration_consecutive_queries",
                "test_integration_error_response_does_not_clear_outstanding",
                "test_edge_zero_origin_timestamp",
                "test_edge_negative_delay_does_not_set_flash",
                "test_edge_wrapping_timestamps",
                "test_edge_very_large_offset",
                "test_edge_zero_delay",
                "test_edge_kiss_code_check",
                "test_edge_round_trip_encode_decode_response",
                "test_edge_outstanding_query_replace",
                "test_edge_display_error",
                "test_query_state_default",
            ],
        },
        Surface {
            c_file: "ntpd.c (clock discipline)",
            rs_module: "ntp::clock",
            status: "Implemented — internally tested",
            tests: &[
                "test_clock_state_new_defaults",
                "test_clock_state_default_equals_new",
                "test_single_update_produces_adjustment",
                "test_single_update_nonzero_freq_delta",
                "test_multiple_updates_converge_frequency",
                "test_pure_fll_convergence",
                "test_step_when_offset_exceeds_max_step",
                "test_slew_when_offset_within_max_step",
                "test_first_update_always_slews_even_large_offset",
                "test_step_resets_jitter",
                "test_step_count_increments",
                "test_pll_mode_at_or_below_threshold",
                "test_fll_mode_above_threshold",
                "test_pll_to_fll_transition",
                "test_fll_to_pll_transition",
                "test_set_frequency",
                "test_update_does_not_clobber_external_frequency",
                "test_should_step_exactly_at_boundary",
                "test_should_step_just_beyond_boundary",
                "test_should_step_zero",
                "test_should_step_small",
                "test_zero_offset_update",
                "test_negative_offset_update",
                "test_very_large_offset_triggers_step",
                "test_negative_large_offset_triggers_step",
                "test_jitter_increases_with_larger_offset",
                "test_jitter_decreases_with_smaller_offset",
                "test_wander_tracks_frequency_changes",
                "test_filter_jitter_all_same_offset",
                "test_filter_jitter_with_spread",
                "test_filter_jitter_single_sample",
                "test_filter_jitter_empty_filter",
                "test_filter_jitter_partial_filter",
                "test_filter_dispersion_single_peer",
                "test_filter_dispersion_multiple_peers",
                "test_filter_dispersion_empty",
                "test_rms_all_positive",
                "test_rms_negative_values",
                "test_rms_single_value",
                "test_rms_all_zeros",
                "test_rms_empty",
                "test_update_count_increments",
                "test_update_count_increments_through_step",
                "test_adjustment_offset_matches_input",
                "test_adjustment_step_sets_freq_delta_zero",
                "test_pll_freq_delta_formula",
                "test_fll_freq_delta_formula",
                "test_negative_poll_does_not_panic",
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
            c_file: "ntpd.c (event loop)",
            rs_module: "io::daemon",
            status: "Implemented — internally tested",
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
            rs_module: "config::runtime",
            status: "Implemented — internally tested",
            tests: &[
                "runtime_empty_config",
                "runtime_listen_wildcard",
                "runtime_listen_wildcard_ipv6",
                "runtime_listen_numeric",
                "runtime_server_numeric",
                "runtime_server_with_options",
                "runtime_server_hostname",
                "runtime_servers_pool",
                "runtime_constraint_url_quoted",
                "runtime_constraint_url_unquoted",
                "runtime_constraint_pinned",
                "runtime_constraint_numeric_host",
                "runtime_sensor_all_options",
                "runtime_sensor_minimal",
                "runtime_sensor_with_path",
                "runtime_query_from_ipv4",
                "runtime_query_from_ipv6",
                "runtime_rtable_preserved",
                "runtime_multiple_directives",
                "runtime_dns_id_uniqueness",
                "runtime_invalid_config_graceful",
                "runtime_server_with_dns",
                "runtime_constraint_with_dns",
                "runtime_sensor_refid_none",
            ],
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
            status: "Implemented — internally tested",
            tests: &[
                "test_peer_defaults",
                "test_peer_id_uniqueness",
                "test_peer_trusted_flag",
                "test_peer_trusted_default_false",
                "test_filter_add_sample",
                "test_filter_ring_buffer_wrap",
                "test_filter_best_sample_empty",
                "test_filter_best_sample_lowest_delay",
                "test_filter_weighted_average_of_four",
                "test_filter_dispersion_empty",
                "test_filter_dispersion_computed",
                "test_reach_all_zeros",
                "test_reach_all_ones",
                "test_reach_shift_behavior",
                "test_reach_mixed_pattern",
                "test_reach_ring_overflow",
                "test_flash_set_clear_has",
                "test_flash_combined_bits",
                "test_flash_has_any",
                "test_flash_all_bits_roundtrip",
                "test_poll_rapid_phase",
                "test_poll_stable_increase",
                "test_poll_jitter_decrease",
                "test_poll_backoff",
                "test_poll_reset_after_max_unreachable",
                "test_poll_clamped_to_min",
                "test_poll_clamped_to_max",
                "test_poll_state_recovers",
                "test_poll_no_query_clears_reach",
                "test_poll_consecutive_unreachable",
                "test_offset_delay_symmetric",
                "test_offset_delay_positive_offset",
                "test_offset_delay_negative_offset",
                "test_offset_delay_large_delay",
                "test_selection_empty",
                "test_selection_single_peer",
                "test_selection_three_close_peers",
                "test_selection_outlier_removal",
                "test_selection_intersection_filters",
                "test_selection_clustering_reduces_to_three",
                "test_selection_weighted_combine",
                "test_filter_wrapping",
                "test_reach_overflow",
                "test_poll_counting",
                "test_poll_unreachable_tracking",
                "test_wrong_f64_negative",
                "test_full_peer_lifecycle",
            ],
        },
        Surface {
            c_file: "server.c",
            rs_module: "server",
            status: "Implemented — internally tested",
            tests: &[
                "server_peer_defaults",
                "server_peer_usage_tracking",
                "validate_client_request_mode_3",
                "validate_client_request_rejects_mode_1",
                "validate_client_request_rejects_mode_2",
                "validate_client_request_rejects_mode_4",
                "validate_client_request_rejects_mode_5",
                "validate_client_request_rejects_mode_6",
                "validate_client_request_rejects_mode_7",
                "validate_client_request_version_0_rejected",
                "validate_client_request_version_5_rejected",
                "validate_request_kiss_of_death",
                "response_basic_mode_4",
                "response_vn_propagated_from_request",
                "response_stratum_propagated",
                "response_poll_reflected",
                "response_alarm_leap_indicator",
                "response_root_delay_positive",
                "response_root_delay_negative",
                "response_reference_id_known_codes",
                "response_timestamp_origin_from_request",
                "response_timestamp_receive_from_recv_time",
                "response_timestamp_transmit_from_recv_time",
                "response_multi_request_independence",
                "response_wire_roundtrip",
                "response_zero_timestamps",
            ],
        },
        Surface {
            c_file: "control.c",
            rs_module: "control",
            status: "Implemented — internally tested",
            tests: &[
                "control_req_status_encode_decode",
                "control_req_peers_encode_decode",
                "control_req_sensors_encode_decode",
                "control_req_all_encode_decode",
                "control_req_short_buffer",
                "control_resp_status_roundtrip",
                "control_resp_status_zero_values",
                "control_resp_status_constrained",
                "control_resp_status_short_buffer",
                "control_resp_peers_roundtrip",
                "control_resp_peers_empty",
                "control_resp_peers_long_address",
                "control_resp_peers_multiple",
                "control_resp_sensors_roundtrip",
                "control_resp_sensors_empty",
                "control_resp_sensors_multiple",
                "control_resp_all_composition",
                "control_resp_truncated_decode",
                "control_resp_decode_type_short",
                "control_resp_decode_type_valid",
                "control_invalid_sync_state",
                "control_negative_offset_roundtrip",
                "control_sync_state_display",
                "control_decode_type_too_short",
                "control_payload_decode_type_too_short",
                "control_resp_decode_type_too_short",
                "control_resp_decode_type_from_empty",
            ],
        },
        Surface {
            c_file: "constraint.c",
            rs_module: "constraint",
            status: "Implemented — internally tested",
            tests: &[
                "http_date_standard_format",
                "http_date_single_digit_day",
                "http_date_all_months",
                "http_date_case_insensitive_month",
                "http_date_missing_gmt",
                "http_date_variable_whitespace",
                "http_date_leap_year",
                "http_date_non_leap_year",
                "http_date_year_2000",
                "http_date_year_2038",
                "http_date_empty_string",
                "http_date_garbage",
                "http_date_iso_8601",
                "http_date_invalid_month",
                "http_date_invalid_hour",
                "http_date_missing_tokens",
                "median_odd_count",
                "median_even_count",
                "median_single_element",
                "median_empty_list",
                "median_skips_failed",
                "median_skips_unknown",
                "median_skips_none_date",
                "window_zero",
                "window_boundary",
                "window_inside",
                "window_outside",
                "window_far_outside",
                "constraint_construction_default",
                "constraint_with_pinned_address",
                "reasonable_date_current",
                "reasonable_date_epoch",
                "reasonable_date_before_1970_rejected",
                "reasonable_date_after_2100_rejected",
                "reasonable_date_year_2099",
                "median_even_averages_middle",
                "http_date_timezone_variants",
                "constraint_status_order",
                "constraint_status_default",
                "constraint_status_transitions",
                "is_within_constraint_edge_cases",
            ],
        },
        Surface {
            c_file: "sensors.c",
            rs_module: "sensor",
            status: "Implemented — internally tested",
            tests: &[
                "sensor_default_construction",
                "sensor_zero_correction",
                "sensor_positive_correction",
                "sensor_negative_correction",
                "sensor_multiple_readings",
                "sensor_stale_detection",
                "sensor_stale_no_reading",
                "sensor_stale_boundary",
                "sensor_mark_failed",
                "sensor_readings_increment_count",
                "sensor_pps_discovery_default",
                "sensor_pps_discovery_custom",
                "sensor_pps_discovery_zero",
                "sensor_offset_zero_nanos",
                "sensor_offset_negative_time",
                "sensor_offset_negative_nanos",
                "sensor_offset_large_correction",
                "sensor_selection_empty",
                "sensor_selection_single",
                "sensor_selection_no_readings",
                "sensor_selection_all_failed",
                "sensor_selection_weighted",
                "sensor_selection_zero_weight_fallback",
                "sensor_selection_partial_eligibility",
                "sensor_future_timestamp",
                "sensor_i64_max_correction",
            ],
        },
        Surface {
            c_file: "dns.c",
            rs_module: "dns",
            status: "Implemented — internally tested",
            tests: &[
                "dns_request_creation",
                "dns_response_success",
                "dns_response_failure",
                "dns_response_empty_addresses",
                "dns_response_id_matches_request",
                "dns_response_multiple_addresses",
                "url_split_no_scheme",
                "url_split_with_scheme",
                "url_split_with_path",
                "url_split_default_path",
                "url_split_backslash_path",
                "url_split_empty",
                "url_split_https_only",
                "hostname_valid_simple",
                "hostname_valid_with_dots",
                "hostname_valid_with_hyphens",
                "hostname_rejected_empty",
                "hostname_rejected_too_long",
                "hostname_rejected_invalid_chars",
                "hostname_rejected_leading_hyphen",
                "hostname_rejected_trailing_dot",
                "address_family_default",
                "address_family_explicit",
                "dns_request_id_uniqueness",
                "dns_response_success_with_addresses",
                "url_split_complex_url",
            ],
        },
        Surface {
            c_file: "log.c",
            rs_module: "log",
            status: "Implemented — internally tested",
            tests: &[
                "log_level_ordering",
                "log_threshold_default",
                "log_threshold_set_get",
                "log_threshold_filters_above",
                "adjtime_threshold_exact",
                "adjtime_threshold_above",
                "adjtime_threshold_below",
                "adjtime_threshold_negative",
                "log_message_creation",
                "log_message_fields",
                "log_debug_levels",
                "log_threshold_reset",
            ],
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
    md.push_str(&format!(
        "**Total project tests: {total} (+ 3 xtask harness)**\n\n"
    ));
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
    md.push_str("| Config runtime lowering (`config::runtime`) | 24: listener creation, server config, constraint URL splitting, sensor config, query from, rtable, DNS requests |\n");
    md.push_str("| NTP client state machine (`peer`) | 47: clock filter, reachability, flash bits, poll interval, offset/delay, clock selection |\n");
    md.push_str("| NTP mode 4 server (`server`) | 26: request validation, response construction, timestamp propagation, wire roundtrip |\n");
    md.push_str("| Control socket protocol (`control`) | 27: request/response encoding, status/peers/sensors payloads, all composition |\n");
    md.push_str("| HTTPS constraint validation (`constraint`) | 41: HTTP Date parsing, median computation, constraint window, status transitions |\n");
    md.push_str("| Sensor framework (`sensor`) | 26: device model, corrections, PPS discovery, staleness, weighted selection |\n");
    md.push_str("| DNS protocol (`dns`) | 26: request/response types, URL splitting, hostname validation, address families |\n");
    md.push_str(
        "| Logging subsystem (`log`) | 12: log levels, threshold filtering, adjtime threshold |\n",
    );
    md.push_str("| Clock adjfreq (`io::clock`) | 3: adjtimex conversion, overflow |\n");
    md.push_str("| Socket loopback (`io::socket`) | 6: IPv4/v6, bind options, timestamp |\n");
    md.push_str(
        "| imsg framework (`io::imsg`) | 14: wire format, socket pair, dispatcher, handlers |\n",
    );
    md.push_str("| NTP mode 3 query engine (`ntp::query`) | 37: query construction, response validation, peer update, timeout, integration |\n");
    md.push_str("| NTP clock discipline (`ntp::clock`) | 48: PLL/FLL, step/slew, jitter, wander, filter, RMS |\n");
    md.push_str("| Daemon event loop (`io::daemon`) | 31: poll loop, timers, NTP I/O, drift file, signal handling |\n\n");

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
    md.push_str("- **config.c runtime lowering** — Implemented: DNS request generation, listen/serve/constraint/sensor lowering, rtable, query from

") ;

    md.push_str(
        "## Not yet wired

- Full daemon event loop (poll/imsg dispatch)
- Privilege separation (privsep fork + credential drop)
- Actual NTP network queries (mode 3 client over UDP)
- Full clock discipline (PLL/FLL via adjtimex)
- Runtime DNS resolution (child process via imsg)
- TLS constraint connections (constraint validation)
- Sensor device I/O (read /dev/pps0)
- Daemon mode background fork (-d without -n)
- Runtime privsep, SCM_RIGHTS, pledge/seccomp
- DNS resolution child process
- TLS constraint connections
- Full daemon mode (background, signal-based lifecycle)

",
    );

    md.push_str(
        "## Platform gaps\n\n| Platform | adjfreq | adjtime | Clock read | Socket | Status |\n|----------|---------|---------|------------|--------|--------|\n",
    );
    md.push_str("| Linux | adjtimex | adjtime_oss | clock_gettime | SOCK_CLOEXEC | Supported |\n| FreeBSD | adjfreq(2) | adjtime_oss | clock_gettime | SOCK_CLOEXEC | Supported |\n| OpenBSD | adjfreq(2) | adjtime_oss | clock_gettime | SOCK_CLOEXEC | Stub |\n");
    md.push_str("| macOS | Unsupported | adjtime_oss | mach_timebase | fcntl FD_CLOEXEC | Supported |\n| Solaris | — | adjtime(2) | — | — | Stub |\n\n");

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
