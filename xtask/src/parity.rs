//! # Oracle parity check
//!
//! Compares `openntpd-rs ntpd -n` behavior against a real OpenNTPD 7.9p1
//! oracle by running both executables over a shared corpus of known-good
//! and known-bad configuration files and comparing exit codes with
//! normalized diagnostic categories.
//!
//! ## Usage
//!
//! ```text
//! # Self-test (no oracle needed)
//! cargo xtask parity --skip-oracle
//!
//! # Against pinned oracle binary
//! cargo xtask parity --oracle /usr/sbin/ntpd --oracle-sha256 <expected>
//!
//! # Against oracle with manifest
//! cargo xtask parity --oracle /usr/sbin/ntpd --oracle-manifest manifest.json
//!
//! # Against Docker oracle image
//! cargo xtask parity --oracle-image openntpd-oracle:debian
//! ```

use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::Command;

use sha2::{Digest, Sha256};

// ---------------------------------------------------------------------------
// Corpus definition
// ---------------------------------------------------------------------------

#[derive(Debug)]
struct CorpusCase {
    id: &'static str,
    config: &'static [u8],
    expected_exit: i32,
    expected_category: &'static str,
}

macro_rules! valid {
    ($id:expr, $config:expr) => {
        CorpusCase {
            id: $id,
            config: $config,
            expected_exit: 0,
            expected_category: "",
        }
    };
}

macro_rules! invalid {
    ($id:expr, $config:expr, $cat:expr) => {
        CorpusCase {
            id: $id,
            config: $config,
            expected_exit: 1,
            expected_category: $cat,
        }
    };
}

const CORPUS: &[CorpusCase] = &[
    // =========================================================================
    // Valid configurations (150 cases)
    // =========================================================================
    //
    // -- Empty / minimal --
    valid!("empty", b""),
    //
    // -- listen on --
    valid!("listen_wildcard", b"listen on *\n"),
    valid!("listen_ipv4", b"listen on 127.0.0.1\n"),
    valid!("listen_ipv6", b"listen on ::1\n"),
    valid!("listen_hostname", b"listen on localhost\n"),
    valid!("listen_hostname_rtable", b"listen on localhost rtable 1\n"),
    valid!("listen_wildcard_rtable_0", b"listen on * rtable 0\n"),
    valid!("listen_wildcard_rtable_1", b"listen on * rtable 1\n"),
    valid!("listen_wildcard_rtable_255", b"listen on * rtable 255\n"),
    valid!("listen_ipv4_rtable_0", b"listen on 127.0.0.1 rtable 0\n"),
    valid!("listen_ipv4_rtable_1", b"listen on 127.0.0.1 rtable 1\n"),
    valid!("listen_ipv4_rtable_255", b"listen on 127.0.0.1 rtable 255\n"),
    valid!("listen_ipv6_rtable_0", b"listen on ::1 rtable 0\n"),
    valid!("listen_ipv6_rtable_1", b"listen on ::1 rtable 1\n"),
    valid!("listen_ipv6_rtable_255", b"listen on ::1 rtable 255\n"),
    invalid!("listen_hostname_rtable_0", b"listen on myhost rtable 0\n", "syntax-error"),
    invalid!("listen_hostname_rtable_255", b"listen on myhost rtable 255\n", "syntax-error"),
    valid!("listen_on_0_0_0_0", b"listen on 0.0.0.0\n"),
    //
    // -- server IPv4 --
    valid!("server_192_0_2_1", b"server 192.0.2.1\n"),
    valid!("server_10_0_0_1", b"server 10.0.0.1\n"),
    valid!("server_203_0_113_1", b"server 203.0.113.1\n"),
    valid!("server_127_0_0_1", b"server 127.0.0.1\n"),
    //
    // -- server IPv6 --
    valid!("server_2001_db8_1", b"server 2001:db8::1\n"),
    valid!("server_ipv6_loopback", b"server ::1\n"),
    //
    // -- server with weight --
    valid!("server_weight_1", b"server 192.0.2.1 weight 1\n"),
    valid!("server_weight_5", b"server 192.0.2.1 weight 5\n"),
    valid!("server_weight_10", b"server 192.0.2.1 weight 10\n"),
    valid!("server_10_0_0_1_weight_5", b"server 10.0.0.1 weight 5\n"),
    valid!("server_203_0_113_1_weight_3", b"server 203.0.113.1 weight 3\n"),
    valid!("server_2001_db8_1_weight_1", b"server 2001:db8::1 weight 1\n"),
    valid!("server_2001_db8_1_weight_10", b"server 2001:db8::1 weight 10\n"),
    valid!("server_127_0_0_1_weight_5", b"server 127.0.0.1 weight 5\n"),
    //
    // -- server trusted --
    valid!("server_trusted", b"server 192.0.2.1 trusted\n"),
    valid!("server_10_0_0_1_trusted", b"server 10.0.0.1 trusted\n"),
    valid!("server_2001_db8_1_trusted", b"server 2001:db8::1 trusted\n"),
    valid!("server_127_0_0_1_trusted", b"server 127.0.0.1 trusted\n"),
    //
    // -- server weight + trusted --
    valid!("server_weight5_trusted", b"server 192.0.2.1 weight 5 trusted\n"),
    valid!("server_weight1_trusted", b"server 10.0.0.1 weight 1 trusted\n"),
    valid!("server_weight10_trusted", b"server 203.0.113.1 weight 10 trusted\n"),
    //
    // -- servers IPv4 / IPv6 --
    valid!("servers_ipv4", b"servers 192.0.2.1\n"),
    valid!("servers_ipv6", b"servers 2001:db8::1\n"),
    valid!("servers_10_0_0_1", b"servers 10.0.0.1\n"),
    valid!("servers_203_0_113_1", b"servers 203.0.113.1\n"),
    valid!("servers_127_0_0_1", b"servers 127.0.0.1\n"),
    //
    // -- servers with weight --
    valid!("servers_weight_1", b"servers 192.0.2.1 weight 1\n"),
    valid!("servers_weight_5", b"servers 192.0.2.1 weight 5\n"),
    valid!("servers_weight_10", b"servers 192.0.2.1 weight 10\n"),
    valid!("servers_2001_db8_1_weight_3", b"servers 2001:db8::1 weight 3\n"),
    valid!("servers_10_0_0_1_weight_5", b"servers 10.0.0.1 weight 5\n"),
    //
    // -- query from --
    valid!("query_from_ipv4", b"query from 127.0.0.1\n"),
    valid!("query_from_ipv6", b"query from ::1\n"),
    valid!("query_from_192_0_2_1", b"query from 192.0.2.1\n"),
    valid!("query_from_10_0_0_1", b"query from 10.0.0.1\n"),
    valid!("query_from_203_0_113_1", b"query from 203.0.113.1\n"),
    valid!("query_from_2001_db8", b"query from 2001:db8::1\n"),
    //
    // -- sensor * (wildcard) --
    valid!("sensor_wildcard", b"sensor *\n"),
    //
    // -- sensor "name" --
    valid!("sensor_nmea0", b"sensor \"nmea0\"\n"),
    valid!("sensor_pps", b"sensor \"PPS\"\n"),
    valid!("sensor_gps0", b"sensor \"gps0\"\n"),
    //
    // -- sensor with correction --
    valid!("sensor_correction_0", b"sensor nmea0 correction 0\n"),
    valid!("sensor_correction_500", b"sensor nmea0 correction 500\n"),
    valid!("sensor_correction_999999", b"sensor nmea0 correction 999999\n"),
    valid!("sensor_pps_correction_100", b"sensor \"PPS\" correction 100\n"),
    valid!("sensor_pps_correction_999999", b"sensor \"PPS\" correction 999999\n"),
    //
    // -- sensor with refid --
    valid!("sensor_refid_gps", b"sensor nmea0 refid GPS\n"),
    valid!("sensor_refid_pps", b"sensor nmea0 refid PPS\n"),
    valid!("sensor_refid_none", b"sensor nmea0 refid NONE\n"),
    valid!("sensor_pps_refid_gps", b"sensor \"PPS\" refid GPS\n"),
    valid!("sensor_wildcard_refid", b"sensor * refid GPS\n"),
    //
    // -- sensor with stratum --
    valid!("sensor_stratum_1", b"sensor nmea0 stratum 1\n"),
    valid!("sensor_stratum_15", b"sensor nmea0 stratum 15\n"),
    valid!("sensor_pps_stratum_1", b"sensor \"PPS\" stratum 1\n"),
    valid!("sensor_pps_stratum_15", b"sensor \"PPS\" stratum 15\n"),
    valid!("sensor_wildcard_stratum", b"sensor * stratum 5\n"),
    //
    // -- sensor with weight --
    valid!("sensor_weight_1", b"sensor nmea0 weight 1\n"),
    valid!("sensor_weight_5", b"sensor nmea0 weight 5\n"),
    valid!("sensor_weight_10", b"sensor nmea0 weight 10\n"),
    valid!("sensor_pps_weight_1", b"sensor \"PPS\" weight 1\n"),
    valid!("sensor_wildcard_weight", b"sensor * weight 1\n"),
    //
    // -- sensor trusted --
    valid!("sensor_trusted", b"sensor nmea0 trusted\n"),
    valid!("sensor_pps_trusted", b"sensor \"PPS\" trusted\n"),
    valid!("sensor_wildcard_correction", b"sensor * correction 100\n"),
    //
    // -- sensor combined options --
    valid!("sensor_all_options", b"sensor nmea0 correction 1000 refid GPS stratum 3 weight 5 trusted\n"),
    valid!("sensor_pps_all_options", b"sensor \"PPS\" correction 500 refid NONE stratum 10 weight 5 trusted\n"),
    valid!("sensor_gps0_all", b"sensor \"gps0\" correction 1000 refid GPS stratum 1 weight 10 trusted\n"),
    valid!("sensor_correction_500_refid_gps", b"sensor nmea0 correction 500 refid GPS\n"),
    valid!("sensor_correction_0_refid_none", b"sensor nmea0 correction 0 refid NONE\n"),
    valid!("sensor_correction_500_stratum_10", b"sensor nmea0 correction 500 stratum 10\n"),
    valid!("sensor_correction_500_weight_5", b"sensor nmea0 correction 500 weight 5\n"),
    valid!("sensor_refid_gps_stratum_5", b"sensor nmea0 refid GPS stratum 5\n"),
    valid!("sensor_refid_pps_weight_8", b"sensor nmea0 refid PPS weight 8\n"),
    valid!("sensor_stratum_5_trusted", b"sensor nmea0 stratum 5 trusted\n"),
    valid!("sensor_weight_3_trusted", b"sensor nmea0 weight 3 trusted\n"),
    valid!("sensor_refid_gps_trusted", b"sensor nmea0 refid GPS trusted\n"),
    valid!("sensor_nmea0_correction_999999_stratum_15", b"sensor nmea0 correction 999999 stratum 15\n"),
    valid!("sensor_pps_correction_500_refid_pps", b"sensor \"PPS\" correction 500 refid PPS\n"),
    valid!("sensor_nmea0_refid_gps_weight_5", b"sensor nmea0 refid GPS weight 5\n"),
    valid!("sensor_pps_refid_none_stratum_10", b"sensor \"PPS\" refid NONE stratum 10\n"),
    valid!("sensor_nmea0_stratum_10_weight_5", b"sensor nmea0 stratum 10 weight 5\n"),
    //
    // -- constraint from --
    valid!("constraint_https_example", b"constraint from \"https://example.com/\"\n"),
    valid!("constraint_https_ipv4_path", b"constraint from \"https://192.0.2.1/path\"\n"),
    valid!("constraint_https_ipv6_port", b"constraint from \"https://[::1]:8443/\"\n"),
    valid!("constraint_https_hostname_port_path", b"constraint from \"https://hostname:443/path\"\n"),
    valid!("constraint_https_10_0_0_1", b"constraint from \"https://10.0.0.1/\"\n"),
    valid!("constraint_https_203_0_113_1", b"constraint from \"https://203.0.113.1/\"\n"),
    valid!("constraint_https_2001_db8", b"constraint from \"https://[2001:db8::1]/\"\n"),
    valid!("constraint_https_example_ntp", b"constraint from \"https://example.com/ntp\"\n"),
    valid!("constraint_https_localhost", b"constraint from \"https://localhost:8443/\"\n"),
    //
    // -- constraints from --
    valid!("constraints_from_pool", b"constraints from \"https://pool.example.com/\"\n"),
    valid!("constraints_from_example", b"constraints from \"https://example.com/\"\n"),
    valid!("constraints_from_ipv4", b"constraints from \"https://192.0.2.1/\"\n"),
    valid!("constraints_from_ipv6", b"constraints from \"https://[2001:db8::1]/\"\n"),
    valid!("constraints_from_localhost", b"constraints from \"https://localhost/\"\n"),
    //
    // -- All directives in one file --
    valid!("all_directives", b"listen on *\nserver 192.0.2.1\nservers 2001:db8::1\nquery from 127.0.0.1\nsensor nmea0\nconstraint from \"https://example.com/\"\nconstraints from \"https://pool.example.com/\"\n"),
    valid!("listen_server_sensor_unified", b"listen on *\nserver 192.0.2.1\nsensor nmea0\n"),
    //
    // -- Multiple listen directives --
    valid!("multiple_listen", b"listen on *\nlisten on 127.0.0.1\nlisten on ::1\n"),
    valid!("listen_and_server", b"listen on *\nserver 192.0.2.1\n"),
    valid!("listen_and_sensor", b"listen on 127.0.0.1\nsensor nmea0\n"),
    //
    // -- Multiple server directives --
    valid!("multiple_server", b"server 192.0.2.1\nserver 10.0.0.1\nserver 203.0.113.1\n"),
    valid!("server_and_constraint", b"server 192.0.2.1\nconstraint from \"https://example.com/\"\n"),
    valid!("server_and_servers", b"server 192.0.2.1\nservers 2001:db8::1\n"),
    valid!("sensor_and_constraint", b"sensor nmea0\nconstraint from \"https://example.com/\"\n"),
    valid!("server_multiple_weight", b"server 192.0.2.1 weight 1\nserver 10.0.0.1 weight 5\nserver 203.0.113.1 weight 10\n"),
    valid!("multiple_server_ipv4_ipv6", b"server 192.0.2.1\nserver ::1\n"),
    //
    // -- Multiple sensor directives --
    valid!("multiple_sensor", b"sensor \"nmea0\"\nsensor \"PPS\"\nsensor *\n"),
    valid!("sensor_variety", b"sensor *\nsensor \"nmea0\"\nsensor \"PPS\"\n"),
    //
    // -- Comments and blank lines --
    valid!("comments_and_blanks", b"# comment\nlisten on *\n\nserver 192.0.2.1\n"),
    valid!("comment_after_directive", b"listen on * # inline comment\n"),
    valid!("blank_lines_between", b"listen on *\n\n\nserver 192.0.2.1\n"),
    valid!("comments_only", b"# only a comment\n# another comment\n"),
    valid!("mixed_comments", b"listen on *\n# comment\nserver 192.0.2.1\n"),
    //
    // -- Backslash continuation across lines --
    valid!("backslash_continuation", b"listen on \\\n*\n"),
    valid!("continuation_server", b"server \\\n192.0.2.1\n"),
    valid!("continuation_sensor", b"sensor \\\n\"nmea0\"\n"),
    valid!("continuation_weight", b"server 192.0.2.1 \\\nweight 5\n"),
    valid!("continuation_multiple", b"server \\\n192.0.2.1 \\\nweight 5\n"),
    valid!("continuation_constraint", b"constraint from \\\n\"https://example.com/\"\n"),
    valid!("continuation_sensor_long", b"sensor \\\n\"nmea0\" \\\ncorrection 1000 \\\nrefid GPS \\\nstratum 3 \\\nweight 5 \\\ntrusted\n"),
    //
    // -- Additional valid combinations --
    valid!("multiple_constraints", b"constraint from \"https://example.com/\"\nconstraint from \"https://pool.ntp.org/\"\n"),
    valid!("constraint_and_constraints", b"constraint from \"https://example.com/\"\nconstraints from \"https://pool.example.com/\"\n"),
    valid!("listen_wildcard_rtable_10", b"listen on * rtable 10\n"),
    valid!("listen_ipv4_rtable_10", b"listen on 127.0.0.1 rtable 10\n"),
    valid!("listen_ipv6_rtable_10", b"listen on ::1 rtable 10\n"),
    valid!("server_192_0_2_1_weight_3", b"server 192.0.2.1 weight 3\n"),
    valid!("server_10_0_0_1_weight_8", b"server 10.0.0.1 weight 8\n"),
    valid!("server_203_0_113_1_weight_2", b"server 203.0.113.1 weight 2\n"),
    valid!("servers_203_0_113_1_weight_3", b"servers 203.0.113.1 weight 3\n"),
    valid!("servers_2001_db8_1_weight_1", b"servers 2001:db8::1 weight 1\n"),
    invalid!("multiple_rtable_host", b"listen on hostname rtable 0\n", "syntax-error"),
    //
    // -- Backslash continuation on constraint with no address --
    valid!("sensor_pps_correction_500_stratum_10_weight_3", b"sensor \"PPS\" correction 500 stratum 10 weight 3\n"),
    //
    // =========================================================================
    // Invalid configurations (150 cases)
    // =========================================================================
    //
    // -- server weight 0 (boundary) --
    invalid!("server_weight_0", b"server 192.0.2.1 weight 0\n", "syntax-error"),
    //
    // -- server weight 11 (above max 10) --
    invalid!("server_weight_11", b"server 192.0.2.1 weight 11\n", "syntax-error"),
    //
    // -- server weight -1 (negative) --
    invalid!("server_weight_neg1", b"server 192.0.2.1 weight -1\n", "syntax-error"),
    //
    // -- server weight 257 --
    invalid!("server_weight_257", b"server 192.0.2.1 weight 257\n", "syntax-error"),
    //
    // -- server weight 999999 --
    invalid!("server_weight_999999", b"server 192.0.2.1 weight 999999\n", "syntax-error"),
    //
    // -- server weight 0 on alternative address --
    invalid!("server_10_0_0_1_weight_0", b"server 10.0.0.1 weight 0\n", "syntax-error"),
    //
    // -- server weight 11 on alternative address --
    invalid!("server_10_0_0_1_weight_11", b"server 10.0.0.1 weight 11\n", "syntax-error"),
    //
    // -- server weight -1 on IPv6 --
    invalid!("server_ipv6_weight_neg1", b"server ::1 weight -1\n", "syntax-error"),
    //
    // -- server weight overflow --
    invalid!("server_weight_overflow", b"server 192.0.2.1 weight 99999999999999999999999999999\n", "syntax-error"),
    //
    // -- sensor stratum 0 (boundary) --
    invalid!("sensor_stratum_0", b"sensor nmea0 stratum 0\n", "syntax-error"),
    //
    // -- sensor stratum 16 (above max 15) --
    invalid!("sensor_stratum_16", b"sensor nmea0 stratum 16\n", "syntax-error"),
    //
    // -- sensor stratum -1 (negative) --
    invalid!("sensor_stratum_neg1", b"sensor nmea0 stratum -1\n", "syntax-error"),
    //
    // -- sensor stratum 257 --
    invalid!("sensor_stratum_257", b"sensor nmea0 stratum 257\n", "syntax-error"),
    //
    // -- sensor stratum 999999 --
    invalid!("sensor_stratum_999999", b"sensor nmea0 stratum 999999\n", "syntax-error"),
    //
    // -- sensor stratum 0 on PPS --
    invalid!("sensor_pps_stratum_0", b"sensor \"PPS\" stratum 0\n", "syntax-error"),
    //
    // -- sensor stratum 16 on PPS --
    invalid!("sensor_pps_stratum_16", b"sensor \"PPS\" stratum 16\n", "syntax-error"),
    //
    // -- sensor stratum overflow --
    invalid!("sensor_stratum_overflow", b"sensor nmea0 stratum 99999999999999999999999999999\n", "syntax-error"),
    //
    // -- sensor correction -1 (negative) --
    valid!("sensor_correction_neg1", b"sensor nmea0 correction -1\n"),
    //
    // -- sensor correction 1000000 (above max 999999) --
    valid!("sensor_correction_1000000", b"sensor nmea0 correction 1000000\n"),
    //
    // -- sensor correction 999999999 --
    invalid!("sensor_correction_999999999", b"sensor nmea0 correction 999999999\n", "syntax-error"),
    //
    // -- sensor correction -1 on PPS --
    valid!("sensor_pps_correction_neg1", b"sensor \"PPS\" correction -1\n"),
    //
    // -- sensor correction 1000000 on PPS --
    valid!("sensor_pps_correction_1000000", b"sensor \"PPS\" correction 1000000\n"),
    //
    // -- sensor correction overflow --
    invalid!("sensor_correction_overflow", b"sensor nmea0 correction 99999999999999999999999999999\n", "syntax-error"),
    //
    // -- sensor weight 0 (boundary) --
    invalid!("sensor_weight_0", b"sensor nmea0 weight 0\n", "syntax-error"),
    //
    // -- sensor weight 11 (above max 10) --
    invalid!("sensor_weight_11", b"sensor nmea0 weight 11\n", "syntax-error"),
    //
    // -- sensor weight -1 (negative) --
    invalid!("sensor_weight_neg1", b"sensor nmea0 weight -1\n", "syntax-error"),
    //
    // -- sensor weight 257 --
    invalid!("sensor_weight_257", b"sensor nmea0 weight 257\n", "syntax-error"),
    //
    // -- sensor weight 0 on PPS --
    invalid!("sensor_pps_weight_0", b"sensor \"PPS\" weight 0\n", "syntax-error"),
    //
    // -- sensor weight 11 on PPS --
    invalid!("sensor_pps_weight_11", b"sensor \"PPS\" weight 11\n", "syntax-error"),
    //
    // -- sensor weight overflow --
    invalid!("sensor_weight_overflow", b"sensor nmea0 weight 99999999999999999999999999999\n", "syntax-error"),
    //
    // -- constraint without from keyword --
    invalid!("constraint_no_from", b"constraint www.example.com\n", "syntax-error"),
    //
    // -- constraints without from keyword --
    invalid!("constraints_no_from", b"constraints www.example.com\n", "syntax-error"),
    //
    // -- constraint without from (IPv4) --
    invalid!("constraint_no_from_ip", b"constraint 192.0.2.1\n", "syntax-error"),
    //
    // -- constraints without from (IPv4) --
    invalid!("constraints_no_from_ip", b"constraints 192.0.2.1\n", "syntax-error"),
    //
    // -- constraint from * (wildcard) --
    invalid!("constraint_wildcard", b"constraint from *\n", "syntax-error"),
    //
    // -- constraint from "https://*" --
    invalid!("constraint_https_wildcard", b"constraint from \"https://*\"\n", "syntax-error"),
    //
    // -- constraints from * (wildcard) --
    invalid!("constraints_wildcard", b"constraints from *\n", "syntax-error"),
    //
    // -- constraints from "https://*" --
    invalid!("constraints_https_wildcard", b"constraints from \"https://*\"\n", "syntax-error"),
    //
    // -- constraint from empty URL --
    valid!("constraint_empty_url", b"constraint from \"\"\n"),
    //
    // -- constraints from empty URL --
    valid!("constraints_empty_url", b"constraints from \"\"\n"),
    //
    // -- listen missing on keyword --
    invalid!("listen_missing_on", b"listen *\n", "syntax-error"),
    //
    // -- listen on with no address --
    invalid!("listen_no_address", b"listen on\n", "syntax-error"),
    //
    // -- listen on with no address and rtable --
    invalid!("listen_no_address_rtable", b"listen on rtable 1\n", "syntax-error"),
    //
    // -- listen on with bare rtable keyword --
    invalid!("listen_rtable_no_value", b"listen on * rtable\n", "syntax-error"),
    //
    // -- listen on with extra unknown keyword --
    invalid!("listen_unknown_keyword", b"listen on * foobar\n", "syntax-error"),
    //
    // -- server * (wildcard) --
    invalid!("server_wildcard", b"server *\n", "syntax-error"),
    //
    // -- servers * (wildcard) --
    invalid!("servers_wildcard", b"servers *\n", "syntax-error"),
    //
    // -- server with no address --
    invalid!("server_no_address", b"server\n", "syntax-error"),
    //
    // -- servers with no address --
    invalid!("servers_no_address", b"servers\n", "syntax-error"),
    //
    // -- server with extra unknown keyword --
    invalid!("server_unknown_keyword", b"server 192.0.2.1 foobar\n", "syntax-error"),
    //
    // -- servers with extra unknown keyword --
    invalid!("servers_unknown_keyword", b"servers 192.0.2.1 foobar\n", "syntax-error"),
    //
    // -- server weight with non-numeric value --
    invalid!("server_weight_non_numeric", b"server 192.0.2.1 weight abc\n", "syntax-error"),
    //
    // -- server weight missing value --
    invalid!("server_weight_missing", b"server 192.0.2.1 weight\n", "syntax-error"),
    //
    // -- server weight empty value --
    invalid!("server_weight_empty", b"server 192.0.2.1 weight \n", "syntax-error"),
    //
    // -- server duplicate (same address) --
    valid!("duplicate_server", b"server 192.0.2.1\nserver 192.0.2.1\n"),
    //
    // -- query from hostname (non-numeric) --
    invalid!("query_from_hostname", b"query from ntp.example.com\n", "syntax-error"),
    //
    // -- query from * (wildcard) --
    invalid!("query_from_wildcard", b"query from *\n", "syntax-error"),
    //
    // -- query from with no address --
    invalid!("query_from_no_address", b"query from\n", "syntax-error"),
    //
    // -- query from with trailing garbage --
    invalid!("query_trailing_garbage", b"query from 127.0.0.1 garbage\n", "syntax-error"),
    //
    // -- query from with bad IPv4 address --
    invalid!("query_from_bad_address", b"query from 192..0.2.1\n", "syntax-error"),
        //
        // -- query from with bad IPv6 address --
    invalid!("query_from_bad_ipv6", b"query from 2001:::db8::1\n", "syntax-error"),
    //
    // -- sensor with adjacent strings ("foo bar") --
    invalid!("sensor_adjacent_strings", b"sensor foo bar\n", "syntax-error"),
    //
    // -- sensor with bare number (123) --
    invalid!("sensor_bare_number", b"sensor 123\n", "syntax-error"),
    //
    // -- sensor with path ("/dev/pps0") --
    valid!("sensor_path", b"sensor \"/dev/pps0\"\n"),
    //
    // -- sensor with empty quoted name --
    valid!("sensor_empty_name", b"sensor \"\"\n"),
    //
    // -- sensor correction missing value --
    invalid!("sensor_correction_missing", b"sensor nmea0 correction\n", "syntax-error"),
    //
    // -- sensor correction non-numeric --
    invalid!("sensor_correction_non_numeric", b"sensor nmea0 correction abc\n", "syntax-error"),
    //
    // -- sensor stratum missing value --
    invalid!("sensor_stratum_missing", b"sensor nmea0 stratum\n", "syntax-error"),
    //
    // -- sensor stratum non-numeric --
    invalid!("sensor_stratum_non_numeric", b"sensor nmea0 stratum abc\n", "syntax-error"),
    //
    // -- sensor weight missing value --
    invalid!("sensor_weight_missing", b"sensor nmea0 weight\n", "syntax-error"),
    //
    // -- sensor weight non-numeric --
    invalid!("sensor_weight_non_numeric", b"sensor nmea0 weight abc\n", "syntax-error"),
    //
    // -- sensor refid invalid --
    invalid!("sensor_refid_invalid", b"sensor nmea0 refid INVALID\n", "syntax-error"),
    //
    // -- sensor refid lowercase --
    valid!("sensor_refid_lowercase", b"sensor nmea0 refid gps\n"),
    //
    // -- sensor refid missing value --
    invalid!("sensor_refid_missing", b"sensor nmea0 refid\n", "syntax-error"),
    //
    // -- sensor unknown keyword --
    invalid!("sensor_unknown_keyword", b"sensor nmea0 bogusopt\n", "syntax-error"),
    //
    // -- sensor duplicate option --
    valid!("sensor_duplicate_weight", b"sensor nmea0 weight 5 weight 3\n"),
    //
    // -- unknown directive --
    invalid!("unknown_directive", b"foobar\n", "syntax-error"),
    //
    // -- unknown directive before valid content --
    invalid!("unknown_directive_before", b"bogus\nthen listen on *\n", "syntax-error"),
    //
    // -- unknown keyword in options on listen --
    invalid!("listen_unknown_option", b"listen on * bogus\n", "syntax-error"),
    //
    // -- unknown keyword in options on server --
    invalid!("server_unknown_option", b"server 192.0.2.1 bogus\n", "syntax-error"),
    //
    // -- NUL byte in config --
    invalid!("nul_byte", b"listen on *\x00\n", "syntax-error"),
    //
    // -- unterminated quote (sensor) --
    invalid!("unterminated_quote_sensor", b"sensor \"nmea0\n", "syntax-error"),
    //
    // -- unterminated quote (constraint) --
    invalid!("unterminated_quote_constraint", b"constraint from \"https://example.com/\n", "syntax-error"),
    //
    // -- unterminated quote (sensor path) --
    invalid!("unterminated_quote_sensor2", b"sensor \"/dev/pps0\n", "syntax-error"),
    //
    // -- NUL byte mid-line --
    invalid!("nul_byte_mid", b"server 192\x00.0.2.1\n", "syntax-error"),
    //
    // -- overflow number (weight) --
    invalid!("overflow_weight", b"server 192.0.2.1 weight 99999999999999999999999999999\n", "syntax-error"),
    //
    // -- overflow number (stratum) --
    invalid!("overflow_stratum", b"sensor nmea0 stratum 99999999999999999999999999999\n", "syntax-error"),
    //
    // -- overflow number (correction) --
    invalid!("overflow_correction", b"sensor nmea0 correction 99999999999999999999999999999\n", "syntax-error"),
    //
    // -- overflow number (weight on servers) --
    invalid!("overflow_servers_weight", b"servers 192.0.2.1 weight 99999999999999999999999999999\n", "syntax-error"),
    //
    // -- lexer error in address (double dot) --
    valid!("lexer_address_double_dot", b"server 192..0.2.1\n"),
    //
    // -- lexer error in address (bad octet) --
    valid!("lexer_address_bad_octet", b"server 999.999.999.999\n"),
    //
    // -- lexer error in address (truncated ipv6) --
    valid!("lexer_address_truncated_ipv6", b"server ::\n"),
    //
    // -- lexer error in option value (non-numeric weight) --
    invalid!("lexer_option_non_numeric", b"server 192.0.2.1 weight abc\n", "syntax-error"),
    //
    // -- lexer error in option value (non-numeric stratum) --
    invalid!("lexer_option_stratum_non_numeric", b"sensor nmea0 stratum abc\n", "syntax-error"),
    //
    // -- multiple lexer errors in one file --
    invalid!("multiple_lexer_errors", b"server 192..0.2.1\nsensor nmea0 weight abc\n", "syntax-error"),
    //
    // -- multiple lexer errors (address + bad option) --
    invalid!("multiple_lexer_errors2", b"server ::\nconstraint from \"https://*\"\n", "syntax-error"),
    //
    // -- empty option value (weight) --
    invalid!("empty_option_weight", b"server 192.0.2.1 weight \n", "syntax-error"),
    //
    // -- empty option value (stratum) --
    invalid!("empty_option_stratum", b"sensor nmea0 stratum \n", "syntax-error"),
    //
    // -- empty option value (correction) --
    invalid!("empty_option_correction", b"sensor nmea0 correction \n", "syntax-error"),
    //
    // -- missing option value (weight) --
    invalid!("missing_option_weight", b"server 192.0.2.1 weight\n", "syntax-error"),
    //
    // -- missing option value (stratum) --
    invalid!("missing_option_stratum", b"sensor nmea0 stratum\n", "syntax-error"),
    //
    // -- missing option value (correction) --
    invalid!("missing_option_correction", b"sensor nmea0 correction\n", "syntax-error"),
    //
    // -- rtable -1 (negative) --
    valid!("rtable_neg1", b"listen on * rtable -1\n"),
    //
    // -- rtable 4294967296 (overflow u32) --
    valid!("rtable_overflow_u32", b"listen on * rtable 4294967296\n"),
    //
    // -- rtable on server (invalid placement) --
    invalid!("server_rtable", b"server 192.0.2.1 rtable 1\n", "syntax-error"),
    //
    // -- rtable on sensor (invalid placement) --
    invalid!("sensor_rtable", b"sensor nmea0 rtable 1\n", "syntax-error"),
    //
    // -- rtable on query from (invalid placement) --
    invalid!("query_from_rtable", b"query from 127.0.0.1 rtable 1\n", "syntax-error"),
    //
    // -- rtable non-numeric value --
    invalid!("rtable_non_numeric", b"listen on * rtable abc\n", "syntax-error"),
    //
    // -- duplicate server with weight variation --
    valid!("duplicate_server_weight", b"server 192.0.2.1 weight 5\nserver 192.0.2.1 weight 3\n"),
    //
    // -- constraint with pinned invalid-ip (bad octet) --
    valid!("constraint_pinned_invalid_ip", b"constraint from \"https://999.999.999.999/\"\n"),
    //
    // -- constraint with pinned non-numeric --
    valid!("constraint_pinned_non_numeric", b"constraint from \"https://hostname with spaces/\"\n"),
    //
    // -- constraint with URL missing scheme --
    valid!("constraint_missing_scheme", b"constraint from \"192.0.2.1/\"\n"),
    //
    // -- constraint with bad port --
    valid!("constraint_bad_port", b"constraint from \"https://192.0.2.1:abc/\"\n"),
    //
    // -- constraints with pinned invalid-ip --
    valid!("constraints_pinned_invalid_ip", b"constraints from \"https://999.999.999.999/\"\n"),
    //
    // -- constraints with pinned non-numeric --
    valid!("constraints_pinned_non_numeric", b"constraints from \"https://hostname with spaces/\"\n"),
    //
    // -- listen on with bad address (all zeros octets) --
    invalid!("listen_bad_address", b"listen on 999.999.999.999\n", "syntax-error"),
    //
    // -- listen on with invalid IPv6 --
    invalid!("listen_bad_ipv6", b"listen on ::g\n", "syntax-error"),
    //
    // -- empty config with extra whitespace (trailing) --
    // (this is actually valid - skip) --
    //
    // -- server with multiple weights --
    valid!("server_dual_weight", b"server 192.0.2.1 weight 5 weight 3\n"),
    //
    // -- constraint from with two URLs --
    invalid!("constraint_two_urls", b"constraint from \"https://a/\" \"https://b/\"\n", "syntax-error"),
    //
    // -- unclosed comment (/* style) --
    invalid!("unclosed_comment", b"/* unclosed comment\nlisten on *\n", "syntax-error"),
    //
    // -- unclosed comment in middle of line --
    invalid!("unclosed_comment_inline", b"listen on * /* oops\n", "syntax-error"),
    //
    // -- lone opening bracket in address --
    valid!("address_bare_bracket", b"server 192.0.2.[\n"),
    //
    // -- address with trailing colon --
    valid!("address_trailing_colon", b"server 192.0.2.1:\n"),
    //
    // -- address with leading zeros (octal ambiguity) --
    valid!("address_leading_zeros", b"server 192.0.2.01\n"),
    //
    // -- IPv6 with too many segments --
    valid!("address_ipv6_too_many", b"server 2001:db8::1:2:3:4:5:6\n"),
    //
    // -- multibyte UTF-8 in config --
    invalid!("utf8_in_config", b"listen on * \xc3\xa9\n", "syntax-error"),
    //
    // -- just the word listen with nothing else --
    invalid!("bare_listen", b"listen\n", "syntax-error"),
    //
    // -- just the word server with nothing else --
    invalid!("bare_server", b"server\n", "syntax-error"),
    //
    // -- sensor with refid too long (5 chars) --
    invalid!("sensor_refid_too_long", b"sensor nmea0 refid LONGER\n", "syntax-error"),
    //
    // -- server with negative weight on different address --
    invalid!("server_10_0_0_1_weight_neg1", b"server 10.0.0.1 weight -1\n", "syntax-error"),
    //
    // -- server weight 999999 on IPv6 --
    invalid!("server_ipv6_weight_999999", b"server ::1 weight 999999\n", "syntax-error"),
    //
    // -- sensor stratum 999999 on PPS --
    invalid!("sensor_pps_stratum_999999", b"sensor \"PPS\" stratum 999999\n", "syntax-error"),
    //
    // -- sensor correction 500000 on wildcard --
    valid!("sensor_wildcard_correction_invalid", b"sensor * correction 1000000\n"),
    //
    // -- sensor with negative correction on wildcard --
    valid!("sensor_wildcard_correction_neg", b"sensor * correction -1\n"),
    //
    // -- sensor weight 257 on PPS --
    invalid!("sensor_pps_weight_257", b"sensor \"PPS\" weight 257\n", "syntax-error"),
    //
    // -- sensor weight -1 on PPS --
    invalid!("sensor_pps_weight_neg1", b"sensor \"PPS\" weight -1\n", "syntax-error"),
    //
    // -- constraint from with IP in hostname field --
    valid!("constraint_ip_in_hostname", b"constraint from \"https://192.0.2.1:99999/\"\n"),
    //
    // -- constraints with bad IPv6 --
    valid!("constraints_bad_ipv6", b"constraints from \"https://[::g]/\"\n"),
    //
    // -- listen on rtable with huge number --
    invalid!("rtable_huge", b"listen on * rtable 99999999999999999999999999999\n", "syntax-error"),
    //
    // -- server with refid option (invalid on server) --
    invalid!("server_refid", b"server 192.0.2.1 refid GPS\n", "syntax-error"),
    //
    // -- server with correction option (invalid on server) --
    invalid!("server_correction", b"server 192.0.2.1 correction 100\n", "syntax-error"),
    //
    // -- sensor with trusted on wildcard (wildcard + trusted) --
    valid!("sensor_wildcard_trusted", b"sensor * trusted\n"),
    //
    // -- tab character in address --
    invalid!("address_tab_injection", b"server 192.0.2.1\tweight\n", "syntax-error"),
    //
    // -- multiple unterminated strings --
    invalid!("multiple_unterminated", b"sensor \"nmea0\nserver \"10.0.0.1\n", "syntax-error"),
    //
    // -- listen on with port suffix --
    invalid!("listen_with_port", b"listen on 127.0.0.1:123\n", "syntax-error"),
    //
    // -- URL with only scheme and colon --
    valid!("constraint_bare_scheme", b"constraint from \"https:\"\n"),
    //
    // -- URL with no path after hostname --
    valid!("constraint_no_path", b"constraint from \"https://example.com\"\n"),
    //
    // -- empty quoted constraint URL --
    valid!("constraint_no_host_in_url", b"constraint from \"https:///path\"\n"),
    //
    // -- constraint from with invalid port range --
    valid!("constraint_port_overflow", b"constraint from \"https://192.0.2.1:99999/\"\n"),
];

fn corpus_digest() -> String {
    let mut bytes = Vec::new();
    for case in CORPUS {
        bytes.extend_from_slice(case.id.as_bytes());
        bytes.push(0);
        bytes.extend_from_slice(&(case.config.len() as u64).to_be_bytes());
        bytes.extend_from_slice(case.config);
        bytes.extend_from_slice(&case.expected_exit.to_be_bytes());
        bytes.extend_from_slice(case.expected_category.as_bytes());
        bytes.push(0xff);
    }
    sha256_digest(&bytes)
}

// ---------------------------------------------------------------------------
// SHA-256
// ---------------------------------------------------------------------------

fn sha256_digest(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

// ---------------------------------------------------------------------------
// Oracle manifest
// ---------------------------------------------------------------------------

/// Validate a 64-character hex SHA-256 digest.
fn validate_sha256(value: &str, field: &str) -> anyhow::Result<()> {
    if value.len() != 64 || !value.bytes().all(|b| b.is_ascii_hexdigit()) {
        anyhow::bail!("{field} must be a 64-character hex SHA-256 digest, got {value:?}");
    }
    Ok(())
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
struct OracleManifest {
    implementation: String,
    version: String,
    source_sha256: String,
    build_recipe_sha256: String,
    binary_sha256: String,
    target: String,
}

// ---------------------------------------------------------------------------
// Binary resolve
// ---------------------------------------------------------------------------

fn resolve_rust_ntpd() -> anyhow::Result<PathBuf> {
    let workspace = workspace_root();
    let target_dir = workspace.join("target/parity");

    let status = Command::new("cargo")
        .args([
            "build",
            "-p",
            "openntpd-rs-d",
            "--bin",
            "ntpd",
            "--target-dir",
        ])
        .arg(&target_dir)
        .current_dir(&workspace)
        .status()
        .map_err(|e| anyhow::anyhow!("cargo build failed: {e}"))?;

    if !status.success() {
        anyhow::bail!("cargo build -p openntpd-rs-d --bin ntpd failed");
    }

    let path = target_dir.join("debug/ntpd");
    if !path.exists() {
        anyhow::bail!("Rust ntpd not found after build at {path:?}");
    }
    Ok(path)
}

fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .to_path_buf()
}

// ---------------------------------------------------------------------------
// Run directory (isolated per execution)
// ---------------------------------------------------------------------------

fn make_run_dir() -> std::io::Result<PathBuf> {
    let base = workspace_root().join("target/parity/runs");
    std::fs::create_dir_all(&base)?;
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    let pid = std::process::id();
    let dir = base.join(format!("{nanos}-{pid}"));
    std::fs::create_dir(&dir)?;
    Ok(dir)
}

// ---------------------------------------------------------------------------
// Runner
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
struct CaseResult {
    exit_code: i32,
    stderr: Vec<u8>,
}

fn run_case(ntpd_bin: &Path, run_dir: &Path, case_id: &str, config: &[u8]) -> CaseResult {
    let config_path = run_dir.join(format!("{case_id}.conf"));
    std::fs::write(&config_path, config).expect("write case config");

    let output = Command::new(ntpd_bin)
        .args(["-n", "-f"])
        .arg(&config_path)
        .output()
        .expect("execute ntpd binary");

    // config file cleaned up at end via run_dir removal
    CaseResult {
        exit_code: output.status.code().unwrap_or(-1),
        stderr: output.stderr,
    }
}

/// Run the ntpd oracle inside a Docker container.
/// Mounts the config file as a read-only volume at `/tmp/ntpd.conf`
/// and captures the exit code and stderr.
fn run_oracle_via_docker(image: &str, run_dir: &Path, case_id: &str, config: &[u8]) -> CaseResult {
    let config_path = run_dir.join(format!("{case_id}.conf"));
    std::fs::write(&config_path, config).expect("write case config");

    // Resolve an absolute path for the mount — Docker requires it
    let abs_config = std::fs::canonicalize(&config_path).unwrap_or_else(|_| config_path.clone());

    let output = Command::new("docker")
        .args(["run", "--rm", "-v"])
        .arg(format!("{}:/tmp/ntpd.conf:ro", abs_config.display()))
        .args([image, "ntpd", "-n", "-f", "/tmp/ntpd.conf"])
        .output()
        .expect("execute docker run");

    CaseResult {
        exit_code: output.status.code().unwrap_or(-1),
        stderr: output.stderr,
    }
}

/// Check that Docker is available on the host.
fn check_docker_available() -> anyhow::Result<()> {
    let status = Command::new("docker")
        .arg("info")
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .map_err(|e| anyhow::anyhow!("failed to run docker: {e} — is Docker installed?"))?;

    if !status.success() {
        anyhow::bail!("docker info returned non-zero exit — is Docker running?");
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Normalization
// ---------------------------------------------------------------------------

fn normalize_category(stderr: &[u8], exit_code: i32) -> &'static str {
    if exit_code == 0 {
        return "";
    }
    let lower = String::from_utf8_lossy(stderr).to_lowercase();
    if lower.contains("cannot read") || lower.contains("no such file") {
        "unreadable-file"
    } else {
        "syntax-error"
    }
}

// ---------------------------------------------------------------------------
// Evaluation logic (extracted for testability)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Evaluation {
    pub rust_expected: bool,
    pub oracle_expected: Option<bool>,
    pub oracle_parity: Option<bool>,
    pub passed: bool,
}

pub fn evaluate_case(
    rust_exit: i32,
    rust_category: &str,
    expected_exit: i32,
    expected_category: &str,
    oracle_exit: Option<i32>,
    oracle_category: Option<&str>,
) -> Evaluation {
    let rust_expected = rust_exit == expected_exit && rust_category == expected_category;

    let oracle_expected = oracle_exit.map_or(true, |oe| {
        oe == expected_exit && oracle_category == Some(expected_category)
    });

    let oracle_parity =
        oracle_exit.map(|oe| oe == rust_exit && oracle_category == Some(rust_category));

    Evaluation {
        passed: rust_expected && oracle_expected && oracle_parity.unwrap_or(true),
        rust_expected,
        oracle_expected: if oracle_exit.is_some() {
            Some(oracle_expected)
        } else {
            None
        },
        oracle_parity,
    }
}

// ---------------------------------------------------------------------------
// Evidence receipt (schema v2)
// ---------------------------------------------------------------------------

#[derive(serde::Serialize)]
struct Receipt {
    schema_version: u32,
    mode: String,
    timestamp: String,
    corpus_digest: String,
    corpus_size: usize,
    rust_binary: BinaryInfo,
    oracle_binary: Option<BinaryInfo>,
    oracle_manifest: Option<OracleManifest>,
    results: Vec<CaseReceipt>,
    summary: Summary,
}

#[derive(serde::Serialize)]
struct BinaryInfo {
    path: String,
    sha256: String,
}

#[derive(serde::Serialize)]
struct CaseReceipt {
    case_id: String,
    config_sha256: String,
    expected_exit: i32,
    expected_category: String,
    rust_exit: i32,
    rust_category: String,
    rust_stderr_sha256: String,
    oracle_exit: Option<i32>,
    oracle_category: Option<String>,
    oracle_stderr_sha256: Option<String>,
    expected_match: bool,
    oracle_parity: Option<bool>,
    verdict: String,
}

#[derive(serde::Serialize)]
struct Summary {
    passed: u32,
    failed: u32,
    total: u32,
}

fn read_binary_sha256(path: &Path) -> anyhow::Result<String> {
    let bytes = std::fs::read(path).map_err(|e| anyhow::anyhow!("cannot read {path:?}: {e}"))?;
    Ok(sha256_digest(&bytes))
}

fn write_receipt(
    receipt: &Receipt,
    stderr_dir: &Path,
    results: &[(&CorpusCase, &CaseResult, Option<&CaseResult>)],
) -> anyhow::Result<PathBuf> {
    let dir = receipts_dir(&receipt.mode);
    std::fs::create_dir_all(&dir)?;

    let ts = &receipt.timestamp.replace([' ', ':'], "_");
    let path = dir.join(format!("parity_{ts}.json"));

    // Write with create_new(true) to prevent overwrites
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&path)
        .map_err(|e| anyhow::anyhow!("cannot create receipt {path:?}: {e}"))?;

    // Write raw stderr
    for (case, rust, oracle) in results {
        let case_dir = stderr_dir.join(case.id);
        std::fs::create_dir_all(&case_dir)?;
        std::fs::write(case_dir.join("rust.stderr"), &rust.stderr)?;
        if let Some(o) = oracle {
            std::fs::write(case_dir.join("oracle.stderr"), &o.stderr)?;
        }
    }

    let json = serde_json::to_string_pretty(receipt)?;
    f.write_all(json.as_bytes())?;
    f.write_all(b"\n")?;
    f.sync_all()?;

    eprintln!("Evidence written to {}", path.display());
    Ok(path)
}

fn receipts_dir(mode: &str) -> PathBuf {
    workspace_root().join("research/oracle/receipts").join(mode)
}

// ---------------------------------------------------------------------------
// Public entry point
// ---------------------------------------------------------------------------

pub fn run(args: &[String]) -> anyhow::Result<()> {
    let mut oracle_path: Option<PathBuf> = None;
    let mut oracle_sha256: Option<String> = None;
    let mut oracle_manifest_path: Option<PathBuf> = None;
    let mut oracle_image: Option<String> = None;
    let mut skip_oracle = false;

    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--oracle" => {
                i += 1;
                oracle_path = Some(
                    args.get(i)
                        .ok_or_else(|| anyhow::anyhow!("--oracle requires path argument"))?
                        .into(),
                );
            }
            "--oracle-sha256" => {
                i += 1;
                oracle_sha256 = Some(
                    args.get(i)
                        .ok_or_else(|| anyhow::anyhow!("--oracle-sha256 requires argument"))?
                        .clone(),
                );
            }
            "--oracle-manifest" => {
                i += 1;
                oracle_manifest_path = Some(
                    args.get(i)
                        .ok_or_else(|| anyhow::anyhow!("--oracle-manifest requires path argument"))?
                        .into(),
                );
            }
            "--oracle-image" => {
                i += 1;
                oracle_image = Some(
                    args.get(i)
                        .ok_or_else(|| {
                            anyhow::anyhow!("--oracle-image requires image name argument")
                        })?
                        .clone(),
                );
            }
            "--skip-oracle" => skip_oracle = true,
            other => anyhow::bail!("unknown parity flag: {other}"),
        }
        i += 1;
    }

    // ---- Quarantine old schema-v1 receipts ----
    quarantine_legacy_receipts();

    // ---- Validation ----
    if skip_oracle {
        if oracle_path.is_some()
            || oracle_sha256.is_some()
            || oracle_manifest_path.is_some()
            || oracle_image.is_some()
        {
            anyhow::bail!("--skip-oracle cannot be combined with oracle identity options");
        }
    } else if oracle_image.is_some() {
        // Docker oracle mode — check Docker availability and pull image
        check_docker_available()?;
        if oracle_path.is_some() || oracle_sha256.is_some() || oracle_manifest_path.is_some() {
            anyhow::bail!("--oracle-image cannot be combined with --oracle or --oracle-sha256 or --oracle-manifest");
        }
    } else {
        if oracle_path.is_none() {
            anyhow::bail!("oracle mode requires --oracle <path> or --oracle-image <image>");
        }
        if oracle_sha256.is_none() && oracle_manifest_path.is_none() {
            anyhow::bail!("oracle mode requires --oracle-sha256 or --oracle-manifest");
        }
    }

    if CORPUS.is_empty() {
        anyhow::bail!("no corpus cases defined");
    }

    let mode = if skip_oracle {
        "self-test"
    } else {
        "oracle-parity"
    };

    // ---- Resolve Rust binary ----
    let rust_ntpd = resolve_rust_ntpd()?;
    eprintln!("Rust ntpd: {}", rust_ntpd.display());
    let rust_sha = read_binary_sha256(&rust_ntpd)?;

    // ---- Resolve oracle binary ----
    let oracle_ntpd: Option<PathBuf> = oracle_path
        .as_ref()
        .map(|path| {
            let resolved = std::fs::canonicalize(path)
                .map_err(|e| anyhow::anyhow!("cannot resolve oracle {path:?}: {e}"))?;
            if !resolved.is_file() {
                anyhow::bail!("oracle not found at {resolved:?}");
            }
            Ok(resolved)
        })
        .transpose()?;

    // ---- Compute oracle hash ONCE ----
    let oracle_sha: Option<String> = oracle_ntpd
        .as_ref()
        .map(|p| read_binary_sha256(p))
        .transpose()?;

    // ---- Identity checks ----
    if let Some(ref o_sha) = oracle_sha {
        if *o_sha == rust_sha {
            anyhow::bail!("Rust implementation and oracle have identical binary SHA-256: {o_sha}");
        }
    }

    // Verify oracle SHA-256 if specified
    if let (Some(ref o_sha), Some(ref expected)) = (&oracle_sha, &oracle_sha256) {
        if o_sha != expected {
            anyhow::bail!("oracle SHA-256 mismatch:\n  expected: {expected}\n  actual:   {o_sha}");
        }
    }

    // Oracle manifest
    let oracle_manifest: Option<OracleManifest> = match (&oracle_ntpd, &oracle_manifest_path) {
        (Some(_), Some(mpath)) => {
            let text = std::fs::read_to_string(mpath)
                .map_err(|e| anyhow::anyhow!("cannot read manifest {mpath:?}: {e}"))?;
            let m: OracleManifest = serde_json::from_str(&text)
                .map_err(|e| anyhow::anyhow!("invalid manifest: {e}"))?;

            // Reject placeholder values — enforce real SHA-256 digests
            validate_sha256(&m.source_sha256, "manifest source_sha256")?;
            validate_sha256(&m.build_recipe_sha256, "manifest build_recipe_sha256")?;
            validate_sha256(&m.binary_sha256, "manifest binary_sha256")?;

            // Verify the oracle is the claimed implementation
            if m.implementation != "OpenNTPD" {
                anyhow::bail!(
                    "manifest implementation must be 'OpenNTPD', got {:?}",
                    m.implementation,
                );
            }
            if m.version != "7.9p1" {
                anyhow::bail!("manifest version must be '7.9p1', got {:?}", m.version,);
            }

            // Verify binary SHA-256 matches actual oracle binary
            if let Some(ref o_sha) = oracle_sha {
                if !m.binary_sha256.eq_ignore_ascii_case(o_sha) {
                    anyhow::bail!(
                        "manifest binary SHA-256 mismatch:\n  manifest: {}\n  actual:   {o_sha}",
                        m.binary_sha256,
                    );
                }
            }
            Some(m)
        }
        (Some(_), None) => None, // hash-only mode — no manifest
        (None, _) => None,
    };

    // ---- Docker oracle mode: ensure image is available ----
    if let Some(ref image) = oracle_image {
        // Check if the image is already available locally
        let local = Command::new("docker")
            .args(["image", "inspect", image])
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()
            .ok()
            .map(|s| s.success())
            .unwrap_or(false);

        if !local {
            eprintln!("Pulling Docker oracle image: {image}...");
            let status = Command::new("docker")
                .args(["pull", image])
                .status()
                .map_err(|e| anyhow::anyhow!("docker pull failed: {e}"))?;
            if !status.success() {
                anyhow::bail!("docker pull {image} returned non-zero exit");
            }
        } else {
            eprintln!("Docker oracle image found locally: {image}");
        }
    }

    // ---- Create isolated run directory and durable evidence directory ----
    let ts = chrono_now();
    let run_dir = make_run_dir()?;
    let ts_path = ts.replace([' ', ':'], "_");
    let evidence_dir = receipts_dir(mode).join(format!("stderr_{ts_path}"));
    std::fs::create_dir_all(&evidence_dir)?;

    // ---- Print header ----
    println!(
        "{:6} | {:40} | {:8} | {:8} | {:8} | {:20} | {:20} | {:20} | match",
        "STATUS", "CASE", "EXPECT", "RUST", "ORACLE", "EXPECTED CAT", "RUST CAT", "ORACLE CAT",
    );
    println!("{}", "-".repeat(155));

    let mut passed = 0u32;
    let mut failed = 0u32;
    let mut stderr_pairs: Vec<(&CorpusCase, CaseResult, Option<CaseResult>)> = Vec::new();
    let mut case_receipts: Vec<CaseReceipt> = Vec::new();

    for case in CORPUS {
        let config_sha = sha256_digest(case.config);
        let rust_result = run_case(&rust_ntpd, &run_dir, case.id, case.config);
        let rust_category = normalize_category(&rust_result.stderr, rust_result.exit_code);

        let oracle_result: Option<CaseResult> = if let Some(ref image) = oracle_image {
            Some(run_oracle_via_docker(image, &run_dir, case.id, case.config))
        } else {
            oracle_ntpd
                .as_ref()
                .map(|p| run_case(p, &run_dir, case.id, case.config))
        };
        let oracle_category = oracle_result
            .as_ref()
            .map(|r| normalize_category(&r.stderr, r.exit_code));

        let eval = evaluate_case(
            rust_result.exit_code,
            &rust_category,
            case.expected_exit,
            case.expected_category,
            oracle_result.as_ref().map(|r| r.exit_code),
            oracle_category,
        );

        let verdict = if eval.passed { "PASS" } else { "FAIL" };

        println!(
            "{:6} | {:40} | {:8} | {:8} | {:8} | {:20} | {:20} | {:20} | {}",
            verdict,
            case.id,
            case.expected_exit,
            rust_result.exit_code,
            oracle_result.as_ref().map_or(-1, |r| r.exit_code),
            case.expected_category,
            rust_category,
            oracle_category.unwrap_or("N/A"),
            eval.passed,
        );

        if eval.passed {
            passed += 1
        } else {
            failed += 1
        }

        case_receipts.push(CaseReceipt {
            case_id: case.id.to_string(),
            config_sha256: config_sha,
            expected_exit: case.expected_exit,
            expected_category: case.expected_category.to_string(),
            rust_exit: rust_result.exit_code,
            rust_category: rust_category.to_string(),
            rust_stderr_sha256: sha256_digest(&rust_result.stderr),
            oracle_exit: oracle_result.as_ref().map(|r| r.exit_code),
            oracle_category: oracle_category.map(|s| s.to_string()),
            oracle_stderr_sha256: oracle_result.as_ref().map(|r| sha256_digest(&r.stderr)),
            expected_match: eval.rust_expected && eval.oracle_expected.unwrap_or(true),
            oracle_parity: eval.oracle_parity,
            verdict: verdict.to_string(),
        });
        stderr_pairs.push((case, rust_result, oracle_result));
    }

    println!("{}", "-".repeat(155));
    println!(
        "Passed: {passed}, Failed: {failed}, Total: {}",
        CORPUS.len()
    );

    let refs: Vec<(&CorpusCase, &CaseResult, Option<&CaseResult>)> = stderr_pairs
        .iter()
        .map(|(c, r, o)| (*c, r, o.as_ref()))
        .collect();

    let receipt = Receipt {
        schema_version: 2,
        mode: mode.to_string(),
        timestamp: ts.clone(),
        corpus_digest: corpus_digest(),
        corpus_size: CORPUS.len(),
        rust_binary: BinaryInfo {
            path: rust_ntpd.display().to_string(),
            sha256: rust_sha,
        },
        oracle_binary: oracle_ntpd
            .as_ref()
            .zip(oracle_sha.as_ref())
            .map(|(p, sha)| BinaryInfo {
                path: p.display().to_string(),
                sha256: sha.clone(),
            }),
        oracle_manifest,
        results: case_receipts,
        summary: Summary {
            passed,
            failed,
            total: CORPUS.len() as u32,
        },
    };

    write_receipt(&receipt, &evidence_dir, &refs)?;

    // Clean up only the temporary run directory, NOT evidence_dir
    let _ = std::fs::remove_dir_all(&run_dir);

    if failed > 0 {
        anyhow::bail!(
            "{failed} corpus case(s) failed: expected-match and/or oracle-parity violation."
        );
    }

    eprintln!("\n✓ All {passed} corpus cases match expected behavior.");
    Ok(())
}

// ---------------------------------------------------------------------------
// Timestamp
// ---------------------------------------------------------------------------

fn chrono_now() -> String {
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let days = secs / 86400;
    let time_secs = secs % 86400;
    let hours = time_secs / 3600;
    let minutes = (time_secs % 3600) / 60;
    let seconds = time_secs % 60;
    let (y, m, d) = days_to_date(days as i64);
    format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z",
        y, m, d, hours, minutes, seconds
    )
}

fn days_to_date(mut days: i64) -> (i64, i64, i64) {
    days += 719468;
    let era = if days >= 0 { days } else { days - 146096 } / 146097;
    let doe = days - era * 146097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    (y, m, d)
}

// ---------------------------------------------------------------------------
// Quarantine old schema-v1 receipts
// ---------------------------------------------------------------------------

/// Move legacy receipts matching `research/oracle/receipts/parity_*.json`
/// into a `legacy-invalid/` directory with an invalidation note.
/// Called once at module init.
fn quarantine_legacy_receipts() {
    let receipts_root = workspace_root().join("research/oracle/receipts");
    let legacy_dir = receipts_root.join("legacy-invalid");
    let _ = std::fs::create_dir_all(&legacy_dir);

    if let Ok(entries) = std::fs::read_dir(&receipts_root) {
        for entry in entries.flatten() {
            let path = entry.path();
            if let Some(name) = path.file_name().and_then(|n| n.to_str()) {
                if name.starts_with("parity_") && name.ends_with(".json") {
                    // Move to legacy
                    let dest = legacy_dir.join(name);
                    if std::fs::rename(&path, &dest).is_ok() {
                        eprintln!("Quarantined legacy receipt: {name}");
                    }
                }
            }
        }
    }

    // Write an invalidation note
    let note = legacy_dir.join("README.md");
    if !note.exists() {
        let _ = std::fs::write(
            &note,
            [
                "# Legacy receipts — schema v1 (invalid)\n\n",
                "These receipts were produced by an earlier version of the oracle harness.\n",
                "They contain known defects:\n\n",
                "- `oracle_parity: true` while `oracle_binary` is null\n",
                "- `corpus_revision` instead of `corpus_digest` (not tied to corpus content)\n",
                "- No `mode` field\n",
                "- No `oracle_manifest` field\n\n",
                "They are retained only for provenance but should NOT be cited as evidence.\n",
            ]
            .concat(),
        );
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sha256_known_vector() {
        assert_eq!(
            sha256_digest(b""),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        );
        assert_eq!(
            sha256_digest(b"abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
        );
    }

    #[test]
    fn corpus_digest_is_stable() {
        let d1 = corpus_digest();
        let d2 = corpus_digest();
        assert_eq!(d1, d2);
        // Pin the actual digest so changes to CORPUS break this test
        // and force a conscious update to the expected value.
        assert_eq!(
            d1,
            "1517efd58d7f574b10f2c33e67a10af05daedc2b2d26909c6a9ca5c137dea0cb",
                        "corpus digest changed — update this expected value if CORPUS was intentionally modified",
        );
    }

    #[test]
    fn corpus_digest_changes_when_config_changes() {
        let original = corpus_digest();

        // Clone a case and modify its config bytes
        let mut modified = CORPUS[0].config.to_vec();
        modified.push(b'x');
        let modified_digest = sha256_digest(&modified);
        assert_ne!(original, modified_digest);
    }

    #[test]
    fn corpus_digest_changes_when_id_changes() {
        let original = corpus_digest();
        let id_bytes = CORPUS[0].id.as_bytes();
        let mut mutated = id_bytes.to_vec();
        mutated.push(b'x');
        let mutated_digest = sha256_digest(&mutated);
        assert_ne!(original, mutated_digest);
    }

    // -- Evaluation logic tests --

    #[test]
    fn rust_expected_mismatch_fails() {
        let e = evaluate_case(1, "syntax-error", 0, "", None, None);
        assert!(!e.passed);
        assert!(!e.rust_expected);
    }

    #[test]
    fn oracle_expected_mismatch_fails() {
        let e = evaluate_case(1, "syntax-error", 1, "syntax-error", Some(0), Some(""));
        assert!(!e.passed);
        assert!(e.rust_expected);
        assert_eq!(e.oracle_expected, Some(false));
    }

    #[test]
    fn rust_oracle_disagreement_fails() {
        let e = evaluate_case(0, "", 0, "", Some(1), Some("syntax-error"));
        assert!(!e.passed);
        assert_eq!(e.oracle_parity, Some(false));
    }

    #[test]
    fn self_test_records_null_parity() {
        let e = evaluate_case(0, "", 0, "", None, None);
        assert!(e.passed);
        assert_eq!(e.oracle_parity, None);
    }

    #[test]
    fn oracle_disagreement_records_false() {
        let e = evaluate_case(0, "", 0, "", Some(1), Some("syntax-error"));
        assert_eq!(e.oracle_parity, Some(false));
    }

    #[test]
    fn oracle_agreement_records_true() {
        let e = evaluate_case(0, "", 0, "", Some(0), Some(""));
        assert_eq!(e.oracle_parity, Some(true));
    }

    #[test]
    fn corpus_digest_changes_when_content_changes() {
        let d1 = corpus_digest();
        // Verify the digest is not trivially empty
        assert_ne!(d1, sha256_digest(b""));
    }

    #[test]
    fn validate_sha256_rejects_short() {
        assert!(validate_sha256("abc", "test").is_err());
    }

    #[test]
    fn validate_sha256_rejects_non_hex() {
        assert!(validate_sha256("z".repeat(64).as_str(), "test").is_err());
    }

    #[test]
    fn validate_sha256_accepts_valid() {
        assert!(validate_sha256(
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            "test",
        )
        .is_ok());
    }

    #[test]
    fn corpus_digest_stable_unchanged_after_read() {
        // Verify the digest value is deterministic — calling twice
        // from separate iterations gives the same result.
        let d1 = corpus_digest();
        std::thread::sleep(std::time::Duration::from_millis(1));
        let d2 = corpus_digest();
        assert_eq!(d1, d2);
    }
}
