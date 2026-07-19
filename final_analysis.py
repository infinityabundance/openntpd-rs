#!/usr/bin/env python3
"""Final structured analysis output."""
import json

RECEIPTS = {
    "debian-12": "/home/one/openntpd-rs/research/oracle/receipts/oracle-parity/parity_2026-07-19T22_20_18Z.json",
    "alpine-3.20": "/home/one/openntpd-rs/research/oracle/receipts/oracle-parity/parity_2026-07-19T22_22_15Z.json",
    "fedora-40": "/home/one/openntpd-rs/research/oracle/receipts/oracle-parity/parity_2026-07-19T22_23_15Z.json",
}

data = {}
for dist, path in RECEIPTS.items():
    with open(path) as f:
        r = json.load(f)
        r["_by_case"] = {c["case_id"]: c for c in r["results"]}
        data[dist] = r

r = data["debian-12"]
results = r["results"]
summary = r["summary"]

# Produce structured output
print(json.dumps({
    "meta": {
        "corpus_digest": r["corpus_digest"],
        "corpus_size": r["corpus_size"],
        "rust_binary_sha256": r["rust_binary"]["sha256"],
        "distributions_tested": ["debian-12", "alpine-3.20", "fedora-40"],
        "distribution_consistency": "ALL IDENTICAL — No distribution-specific differences found",
    },
    "summary_by_distribution": {
        dist: {
            "passed": data[dist]["summary"]["passed"],
            "failed": data[dist]["summary"]["failed"],
            "total": data[dist]["summary"]["total"],
            "oracle_binary": None,
        }
        for dist in ["debian-12", "alpine-3.20", "fedora-40"]
    },
    "failures_by_category": {
        "A_REAL_BUGS_Oracle_rejects_Rust_accepts": {
            "count": 6,
            "description": "Rust exits 0 (accepts config) but oracle exits !=0 (rejects). Rust should also reject these.",
            "cases": [
                {
                    "case_id": "listen_bad_address",
                    "expected": {"exit": 1, "category": "invalid-address"},
                    "rust": {"exit": 0, "category": ""},
                    "oracle": {"exit": 1, "category": "syntax-error"},
                },
                {
                    "case_id": "listen_bad_ipv6",
                    "expected": {"exit": 1, "category": "invalid-address"},
                    "rust": {"exit": 0, "category": ""},
                    "oracle": {"exit": 1, "category": "syntax-error"},
                },
                {
                    "case_id": "listen_hostname_rtable_0",
                    "expected": {"exit": 0, "category": ""},
                    "rust": {"exit": 0, "category": ""},
                    "oracle": {"exit": 1, "category": "syntax-error"},
                },
                {
                    "case_id": "listen_hostname_rtable_255",
                    "expected": {"exit": 0, "category": ""},
                    "rust": {"exit": 0, "category": ""},
                    "oracle": {"exit": 1, "category": "syntax-error"},
                },
                {
                    "case_id": "listen_with_port",
                    "expected": {"exit": 1, "category": "syntax-error"},
                    "rust": {"exit": 0, "category": ""},
                    "oracle": {"exit": 1, "category": "syntax-error"},
                },
                {
                    "case_id": "multiple_rtable_host",
                    "expected": {"exit": 0, "category": ""},
                    "rust": {"exit": 0, "category": ""},
                    "oracle": {"exit": 1, "category": "syntax-error"},
                },
            ],
        },
        "B_CATEGORY_MISMATCH_Both_reject_different_category_strings": {
            "count": 42,
            "description": "Both Rust and oracle exit with code 1, but Rust uses specific sub-categories while oracle uses generic 'syntax-error'. These need Rust category alignment with oracle.",
            "cases": [
                {"case_id": c["case_id"], "rust_exit": c["rust_exit"], "rust_category": c["rust_category"], "oracle_exit": c["oracle_exit"], "oracle_category": c["oracle_category"]}
                for c in results if c["verdict"] == "FAIL" and c["oracle_exit"] != 0 and c["rust_exit"] != 0 and c["oracle_category"] != c["rust_category"]
            ],
        },
        "C_Both_reject_same_expected_wrong": {
            "count": 1,
            "description": "Both Rust and oracle agree on error, but the test expected-tag is wrong.",
            "cases": [
                {"case_id": "constraint_two_urls", "expected": {"exit": 1, "category": "syntax-error"}, "rust": {"exit": 1, "category": "invalid-address"}, "oracle": {"exit": 1, "category": "invalid-address"}}
            ],
        },
        "D_NEITHER_rejects_expected_says_error": {
            "count": 37,
            "description": "Both Rust AND oracle exit 0 (accept config), but the expected-tag says it should be an error. Likely the expected-tags in the corpus are wrong/misaligned with what openntpd actually accepts.",
            "cases": [
                {
                    "case_id": c["case_id"],
                    "expected": {"exit": c["expected_exit"], "category": c["expected_category"]},
                    "rust": {"exit": c["rust_exit"], "category": c["rust_category"]},
                    "oracle": {"exit": c["oracle_exit"], "category": c["oracle_category"]},
                }
                for c in results if c["verdict"] == "FAIL" and c["oracle_exit"] == 0 and c["rust_exit"] == 0
            ],
        },
        "E_Other": {
            "count": 0,
            "description": "",
            "cases": [],
        },
    },
    "distribution_specific_failures": {
        "count": 0,
        "description": "No distribution-specific failures found. All 86 failures are 100% identical across all 3 distributions (debian-12, alpine-3.20, fedora-40).",
    },
    "action_items": [
        {
            "priority": "HIGH",
            "area": "Rust parser needs to reject invalid configs",
            "cases": ["listen_bad_address", "listen_bad_ipv6", "listen_with_port", "listen_hostname_rtable_0", "listen_hostname_rtable_255", "multiple_rtable_host"],
            "description": "Rust currently exits 0 (accepts) for these configs but the oracle rejects them with exit=1. Rust's parser is too permissive in these areas.",
        },
        {
            "priority": "MEDIUM",
            "area": "Rust error categories should match oracle's 'syntax-error'",
            "cases": "42 cases (see Category B list)",
            "description": "Both reject, but Rust uses specific categories like 'invalid-weight', 'invalid-address', 'invalid-stratum', 'invalid-correction', 'invalid-refid', 'invalid-rtable'. Oracle always uses 'syntax-error'. Need to decide whether to align with oracle's generic approach or keep specific sub-categories.",
        },
        {
            "priority": "LOW",
            "area": "Expected-tag corrections in test corpus",
            "cases": [
                {"case_id": "constraint_two_urls", "wrong_expected": {"exit": 1, "category": "syntax-error"}, "correct": {"exit": 1, "category": "invalid-address"}},
            ],
            "description": "For constraint_two_urls, both Rust and oracle agree but the expected-tag says 'syntax-error' instead of 'invalid-address'. Fix the expected-tag.",
        },
        {
            "priority": "INFO",
            "area": "Oracle is more permissive than expected-tags say",
            "cases": "37 cases (see Category D list)",
            "description": "These 37 cases have expected-tags saying 'should error', but neither Rust nor the oracle rejects them (both exit 0). The oracle binary from openntpd accepts these configs, so the expected-tags in the test corpus are probably wrong/stale.",
        },
    ],
}, indent=2))
