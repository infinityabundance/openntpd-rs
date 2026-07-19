#!/usr/bin/env python3
"""Compare oracle parity receipts across distributions."""
import json
import sys
from collections import defaultdict

# Map timestamps to distributions
RECEIPTS = {
    "debian-12": "/home/one/openntpd-rs/research/oracle/receipts/oracle-parity/parity_2026-07-19T22_20_18Z.json",
    "alpine-3.20": "/home/one/openntpd-rs/research/oracle/receipts/oracle-parity/parity_2026-07-19T22_22_15Z.json",
    "fedora-40": "/home/one/openntpd-rs/research/oracle/receipts/oracle-parity/parity_2026-07-19T22_23_15Z.json",
}

# Load all receipts
data = {}
for dist, path in RECEIPTS.items():
    with open(path) as f:
        r = json.load(f)
        r["_by_case"] = {c["case_id"]: c for c in r["results"]}
        data[dist] = r

# Get all case IDs across all receipts
all_cases = set()
for r in data.values():
    all_cases.update(r["_by_case"].keys())

print("=" * 140)
print("ORACLE PARITY MATRIX COMPARISON: debian-12 | alpine-3.20 | fedora-40")
print("=" * 140)

# Summary per distribution
print("\n--- SUMMARY ---")
for dist in ["debian-12", "alpine-3.20", "fedora-40"]:
    s = data[dist]["summary"]
    print(f"  {dist:15s}: passed={s['passed']}, failed={s['failed']}, total={s['total']}")

# Collect all failures and differences
all_fail_cases = set()
for dist in RECEIPTS:
    for c in data[dist]["results"]:
        if c["verdict"] == "FAIL":
            all_fail_cases.add(c["case_id"])

# Detailed comparison for failures
print(f"\n--- DETAILED FAILURE COMPARISON ({len(all_fail_cases)} unique failing cases) ---\n")

# Categorize failures
consistent_vs_expected = []  # Both Rust and oracle differ from expected
consistent_oracle_diff = []  # Rust passes expected but oracle differs (distribution consistent)
distribution_specific = []   # Only some distributions fail
category_mismatch = []       # Both reject but use different category strings
rust_behavior_diff = []      # Rust behaves differently across distributions

for case_id in sorted(all_fail_cases):
    results = {}
    for dist in ["debian-12", "alpine-3.20", "fedora-40"]:
        c = data[dist]["_by_case"].get(case_id)
        if c:
            results[dist] = {
                "expected_exit": c["expected_exit"],
                "expected_cat": c["expected_category"],
                "rust_exit": c["rust_exit"],
                "rust_cat": c["rust_category"],
                "oracle_exit": c["oracle_exit"],
                "oracle_cat": c["oracle_category"],
                "verdict": c["verdict"],
                "expected_match": c["expected_match"],
                "oracle_parity": c["oracle_parity"],
            }

    # Check if oracle behavior is same across all dists
    oracle_exits = {r["oracle_exit"] for r in results.values()}
    oracle_cats = {r["oracle_cat"] for r in results.values()}
    oracle_same = len(oracle_exits) == 1 and len(oracle_cats) == 1
    
    # Check if rust behavior is same across all dists
    rust_exits = {r["rust_exit"] for r in results.values()}
    rust_cats = {r["rust_cat"] for r in results.values()}
    rust_same = len(rust_exits) == 1 and len(rust_cats) == 1

    verdicts = {r["verdict"] for r in results.values()}
    all_fail = len(verdicts) == 1 and "FAIL" in verdicts

    # Categorize
    if oracle_same and rust_same:
        # Same everywhere - consistent failure
        r = list(results.values())[0]
        if r["expected_match"] == False and r["oracle_parity"] == False:
            # Both expected_match AND oracle_parity fail
            # This means Oracle rejects AND Rust also disagrees with expected
            if r["oracle_exit"] != r["expected_exit"] and r["rust_exit"] != r["expected_exit"]:
                consistent_vs_expected.append(case_id)
            elif r["oracle_exit"] != r["expected_exit"] and r["rust_exit"] == r["expected_exit"]:
                # Rust matches expected, oracle rejects -> this is the most common pattern
                if r["oracle_exit"] != 0 and r["rust_exit"] == 0:
                    consistent_oracle_diff.append(case_id)
                else:
                    consistent_vs_expected.append(case_id)
            else:
                consistent_oracle_diff.append(case_id)
        elif r["expected_match"] == True and r["oracle_parity"] == False:
            # Expected matches, but oracle_parity fails -> oracle and rust differ
            consistent_oracle_diff.append(case_id)
        elif r["expected_match"] == False and r["oracle_parity"] == True:
            # Both oracle and rust match but differ from expected in same way
            consistent_vs_expected.append(case_id)
        else:
            consistent_vs_expected.append(case_id)
    else:
        # Not same across distributions
        distribution_specific.append(case_id)

# Print consistent: Rust matches expected, oracle rejects (the main "real" issue)
print(">>> CATEGORY 1: Consistent ACROSS ALL distributions - Oracle rejects, Rust accepts (REAL BUGS) <<<")
print(f"    ({len(consistent_oracle_diff)} cases)\n")

for case_id in sorted(consistent_oracle_diff):
    r = data["debian-12"]["_by_case"][case_id]
    print(f"  {case_id:45s} | expected=({r['expected_exit']}, '{r['expected_category']}') "
          f"| rust=({r['rust_exit']}, '{r['rust_category']}') "
          f"| oracle=({r['oracle_exit']}, '{r['oracle_category']}')")

# Check for category-only differences within the consistent set
print("\n>>> CATEGORY 2: Consistent across ALL - Both reject but category strings differ <<<")
print("    (Looking for cases where both oracle and rust have non-zero exit codes)\n")

for case_id in sorted(all_fail_cases):
    r = data["debian-12"]["_by_case"].get(case_id)
    if not r:
        continue
    # Both reject (non-zero exit) but may differ in category
    if r["rust_exit"] != 0 and r["oracle_exit"] != 0:
        if r["rust_category"] != r["oracle_category"]:
            print(f"  {case_id:45s} | rust=({r['rust_exit']}, '{r['rust_category']}') "
                  f"| oracle=({r['oracle_exit']}, '{r['oracle_category']}')")
        else:
            # Both reject with same category - this is a different kind of issue
            # Rust is rejecting but expected says pass
            print(f"  {case_id:45s} | BOTH REJECT SAME | rust=({r['rust_exit']}, '{r['rust_category']}') "
                  f"| oracle=({r['oracle_exit']}, '{r['oracle_category']}') "
                  f"| expected=({r['expected_exit']}, '{r['expected_category']}')")

# Distribution-specific
if distribution_specific:
    print(f"\n>>> CATEGORY 3: Distribution-Specific Failures ({len(distribution_specific)} cases) <<<\n")
    for case_id in sorted(distribution_specific):
        print(f"  {case_id:45s}")
        for dist in ["debian-12", "alpine-3.20", "fedora-40"]:
            r = data[dist]["_by_case"].get(case_id)
            if r:
                verdict_mark = "FAIL" if r["verdict"] == "FAIL" else "   "
                print(f"    {dist:15s}: {verdict_mark}  expected=({r['expected_exit']},'{r['expected_category']}') "
                      f"| rust=({r['rust_exit']},'{r['rust_category']}') "
                      f"| oracle=({r['oracle_exit']},'{r['oracle_category']}')")
else:
    print("\n>>> No distribution-specific failures found <<<")

# Print consistent vs expected cases
print(f"\n>>> CATEGORY 4: Consistent across ALL - Both differ from expected in same way")
print(f"    ({{len(consistent_vs_expected)}} cases - may be expected behavior not in test expectations)\n")

# Full case-by-case pass/fail per distribution
print("\n--- FULL CASE-BY-CASE BREAKDOWN ---")
print(f"{'Case ID':45s} {'Debian':20s} {'Alpine':20s} {'Fedora':20s}")
print("-" * 105)
for case_id in sorted(all_cases):
    results = []
    for dist in ["debian-12", "alpine-3.20", "fedora-40"]:
        c = data[dist]["_by_case"].get(case_id)
        if c:
            results.append(f"{'PASS' if c['verdict']=='PASS' else 'FAIL'}")
        else:
            results.append("N/A")
    if results[0] != "PASS" or results[1] != "PASS" or results[2] != "PASS":
        print(f"{case_id:45s} {results[0]:20s} {results[1]:20s} {results[2]:20s}")

print("\n--- END OF COMPARISON ---")
