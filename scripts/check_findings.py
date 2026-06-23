#!/usr/bin/env python3
"""Deterministic CodeQL findings checker.

Parses a CodeQL SARIF file and asserts it against scripts/expectations.json as a
CLOSED-WORLD check over the whole alert set:

  - "counts"    : exact number of alerts expected per (rule, file). Every alert must
                  be accounted for here. A count that drifts (regression or new finding)
                  fails the build.
  - "forbidden" : (rule, file) pairs that must have ZERO alerts (barriers / framework
                  sanitization). Documented explicitly even though count 0 would also do.
  - any alert whose (rule, file) is NOT declared in "counts" fails the build (catches
    unexpected new findings).

Counts are matched by ruleId + file basename, which is robust to line-number shifts
(rewriting a file moves alert lines but not counts). Dependency-free (Python 3 stdlib).
Exits non-zero on any mismatch so CI fails on regression.

Usage:
    python scripts/check_findings.py <sarif-file-or-dir> [expectations.json]
"""
import json
import os
import sys
from collections import Counter


def find_sarif(path):
    if os.path.isfile(path):
        return [path]
    if os.path.isdir(path):
        hits = [os.path.join(r, f) for r, _d, fs in os.walk(path)
                for f in fs if f.endswith(".sarif")]
        if not hits:
            sys.exit(f"ERROR: no .sarif file found under {path}")
        return hits
    sys.exit(f"ERROR: path not found: {path}")


def load_results(sarif_paths):
    """Return Counter keyed by (ruleId, basename)."""
    counts = Counter()
    for sp in sarif_paths:
        with open(sp, encoding="utf-8") as fh:
            sarif = json.load(fh)
        for run in sarif.get("runs", []):
            for res in run.get("results", []):
                rule = res.get("ruleId") or (res.get("rule") or {}).get("id", "")
                locs = res.get("locations", [])
                uri = ""
                if locs:
                    uri = (locs[0].get("physicalLocation", {})
                           .get("artifactLocation", {}).get("uri", ""))
                base = os.path.basename(uri)
                counts[(rule, base)] += 1
    return counts


def main():
    if len(sys.argv) < 2:
        sys.exit(__doc__)
    sarif_arg = sys.argv[1]
    exp_path = sys.argv[2] if len(sys.argv) > 2 else os.path.join(
        os.path.dirname(__file__), "expectations.json")

    observed = load_results(find_sarif(sarif_arg))
    with open(exp_path, encoding="utf-8") as fh:
        expectations = json.load(fh)

    failures = []
    declared = set()
    total = sum(observed.values())
    print(f"Loaded {total} CodeQL results across {len(observed)} (rule, file) groups.\n")

    print("EXPECTED counts (exact match):")
    for spec in expectations.get("counts", []):
        key = (spec["rule"], spec["file"])
        declared.add(key)
        got = observed.get(key, 0)
        want = spec["count"]
        ok = got == want
        if not ok:
            failures.append(f"COUNT {spec['rule']} in {spec['file']}: expected {want}, got {got}")
        print(f"  [{'PASS' if ok else 'FAIL'}] {spec['rule']:42} {spec['file']:30} {got}/{want}")

    print("\nFORBIDDEN (must be absent):")
    for spec in expectations.get("forbidden", []):
        key = (spec["rule"], spec["file"])
        declared.add(key)
        got = observed.get(key, 0)
        if got:
            failures.append(f"FORBIDDEN {spec['rule']} in {spec['file']}: found {got}")
        print(f"  [{'PASS' if got == 0 else 'FAIL'}] {spec['rule']:42} {spec['file']:30} {got}")

    print("\nUNDECLARED findings (closed-world check):")
    undeclared = [(k, v) for k, v in sorted(observed.items()) if k not in declared and v > 0]
    if not undeclared:
        print("  [PASS] no undeclared (rule, file) findings")
    for (rule, base), v in undeclared:
        failures.append(f"UNDECLARED {rule} in {base}: {v} (add to expectations.json or investigate)")
        print(f"  [FAIL] {rule:42} {base:30} {v}")

    print()
    if failures:
        print(f"RESULT: FAIL ({len(failures)} problem(s))")
        for f in failures:
            print(f"  - {f}")
        sys.exit(1)
    print(f"RESULT: PASS — all {total} findings match expectations.")


if __name__ == "__main__":
    main()
