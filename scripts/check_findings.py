#!/usr/bin/env python3
"""Deterministic CodeQL findings checker.

Parses a CodeQL SARIF file and asserts it against scripts/expectations.json:
  - every "expected" finding (ruleId + file substring) MUST be present
  - every "forbidden" finding MUST be absent

This is the deterministic test layer: positive controls prove sinks/flows fire,
forbidden entries prove barriers (sanitizers) and framework-internal sanitization
actually suppress findings. Exits non-zero on any mismatch so CI fails on regression.

Usage:
    python scripts/check_findings.py <sarif-file-or-dir> [expectations.json]

Dependency-free (Python 3 stdlib only).
"""
import json
import os
import sys


def find_sarif(path):
    if os.path.isfile(path):
        return path
    if os.path.isdir(path):
        hits = []
        for root, _dirs, files in os.walk(path):
            for f in files:
                if f.endswith(".sarif"):
                    hits.append(os.path.join(root, f))
        if not hits:
            sys.exit(f"ERROR: no .sarif file found under {path}")
        if len(hits) > 1:
            print(f"WARNING: multiple SARIF files found, using all {len(hits)}:")
            for h in hits:
                print(f"  - {h}")
        return hits
    sys.exit(f"ERROR: path not found: {path}")


def load_results(sarif_paths):
    if isinstance(sarif_paths, str):
        sarif_paths = [sarif_paths]
    results = []
    for sp in sarif_paths:
        with open(sp, encoding="utf-8") as fh:
            sarif = json.load(fh)
        for run in sarif.get("runs", []):
            for res in run.get("results", []):
                rule = res.get("ruleId") or (res.get("rule") or {}).get("id", "")
                locs = res.get("locations", [])
                uri = ""
                line = None
                if locs:
                    phys = locs[0].get("physicalLocation", {})
                    uri = phys.get("artifactLocation", {}).get("uri", "")
                    line = phys.get("region", {}).get("startLine")
                results.append({"rule": rule, "uri": uri, "line": line})
    return results


def matches(result, spec):
    if result["rule"] != spec["rule"]:
        return False
    return spec["file"] in result["uri"]


def main():
    if len(sys.argv) < 2:
        sys.exit(__doc__)
    sarif_arg = sys.argv[1]
    exp_path = sys.argv[2] if len(sys.argv) > 2 else os.path.join(
        os.path.dirname(__file__), "expectations.json")

    results = load_results(find_sarif(sarif_arg))
    with open(exp_path, encoding="utf-8") as fh:
        expectations = json.load(fh)

    failures = []
    print(f"Loaded {len(results)} CodeQL results.\n")

    print("Checking EXPECTED findings (must be present):")
    for spec in expectations.get("expected", []):
        hits = [r for r in results if matches(r, spec)]
        status = "PASS" if hits else "FAIL"
        if not hits:
            failures.append(f"MISSING expected: {spec['rule']} in {spec['file']}")
        locs = ", ".join(f"{r['uri']}:{r['line']}" for r in hits) if hits else "(none)"
        print(f"  [{status}] {spec['rule']} in {spec['file']} -> {locs}")

    print("\nChecking FORBIDDEN findings (must be absent):")
    for spec in expectations.get("forbidden", []):
        hits = [r for r in results if matches(r, spec)]
        status = "PASS" if not hits else "FAIL"
        if hits:
            locs = ", ".join(f"{r['uri']}:{r['line']}" for r in hits)
            failures.append(f"UNEXPECTED forbidden: {spec['rule']} in {spec['file']} at {locs}")
        print(f"  [{status}] {spec['rule']} absent from {spec['file']}")

    print()
    if failures:
        print(f"RESULT: FAIL ({len(failures)} problem(s))")
        for f in failures:
            print(f"  - {f}")
        sys.exit(1)
    print("RESULT: PASS — all expectations satisfied.")


if __name__ == "__main__":
    main()
