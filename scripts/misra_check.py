#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-2-Clause
"""
MISRA CI regression gate.

Parses a cppcheck --addon=misra output file, compares per-rule violation
counts against the checked-in baseline (docs/safety/misra_baseline.json),
and exits non-zero if any Required or Mandatory rule regresses.

Usage:
  python3 scripts/misra_check.py <misra-report.txt> [--check-deviation-doc]

  --check-deviation-doc
      Also verify that if the baseline is being increased (a new deviation
      accepted), docs/safety/misra_deviations.md was modified in the same
      git commit/MR. Requires git to be available. Pass this flag only in
      MR pipelines (CI_MERGE_REQUEST_IID is set).

Exit codes:
  0  No Required/Mandatory regressions (Advisory regressions emit warnings).
  1  One or more Required/Mandatory rules regressed vs. baseline.
  2  Baseline increased without a matching misra_deviations.md update.
  3  Usage / file-not-found error.
"""

import json
import os
import re
import subprocess
import sys
from collections import defaultdict
from pathlib import Path

BASELINE_PATH = Path("docs/safety/misra_baseline.json")
DEVIATION_DOC = Path("docs/safety/misra_deviations.md")

BLOCKING_CLASSES = {"Mandatory", "Required"}

ANSI_RED    = "\033[31m"
ANSI_YELLOW = "\033[33m"
ANSI_GREEN  = "\033[32m"
ANSI_RESET  = "\033[0m"
ANSI_BOLD   = "\033[1m"


def parse_report(path: Path) -> dict[str, int]:
    """Return {rule: count} from a cppcheck misra output file."""
    counts: dict[str, int] = defaultdict(int)
    pattern = re.compile(r"misra-c2012-(\d+\.\d+)")
    for line in path.read_text().splitlines():
        for match in pattern.finditer(line):
            counts[match.group(1)] += 1
    return dict(counts)


def load_baseline(path: Path) -> dict:
    try:
        return json.loads(path.read_text())
    except FileNotFoundError:
        print(f"{ANSI_RED}ERROR: baseline not found: {path}{ANSI_RESET}", file=sys.stderr)
        sys.exit(3)
    except json.JSONDecodeError as exc:
        print(f"{ANSI_RED}ERROR: malformed baseline JSON: {exc}{ANSI_RESET}", file=sys.stderr)
        sys.exit(3)


def changed_files_in_mr() -> set[str]:
    """Return set of files changed vs. the merge-base (best-effort)."""
    try:
        default_branch = os.environ.get("CI_DEFAULT_BRANCH", "main")
        base = subprocess.check_output(
            ["git", "merge-base", "HEAD", f"origin/{default_branch}"],
            text=True, stderr=subprocess.DEVNULL
        ).strip()
        out = subprocess.check_output(
            ["git", "diff", "--name-only", base, "HEAD"],
            text=True, stderr=subprocess.DEVNULL
        )
        return set(out.splitlines())
    except subprocess.CalledProcessError:
        return set()


def main() -> None:
    args = sys.argv[1:]
    check_deviation_doc = "--check-deviation-doc" in args
    report_args = [a for a in args if not a.startswith("--")]

    if not report_args:
        print(__doc__)
        sys.exit(3)

    report_path = Path(report_args[0])
    if not report_path.exists():
        print(f"{ANSI_RED}ERROR: report file not found: {report_path}{ANSI_RESET}", file=sys.stderr)
        sys.exit(3)

    actual   = parse_report(report_path)
    baseline = load_baseline(BASELINE_PATH)
    rules    = baseline.get("rules", {})

    blocking_regressions: list[tuple[str, int, int, str]] = []
    advisory_regressions: list[tuple[str, int, int, str]] = []
    improvements:         list[tuple[str, int, int]] = []
    new_rules:            list[tuple[str, int, str]] = []
    accepted_increases:   list[str] = []

    all_rules = set(rules) | set(actual)

    for rule in sorted(all_rules, key=lambda r: [int(x) for x in r.split(".")]):
        actual_count   = actual.get(rule, 0)
        entry          = rules.get(rule, {})
        baseline_count = entry.get("count", 0)
        classification = entry.get("classification", "Advisory")

        if actual_count > baseline_count:
            if rule not in rules:
                new_rules.append((rule, actual_count, classification))
            elif classification in BLOCKING_CLASSES:
                blocking_regressions.append((rule, baseline_count, actual_count, classification))
            else:
                advisory_regressions.append((rule, baseline_count, actual_count, classification))
        elif actual_count < baseline_count:
            improvements.append((rule, baseline_count, actual_count))

    # ── Print report ────────────────────────────────────────────────────────

    print(f"\n{ANSI_BOLD}=== MISRA Regression Gate ==={ANSI_RESET}")
    print(f"Baseline: {BASELINE_PATH}")
    print(f"Report:   {report_path}\n")

    if improvements:
        print(f"{ANSI_GREEN}Improvements (you can lower the baseline):{ANSI_RESET}")
        for rule, old, new in improvements:
            print(f"  Rule {rule:6s}: {old} → {new}  (-{old - new})")
        print()

    if advisory_regressions:
        print(f"{ANSI_YELLOW}Advisory regressions (warning, not blocking):{ANSI_RESET}")
        for rule, old, new, cls in advisory_regressions:
            entry = rules.get(rule, {})
            print(f"  Rule {rule:6s} [{cls}]: {old} → {new}  (+{new - old})")
            if entry.get("note"):
                print(f"           note: {entry['note']}")
        print(f"  {ANSI_YELLOW}To accept: update docs/safety/misra_baseline.json and "
              f"docs/safety/misra_deviations.md{ANSI_RESET}\n")

    if new_rules:
        print(f"{ANSI_YELLOW}New rules not in baseline:{ANSI_RESET}")
        for rule, count, cls in new_rules:
            blocking = cls in BLOCKING_CLASSES
            colour = ANSI_RED if blocking else ANSI_YELLOW
            print(f"  {colour}Rule {rule:6s} [{cls}]: {count} violations{ANSI_RESET}")
        print()
        blocking_regressions.extend(
            (rule, 0, count, cls) for rule, count, cls in new_rules
            if cls in BLOCKING_CLASSES
        )
        advisory_regressions.extend(
            (rule, 0, count, cls) for rule, count, cls in new_rules
            if cls not in BLOCKING_CLASSES
        )

    if blocking_regressions:
        print(f"{ANSI_RED}{ANSI_BOLD}BLOCKING regressions — Required/Mandatory rules increased:{ANSI_RESET}")
        for rule, old, new, cls in blocking_regressions:
            print(f"  {ANSI_RED}Rule {rule:6s} [{cls}]: {old} → {new}  (+{new - old}){ANSI_RESET}")
        print()
        print(f"{ANSI_RED}To fix:{ANSI_RESET}")
        print("  1. Resolve the violations (preferred), OR")
        print("  2. Document the deviation:")
        print("     a. Add justification to docs/safety/misra_deviations.md")
        print("     b. Update the count in docs/safety/misra_baseline.json")
        print("     Both files must change in the same commit.\n")
        print(f"{ANSI_RED}See docs/safety/misra_deviations.md for the deviation record format.{ANSI_RESET}\n")
        sys.exit(1)

    # ── Deviation-doc gate ───────────────────────────────────────────────────
    if check_deviation_doc and (advisory_regressions or new_rules):
        changed = changed_files_in_mr()
        baseline_changed = str(BASELINE_PATH) in changed
        deviation_changed = str(DEVIATION_DOC) in changed

        if baseline_changed and not deviation_changed:
            print(f"{ANSI_RED}GATE FAIL: {BASELINE_PATH} was updated (counts increased) "
                  f"but {DEVIATION_DOC} was not modified in this MR.{ANSI_RESET}")
            print("Each new accepted deviation must be documented in misra_deviations.md "
                  "in the same commit as the baseline update.")
            sys.exit(2)

    # ── All clear ────────────────────────────────────────────────────────────
    total_actual   = sum(actual.values())
    total_baseline = sum(e.get("count", 0) for e in rules.values())

    if not blocking_regressions and not advisory_regressions and not new_rules:
        print(f"{ANSI_GREEN}No regressions.{ANSI_RESET} "
              f"Total violations: {total_actual} (baseline: {total_baseline})")
    else:
        print(f"{ANSI_YELLOW}Advisory warnings present but no blocking regressions.{ANSI_RESET} "
              f"Total violations: {total_actual} (baseline: {total_baseline})")

    if improvements:
        print(f"{ANSI_GREEN}Tip: {len(improvements)} rule(s) improved — "
              f"run 'python3 scripts/misra_check.py --update-baseline' to lower the baseline.{ANSI_RESET}")


if __name__ == "__main__":
    main()
