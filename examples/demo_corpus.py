#!/usr/bin/env python3
"""Score the shipped corpora and print a table.

Runs with no server and no network. Useful for eyeballing the current state of
detection after any change to signatures.py or thresholds.

    python examples/demo_corpus.py
    python examples/demo_corpus.py --show-passing
    python examples/demo_corpus.py --json
"""

from __future__ import annotations

import argparse
import json
import statistics
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))

from novagate import VectorThreatEvaluator  # noqa: E402

CORPUS = ROOT / "tests" / "corpus"


def load(name: str, key: str) -> list[dict]:
    with open(CORPUS / name, encoding="utf-8") as handle:
        return json.load(handle)[key]


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--show-passing",
        action="store_true",
        help="also print benign prompts that were flagged for review",
    )
    parser.add_argument("--json", action="store_true", help="emit JSON instead of a table")
    parser.add_argument(
        "--fail-on-false-positive",
        action="store_true",
        help="exit non-zero if any benign prompt is blocked",
    )
    args = parser.parse_args()

    evaluator = VectorThreatEvaluator()
    attacks = load("attacks.json", "attacks")
    benign = load("benign.json", "benign")

    attack_rows = []
    for entry in attacks:
        blocked, telemetry, report = evaluator.inspect(entry["prompt"])
        attack_rows.append(
            {
                "id": entry["id"],
                "blocked": blocked,
                "risk": telemetry["calculated_risk_index"],
                "categories": telemetry["categories_triggered"],
                "layers": report.layers_unwrapped,
            }
        )

    benign_rows = []
    for entry in benign:
        blocked, telemetry, report = evaluator.inspect(entry["prompt"])
        benign_rows.append(
            {
                "id": entry["id"],
                "blocked": blocked,
                "review": telemetry["needs_review"],
                "risk": telemetry["calculated_risk_index"],
                "categories": telemetry["categories_triggered"],
            }
        )

    missed = [r for r in attack_rows if not r["blocked"]]
    false_positives = [r for r in benign_rows if r["blocked"]]
    reviewed = [r for r in benign_rows if r["review"]]
    risks = [r["risk"] for r in benign_rows]

    if args.json:
        print(
            json.dumps(
                {
                    "attacks": {
                        "total": len(attack_rows),
                        "blocked": len(attack_rows) - len(missed),
                        "missed": missed,
                    },
                    "benign": {
                        "total": len(benign_rows),
                        "blocked": len(false_positives),
                        "review": len(reviewed),
                        "max_risk": max(risks),
                        "median_risk": statistics.median(risks),
                        "false_positives": false_positives,
                    },
                },
                indent=2,
            )
        )
        return 1 if (missed or false_positives) else 0

    print(f"\n  ATTACK CORPUS  ({len(attack_rows) - len(missed)}/{len(attack_rows)} blocked)\n")
    print(f"  {'risk':>5}  {'id':<34} categories")
    print(f"  {'-' * 5}  {'-' * 34} {'-' * 40}")
    for row in sorted(attack_rows, key=lambda r: r["risk"]):
        flag = "  " if row["blocked"] else "!!"
        print(f" {row['risk']:>5.2f}{flag} {row['id']:<34} {','.join(row['categories'])[:44]}")

    print(
        f"\n  BENIGN CORPUS  ({len(benign_rows) - len(false_positives)}/{len(benign_rows)} clean)\n"
    )
    print(f"  {'risk':>5}  {'id':<34} verdict")
    print(f"  {'-' * 5}  {'-' * 34} {'-' * 20}")
    for row in sorted(benign_rows, key=lambda r: -r["risk"])[:10]:
        if not (args.show_passing or row["review"] or row["blocked"]):
            continue
        verdict = "BLOCKED" if row["blocked"] else ("review" if row["review"] else "pass")
        print(
            f"  {row['risk']:>5.2f}  {row['id']:<34} {verdict}  {','.join(row['categories'])[:32]}"
        )

    print(
        f"\n  blocked {len(attack_rows) - len(missed)}/{len(attack_rows)} attacks, "
        f"{len(false_positives)}/{len(benign_rows)} benign false positives, "
        f"{len(reviewed)} flagged for review"
    )
    print(f"  benign risk: median {statistics.median(risks)}, max {max(risks)}\n")

    if missed:
        print("  MISSED ATTACKS (these would reach the model):")
        for row in missed:
            print(f"    - {row['id']}  risk={row['risk']}  {row['categories']}")
        print()

    if false_positives:
        print("  FALSE POSITIVES (these users would be blocked):")
        for row in false_positives:
            print(f"    - {row['id']}  risk={row['risk']}  {row['categories']}")
        print()

    if args.fail_on_false_positive and false_positives:
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
