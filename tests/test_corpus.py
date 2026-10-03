"""Corpus-driven detection tests.

Two properties matter, and the second one matters more:

1. Every payload in ``attacks.json`` is blocked.
2. Every prompt in ``benign.json`` passes.

A prompt firewall that blocks everything scores 100% on property 1 and is
useless, so most of this file exists to protect property 2.
"""

from __future__ import annotations

import pytest


def _describe_failures(failures: list[str]) -> str:
    return "\n".join(failures)


@pytest.mark.attack
def test_attacks_are_blocked(attack_corpus, evaluator):
    failures = []
    for entry in attack_corpus:
        blocked, telemetry, _ = evaluator.inspect(entry["prompt"])
        problems = []
        if not blocked:
            problems.append(f"NOT BLOCKED (risk={telemetry['calculated_risk_index']})")
        min_risk = entry.get("min_risk")
        if min_risk is not None and telemetry["calculated_risk_index"] < min_risk:
            problems.append(f"risk {telemetry['calculated_risk_index']} below min_risk {min_risk}")
        for category in entry.get("expect", []):
            if category not in telemetry["categories_triggered"]:
                problems.append(f"missing category {category}")
        if problems:
            failures.append(f"  [{entry['id']}] {'; '.join(problems)}")

    assert not failures, "Attack corpus failures:\n" + _describe_failures(failures)


@pytest.mark.benign
def test_benign_prompts_pass(benign_corpus, evaluator):
    failures = []
    for entry in benign_corpus:
        blocked, telemetry, _ = evaluator.inspect(entry["prompt"])
        if blocked:
            failures.append(
                f"  [{entry['id']}] FALSE POSITIVE "
                f"(risk={telemetry['calculated_risk_index']}, "
                f"categories={telemetry['categories_triggered']}) "
                f"prompt={entry['prompt'][:70]!r}"
            )
    assert not failures, "Benign corpus false positives:\n" + _describe_failures(failures)


@pytest.mark.benign
def test_benign_prompts_stay_below_review_threshold(benign_corpus, evaluator):
    """Benign traffic should look clean, not merely squeak under the limit.

    Catches "passes by a hair" regressions where a later threshold change would
    silently turn a benign prompt into a block.

    Entries flagged ``allow_review`` are exempt: a handful of prompts are
    genuinely ambiguous ("how do I disable the safety filter on my own home
    router?") and we *want* those surfaced for a human, just never blocked
    automatically. Exempting them keeps the signal honest instead of tuning the
    engine until it cannot see them.
    """
    noisy = []
    for entry in benign_corpus:
        if entry.get("allow_review"):
            continue
        _, telemetry, _ = evaluator.inspect(entry["prompt"])
        risk = telemetry["calculated_risk_index"]
        if risk >= evaluator.config.review_threshold:
            noisy.append(
                f"  [{entry['id']}] risk={risk} categories={telemetry['categories_triggered']}"
            )
    assert not noisy, "Benign prompts at or above the review threshold:\n" + _describe_failures(
        noisy
    )


@pytest.mark.benign
def test_review_allowed_entries_are_still_not_blocked(benign_corpus, evaluator):
    """``allow_review`` grants a REVIEW verdict, never a block."""
    flagged = [entry for entry in benign_corpus if entry.get("allow_review")]
    assert flagged, "no allow_review entries - the exemption is untested"
    for entry in flagged:
        blocked, telemetry, _ = evaluator.inspect(entry["prompt"])
        assert not blocked, (
            f"{entry['id']} is marked allow_review but was blocked "
            f"(risk={telemetry['calculated_risk_index']})"
        )


@pytest.mark.attack
def test_blocked_payloads_always_report_a_reason(attack_corpus, evaluator):
    """Triage is impossible if a block arrives with no explanation."""
    for entry in attack_corpus:
        blocked, telemetry, _ = evaluator.inspect(entry["prompt"])
        assert blocked, entry["id"]
        assert telemetry["categories_triggered"], f"{entry['id']} blocked with no category reported"


def test_corpus_files_are_healthy(attack_corpus, benign_corpus):
    assert len(attack_corpus) >= 20, "attack corpus is suspiciously small"
    assert len(benign_corpus) >= 20, "benign corpus is suspiciously small"

    for corpus, label in ((attack_corpus, "attack"), (benign_corpus, "benign")):
        ids = [entry["id"] for entry in corpus]
        duplicates = {i for i in ids if ids.count(i) > 1}
        assert not duplicates, f"duplicate {label} ids: {duplicates}"

    known_ids = {entry["id"] for entry in attack_corpus} | {entry["id"] for entry in benign_corpus}
    assert len(known_ids) == len(attack_corpus) + len(benign_corpus), (
        "an id is reused across attacks.json and benign.json"
    )
