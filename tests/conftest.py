"""Shared pytest fixtures and corpus loaders."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

CORPUS_DIR = Path(__file__).parent / "corpus"


def _load(name: str) -> dict:
    with open(CORPUS_DIR / name, encoding="utf-8") as handle:
        return json.load(handle)


@pytest.fixture(scope="session")
def attack_corpus() -> list[dict]:
    return _load("attacks.json")["attacks"]


@pytest.fixture(scope="session")
def benign_corpus() -> list[dict]:
    return _load("benign.json")["benign"]


@pytest.fixture(scope="session")
def evaluator():
    from novagate.evaluator import VectorThreatEvaluator

    return VectorThreatEvaluator()
