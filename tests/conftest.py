from __future__ import annotations

import json
from pathlib import Path

import pytest

from boundary_probe.models import SignalSnapshot

FIXTURES_DIR = Path(__file__).parent / "fixtures"


def load_signal_fixture(name: str) -> SignalSnapshot:
    path = FIXTURES_DIR / f"{name}.json"
    data = json.loads(path.read_text(encoding="utf-8"))
    data.pop("scenario", None)
    return SignalSnapshot(**data)


@pytest.fixture
def signal_fixture():
    return load_signal_fixture
