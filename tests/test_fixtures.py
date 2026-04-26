from __future__ import annotations

import pytest

from boundary_probe.engine import diagnose
from boundary_probe.models import SignalSnapshot

SCENARIOS = [
    ("router-down", "router-gateway"),
    ("dns-failure", "dns"),
    ("isp-path", "isp-upstream"),
    ("remote-service", "remote-service"),
]


@pytest.mark.parametrize("name,expected_boundary", SCENARIOS)
def test_fixture_loads_and_classifies(name: str, expected_boundary: str, signal_fixture) -> None:
    snapshot = signal_fixture(name)
    assert isinstance(snapshot, SignalSnapshot)
    diagnosis = diagnose(snapshot)
    assert diagnosis.boundary == expected_boundary, (
        f"fixture '{name}': expected boundary '{expected_boundary}', got '{diagnosis.boundary}'"
    )
