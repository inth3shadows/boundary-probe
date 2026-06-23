"""The post-classification vantage refinement (engine.refine).

refine() is pure and advisory: it only ever touches the isp-upstream and
remote-service verdicts, never changes the boundary, and is a no-op when the
vantage was not consulted. These tests pin that contract — and that the vantage
signal stays OUT of the decision table (so the 256-combo coverage guarantee on
diagnose() is unaffected).
"""

from __future__ import annotations

import itertools

from boundary_probe.engine import BOUNDARIES, diagnose, refine
from boundary_probe.models import Diagnosis, EvidenceItem, SignalSnapshot, VantageSlice

# The boolean signal fields the engine enumerates (mirrors test_engine_coverage).
_BOOL_FIELDS = (
    "gateway_reachable",
    "dns_ok",
    "ip_connectivity_ok",
    "control_hosts_ok",
    "target_service_ok",
    "default_route_present",
    "packet_loss_after_hop1",
    "packet_loss_multiple_targets",
)


def _diag(boundary: str, confidence: float = 0.9) -> Diagnosis:
    return Diagnosis(boundary=boundary, confidence=confidence, summary="s",
                     evidence=[EvidenceItem("x", "y")], remediation=["r"])


_CONSULTED_TRUE = VantageSlice(True, True, "")
_CONSULTED_FALSE = VantageSlice(True, False, "")
_NOT_CONSULTED = VantageSlice(False, None, "vantage unreachable")


def test_refine_noop_when_not_consulted() -> None:
    base = _diag("remote-service", 0.95)
    assert refine(base, _NOT_CONSULTED) is base


def test_refine_noop_for_non_refinable_boundaries() -> None:
    for boundary in BOUNDARIES:
        if boundary in ("isp-upstream", "remote-service"):
            continue
        base = _diag(boundary)
        # both vantage answers must pass through unchanged
        assert refine(base, _CONSULTED_TRUE) is base
        assert refine(base, _CONSULTED_FALSE) is base


def test_refine_never_changes_the_boundary() -> None:
    for boundary in ("isp-upstream", "remote-service"):
        for vantage in (_CONSULTED_TRUE, _CONSULTED_FALSE, _NOT_CONSULTED):
            assert refine(_diag(boundary), vantage).boundary == boundary


def test_remote_service_confirmed_down_raises_confidence() -> None:
    out = refine(_diag("remote-service", 0.95), _CONSULTED_FALSE)
    assert out.confidence > 0.95
    assert any("down for everyone" in e.detail for e in out.evidence)


def test_remote_service_reachable_elsewhere_lowers_confidence() -> None:
    out = refine(_diag("remote-service", 0.95), _CONSULTED_TRUE)
    assert out.confidence < 0.95
    assert any("path" in e.detail.lower() for e in out.evidence)


def test_isp_upstream_reachable_elsewhere_raises_confidence() -> None:
    out = refine(_diag("isp-upstream", 0.93), _CONSULTED_TRUE)
    assert out.confidence > 0.93
    assert any("not a widespread outage" in e.detail for e in out.evidence)


def test_isp_upstream_also_failed_adds_evidence_without_reclassifying() -> None:
    out = refine(_diag("isp-upstream", 0.93), _CONSULTED_FALSE)
    assert out.boundary == "isp-upstream"
    assert any("wider" in e.detail for e in out.evidence)


def test_refine_does_not_mutate_input() -> None:
    base = _diag("remote-service", 0.95)
    original_len = len(base.evidence)
    refine(base, _CONSULTED_FALSE)
    assert len(base.evidence) == original_len  # caller's list untouched


def test_confidence_stays_in_unit_range() -> None:
    for boundary in ("isp-upstream", "remote-service"):
        for conf in (0.5, 0.93, 0.95, 0.99):
            for vantage in (_CONSULTED_TRUE, _CONSULTED_FALSE):
                out = refine(_diag(boundary, conf), vantage)
                assert 0.0 <= out.confidence <= 1.0


def test_vantage_is_not_a_decision_table_field() -> None:
    # The determinism contract: vantage must never become one of the booleans the
    # engine enumerates. If someone adds it to SignalSnapshot AND to _BOOL_FIELDS,
    # this guard still holds (it asserts the field simply isn't there).
    assert "vantage_target_reachable" not in _BOOL_FIELDS
    assert "vantage_target_reachable" not in SignalSnapshot.__dataclass_fields__


def test_diagnose_coverage_unaffected_by_vantage() -> None:
    # Sanity: the base table still classifies all 2^8 combos with no vantage in play.
    combos = itertools.product((False, True), repeat=len(_BOOL_FIELDS))
    for combo in combos:
        snap = SignalSnapshot(**dict(zip(_BOOL_FIELDS, combo)))
        assert diagnose(snap).boundary in BOUNDARIES
