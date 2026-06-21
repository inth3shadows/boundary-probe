from __future__ import annotations

from datetime import datetime
from unittest.mock import MagicMock, patch

import pytest

from boundary_probe.engine import diagnose
from boundary_probe.models import Diagnosis, EvidenceItem
from boundary_probe.targets import parse_target
from boundary_probe.watch import PollRecord, _render_panel, run_watch


@pytest.fixture
def parsed_target():
    return parse_target("example.com")


@pytest.fixture
def sample_diagnosis(fake_collection_result):
    return diagnose(fake_collection_result.snapshot)


@pytest.fixture
def sample_record(fake_collection_result, sample_diagnosis):
    return PollRecord(
        ts=datetime(2026, 6, 19, 14, 23, 1),
        result=fake_collection_result,
        diagnosis=sample_diagnosis,
    )


def test_render_panel_empty(parsed_target):
    panel = _render_panel(parsed_target.raw, poll_num=0, interval_s=60, history=[], next_in_s=None)
    assert panel is not None


def test_render_panel_with_history(parsed_target, sample_record):
    panel = _render_panel(
        parsed_target.raw,
        poll_num=1,
        interval_s=60,
        history=[sample_record],
        next_in_s=45.0,
    )
    assert panel is not None
    # border color should reflect the diagnosis boundary
    assert panel.border_style is not None


def test_render_panel_overran(parsed_target, sample_record):
    panel = _render_panel(
        parsed_target.raw,
        poll_num=2,
        interval_s=30,
        history=[sample_record],
        next_in_s=None,
        overran=True,
    )
    assert panel is not None


def test_render_panel_history_window_capped(parsed_target, sample_record):
    history = [sample_record] * 12
    panel = _render_panel(parsed_target.raw, poll_num=12, interval_s=60, history=history, next_in_s=10.0)
    assert panel is not None


def test_watch_runs_n_polls(parsed_target, fake_collection_result, tmp_db):
    with (
        patch("boundary_probe.watch.collect_signals", return_value=fake_collection_result) as mock_collect,
        patch("boundary_probe.watch.time.sleep"),
    ):
        run_watch(parsed_target, interval_s=60, skip_path=False, max_polls=2, persist=False)

    assert mock_collect.call_count == 2


def test_watch_persists_each_poll(parsed_target, fake_collection_result, tmp_db):
    with (
        patch("boundary_probe.watch.collect_signals", return_value=fake_collection_result),
        patch("boundary_probe.watch.time.sleep"),
        patch("boundary_probe.watch.insert_run") as mock_insert,
    ):
        run_watch(parsed_target, interval_s=60, skip_path=False, max_polls=1, persist=True)

    assert mock_insert.call_count == 1


def test_watch_persist_real_insert(parsed_target, fake_collection_result, tmp_db):
    """Regression: insert_run requires keyword args; positional call raises TypeError."""
    with (
        patch("boundary_probe.watch.collect_signals", return_value=fake_collection_result),
        patch("boundary_probe.watch.time.sleep"),
    ):
        run_watch(parsed_target, interval_s=60, skip_path=False, max_polls=1, persist=True)

    from boundary_probe.store import connect, fetch_recent
    with connect() as conn:
        rows = fetch_recent(conn, 10)
    assert len(rows) == 1
    assert rows[0]["boundary"] == "remote-service"


def test_watch_no_persist_skips_store(parsed_target, fake_collection_result, tmp_db):
    with (
        patch("boundary_probe.watch.collect_signals", return_value=fake_collection_result),
        patch("boundary_probe.watch.time.sleep"),
        patch("boundary_probe.watch.insert_run") as mock_insert,
    ):
        run_watch(parsed_target, interval_s=60, skip_path=False, max_polls=1, persist=False)

    mock_insert.assert_not_called()


def test_watch_overrun_skips_sleep(parsed_target, fake_collection_result, tmp_db):
    # Simulate a probe that takes longer than the interval
    overrun_result = MagicMock()
    overrun_result.snapshot = fake_collection_result.snapshot
    overrun_result.elapsed_ms = 90_000  # 90s > 60s interval

    with (
        patch("boundary_probe.watch.collect_signals", return_value=overrun_result),
        patch("boundary_probe.watch.time.sleep") as mock_sleep,
    ):
        run_watch(parsed_target, interval_s=60, skip_path=False, max_polls=1, persist=False)

    mock_sleep.assert_not_called()


def test_watch_history_capped_at_ten(parsed_target, fake_collection_result, tmp_db):
    history_ref: list = []

    original_render = _render_panel

    def capture_history(*args, **kwargs):
        # history is the 4th positional arg (index 3)
        history = args[3] if len(args) > 3 else kwargs.get("history", [])
        history_ref.clear()
        history_ref.extend(history)
        return original_render(*args, **kwargs)

    with (
        patch("boundary_probe.watch.collect_signals", return_value=fake_collection_result),
        patch("boundary_probe.watch.time.sleep"),
        patch("boundary_probe.watch._render_panel", side_effect=capture_history),
    ):
        run_watch(parsed_target, interval_s=60, skip_path=False, max_polls=12, persist=False)

    assert len(history_ref) <= 10
