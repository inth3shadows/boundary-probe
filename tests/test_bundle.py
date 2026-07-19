from __future__ import annotations

import dataclasses
import json

from boundary_probe.bundle import (
    BUNDLE_VERSION,
    SCRUB_PLACEHOLDER,
    build_bundle,
    payload_sha256,
    verify_bundle,
)
from boundary_probe.engine import diagnose
from boundary_probe.store import connect, fetch_run, insert_run
from boundary_probe.targets import parse_target


def _row_with_public_path(fake_collection_result, tmp_db):
    """Seed a run whose traceroute crosses public hops, and return its row.

    The default fixture records no hops, so scrubbing has nothing to act on —
    these tests need a run that actually exposes a WAN path.
    """
    from boundary_probe.collectors.gateway import GatewaySlice
    from boundary_probe.collectors.path import PathSlice

    result = dataclasses.replace(
        fake_collection_result,
        gateway=GatewaySlice(reachable=True, gateway_ip="192.168.1.1", rtt_ms=2.0, note=""),
        path_primary=PathSlice(
            raw_hops=[
                {"index": 1, "host": "192.168.1.1", "rtt_ms": 2.0},
                {"index": 2, "host": "100.64.0.1", "rtt_ms": 9.0},
                # 203.0.113.x (TEST-NET-3) is *not* globally routable, so it would
                # not exercise the scrubber. This is a real public address.
                {"index": 3, "host": "72.14.205.1", "rtt_ms": 18.0},
                {"index": 4, "host": "*", "rtt_ms": None},
            ],
            target="example.com",
            completed=True,
            note="",
        ),
    )
    parsed = parse_target("example.com")
    diag = diagnose(result.snapshot)
    with connect() as conn:
        uuid = insert_run(conn, parsed_target=parsed, snapshot=result.snapshot,
                          diagnosis=diag, collection_result=result)
    with connect() as conn:
        return fetch_run(conn, uuid), uuid


class TestBundleContract:
    def test_declares_version_and_tool(self, tmp_db, fake_collection_result):
        row, _ = _row_with_public_path(fake_collection_result, tmp_db)
        bundle, _ = build_bundle(row, "REPORT")
        assert bundle["bundle_version"] == BUNDLE_VERSION
        assert bundle["tool"]["name"] == "boundary-probe"
        assert bundle["tool"]["version"]

    def test_carries_run_target_diagnosis_and_report(self, tmp_db, fake_collection_result):
        row, uuid = _row_with_public_path(fake_collection_result, tmp_db)
        bundle, _ = build_bundle(row, "REPORT TEXT HERE")
        assert bundle["run"]["uuid"] == uuid
        assert bundle["target"]["host"] == "example.com"
        assert bundle["diagnosis"]["boundary"] == row["boundary"]
        assert bundle["diagnosis"]["evidence"]
        assert bundle["report_text"] == "REPORT TEXT HERE"

    def test_carries_raw_measurements_not_just_booleans(self, tmp_db, fake_collection_result):
        # The point of the bundle over the .txt: the recipient gets the numbers,
        # not only the engine's verdict on them.
        row, _ = _row_with_public_path(fake_collection_result, tmp_db)
        bundle, _ = build_bundle(row, "REPORT")
        m = bundle["measurements"]
        assert m["gateway"]["rtt_ms"] == 2.0
        assert m["dns"]["resolved_ips"] == ["93.184.216.34"]
        assert m["ip_connectivity"]["loss_pct"] == 0.0
        assert len(m["control_hosts"]) == 4
        assert len(m["path_primary"]["raw_hops"]) == 4

    def test_is_json_serializable(self, tmp_db, fake_collection_result):
        row, _ = _row_with_public_path(fake_collection_result, tmp_db)
        bundle, _ = build_bundle(row, "REPORT")
        assert json.loads(json.dumps(bundle))["bundle_version"] == BUNDLE_VERSION


class TestBundleIntegrity:
    def test_hash_verifies_on_a_freshly_built_bundle(self, tmp_db, fake_collection_result):
        row, _ = _row_with_public_path(fake_collection_result, tmp_db)
        bundle, _ = build_bundle(row, "REPORT")
        assert verify_bundle(bundle)

    def test_hash_survives_a_json_round_trip(self, tmp_db, fake_collection_result):
        # A recipient verifies the file they received, not the in-memory dict.
        row, _ = _row_with_public_path(fake_collection_result, tmp_db)
        bundle, _ = build_bundle(row, "REPORT")
        assert verify_bundle(json.loads(json.dumps(bundle, indent=2)))

    def test_hash_fails_after_a_hand_edit(self, tmp_db, fake_collection_result):
        row, _ = _row_with_public_path(fake_collection_result, tmp_db)
        bundle, _ = build_bundle(row, "REPORT")
        bundle["diagnosis"]["boundary"] = "isp-upstream"
        assert not verify_bundle(bundle)

    def test_hash_ignores_the_integrity_key_itself(self, tmp_db, fake_collection_result):
        row, _ = _row_with_public_path(fake_collection_result, tmp_db)
        bundle, _ = build_bundle(row, "REPORT")
        before = payload_sha256(bundle)
        bundle["integrity"]["algorithm"] = "tampered"
        assert payload_sha256(bundle) == before

    def test_missing_integrity_block_does_not_verify(self, tmp_db, fake_collection_result):
        row, _ = _row_with_public_path(fake_collection_result, tmp_db)
        bundle, _ = build_bundle(row, "REPORT")
        del bundle["integrity"]
        assert not verify_bundle(bundle)


class TestBundleScrubbing:
    def test_unscrubbed_by_default_keeps_the_wan_path(self, tmp_db, fake_collection_result):
        # Inverse of `capture`'s default on purpose: the public path is the
        # evidence an ISP needs to act on an isp-upstream verdict.
        row, _ = _row_with_public_path(fake_collection_result, tmp_db)
        bundle, hits = build_bundle(row, "REPORT")
        hops = bundle["measurements"]["path_primary"]["raw_hops"]
        assert hops[2]["host"] == "72.14.205.1"
        assert bundle["redacted"] is False
        # ...but the public IPs are still *reported*, so the CLI can warn.
        assert any("72.14.205.1" in h for h in hits)

    def test_scrub_redacts_public_hops_and_flags_the_bundle(self, tmp_db, fake_collection_result):
        row, _ = _row_with_public_path(fake_collection_result, tmp_db)
        bundle, hits = build_bundle(row, "REPORT", scrub=True)
        hops = bundle["measurements"]["path_primary"]["raw_hops"]
        assert hops[2]["host"] == SCRUB_PLACEHOLDER
        assert bundle["redacted"] is True
        assert hits

    def test_scrub_keeps_private_cgnat_and_unanswered_hops(self, tmp_db, fake_collection_result):
        # Redacting these would cost the recipient the local-vs-upstream boundary
        # while protecting nothing: none of them identify the user.
        row, _ = _row_with_public_path(fake_collection_result, tmp_db)
        bundle, _ = build_bundle(row, "REPORT", scrub=True)
        hops = bundle["measurements"]["path_primary"]["raw_hops"]
        assert hops[0]["host"] == "192.168.1.1"
        assert hops[1]["host"] == "100.64.0.1"
        assert hops[2]["host"] == SCRUB_PLACEHOLDER
        assert hops[3]["host"] == "*"

    def test_scrubbed_bundle_still_verifies(self, tmp_db, fake_collection_result):
        # The hash must cover the post-redaction document, or every scrubbed
        # bundle would arrive looking tampered with.
        row, _ = _row_with_public_path(fake_collection_result, tmp_db)
        bundle, _ = build_bundle(row, "REPORT", scrub=True)
        assert verify_bundle(bundle)
