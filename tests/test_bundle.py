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


class TestScrubReachesTheWholeDocument:
    """Regression: --scrub redacted structured fields only, while the same address
    stayed legible in `collector_notes` and the embedded `report_text` — in a
    document that stamps itself `"redacted": true`."""

    def _row_with_public_gateway(self, fake_collection_result):
        from boundary_probe.collectors.gateway import GatewaySlice
        from boundary_probe.collectors.path import PathSlice

        result = dataclasses.replace(
            fake_collection_result,
            # A publicly-addressed gateway is the hotspot / direct-to-modem case,
            # and the only one that produces a gateway hit at all.
            gateway=GatewaySlice(reachable=False, gateway_ip="72.14.205.1", rtt_ms=None,
                                 note="ping to 72.14.205.1 timed out after 8s"),
            path_primary=PathSlice(raw_hops=[{"index": 1, "host": "72.14.205.9", "rtt_ms": 5.0}],
                                   target="example.com", completed=True, note=""),
        )
        parsed = parse_target("example.com")
        diag = diagnose(result.snapshot)
        with connect() as conn:
            uuid = insert_run(conn, parsed_target=parsed, snapshot=result.snapshot,
                              diagnosis=diag, collection_result=result)
        with connect() as conn:
            return fetch_run(conn, uuid)

    def test_gateway_ip_is_gone_from_the_rendered_report(self, tmp_db, fake_collection_result):
        from boundary_probe.templates import render_escalation

        row = self._row_with_public_gateway(fake_collection_result)
        bundle, _ = build_bundle(row, render_escalation(row), scrub=True)
        assert "72.14.205.1" not in bundle["report_text"]
        assert SCRUB_PLACEHOLDER in bundle["report_text"]

    def test_gateway_ip_is_gone_from_the_collector_notes(self, tmp_db, fake_collection_result):
        row = self._row_with_public_gateway(fake_collection_result)
        bundle, _ = build_bundle(row, "REPORT", scrub=True)
        assert "72.14.205.1" not in json.dumps(bundle["collector_notes"])

    def test_no_scrubbed_address_survives_anywhere_in_the_document(self, tmp_db, fake_collection_result):
        from boundary_probe.templates import render_escalation

        row = self._row_with_public_gateway(fake_collection_result)
        bundle, hits = build_bundle(row, render_escalation(row), scrub=True)
        blob = json.dumps(bundle)
        assert hits
        for addr in ("72.14.205.1", "72.14.205.9"):
            assert addr not in blob, f"{addr} survived --scrub"

    def test_destination_addresses_are_deliberately_kept(self, tmp_db, fake_collection_result):
        # Scrubbing is about the reporting user's network, not the target's.
        # Redacting these would strip the report of what it is reporting on.
        row = self._row_with_public_gateway(fake_collection_result)
        bundle, _ = build_bundle(row, "REPORT", scrub=True)
        assert bundle["measurements"]["dns"]["resolved_ips"] == ["93.184.216.34"]
        assert bundle["measurements"]["ip_connectivity"]["target_ip"] == "1.1.1.1"

    def test_document_wide_scrub_still_verifies(self, tmp_db, fake_collection_result):
        from boundary_probe.templates import render_escalation

        row = self._row_with_public_gateway(fake_collection_result)
        bundle, _ = build_bundle(row, render_escalation(row), scrub=True)
        assert verify_bundle(bundle)

    def test_reverse_dns_form_of_the_address_is_redacted_too(self, tmp_db, fake_collection_result):
        # An ISP CPE name spells the address out with dashes, so redacting only
        # the dotted form leaves it perfectly readable.
        from boundary_probe.bundle import _redact_in_text

        text = "hop via cpe-72-14-205-1.socal.res.rr.com [72.14.205.1]"
        out = _redact_in_text(text, ["72.14.205.1"])
        assert "72.14.205.1" not in out
        assert "72-14-205-1" not in out


class TestCompositeHopHosts:
    def test_a_name_bracket_ip_host_is_detected_and_redacted(self, tmp_db, fake_collection_result):
        # Pre-normalization fixtures and any stored run captured on Windows before
        # the parser fix still carry the composite; is_public_ip cannot parse it.
        from boundary_probe.bundle import scrub_measurements

        measurements = {
            "gateway": {"gateway_ip": "192.168.1.1"},
            "path_primary": {"raw_hops": [
                {"index": 1, "host": "cpe-72-14-205-1.socal.res.rr.com [72.14.205.1]"},
            ]},
        }
        scrubbed, hits = scrub_measurements(measurements, scrub=True)
        assert hits
        assert scrubbed["path_primary"]["raw_hops"][0]["host"] == SCRUB_PLACEHOLDER


class TestIntegrityRobustness:
    def test_malformed_integrity_block_returns_false_not_raises(self, tmp_db, fake_collection_result):
        # A truncated or mangled bundle is precisely what this detects, so it
        # must not blow up on one.
        row, _ = _row_with_public_path(fake_collection_result, tmp_db)
        bundle, _ = build_bundle(row, "REPORT")
        for broken in (None, [], "nope", 7):
            bundle["integrity"] = broken
            assert verify_bundle(bundle) is False

    def test_hash_recipe_pins_ensure_ascii(self, tmp_db, fake_collection_result):
        # report_text always contains an em dash, so a verifier following the
        # documented recipe with ensure_ascii=False would reject a good bundle.
        # The published recipe and the implementation must agree.
        import hashlib

        from boundary_probe.bundle import payload_sha256
        from boundary_probe.templates import render_escalation

        row, _ = _row_with_public_path(fake_collection_result, tmp_db)
        bundle, _ = build_bundle(row, render_escalation(row))
        assert "—" in bundle["report_text"]

        payload = {k: v for k, v in bundle.items() if k != "integrity"}
        recomputed = hashlib.sha256(
            json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
            .encode("utf-8")
        ).hexdigest()
        assert recomputed == payload_sha256(bundle) == bundle["integrity"]["payload_sha256"]


class TestPathSecondary:
    def test_secondary_path_is_carried_and_scrubbed(self, tmp_db, fake_collection_result):
        # The default fixture leaves path_secondary None, so this limb of both
        # the row reconstruction and the scrubber was previously unexercised.
        from boundary_probe.collectors.path import PathSlice

        result = dataclasses.replace(
            fake_collection_result,
            path_secondary=PathSlice(
                raw_hops=[{"index": 1, "host": "192.168.1.1"},
                          {"index": 2, "host": "72.14.205.1"}],
                target="1.0.0.1", completed=True, note="",
            ),
        )
        parsed = parse_target("example.com")
        diag = diagnose(result.snapshot)
        with connect() as conn:
            uuid = insert_run(conn, parsed_target=parsed, snapshot=result.snapshot,
                              diagnosis=diag, collection_result=result)
        with connect() as conn:
            row = fetch_run(conn, uuid)

        plain, _ = build_bundle(row, "REPORT")
        assert len(plain["measurements"]["path_secondary"]["raw_hops"]) == 2

        scrubbed, hits = build_bundle(row, "REPORT", scrub=True)
        assert any("path_secondary" in h for h in hits)
        hops = scrubbed["measurements"]["path_secondary"]["raw_hops"]
        assert hops[0]["host"] == "192.168.1.1"
        assert hops[1]["host"] == SCRUB_PLACEHOLDER
        assert verify_bundle(scrubbed)

    def test_absent_secondary_path_stays_null(self, tmp_db, fake_collection_result):
        row, _ = _row_with_public_path(fake_collection_result, tmp_db)
        bundle, _ = build_bundle(row, "REPORT")
        assert bundle["measurements"]["path_secondary"] is None
