from __future__ import annotations

import datetime
import json
import os
import sqlite3
import uuid
from contextlib import contextmanager
from pathlib import Path
from typing import TYPE_CHECKING

from boundary_probe.models import Diagnosis, SignalSnapshot
from boundary_probe.targets import ParsedTarget

if TYPE_CHECKING:
    from boundary_probe.collectors.orchestrator import CollectionResult

SCHEMA_VERSION = "1"

_DDL = """
CREATE TABLE IF NOT EXISTS schema_meta (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS runs (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    run_uuid        TEXT    NOT NULL UNIQUE,
    started_at      TEXT    NOT NULL,
    duration_ms     INTEGER NOT NULL,

    target_raw      TEXT    NOT NULL,
    target_kind     TEXT    NOT NULL,
    target_host     TEXT    NOT NULL,
    target_port     INTEGER,
    target_scheme   TEXT,

    gateway_reachable             INTEGER NOT NULL CHECK (gateway_reachable IN (0,1)),
    dns_ok                        INTEGER NOT NULL CHECK (dns_ok IN (0,1)),
    ip_connectivity_ok            INTEGER NOT NULL CHECK (ip_connectivity_ok IN (0,1)),
    control_hosts_ok              INTEGER NOT NULL CHECK (control_hosts_ok IN (0,1)),
    target_service_ok             INTEGER NOT NULL CHECK (target_service_ok IN (0,1)),
    packet_loss_after_hop1        INTEGER NOT NULL CHECK (packet_loss_after_hop1 IN (0,1)),
    packet_loss_multiple_targets  INTEGER NOT NULL CHECK (packet_loss_multiple_targets IN (0,1)),

    boundary         TEXT    NOT NULL,
    confidence_float REAL    NOT NULL,
    confidence_band  TEXT    NOT NULL,
    summary          TEXT    NOT NULL,
    evidence_json    TEXT    NOT NULL,
    remediation_json TEXT    NOT NULL,

    gateway_ip            TEXT,
    gateway_rtt_ms        REAL,
    dns_resolved_ips_json TEXT    NOT NULL,
    dns_elapsed_ms        INTEGER NOT NULL,
    ip_target             TEXT    NOT NULL,
    ip_loss_pct           REAL    NOT NULL,
    ip_avg_rtt_ms         REAL,
    controls_json         TEXT    NOT NULL,
    target_method         TEXT    NOT NULL,
    target_elapsed_ms     INTEGER NOT NULL,
    path_primary_json     TEXT    NOT NULL,
    path_secondary_json   TEXT,

    collector_notes_json  TEXT    NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_runs_started_at ON runs(started_at DESC);
CREATE INDEX IF NOT EXISTS idx_runs_target_host ON runs(target_host);
CREATE INDEX IF NOT EXISTS idx_runs_boundary    ON runs(boundary);
"""


def get_db_path() -> Path:
    override = os.environ.get("BOUNDARY_PROBE_DB")
    if override:
        return Path(override)
    local_app_data = os.environ.get(
        "LOCALAPPDATA",
        str(Path.home() / "AppData" / "Local"),
    )
    return Path(local_app_data) / "boundary-probe" / "runs.db"


def _ensure_schema(conn: sqlite3.Connection) -> None:
    conn.execute("CREATE TABLE IF NOT EXISTS schema_meta (key TEXT PRIMARY KEY, value TEXT NOT NULL)")
    conn.commit()
    row = conn.execute("SELECT value FROM schema_meta WHERE key='schema_version'").fetchone()
    if row is None or row[0] != SCHEMA_VERSION:
        conn.execute("DROP TABLE IF EXISTS runs")
        conn.execute("DROP TABLE IF EXISTS schema_meta")
        conn.executescript(_DDL)
        conn.execute("INSERT INTO schema_meta (key, value) VALUES ('schema_version', ?)", (SCHEMA_VERSION,))
        conn.commit()


@contextmanager
def connect():
    """Open a schema-ensured SQLite connection; commit on success, rollback on exception."""
    db_path = get_db_path()
    db_path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(db_path), timeout=5)
    conn.row_factory = sqlite3.Row
    try:
        _ensure_schema(conn)
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def confidence_band(confidence: float) -> str:
    if confidence >= 0.97:
        return "High"
    if confidence >= 0.90:
        return "Moderate"
    return "Low"


_COMPACT = (",", ":")


def insert_run(
    conn: sqlite3.Connection,
    *,
    parsed_target: ParsedTarget,
    snapshot: SignalSnapshot,
    diagnosis: Diagnosis,
    collection_result: "CollectionResult",
) -> str:
    run_uuid = uuid.uuid4().hex
    started_at = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    band = confidence_band(diagnosis.confidence)

    cr = collection_result
    evidence_json = json.dumps(
        [{"label": e.label, "detail": e.detail} for e in diagnosis.evidence],
        separators=_COMPACT,
    )
    remediation_json = json.dumps(diagnosis.remediation, separators=_COMPACT)
    controls_json = json.dumps(
        [{"host": r.host, "reachable": r.reachable, "loss_pct": r.loss_pct,
          "avg_rtt_ms": r.avg_rtt_ms}
         for r in cr.controls.results],
        separators=_COMPACT,
    )
    notes = {
        "gateway": cr.gateway.note,
        "dns": cr.dns.note,
        "ip": cr.ip.note,
        "controls": cr.controls.note,
        "target": cr.target.note,
        "path_primary": cr.path_primary.note,
        "path_secondary": cr.path_secondary.note if cr.path_secondary else "",
    }

    conn.execute(
        """
        INSERT INTO runs (
            run_uuid, started_at, duration_ms,
            target_raw, target_kind, target_host, target_port, target_scheme,
            gateway_reachable, dns_ok, ip_connectivity_ok, control_hosts_ok,
            target_service_ok, packet_loss_after_hop1, packet_loss_multiple_targets,
            boundary, confidence_float, confidence_band, summary,
            evidence_json, remediation_json,
            gateway_ip, gateway_rtt_ms,
            dns_resolved_ips_json, dns_elapsed_ms,
            ip_target, ip_loss_pct, ip_avg_rtt_ms,
            controls_json, target_method, target_elapsed_ms,
            path_primary_json, path_secondary_json,
            collector_notes_json
        ) VALUES (
            ?,?,?,  ?,?,?,?,?,  ?,?,?,?,?,?,?,  ?,?,?,?,  ?,?,  ?,?,  ?,?,  ?,?,?,
            ?,?,?,  ?,?,  ?
        )
        """,
        (
            run_uuid, started_at, cr.elapsed_ms,
            parsed_target.raw, parsed_target.kind, parsed_target.host,
            parsed_target.port, parsed_target.scheme,
            int(snapshot.gateway_reachable), int(snapshot.dns_ok),
            int(snapshot.ip_connectivity_ok), int(snapshot.control_hosts_ok),
            int(snapshot.target_service_ok), int(snapshot.packet_loss_after_hop1),
            int(snapshot.packet_loss_multiple_targets),
            diagnosis.boundary, diagnosis.confidence, band, diagnosis.summary,
            evidence_json, remediation_json,
            cr.gateway.gateway_ip, cr.gateway.rtt_ms,
            json.dumps(cr.dns.resolved_ips, separators=_COMPACT), cr.dns.elapsed_ms,
            cr.ip.target_ip, cr.ip.loss_pct, cr.ip.avg_rtt_ms,
            controls_json, cr.target.method, cr.target.elapsed_ms,
            json.dumps(cr.path_primary.raw_hops, separators=_COMPACT),
            json.dumps(cr.path_secondary.raw_hops, separators=_COMPACT) if cr.path_secondary else None,
            json.dumps(notes, separators=_COMPACT),
        ),
    )
    return run_uuid


def fetch_recent(conn: sqlite3.Connection, limit: int) -> list[sqlite3.Row]:
    return conn.execute(
        "SELECT * FROM runs ORDER BY started_at DESC, id DESC LIMIT ?", (limit,)
    ).fetchall()
