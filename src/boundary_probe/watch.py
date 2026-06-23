from __future__ import annotations

import time
from datetime import datetime
from typing import NamedTuple

from rich.console import Group
from rich.live import Live
from rich.panel import Panel
from rich.rule import Rule
from rich.table import Table
from rich.text import Text

from boundary_probe.collectors import collect_signals
from boundary_probe.collectors.orchestrator import CollectionResult
from boundary_probe.engine import diagnose
from boundary_probe.models import Diagnosis
from boundary_probe.store import confidence_band, connect, insert_run
from boundary_probe.targets import ParsedTarget


class PollRecord(NamedTuple):
    ts: datetime
    result: CollectionResult
    diagnosis: Diagnosis


_SIGNALS = [
    ("gateway_reachable", "gateway", False),
    ("ip_connectivity_ok", "ip", False),
    ("dns_ok", "dns", False),
    ("control_hosts_ok", "controls", False),
    ("target_service_ok", "target", False),
    ("packet_loss_after_hop1", "path-loss", True),
    ("packet_loss_multiple_targets", "multi-loss", True),
]

_BOUNDARY_COLOR = {
    "local-device": "red",
    "router-gateway": "red",
    "wan-gateway": "red",
    "captive-portal": "yellow",
    "dns": "yellow",
    "isp-upstream": "yellow",
    "remote-service": "magenta",
    "healthy": "green",
    "inconclusive": "dim",
}


def _sig_char(field: str, inverted: bool, value: bool) -> Text:
    good = (not value) if inverted else value
    return Text("✓", style="green bold") if good else Text("✗", style="red bold")


def _render_panel(
    target_raw: str,
    poll_num: int,
    interval_s: int,
    history: list[PollRecord],
    next_in_s: float | None,
    overran: bool = False,
) -> Panel:
    if overran:
        timing = Text("probe overran interval — starting next poll", style="dim")
    elif next_in_s is None:
        timing = Text("probing…", style="dim")
    else:
        timing = Text(f"next in {int(next_in_s)}s", style="dim")

    header = Table.grid(padding=(0, 2))
    header.add_row(
        Text(f"boundary-probe watch › {target_raw}", style="bold"),
        Text(f"poll {poll_num}  ·  {interval_s}s interval  ·  ", style="dim").append_text(timing),
    )

    if not history:
        return Panel(header, title="[bold]Boundary Probe[/bold]", border_style="dim")

    latest = history[-1]
    diag = latest.diagnosis
    snap = latest.result.snapshot
    color = _BOUNDARY_COLOR.get(diag.boundary, "white")

    diag_table = Table.grid(padding=(0, 1))
    diag_table.add_row(Text("Boundary:", style="dim"), Text(diag.boundary, style=f"bold {color}"))
    diag_table.add_row(
        Text("Confidence:", style="dim"),
        Text(f"{confidence_band(diag.confidence)} ({diag.confidence:.2f} prior)"),
    )
    diag_table.add_row(Text("Summary:", style="dim"), Text(diag.summary))

    hist_window = min(len(history), 8)
    sig_table = Table(show_header=True, header_style="dim", box=None, padding=(0, 1))
    sig_table.add_column("Signal", style="dim", min_width=12)
    sig_table.add_column("Now", min_width=3)
    sig_table.add_column(f"Last {hist_window}", no_wrap=True)

    for field, label, inverted in _SIGNALS:
        now_val = getattr(snap, field)
        now_char = _sig_char(field, inverted, now_val)
        hist_text = Text()
        for rec in history[-hist_window:]:
            hist_text.append_text(_sig_char(field, inverted, getattr(rec.result.snapshot, field)))
        sig_table.add_row(label, now_char, hist_text)

    log_table = Table(show_header=True, header_style="dim", box=None, padding=(0, 1))
    log_table.add_column("Time", style="dim", min_width=8)
    log_table.add_column("Boundary", min_width=14)
    log_table.add_column("Conf", min_width=4)
    log_table.add_column("Duration", min_width=6)
    for rec in reversed(history[-5:]):
        c = _BOUNDARY_COLOR.get(rec.diagnosis.boundary, "white")
        log_table.add_row(
            rec.ts.strftime("%H:%M:%S"),
            Text(rec.diagnosis.boundary, style=c),
            f"{rec.diagnosis.confidence:.2f}",
            f"{rec.result.elapsed_ms / 1000:.1f}s",
        )

    content = Group(header, Rule(style="dim"), diag_table, Rule(style="dim"), sig_table, Rule(style="dim"), log_table)
    return Panel(content, title="[bold]Boundary Probe[/bold]", border_style=color)


def run_watch(
    parsed_target: ParsedTarget,
    interval_s: int,
    skip_path: bool,
    max_polls: int | None,
    persist: bool = True,
) -> None:
    history: list[PollRecord] = []
    poll_num = 0

    with Live(
        _render_panel(parsed_target.raw, poll_num, interval_s, history, None),
        refresh_per_second=2,
        screen=False,
    ) as live:
        try:
            while max_polls is None or poll_num < max_polls:
                try:
                    result = collect_signals(parsed_target, skip_path=skip_path)
                except FileNotFoundError as exc:
                    from rich.console import Console
                    Console().print(f"[red]error:[/red] required network tool not found ({exc}). Stopping watch.")
                    break
                diagnosis = diagnose(result.snapshot)

                if persist:
                    with connect() as conn:
                        insert_run(
                            conn,
                            parsed_target=parsed_target,
                            snapshot=result.snapshot,
                            diagnosis=diagnosis,
                            collection_result=result,
                        )

                poll_num += 1
                history.append(PollRecord(ts=datetime.now(), result=result, diagnosis=diagnosis))
                if len(history) > 8:
                    history.pop(0)

                elapsed_s = result.elapsed_ms / 1000
                sleep_s = max(0.0, interval_s - elapsed_s)
                overran = elapsed_s > interval_s

                if overran:
                    live.update(_render_panel(parsed_target.raw, poll_num, interval_s, history, None, overran=True))
                    continue

                remaining = sleep_s
                while remaining > 0.5:
                    live.update(_render_panel(parsed_target.raw, poll_num, interval_s, history, remaining))
                    time.sleep(1.0)
                    remaining -= 1.0
                if remaining > 0:
                    time.sleep(remaining)

        except KeyboardInterrupt:
            pass
