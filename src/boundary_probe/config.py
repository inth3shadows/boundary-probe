from __future__ import annotations

import os
import sys
import tomllib
from dataclasses import dataclass
from pathlib import Path


@dataclass(slots=True, frozen=True)
class ProbeConfig:
    # [probes]
    control_hosts: tuple[str, ...] = ("1.1.1.1", "8.8.8.8", "8.8.4.4", "cloudflare.com")
    canary_ip: str = "1.1.1.1"
    secondary_target: str = "8.8.8.8"
    control_quorum: int = 3

    # [thresholds]
    path_loss_pct: float = 20.0
    control_loss_pct: float = 50.0
    ip_loss_pct: float = 50.0
    gateway_min_replies: int = 2

    # [timeouts]
    gateway_route_s: float = 5.0
    gateway_ping_s: float = 8.0
    ip_connectivity_s: float = 15.0
    control_hosts_s: float = 10.0
    target_ping_s: float = 8.0
    target_tcp_s: float = 5.0
    tracert_s: float = 60.0


_DEFAULTS = ProbeConfig()


def _validate(cfg: ProbeConfig) -> None:
    errors: list[str] = []

    if cfg.control_quorum < 1:
        errors.append(f"control_quorum must be >= 1 (got {cfg.control_quorum})")
    if cfg.control_quorum > len(cfg.control_hosts):
        errors.append(
            f"control_quorum ({cfg.control_quorum}) exceeds number of "
            f"control_hosts ({len(cfg.control_hosts)})"
        )
    if cfg.gateway_min_replies < 1:
        errors.append(f"gateway_min_replies must be >= 1 (got {cfg.gateway_min_replies})")

    for name, val in (
        ("gateway_route_s", cfg.gateway_route_s),
        ("gateway_ping_s", cfg.gateway_ping_s),
        ("ip_connectivity_s", cfg.ip_connectivity_s),
        ("control_hosts_s", cfg.control_hosts_s),
        ("target_ping_s", cfg.target_ping_s),
        ("target_tcp_s", cfg.target_tcp_s),
        ("tracert_s", cfg.tracert_s),
    ):
        if val <= 0:
            errors.append(f"{name} must be > 0 (got {val})")

    for name, val in (
        ("path_loss_pct", cfg.path_loss_pct),
        ("control_loss_pct", cfg.control_loss_pct),
        ("ip_loss_pct", cfg.ip_loss_pct),
    ):
        if not (0.0 <= val <= 100.0):
            errors.append(f"{name} must be in 0–100 (got {val})")

    if errors:
        raise ValueError("\n".join(errors))


_PLATFORM: str = sys.platform
_WIN: bool = _PLATFORM == "win32"


def get_data_dir() -> Path:
    """Return the platform-appropriate app data directory."""
    if _WIN:
        base = os.environ.get("LOCALAPPDATA", str(Path.home() / "AppData" / "Local"))
    else:
        base = os.environ.get("XDG_DATA_HOME", str(Path.home() / ".local" / "share"))
    return Path(base) / "boundary-probe"


def get_config_path() -> Path:
    """Return the config file path (env override or default platform location)."""
    override = os.environ.get("BOUNDARY_PROBE_CONFIG")
    if override:
        return Path(override)
    return get_data_dir() / "config.toml"


def load_config() -> ProbeConfig:
    """Load config from TOML file; return defaults if file missing or invalid."""
    path = get_config_path()
    if not path.exists():
        return _DEFAULTS
    try:
        with open(path, "rb") as f:
            data = tomllib.load(f)
    except Exception as exc:
        print(f"warning: config file parse error ({exc}); using defaults", file=sys.stderr)
        return _DEFAULTS

    probes = data.get("probes", {})
    thresholds = data.get("thresholds", {})
    timeouts = data.get("timeouts", {})

    raw_hosts = probes.get("control_hosts", None)
    if raw_hosts is None:
        control_hosts = _DEFAULTS.control_hosts
    elif isinstance(raw_hosts, (list, tuple)):
        control_hosts = tuple(str(h) for h in raw_hosts)
    else:
        # A scalar (e.g. control_hosts = "1.1.1.1") would otherwise char-iterate
        # into bogus single-character hosts that silently pass validation.
        print(
            "error: config: control_hosts must be an array of strings, "
            f"e.g. [\"1.1.1.1\", \"8.8.8.8\"] (got {type(raw_hosts).__name__})",
            file=sys.stderr,
        )
        sys.exit(1)

    try:
        cfg = ProbeConfig(
            control_hosts=control_hosts,
            canary_ip=str(probes.get("canary_ip", _DEFAULTS.canary_ip)),
            secondary_target=str(probes.get("secondary_target", _DEFAULTS.secondary_target)),
            control_quorum=int(probes.get("control_quorum", _DEFAULTS.control_quorum)),
            path_loss_pct=float(thresholds.get("path_loss_pct", _DEFAULTS.path_loss_pct)),
            control_loss_pct=float(thresholds.get("control_loss_pct", _DEFAULTS.control_loss_pct)),
            ip_loss_pct=float(thresholds.get("ip_loss_pct", _DEFAULTS.ip_loss_pct)),
            gateway_min_replies=int(thresholds.get("gateway_min_replies", _DEFAULTS.gateway_min_replies)),
            gateway_route_s=float(timeouts.get("gateway_route_s", _DEFAULTS.gateway_route_s)),
            gateway_ping_s=float(timeouts.get("gateway_ping_s", _DEFAULTS.gateway_ping_s)),
            ip_connectivity_s=float(timeouts.get("ip_connectivity_s", _DEFAULTS.ip_connectivity_s)),
            control_hosts_s=float(timeouts.get("control_hosts_s", _DEFAULTS.control_hosts_s)),
            target_ping_s=float(timeouts.get("target_ping_s", _DEFAULTS.target_ping_s)),
            target_tcp_s=float(timeouts.get("target_tcp_s", _DEFAULTS.target_tcp_s)),
            tracert_s=float(timeouts.get("tracert_s", _DEFAULTS.tracert_s)),
        )
        _validate(cfg)
    except (ValueError, TypeError) as exc:
        for msg in str(exc).splitlines():
            print(f"error: config: {msg}", file=sys.stderr)
        sys.exit(1)
    return cfg
