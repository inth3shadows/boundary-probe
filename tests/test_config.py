from __future__ import annotations

import os
from pathlib import Path

import pytest

from boundary_probe.config import ProbeConfig, get_config_path, load_config

_DEFAULTS = ProbeConfig()


# ---------------------------------------------------------------------------
# get_config_path
# ---------------------------------------------------------------------------


def test_get_config_path_default(monkeypatch, tmp_path):
    import sys
    monkeypatch.delenv("BOUNDARY_PROBE_CONFIG", raising=False)
    if sys.platform == "win32":
        monkeypatch.setenv("LOCALAPPDATA", str(tmp_path))
    else:
        monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path))
    path = get_config_path()
    assert path == tmp_path / "boundary-probe" / "config.toml"


def test_get_config_path_env_override(monkeypatch, tmp_path):
    override = tmp_path / "custom.toml"
    monkeypatch.setenv("BOUNDARY_PROBE_CONFIG", str(override))
    assert get_config_path() == override


# ---------------------------------------------------------------------------
# load_config — missing file returns defaults
# ---------------------------------------------------------------------------


def test_defaults_when_no_file(monkeypatch, tmp_path):
    monkeypatch.setenv("BOUNDARY_PROBE_CONFIG", str(tmp_path / "nonexistent.toml"))
    cfg = load_config()
    assert cfg == _DEFAULTS


# ---------------------------------------------------------------------------
# load_config — TOML overrides
# ---------------------------------------------------------------------------


def _write_config(tmp_path: Path, content: str) -> None:
    config_file = tmp_path / "config.toml"
    config_file.write_text(content, encoding="utf-8")


def test_toml_overrides_control_hosts(monkeypatch, tmp_path):
    # Set quorum=2 to match the 2 hosts (default quorum=3 would fail validation)
    _write_config(tmp_path, '[probes]\ncontrol_hosts = ["1.2.3.4", "5.6.7.8"]\ncontrol_quorum = 2\n')
    monkeypatch.setenv("BOUNDARY_PROBE_CONFIG", str(tmp_path / "config.toml"))
    cfg = load_config()
    assert cfg.control_hosts == ("1.2.3.4", "5.6.7.8")
    # Other fields stay at defaults
    assert cfg.canary_ip == _DEFAULTS.canary_ip


def test_scalar_control_hosts_is_rejected_not_char_iterated(monkeypatch, tmp_path):
    # A natural TOML mistake: writing a scalar instead of an array. The old
    # behavior char-iterated the string into 7 single-character "hosts"
    # ("1", ".", "1", ...) that silently passed validation and would be pinged
    # as bogus targets. A scalar must be rejected at the boundary (#36).
    _write_config(tmp_path, '[probes]\ncontrol_hosts = "1.1.1.1"\n')
    monkeypatch.setenv("BOUNDARY_PROBE_CONFIG", str(tmp_path / "config.toml"))
    with pytest.raises(SystemExit):
        load_config()


def test_toml_overrides_threshold(monkeypatch, tmp_path):
    _write_config(tmp_path, "[thresholds]\npath_loss_pct = 35.0\n")
    monkeypatch.setenv("BOUNDARY_PROBE_CONFIG", str(tmp_path / "config.toml"))
    cfg = load_config()
    assert cfg.path_loss_pct == 35.0
    assert cfg.control_loss_pct == _DEFAULTS.control_loss_pct


def test_target_tls_verify_default_true(monkeypatch, tmp_path):
    monkeypatch.setenv("BOUNDARY_PROBE_CONFIG", str(tmp_path / "nope.toml"))
    assert load_config().target_tls_verify is True


def test_target_tls_verify_toml_override(monkeypatch, tmp_path):
    _write_config(tmp_path, "[probes]\ntarget_tls_verify = false\n")
    monkeypatch.setenv("BOUNDARY_PROBE_CONFIG", str(tmp_path / "config.toml"))
    assert load_config().target_tls_verify is False


def test_target_tls_verify_stringly_typed_is_rejected(monkeypatch, tmp_path):
    # bool("false") is True — a stringly-typed value must be rejected loudly, not
    # silently coerced to verification ON when the user meant to disable it.
    _write_config(tmp_path, '[probes]\ntarget_tls_verify = "false"\n')
    monkeypatch.setenv("BOUNDARY_PROBE_CONFIG", str(tmp_path / "config.toml"))
    with pytest.raises(SystemExit):
        load_config()


def test_target_http_timeout_override_and_validation(monkeypatch, tmp_path):
    _write_config(tmp_path, "[timeouts]\ntarget_http_s = 9.0\n")
    monkeypatch.setenv("BOUNDARY_PROBE_CONFIG", str(tmp_path / "config.toml"))
    assert load_config().target_http_s == 9.0
    _write_config(tmp_path, "[timeouts]\ntarget_http_s = 0\n")
    with pytest.raises(SystemExit):
        load_config()


def test_vantage_disabled_by_default(monkeypatch, tmp_path):
    monkeypatch.setenv("BOUNDARY_PROBE_CONFIG", str(tmp_path / "nope.toml"))
    cfg = load_config()
    assert cfg.vantage_url is None
    assert cfg.vantage_timeout_s == 4.0


def test_vantage_toml_override(monkeypatch, tmp_path):
    _write_config(tmp_path, '[vantage]\nurl = "https://probe.example/check"\ntimeout_s = 6.0\n')
    monkeypatch.setenv("BOUNDARY_PROBE_CONFIG", str(tmp_path / "config.toml"))
    cfg = load_config()
    assert cfg.vantage_url == "https://probe.example/check"
    assert cfg.vantage_timeout_s == 6.0


def test_vantage_url_must_be_https(monkeypatch, tmp_path):
    # The target travels off-box; a cleartext http:// vantage is rejected.
    _write_config(tmp_path, '[vantage]\nurl = "http://probe.example/check"\n')
    monkeypatch.setenv("BOUNDARY_PROBE_CONFIG", str(tmp_path / "config.toml"))
    with pytest.raises(SystemExit):
        load_config()


def test_vantage_timeout_must_be_positive(monkeypatch, tmp_path):
    _write_config(tmp_path, '[vantage]\nurl = "https://probe.example"\ntimeout_s = 0\n')
    monkeypatch.setenv("BOUNDARY_PROBE_CONFIG", str(tmp_path / "config.toml"))
    with pytest.raises(SystemExit):
        load_config()


def test_captive_check_default_is_http_204(monkeypatch, tmp_path):
    monkeypatch.setenv("BOUNDARY_PROBE_CONFIG", str(tmp_path / "nope.toml"))
    cfg = load_config()
    assert cfg.captive_check_url.startswith("http://")
    assert cfg.captive_check_s == 4.0


def test_captive_check_override_and_disable(monkeypatch, tmp_path):
    _write_config(tmp_path, '[captive]\ncheck_url = ""\ntimeout_s = 2.5\n')
    monkeypatch.setenv("BOUNDARY_PROBE_CONFIG", str(tmp_path / "config.toml"))
    cfg = load_config()
    assert cfg.captive_check_url == ""  # disabled
    assert cfg.captive_check_s == 2.5


def test_captive_check_url_must_be_http(monkeypatch, tmp_path):
    # https would just fail TLS behind a portal; require http (or "" to disable).
    _write_config(tmp_path, '[captive]\ncheck_url = "https://example/generate_204"\n')
    monkeypatch.setenv("BOUNDARY_PROBE_CONFIG", str(tmp_path / "config.toml"))
    with pytest.raises(SystemExit):
        load_config()


def test_captive_timeout_must_be_positive(monkeypatch, tmp_path):
    _write_config(tmp_path, '[captive]\ntimeout_s = 0\n')
    monkeypatch.setenv("BOUNDARY_PROBE_CONFIG", str(tmp_path / "config.toml"))
    with pytest.raises(SystemExit):
        load_config()


def test_toml_overrides_timeout(monkeypatch, tmp_path):
    _write_config(tmp_path, "[timeouts]\ntracert_s = 60.0\n")
    monkeypatch.setenv("BOUNDARY_PROBE_CONFIG", str(tmp_path / "config.toml"))
    cfg = load_config()
    assert cfg.tracert_s == 60.0
    assert cfg.gateway_ping_s == _DEFAULTS.gateway_ping_s


def test_toml_overrides_target_tcp_timeout(monkeypatch, tmp_path):
    _write_config(tmp_path, "[timeouts]\ntarget_tcp_s = 3.0\n")
    monkeypatch.setenv("BOUNDARY_PROBE_CONFIG", str(tmp_path / "config.toml"))
    cfg = load_config()
    assert cfg.target_tcp_s == 3.0


def test_nonpositive_target_tcp_timeout_exits(monkeypatch, tmp_path):
    _write_config(tmp_path, "[timeouts]\ntarget_tcp_s = 0\n")
    monkeypatch.setenv("BOUNDARY_PROBE_CONFIG", str(tmp_path / "config.toml"))
    with pytest.raises(SystemExit):
        load_config()


def test_toml_overrides_quorum(monkeypatch, tmp_path):
    _write_config(tmp_path, "[probes]\ncontrol_quorum = 2\n")
    monkeypatch.setenv("BOUNDARY_PROBE_CONFIG", str(tmp_path / "config.toml"))
    cfg = load_config()
    assert cfg.control_quorum == 2


def test_missing_section_uses_defaults(monkeypatch, tmp_path):
    _write_config(tmp_path, "[probes]\ncanary_ip = \"9.9.9.9\"\n")
    monkeypatch.setenv("BOUNDARY_PROBE_CONFIG", str(tmp_path / "config.toml"))
    cfg = load_config()
    assert cfg.canary_ip == "9.9.9.9"
    # [timeouts] section absent — all timeout defaults intact
    assert cfg.tracert_s == _DEFAULTS.tracert_s
    assert cfg.gateway_ping_s == _DEFAULTS.gateway_ping_s


def test_full_config_file(monkeypatch, tmp_path):
    content = """
[probes]
control_hosts = ["1.0.0.1", "9.9.9.9"]
canary_ip = "9.9.9.9"
secondary_target = "1.0.0.1"
control_quorum = 2

[thresholds]
path_loss_pct = 30.0
control_loss_pct = 60.0
ip_loss_pct = 40.0
gateway_min_replies = 3

[timeouts]
gateway_route_s = 3.0
gateway_ping_s = 6.0
ip_connectivity_s = 12.0
control_hosts_s = 8.0
target_ping_s = 6.0
tracert_s = 45.0
"""
    _write_config(tmp_path, content)
    monkeypatch.setenv("BOUNDARY_PROBE_CONFIG", str(tmp_path / "config.toml"))
    cfg = load_config()
    assert cfg.control_hosts == ("1.0.0.1", "9.9.9.9")
    assert cfg.canary_ip == "9.9.9.9"
    assert cfg.secondary_target == "1.0.0.1"
    assert cfg.control_quorum == 2
    assert cfg.path_loss_pct == 30.0
    assert cfg.control_loss_pct == 60.0
    assert cfg.ip_loss_pct == 40.0
    assert cfg.gateway_min_replies == 3
    assert cfg.gateway_route_s == 3.0
    assert cfg.gateway_ping_s == 6.0
    assert cfg.ip_connectivity_s == 12.0
    assert cfg.control_hosts_s == 8.0
    assert cfg.target_ping_s == 6.0
    assert cfg.tracert_s == 45.0


# ---------------------------------------------------------------------------
# load_config — invalid TOML falls back to defaults with warning
# ---------------------------------------------------------------------------


def test_invalid_toml_warns_and_returns_defaults(monkeypatch, tmp_path, capsys):
    _write_config(tmp_path, "this is not [valid toml\n")
    monkeypatch.setenv("BOUNDARY_PROBE_CONFIG", str(tmp_path / "config.toml"))
    cfg = load_config()
    assert cfg == _DEFAULTS
    captured = capsys.readouterr()
    assert "warning" in captured.err
    assert "config file" in captured.err


# ---------------------------------------------------------------------------
# ControlHostsSlice — ok_count and total
# ---------------------------------------------------------------------------


def test_control_hosts_slice_ok_count(monkeypatch, tmp_path):
    """ok_count and total are populated by the collector."""
    import sys
    monkeypatch.setenv("BOUNDARY_PROBE_CONFIG", str(tmp_path / "nonexistent.toml"))
    from boundary_probe.collectors._runner import CommandResult
    from boundary_probe.collectors.control_hosts import collect_control_hosts

    # Fixture format must match the platform's parser (the collector dispatches
    # parse_ping_output by sys.platform): Windows / macOS(BSD) / Linux each differ.
    FIXTURES = Path(__file__).parent / "fixtures"
    if sys.platform == "win32":
        subdir = ""
    elif sys.platform == "darwin":
        subdir = "mac"
    else:
        subdir = "linux"
    success_out = (FIXTURES / subdir / "ping_success.txt").read_text(encoding="utf-8")
    loss_out = (FIXTURES / subdir / "ping_total_loss.txt").read_text(encoding="utf-8")

    class FakeRunner:
        def run(self, argv, timeout_s):
            host = argv[-1]
            out = success_out if host in ("1.1.1.1", "8.8.8.8") else loss_out
            return CommandResult(returncode=0, stdout=out, stderr="", timed_out=False, duration_ms=10)

    result = collect_control_hosts(FakeRunner(), hosts=("1.1.1.1", "8.8.8.8", "8.8.4.4", "cloudflare.com"))
    assert result.ok_count == 2
    assert result.total == 4
    assert result.all_ok is False  # quorum=3, only 2 ok


# ---------------------------------------------------------------------------
# ProbeConfig validation — invalid values exit with code 1
# ---------------------------------------------------------------------------


def _write_and_load(tmp_path, monkeypatch, content: str):
    _write_config(tmp_path, content)
    monkeypatch.setenv("BOUNDARY_PROBE_CONFIG", str(tmp_path / "config.toml"))
    monkeypatch.setenv("LOCALAPPDATA", str(tmp_path))
    from boundary_probe.config import load_config
    return load_config


def test_validate_quorum_too_large(monkeypatch, tmp_path, capsys):
    _write_config(tmp_path, "[probes]\ncontrol_quorum = 10\n")
    monkeypatch.setenv("BOUNDARY_PROBE_CONFIG", str(tmp_path / "config.toml"))
    from boundary_probe.config import load_config
    with pytest.raises(SystemExit) as exc:
        load_config()
    assert exc.value.code == 1
    assert "control_quorum" in capsys.readouterr().err


def test_validate_quorum_zero(monkeypatch, tmp_path, capsys):
    _write_config(tmp_path, "[probes]\ncontrol_quorum = 0\n")
    monkeypatch.setenv("BOUNDARY_PROBE_CONFIG", str(tmp_path / "config.toml"))
    from boundary_probe.config import load_config
    with pytest.raises(SystemExit) as exc:
        load_config()
    assert exc.value.code == 1
    assert "control_quorum" in capsys.readouterr().err


def test_validate_negative_timeout(monkeypatch, tmp_path, capsys):
    _write_config(tmp_path, "[timeouts]\ntracert_s = -5.0\n")
    monkeypatch.setenv("BOUNDARY_PROBE_CONFIG", str(tmp_path / "config.toml"))
    from boundary_probe.config import load_config
    with pytest.raises(SystemExit) as exc:
        load_config()
    assert exc.value.code == 1
    assert "tracert_s" in capsys.readouterr().err


def test_validate_loss_pct_out_of_range(monkeypatch, tmp_path, capsys):
    _write_config(tmp_path, "[thresholds]\npath_loss_pct = 150.0\n")
    monkeypatch.setenv("BOUNDARY_PROBE_CONFIG", str(tmp_path / "config.toml"))
    from boundary_probe.config import load_config
    with pytest.raises(SystemExit) as exc:
        load_config()
    assert exc.value.code == 1
    assert "path_loss_pct" in capsys.readouterr().err


def test_validate_defaults_pass(monkeypatch, tmp_path):
    monkeypatch.setenv("BOUNDARY_PROBE_CONFIG", str(tmp_path / "nonexistent.toml"))
    from boundary_probe.config import load_config
    cfg = load_config()  # must not raise or exit
    assert cfg.control_quorum <= len(cfg.control_hosts)


def test_validate_raises_valueerror_directly():
    from boundary_probe.config import ProbeConfig, _validate
    bad = ProbeConfig(control_quorum=0)
    with pytest.raises(ValueError, match="control_quorum"):
        _validate(bad)


def test_wrong_typed_toml_value_gives_clean_error(monkeypatch, tmp_path, capsys):
    # TOML allows strings; int("two") must not produce a raw traceback
    _write_config(tmp_path, "[probes]\ncontrol_quorum = \"two\"\n")
    monkeypatch.setenv("BOUNDARY_PROBE_CONFIG", str(tmp_path / "config.toml"))
    from boundary_probe.config import load_config
    with pytest.raises(SystemExit) as exc:
        load_config()
    assert exc.value.code == 1
    err = capsys.readouterr().err
    assert "error: config:" in err
