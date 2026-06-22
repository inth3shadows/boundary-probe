from __future__ import annotations

import pytest

from boundary_probe.targets import parse_target


def test_plain_hostname():
    t = parse_target("example.com")
    assert t.kind == "host"
    assert t.host == "example.com"
    assert t.port is None
    assert t.scheme is None


def test_hostname_with_subdomain():
    t = parse_target("api.example.com")
    assert t.kind == "host"
    assert t.host == "api.example.com"


def test_ipv4_address():
    t = parse_target("1.1.1.1")
    assert t.kind == "ip"
    assert t.host == "1.1.1.1"
    assert t.port is None


def test_ipv4_with_port():
    t = parse_target("192.168.1.1:443")
    assert t.kind == "ip"
    assert t.host == "192.168.1.1"
    assert t.port == 443


def test_https_url():
    t = parse_target("https://example.com/path")
    assert t.kind == "url"
    assert t.host == "example.com"
    assert t.port is None
    assert t.scheme == "https"


def test_http_url_with_port():
    t = parse_target("http://example.com:8080")
    assert t.kind == "url"
    assert t.host == "example.com"
    assert t.port == 8080
    assert t.scheme == "http"


def test_empty_string_raises():
    with pytest.raises(ValueError, match="empty"):
        parse_target("")


def test_whitespace_only_raises():
    with pytest.raises(ValueError, match="empty"):
        parse_target("   ")


def test_ipv6_literal_rejected():
    # "::1".partition(":") yields an empty host_part; hostname validation now
    # rejects it, which also finally honors the docstring's promise to reject
    # IPv6 literals (previously it fell through as kind=host with an empty host).
    with pytest.raises(ValueError):
        parse_target("::1")


# ---------------------------------------------------------------------------
# Hostname validation (#36) — reject targets that would inject into argv or HTML
# ---------------------------------------------------------------------------


def test_rejects_script_breakout_payload():
    with pytest.raises(ValueError):
        parse_target("</script><img src=x onerror=alert(1)>")


def test_rejects_leading_dash_host():
    # Would inject as a flag into ping/tracert on Windows (no "--" separator).
    with pytest.raises(ValueError):
        parse_target("-t")


def test_rejects_host_with_space():
    with pytest.raises(ValueError):
        parse_target("bad host")


def test_rejects_url_with_empty_host():
    with pytest.raises(ValueError):
        parse_target("https:///path")
