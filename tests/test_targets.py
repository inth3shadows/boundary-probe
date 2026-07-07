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


# ---------------------------------------------------------------------------
# Port validation — an unvalidated port doesn't fail loudly, it gets silently
# truncated to 16 bits by socket.getaddrinfo() downstream, so the TCP-connect
# collector would probe the WRONG port and hand back a diagnosis for a target
# the user never asked about. Must raise, matching how the URL branch already
# rejects out-of-range ports via urlsplit's .port property.
# ---------------------------------------------------------------------------


def test_rejects_out_of_range_port_on_hostname():
    with pytest.raises(ValueError):
        parse_target("example.com:99999")


def test_rejects_out_of_range_port_on_ip():
    with pytest.raises(ValueError):
        parse_target("1.1.1.1:99999")


def test_rejects_non_numeric_port():
    with pytest.raises(ValueError):
        parse_target("example.com:abc")


def test_accepts_boundary_port_values():
    assert parse_target("example.com:0").port == 0
    assert parse_target("example.com:65535").port == 65535


def test_url_already_rejects_out_of_range_port():
    # Confirms the URL branch's pre-existing behavior (urlsplit's .port property
    # raises ValueError) so both branches are consistent.
    with pytest.raises(ValueError):
        parse_target("http://example.com:99999/")


def test_rejects_url_with_empty_host():
    with pytest.raises(ValueError):
        parse_target("https:///path")
