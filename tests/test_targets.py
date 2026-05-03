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


def test_ipv6_treated_as_hostname():
    # IPv6 addresses use ":" as a delimiter, so partition(":") splits them before
    # ipaddress.ip_address() can detect the IPv6Address type. They fall through as kind=host.
    t = parse_target("::1")
    assert t.kind == "host"
