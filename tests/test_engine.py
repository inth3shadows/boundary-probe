from boundary_probe.engine import demo_signals, diagnose


def test_router_down_classifies_as_router_gateway() -> None:
    diagnosis = diagnose(demo_signals("router-down"))
    assert diagnosis.boundary == "router-gateway"
    assert diagnosis.confidence == 0.99


def test_dns_failure_classifies_as_dns() -> None:
    diagnosis = diagnose(demo_signals("dns-failure"))
    assert diagnosis.boundary == "dns"
    assert diagnosis.confidence == 0.96

