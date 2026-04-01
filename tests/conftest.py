"""Shared fixtures for analyzer tests."""


def make_sg(
    sg_id="sg-test",
    name="test-sg",
    vpc_id="vpc-123",
    inbound_rules=None,
    outbound_rules=None,
    resources=None,
    sg_references=None,
    description="",
    is_used=True,
):
    """Helper to build a minimal SG dict for testing."""
    return {
        "id": sg_id,
        "name": name,
        "vpc_id": vpc_id,
        "description": description,
        "tags": [],
        "inbound_rules": inbound_rules or [],
        "outbound_rules": outbound_rules or [],
        "resources": resources or ([{"type": "EC2", "id": "i-123", "name": "test"}] if is_used else []),
        "resource_count": len(resources) if resources else (1 if is_used else 0),
        "is_used": is_used,
        "sg_references": sg_references or [],
    }


def make_rule(protocol="TCP", port="443", raw_protocol="tcp", sources=None):
    """Helper to build a minimal rule dict."""
    return {
        "protocol": protocol,
        "port": port,
        "from_port": int(port) if port.isdigit() else 0,
        "to_port": int(port) if port.isdigit() else 0,
        "raw_protocol": raw_protocol,
        "sources": sources or [],
    }


def make_source(type_="cidr", value="10.0.0.0/16", description=""):
    """Helper to build a source dict."""
    return {"type": type_, "value": value, "description": description}
