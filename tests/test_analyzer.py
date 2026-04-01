"""Tests for analyzer.py — risky rules, circular refs, unused SGs, transitive exposure."""

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "app"))

from analyzer import (
    analyze,
    find_unused_sgs,
    find_risky_rules,
    find_circular_references,
    find_redundant_rules,
    find_default_sg_warnings,
    find_transitive_exposure,
)
from tests.conftest import make_sg, make_rule, make_source


# ── Unused SG detection ────────────────────────────────────────

class TestUnusedSgs:
    def test_unused_sg_detected(self):
        sgs = [make_sg(sg_id="sg-1", is_used=False)]
        unused = find_unused_sgs(sgs)
        assert len(unused) == 1
        assert unused[0]["sg_id"] == "sg-1"

    def test_used_sg_not_flagged(self):
        sgs = [make_sg(sg_id="sg-1", is_used=True)]
        assert find_unused_sgs(sgs) == []

    def test_default_sg_excluded(self):
        """Default SGs should not appear in unused list even if unused."""
        sgs = [make_sg(sg_id="sg-1", name="default", is_used=False)]
        assert find_unused_sgs(sgs) == []


# ── Risky rule detection ───────────────────────────────────────

class TestRiskyRules:
    def test_all_traffic_open_to_internet(self):
        sgs = [make_sg(inbound_rules=[
            make_rule("All Traffic", "All", "-1", [make_source("cidr", "0.0.0.0/0")])
        ])]
        risky = find_risky_rules(sgs)
        assert len(risky) == 1
        assert risky[0]["risk_type"] == "open_all_traffic"
        assert risky[0]["risk_level"] == "critical"

    def test_ssh_open_to_internet(self):
        sgs = [make_sg(inbound_rules=[
            make_rule("TCP", "22", "tcp", [make_source("cidr", "0.0.0.0/0")])
        ])]
        risky = find_risky_rules(sgs)
        assert risky[0]["risk_type"] == "admin_port_open"
        assert risky[0]["risk_level"] == "critical"

    def test_rdp_open_to_internet(self):
        sgs = [make_sg(inbound_rules=[
            make_rule("TCP", "3389", "tcp", [make_source("cidr", "0.0.0.0/0")])
        ])]
        risky = find_risky_rules(sgs)
        assert risky[0]["risk_type"] == "admin_port_open"

    def test_db_ports_open_to_internet(self):
        for port in ["3306", "5432", "1433", "27017", "6379", "9200"]:
            sgs = [make_sg(inbound_rules=[
                make_rule("TCP", port, "tcp", [make_source("cidr", "0.0.0.0/0")])
            ])]
            risky = find_risky_rules(sgs)
            assert risky[0]["risk_type"] == "db_port_open", f"Failed for port {port}"
            assert risky[0]["risk_level"] == "critical"

    def test_wide_port_range(self):
        sgs = [make_sg(inbound_rules=[
            make_rule("TCP", "1000-5000", "tcp", [make_source("cidr", "0.0.0.0/0")])
        ])]
        risky = find_risky_rules(sgs)
        assert risky[0]["risk_type"] == "wide_port_range"
        assert risky[0]["risk_level"] == "high"

    def test_specific_port_internet_medium(self):
        sgs = [make_sg(inbound_rules=[
            make_rule("TCP", "8080", "tcp", [make_source("cidr", "0.0.0.0/0")])
        ])]
        risky = find_risky_rules(sgs)
        assert risky[0]["risk_type"] == "internet_facing"
        assert risky[0]["risk_level"] == "medium"

    def test_ipv6_internet_detected(self):
        sgs = [make_sg(inbound_rules=[
            make_rule("All Traffic", "All", "-1", [make_source("cidr_v6", "::/0")])
        ])]
        risky = find_risky_rules(sgs)
        assert risky[0]["risk_type"] == "open_all_traffic"

    def test_wide_cidr_detected(self):
        sgs = [make_sg(inbound_rules=[
            make_rule("TCP", "443", "tcp", [make_source("cidr", "10.0.0.0/8")])
        ])]
        risky = find_risky_rules(sgs)
        assert risky[0]["risk_type"] == "wide_cidr"
        assert risky[0]["risk_level"] == "high"

    def test_private_cidr_not_flagged(self):
        """Normal private CIDR (/16) should not be flagged."""
        sgs = [make_sg(inbound_rules=[
            make_rule("TCP", "443", "tcp", [make_source("cidr", "10.0.0.0/16")])
        ])]
        assert find_risky_rules(sgs) == []

    def test_sg_reference_not_flagged(self):
        """SG-to-SG references are not risky by themselves."""
        sgs = [make_sg(inbound_rules=[
            make_rule("TCP", "443", "tcp", [make_source("sg", "sg-other")])
        ])]
        assert find_risky_rules(sgs) == []

    def test_outbound_not_flagged_for_internet(self):
        """Outbound 0.0.0.0/0 is NOT flagged (only inbound matters)."""
        sgs = [make_sg(outbound_rules=[
            make_rule("All Traffic", "All", "-1", [make_source("cidr", "0.0.0.0/0")])
        ])]
        assert find_risky_rules(sgs) == []


# ── Circular reference detection ───────────────────────────────

class TestCircularReferences:
    def test_simple_cycle(self):
        sgs = [
            make_sg(sg_id="sg-a", sg_references=["sg-b"]),
            make_sg(sg_id="sg-b", sg_references=["sg-a"]),
        ]
        sg_map = {sg["id"]: sg for sg in sgs}
        cycles = find_circular_references(sgs, sg_map)
        assert len(cycles) == 1
        assert set(cycles[0]) == {"sg-a", "sg-b"}

    def test_three_node_cycle(self):
        sgs = [
            make_sg(sg_id="sg-a", sg_references=["sg-b"]),
            make_sg(sg_id="sg-b", sg_references=["sg-c"]),
            make_sg(sg_id="sg-c", sg_references=["sg-a"]),
        ]
        sg_map = {sg["id"]: sg for sg in sgs}
        cycles = find_circular_references(sgs, sg_map)
        assert len(cycles) >= 1
        found_ids = set()
        for cycle in cycles:
            found_ids.update(cycle)
        assert {"sg-a", "sg-b", "sg-c"}.issubset(found_ids)

    def test_no_cycle(self):
        sgs = [
            make_sg(sg_id="sg-a", sg_references=["sg-b"]),
            make_sg(sg_id="sg-b", sg_references=[]),
        ]
        sg_map = {sg["id"]: sg for sg in sgs}
        assert find_circular_references(sgs, sg_map) == []


# ── Redundant rule detection ──────────────────────────────────

class TestRedundantRules:
    def test_narrow_rule_redundant_when_all_traffic_exists(self):
        sgs = [make_sg(inbound_rules=[
            make_rule("TCP", "443", "tcp", [make_source("cidr", "0.0.0.0/0")]),
            make_rule("All Traffic", "All", "-1", [make_source("cidr", "0.0.0.0/0")]),
        ])]
        redundant = find_redundant_rules(sgs)
        assert len(redundant) == 1
        assert "TCP:443" in redundant[0]["narrow_rule"]

    def test_no_redundancy(self):
        sgs = [make_sg(inbound_rules=[
            make_rule("TCP", "443", "tcp", [make_source("cidr", "10.0.0.0/16")]),
            make_rule("TCP", "80", "tcp", [make_source("cidr", "10.0.0.0/16")]),
        ])]
        assert find_redundant_rules(sgs) == []


# ── Default SG warnings ──────────────────────────────────────

class TestDefaultSgWarnings:
    def test_default_sg_with_rules_flagged(self):
        sgs = [make_sg(name="default", inbound_rules=[
            make_rule("TCP", "443", "tcp", [make_source("cidr", "10.0.0.0/16")])
        ], is_used=False)]
        warnings = find_default_sg_warnings(sgs)
        assert len(warnings) == 1
        assert warnings[0]["severity"] == "high"

    def test_default_sg_used_medium(self):
        sgs = [make_sg(name="default", inbound_rules=[
            make_rule("TCP", "443", "tcp", [make_source("cidr", "10.0.0.0/16")])
        ], is_used=True)]
        warnings = find_default_sg_warnings(sgs)
        assert warnings[0]["severity"] == "medium"

    def test_default_sg_no_rules_not_flagged(self):
        sgs = [make_sg(name="default", inbound_rules=[], is_used=False)]
        assert find_default_sg_warnings(sgs) == []

    def test_non_default_sg_not_flagged(self):
        sgs = [make_sg(name="my-sg", inbound_rules=[
            make_rule("TCP", "443", "tcp", [make_source("cidr", "10.0.0.0/16")])
        ])]
        assert find_default_sg_warnings(sgs) == []


# ── Transitive exposure detection ─────────────────────────────

class TestTransitiveExposure:
    def test_transitive_via_internet_sg(self):
        """SG-A references SG-B in inbound, SG-B has 0.0.0.0/0 → SG-A is transitively exposed."""
        sg_b = make_sg(
            sg_id="sg-b", name="public-sg",
            inbound_rules=[make_rule("TCP", "80", "tcp", [make_source("cidr", "0.0.0.0/0")])],
        )
        sg_a = make_sg(
            sg_id="sg-a", name="internal-sg",
            inbound_rules=[make_rule("TCP", "8080", "tcp", [make_source("sg", "sg-b")])],
        )
        sgs = [sg_a, sg_b]
        sg_map = {sg["id"]: sg for sg in sgs}
        transitive = find_transitive_exposure(sgs, sg_map)
        assert len(transitive) == 1
        assert transitive[0]["sg_id"] == "sg-a"
        assert transitive[0]["risk_type"] == "transitive_exposure"
        assert transitive[0]["risk_level"] == "high"
        assert "sg-b" in transitive[0]["source"]

    def test_transitive_via_ipv6(self):
        """SG-B has ::/0 → SG-A referencing SG-B is transitively exposed."""
        sg_b = make_sg(
            sg_id="sg-b",
            inbound_rules=[make_rule("All Traffic", "All", "-1", [make_source("cidr_v6", "::/0")])],
        )
        sg_a = make_sg(
            sg_id="sg-a",
            inbound_rules=[make_rule("TCP", "443", "tcp", [make_source("sg", "sg-b")])],
        )
        sgs = [sg_a, sg_b]
        sg_map = {sg["id"]: sg for sg in sgs}
        transitive = find_transitive_exposure(sgs, sg_map)
        assert len(transitive) == 1

    def test_no_transitive_when_ref_is_private(self):
        """SG-B only has private CIDR → no transitive exposure for SG-A."""
        sg_b = make_sg(
            sg_id="sg-b",
            inbound_rules=[make_rule("TCP", "443", "tcp", [make_source("cidr", "10.0.0.0/16")])],
        )
        sg_a = make_sg(
            sg_id="sg-a",
            inbound_rules=[make_rule("TCP", "8080", "tcp", [make_source("sg", "sg-b")])],
        )
        sgs = [sg_a, sg_b]
        sg_map = {sg["id"]: sg for sg in sgs}
        assert find_transitive_exposure(sgs, sg_map) == []

    def test_directly_exposed_sg_not_duplicated(self):
        """SG already directly exposed to 0.0.0.0/0 should not appear in transitive list."""
        sg_b = make_sg(
            sg_id="sg-b",
            inbound_rules=[make_rule("TCP", "80", "tcp", [make_source("cidr", "0.0.0.0/0")])],
        )
        sg_a = make_sg(
            sg_id="sg-a",
            inbound_rules=[
                make_rule("TCP", "80", "tcp", [make_source("cidr", "0.0.0.0/0")]),
                make_rule("TCP", "8080", "tcp", [make_source("sg", "sg-b")]),
            ],
        )
        sgs = [sg_a, sg_b]
        sg_map = {sg["id"]: sg for sg in sgs}
        assert find_transitive_exposure(sgs, sg_map) == []

    def test_no_sg_references_no_transitive(self):
        """SG with only CIDR sources has no transitive exposure."""
        sgs = [make_sg(
            sg_id="sg-a",
            inbound_rules=[make_rule("TCP", "443", "tcp", [make_source("cidr", "10.0.0.0/16")])],
        )]
        sg_map = {sg["id"]: sg for sg in sgs}
        assert find_transitive_exposure(sgs, sg_map) == []


# ── Full analyze() integration ─────────────────────────────────

class TestAnalyzeIntegration:
    def test_analyze_returns_all_finding_types(self):
        sgs = [
            make_sg(sg_id="sg-used", is_used=True),
            make_sg(sg_id="sg-unused", is_used=False),
        ]
        data = {"security_groups": sgs}
        findings = analyze(data)
        assert "unused_sgs" in findings
        assert "risky_rules" in findings
        assert "circular_references" in findings
        assert "redundant_rules" in findings
        assert "default_sg_warnings" in findings
        assert "summary" in findings

    def test_analyze_attaches_risk_level_to_sgs(self):
        sgs = [
            make_sg(sg_id="sg-risky", inbound_rules=[
                make_rule("All Traffic", "All", "-1", [make_source("cidr", "0.0.0.0/0")])
            ]),
            make_sg(sg_id="sg-safe"),
        ]
        data = {"security_groups": sgs}
        analyze(data)
        sg_map = {sg["id"]: sg for sg in sgs}
        assert sg_map["sg-risky"]["risk_level"] == "critical"
        assert sg_map["sg-safe"]["risk_level"] == "low"

    def test_analyze_includes_transitive_in_risky_rules(self):
        sg_b = make_sg(
            sg_id="sg-public",
            inbound_rules=[make_rule("TCP", "80", "tcp", [make_source("cidr", "0.0.0.0/0")])],
        )
        sg_a = make_sg(
            sg_id="sg-internal",
            inbound_rules=[make_rule("TCP", "8080", "tcp", [make_source("sg", "sg-public")])],
        )
        data = {"security_groups": [sg_a, sg_b]}
        findings = analyze(data)
        transitive = [r for r in findings["risky_rules"] if r["risk_type"] == "transitive_exposure"]
        assert len(transitive) == 1
        assert transitive[0]["sg_id"] == "sg-internal"
