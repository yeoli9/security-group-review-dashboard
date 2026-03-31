"""Security Group analysis - unused SGs, risky rules, circular references."""


def analyze(data):
    """Analyze collected SG data and return findings."""
    sgs = data["security_groups"]
    sg_map = {sg["id"]: sg for sg in sgs}

    findings = {
        "unused_sgs": find_unused_sgs(sgs),
        "default_sg_warnings": find_default_sg_warnings(sgs),
        "risky_rules": find_risky_rules(sgs),
        "circular_references": find_circular_references(sgs, sg_map),
        "redundant_rules": find_redundant_rules(sgs),
        "summary": build_summary(sgs),
    }

    # Attach findings to each SG
    # Build per-SG max risk level from individual rules
    sg_max_risk = {}  # sg_id -> "critical" | "high" | "medium"
    for r in findings["risky_rules"]:
        cur = sg_max_risk.get(r["sg_id"], "")
        rule_level = r["risk_level"]
        if _risk_order(rule_level) < _risk_order(cur):
            sg_max_risk[r["sg_id"]] = rule_level

    risky_sg_ids = set(sg_max_risk.keys())
    circular_sg_ids = set()
    for cycle in findings["circular_references"]:
        circular_sg_ids.update(cycle)

    for sg in sgs:
        sg["has_risky_rules"] = sg["id"] in risky_sg_ids
        sg["in_circular_ref"] = sg["id"] in circular_sg_ids
        sg["risk_level"] = _calc_risk_level(sg, sg_max_risk, circular_sg_ids)

    return findings


def find_unused_sgs(sgs):
    """Find security groups with no attached resources."""
    unused = []
    for sg in sgs:
        if not sg["is_used"] and sg["name"] != "default":
            unused.append({
                "sg_id": sg["id"],
                "sg_name": sg["name"],
                "vpc_id": sg["vpc_id"],
                "description": sg["description"],
                "inbound_count": len(sg["inbound_rules"]),
                "outbound_count": len(sg["outbound_rules"]),
            })
    return unused


def find_default_sg_warnings(sgs):
    """Find default SGs with unnecessary inbound rules (especially unused ones)."""
    warnings = []
    for sg in sgs:
        if sg["name"] != "default":
            continue
        inbound = sg["inbound_rules"]
        if not inbound:
            continue

        # Default SG with inbound rules is worth reviewing
        has_resources = sg["is_used"]
        severity = "medium" if has_resources else "high"
        reason = "리소스 연결 없는 default SG에 인바운드 규칙 존재 — 규칙 제거 권장" if not has_resources \
            else "default SG에 인바운드 규칙 존재 — 최소권한 검토 필요"

        rule_details = []
        for rule in inbound:
            sources = [s["value"] for s in rule["sources"]]
            rule_details.append({
                "protocol": rule["protocol"],
                "port": rule["port"],
                "sources": sources,
            })

        warnings.append({
            "sg_id": sg["id"],
            "sg_name": sg["name"],
            "vpc_id": sg["vpc_id"],
            "severity": severity,
            "reason": reason,
            "has_resources": has_resources,
            "resource_count": sg["resource_count"],
            "inbound_rule_count": len(inbound),
            "inbound_rules": rule_details,
        })
    return warnings


def find_risky_rules(sgs):
    """Find overly permissive or risky rules."""
    risky = []

    for sg in sgs:
        for direction, rules in [("inbound", sg["inbound_rules"]), ("outbound", sg["outbound_rules"])]:
            for rule in rules:
                for source in rule["sources"]:
                    risk = _assess_rule_risk(rule, source, direction)
                    if risk:
                        risky.append({
                            "sg_id": sg["id"],
                            "sg_name": sg["name"],
                            "direction": direction,
                            "protocol": rule["protocol"],
                            "port": rule["port"],
                            "source": source["value"],
                            "risk_type": risk["type"],
                            "risk_level": risk["level"],
                            "description": risk["description"],
                        })
    return risky


def _assess_rule_risk(rule, source, direction):
    """Assess risk of a single rule+source combination."""
    value = source["value"]
    port = rule["port"]
    protocol = rule["protocol"]

    # Inbound 0.0.0.0/0 or ::/0
    if direction == "inbound" and value in ("0.0.0.0/0", "::/0"):
        if protocol == "All Traffic":
            return {
                "type": "open_all_traffic",
                "level": "critical",
                "description": "All traffic open to the internet",
            }
        if port in ("22", "3389"):
            return {
                "type": "admin_port_open",
                "level": "critical",
                "description": f"Admin port {port} open to the internet",
            }
        if port in ("3306", "5432", "1433", "27017", "6379", "9200"):
            return {
                "type": "db_port_open",
                "level": "critical",
                "description": f"Database port {port} open to the internet",
            }
        # Wide port range
        if "-" in port:
            try:
                low, high = port.split("-")
                if int(high) - int(low) > 100:
                    return {
                        "type": "wide_port_range",
                        "level": "high",
                        "description": f"Wide port range {port} open to the internet",
                    }
            except ValueError:
                pass
        return {
            "type": "internet_facing",
            "level": "medium",
            "description": f"Port {port} ({protocol}) open to the internet",
        }

    # /8 or wider CIDR
    if source["type"] == "cidr" and "/" in value:
        try:
            prefix = int(value.split("/")[1])
            if prefix <= 8 and direction == "inbound":
                return {
                    "type": "wide_cidr",
                    "level": "high",
                    "description": f"Very wide CIDR range {value}",
                }
        except ValueError:
            pass

    return None


def find_circular_references(sgs, sg_map):
    """Find circular SG references (A -> B -> A or A -> B -> C -> A)."""
    cycles = []
    visited_cycles = set()

    for sg in sgs:
        _dfs_cycles(sg["id"], sg["id"], [sg["id"]], sg_map, cycles, visited_cycles)

    return cycles


def _dfs_cycles(start, current, path, sg_map, cycles, visited_cycles):
    sg = sg_map.get(current)
    if not sg:
        return

    for ref_id in sg.get("sg_references", []):
        if ref_id == start and len(path) > 1:
            cycle = tuple(sorted(path))
            if cycle not in visited_cycles:
                visited_cycles.add(cycle)
                cycles.append(list(path))
            return
        if ref_id not in path and ref_id in sg_map:
            if len(path) < 5:  # Limit depth
                _dfs_cycles(start, ref_id, path + [ref_id], sg_map, cycles, visited_cycles)


def find_redundant_rules(sgs):
    """Find rules that might be redundant (subset of another rule)."""
    redundant = []
    for sg in sgs:
        for direction, rules in [("inbound", sg["inbound_rules"]), ("outbound", sg["outbound_rules"])]:
            for i, rule_a in enumerate(rules):
                for j, rule_b in enumerate(rules):
                    if i >= j:
                        continue
                    if _is_subset_rule(rule_a, rule_b):
                        redundant.append({
                            "sg_id": sg["id"],
                            "sg_name": sg["name"],
                            "direction": direction,
                            "narrow_rule": f"{rule_a['protocol']}:{rule_a['port']}",
                            "broad_rule": f"{rule_b['protocol']}:{rule_b['port']}",
                        })
    return redundant


def _is_subset_rule(narrow, broad):
    """Check if narrow rule is a subset of broad rule (same sources, narrower ports)."""
    if broad["protocol"] != "All Traffic" and narrow["raw_protocol"] != broad["raw_protocol"]:
        return False

    if broad["protocol"] == "All Traffic" and narrow["protocol"] != "All Traffic":
        narrow_sources = {s["value"] for s in narrow["sources"]}
        broad_sources = {s["value"] for s in broad["sources"]}
        if narrow_sources.issubset(broad_sources):
            return True

    return False


def build_summary(sgs):
    total = len(sgs)
    used = sum(1 for sg in sgs if sg["is_used"])
    unused = total - used
    total_inbound = sum(len(sg["inbound_rules"]) for sg in sgs)
    total_outbound = sum(len(sg["outbound_rules"]) for sg in sgs)

    vpc_counts = {}
    for sg in sgs:
        vpc_id = sg["vpc_id"]
        vpc_counts[vpc_id] = vpc_counts.get(vpc_id, 0) + 1

    default_with_rules = sum(
        1 for sg in sgs
        if sg["name"] == "default" and len(sg["inbound_rules"]) > 0
    )

    return {
        "total_sgs": total,
        "used_sgs": used,
        "unused_sgs": unused,
        "total_inbound_rules": total_inbound,
        "total_outbound_rules": total_outbound,
        "vpc_sg_counts": vpc_counts,
        "default_sg_warnings": default_with_rules,
    }


def _risk_order(level):
    return {"critical": 0, "high": 1, "medium": 2, "low": 3, "": 99}.get(level, 99)


def _calc_risk_level(sg, sg_max_risk, circular_sg_ids):
    if not sg["is_used"]:
        return "unused"
    if sg["id"] in sg_max_risk:
        return sg_max_risk[sg["id"]]  # "critical", "high", or "medium"
    if sg["id"] in circular_sg_ids:
        return "medium"
    return "low"
