"""Governance tag configuration loader with environment variable overrides."""

import json
import os
from pathlib import Path

CONFIG_PATH = Path(__file__).parent.parent / "config.json"

DEFAULTS = {
    "governance_tags": {
        "owner": "Owner",
        "project": "Project",
        "environment": "Environment",
        "reviewed_at": "ReviewedAt",
        "expires_at": "ExpiresAt",
        "justification": "Justification",
        "risk_accepted": "RiskAccepted",
        "approved_by": "ApprovedBy",
    },
    "governance_rules": {
        "required_tags": ["owner", "justification"],
        "review_interval_days": 90,
        "warn_expiry_days_before": 14,
    },
}


def load_config(config_path=None):
    """Load governance config from file, then apply env var overrides.

    Env var convention:
      SG_TAG_OWNER=ResourceOwner      -> governance_tags.owner
      SG_REQUIRED_TAGS=owner,project   -> governance_rules.required_tags
      SG_REVIEW_INTERVAL_DAYS=60       -> governance_rules.review_interval_days
      SG_WARN_EXPIRY_DAYS=7            -> governance_rules.warn_expiry_days_before
    """
    path = Path(config_path) if config_path else CONFIG_PATH
    config = _deep_copy(DEFAULTS)

    if path.exists():
        try:
            with open(path) as f:
                loaded = json.load(f)
            if "governance_tags" in loaded:
                config["governance_tags"].update(loaded["governance_tags"])
            if "governance_rules" in loaded:
                config["governance_rules"].update(loaded["governance_rules"])
        except (json.JSONDecodeError, OSError):
            pass  # fall back to defaults

    # Env var overrides for tag names
    for key in config["governance_tags"]:
        env_val = os.environ.get(f"SG_TAG_{key.upper()}")
        if env_val:
            config["governance_tags"][key] = env_val

    # Env var overrides for rules
    req = os.environ.get("SG_REQUIRED_TAGS")
    if req:
        config["governance_rules"]["required_tags"] = [t.strip() for t in req.split(",") if t.strip()]

    interval = os.environ.get("SG_REVIEW_INTERVAL_DAYS")
    if interval and interval.isdigit():
        config["governance_rules"]["review_interval_days"] = int(interval)

    expiry = os.environ.get("SG_WARN_EXPIRY_DAYS")
    if expiry and expiry.isdigit():
        config["governance_rules"]["warn_expiry_days_before"] = int(expiry)

    return config


def _deep_copy(d):
    """Simple deep copy for dicts/lists without importing copy."""
    if isinstance(d, dict):
        return {k: _deep_copy(v) for k, v in d.items()}
    if isinstance(d, list):
        return [_deep_copy(i) for i in d]
    return d
