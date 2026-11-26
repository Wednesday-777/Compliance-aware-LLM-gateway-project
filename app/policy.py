from dataclasses import dataclass
from pathlib import Path

import yaml

from app.pii import PATTERNS

POLICY_PATH = Path(__file__).resolve().parent.parent / "policy.yaml"

PII_ACTIONS = {"redact", "block", "allow"}
INJECTION_ACTIONS = {"block", "flag"}


@dataclass
class Policy:
    pii_default: str
    pii_actions: dict
    injection_enabled: bool
    injection_threshold: int
    injection_action: str

    def pii_action_for(self, pii_type: str) -> str:
        return self.pii_actions.get(pii_type, self.pii_default)


def _check_choice(value, allowed: set, label: str) -> None:
    if value not in allowed:
        raise ValueError(f"{label} must be one of {sorted(allowed)}, got {value!r}")


def load_policy(path=POLICY_PATH) -> Policy:
    with open(path, encoding="utf-8") as f:
        raw = yaml.safe_load(f) or {}

    pii = raw.get("pii") or {}
    inj = raw.get("injection") or {}

    default = pii.get("default_action", "redact")
    _check_choice(default, PII_ACTIONS, "pii.default_action")

    actions = pii.get("actions") or {}
    for pii_type, action in actions.items():
        if pii_type not in PATTERNS:
            raise ValueError(
                f"Unknown PII type {pii_type!r} in policy. Known: {sorted(PATTERNS)}"
            )
        _check_choice(action, PII_ACTIONS, f"pii.actions.{pii_type}")

    enabled = inj.get("enabled", True)
    if not isinstance(enabled, bool):
        raise ValueError("injection.enabled must be true or false")

    threshold = inj.get("threshold", 5)
    if isinstance(threshold, bool) or not isinstance(threshold, int) or threshold < 1:
        raise ValueError("injection.threshold must be a whole number of 1 or more")

    inj_action = inj.get("action", "block")
    _check_choice(inj_action, INJECTION_ACTIONS, "injection.action")

    return Policy(
        pii_default=default,
        pii_actions=actions,
        injection_enabled=enabled,
        injection_threshold=threshold,
        injection_action=inj_action,
    )