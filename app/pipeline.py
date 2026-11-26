from dataclasses import dataclass, field

from app.injection import check_injection
from app.pii import detect_pii, redact_findings
from app.policy import Policy


@dataclass
class Decision:
    text: str
    blocked: bool = False
    block_reason: str | None = None
    block_details: dict = field(default_factory=dict)
    pii_redacted: list = field(default_factory=list)
    pii_allowed: list = field(default_factory=list)
    injection_flagged: bool = False


def process_message(text: str, role: str, policy: Policy) -> Decision:
    decision = Decision(text=text)

    # 1. Injection check (user messages only; system messages come from the developer)
    if role == "user" and policy.injection_enabled:
        result = check_injection(text, policy.injection_threshold)
        if result.is_injection:
            if policy.injection_action == "block":
                decision.blocked = True
                decision.block_reason = "prompt_injection_detected"
                decision.block_details = {"score": result.score, "rules": result.matched}
                return decision
            decision.injection_flagged = True

    # 2. PII check: apply the policy's action for each type found
    findings = detect_pii(text)

    blocked_types = sorted(
        {f.type for f in findings if policy.pii_action_for(f.type) == "block"}
    )
    if blocked_types:
        decision.blocked = True
        decision.block_reason = "pii_blocked"
        decision.block_details = {"types": blocked_types}  # types only, never the values
        return decision

    to_redact = [f for f in findings if policy.pii_action_for(f.type) == "redact"]
    decision.text = redact_findings(text, to_redact)
    decision.pii_redacted = sorted({f.type for f in to_redact})
    decision.pii_allowed = sorted(
        {f.type for f in findings if policy.pii_action_for(f.type) == "allow"}
    )
    return decision