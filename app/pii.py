import re
from dataclasses import dataclass


@dataclass
class Finding:
    type: str
    start: int
    end: int


PATTERNS = {
    "AADHAAR": re.compile(r"\b[2-9]\d{3}[ -]?\d{4}[ -]?\d{4}\b"),
    "PAN": re.compile(r"\b[A-Z]{5}\d{4}[A-Z]\b"),
    "EMAIL": re.compile(r"\b[\w.+-]+@[\w-]+\.[\w.-]+\b"),
    "PHONE_IN": re.compile(r"(?<!\d)(?:\+91[ -]?)?[6-9]\d{9}(?!\d)"),
    "CREDIT_CARD": re.compile(r"\b(?:\d[ -]?){12,15}\d\b"),
}


def luhn_ok(number: str) -> bool:
    """Checksum used by real card numbers; cuts false positives."""
    digits = [int(c) for c in number if c.isdigit()]
    total = 0
    for i, d in enumerate(reversed(digits)):
        if i % 2 == 1:
            d *= 2
            if d > 9:
                d -= 9
        total += d
    return total % 10 == 0


def detect_pii(text: str) -> list[Finding]:
    findings = []
    for pii_type, pattern in PATTERNS.items():
        for m in pattern.finditer(text):
            if pii_type == "CREDIT_CARD" and not luhn_ok(m.group()):
                continue
            findings.append(Finding(pii_type, m.start(), m.end()))

    # A card number can also look like an Aadhaar number, so when matches
    # overlap, keep the longest one.
    findings.sort(key=lambda f: (-(f.end - f.start), f.start))
    kept = []
    for f in findings:
        if all(f.end <= k.start or f.start >= k.end for k in kept):
            kept.append(f)
    return sorted(kept, key=lambda f: f.start)


def redact(text: str) -> tuple[str, list[Finding]]:
    findings = detect_pii(text)
    # Replace from the end so earlier positions stay valid
    for f in reversed(findings):
        text = text[: f.start] + f"[{f.type}]" + text[f.end :]
    return text, findings