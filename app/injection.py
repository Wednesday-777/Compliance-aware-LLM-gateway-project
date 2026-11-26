import re
import unicodedata
from dataclasses import dataclass


@dataclass
class InjectionResult:
    score: int
    matched: list[str]
    is_injection: bool


# (rule name, pattern, weight). Higher weight = stronger signal.
RULES = [
    (
        "override_instructions",
        re.compile(
            r"\b(ignore|disregard|forget|override)\b.{0,40}"
            r"\b(previous|prior|above|earlier|all|any)\b.{0,40}"
            r"\b(instructions?|rules?|prompts?|guidelines?)\b",
            re.IGNORECASE,
        ),
        5,
    ),
    (
        "reveal_system_prompt",
        re.compile(
            r"\b(reveal|show|print|repeat|display|leak|tell me)\b.{0,40}"
            r"\b(system|hidden|initial|original)\b.{0,20}"
            r"\b(prompt|instructions?|message)\b",
            re.IGNORECASE,
        ),
        5,
    ),
    (
        "disable_safety",
        re.compile(
            r"\b(disable|bypass|turn off|ignore)\b.{0,30}"
            r"\b(safety|filters?|guardrails?|restrictions?|policies|policy)\b",
            re.IGNORECASE,
        ),
        4,
    ),
    (
        "jailbreak_persona",
        re.compile(r"\b(do anything now|developer mode|jailbreak)\b", re.IGNORECASE),
        4,
    ),
    (
        "fake_system_tag",
        re.compile(r"(<\s*/?\s*system\s*>|\[\s*system\s*\]|###\s*system)", re.IGNORECASE),
        3,
    ),
    (
        "role_hijack",
        re.compile(r"\b(you are now|pretend to be|from now on you)\b", re.IGNORECASE),
        2,
    ),
]

THRESHOLD = 5  # total score at or above this gets blocked

# Invisible characters attackers use to sneak past simple filters
ZERO_WIDTH = dict.fromkeys(map(ord, "\u200b\u200c\u200d\u2060\ufeff"), None)


def normalize(text: str) -> str:
    text = unicodedata.normalize("NFKC", text)
    text = text.translate(ZERO_WIDTH)
    return re.sub(r"\s+", " ", text)


def check_injection(text: str) -> InjectionResult:
    text = normalize(text)
    score = 0
    matched = []
    for name, pattern, weight in RULES:
        if pattern.search(text):
            score += weight
            matched.append(name)
    return InjectionResult(score=score, matched=matched, is_injection=score >= THRESHOLD)