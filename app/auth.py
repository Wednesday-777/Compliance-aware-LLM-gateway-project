import hashlib
import hmac
import os
import secrets
import threading
import time
from collections import deque
from dataclasses import dataclass
from pathlib import Path

import yaml
from dotenv import load_dotenv
from fastapi import HTTPException
from fastapi.security import HTTPAuthorizationCredentials

load_dotenv()

KEYS_PATH = Path(
    os.getenv("API_KEYS_FILE", str(Path(__file__).resolve().parent.parent / "api_keys.yaml"))
)
VALID_ROLES = {"client", "admin"}
DEFAULT_RATE_LIMIT = 20  # requests per minute


@dataclass
class ApiKey:
    name: str
    key_hash: str
    role: str
    rate_limit_per_minute: int


def generate_key() -> str:
    return "gw_" + secrets.token_urlsafe(32)


def hash_key(raw: str) -> str:
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def find_key(raw: str, keys: list[ApiKey]) -> ApiKey | None:
    presented = hash_key(raw)
    match = None
    for k in keys:  # check every key; compare_digest avoids timing leaks
        if hmac.compare_digest(presented, k.key_hash):
            match = k
    return match


def load_keys(path=KEYS_PATH) -> list[ApiKey]:
    path = Path(path)
    if not path.exists():
        raise RuntimeError(
            f"{path} not found. Create keys with: "
            "python -m scripts.create_key <name> <client|admin>"
        )
    with open(path, encoding="utf-8") as f:
        raw = yaml.safe_load(f) or {}

    entries = raw.get("keys") or []
    if not entries:
        raise RuntimeError(f"{path} has no keys. The gateway refuses to start without any.")

    keys, names = [], set()
    for e in entries:
        if not isinstance(e, dict):
            raise ValueError("each key entry must be a mapping")
        name = e.get("name")
        role = e.get("role")
        key_hash = e.get("key_hash")
        limit = e.get("rate_limit_per_minute", DEFAULT_RATE_LIMIT)

        if not isinstance(name, str) or not name.strip():
            raise ValueError("every key needs a non-empty name")
        if name in names:
            raise ValueError(f"duplicate key name {name!r}")
        if role not in VALID_ROLES:
            raise ValueError(f"key {name!r}: role must be one of {sorted(VALID_ROLES)}")
        if (
            not isinstance(key_hash, str)
            or len(key_hash) != 64
            or any(c not in "0123456789abcdef" for c in key_hash.lower())
        ):
            raise ValueError(f"key {name!r}: key_hash must be 64 hex characters")
        if isinstance(limit, bool) or not isinstance(limit, int) or limit < 1:
            raise ValueError(f"key {name!r}: rate_limit_per_minute must be a whole number >= 1")

        names.add(name)
        keys.append(ApiKey(name, key_hash.lower(), role, limit))
    return keys


class RateLimiter:
    """Sliding window: at most `limit` hits per `window` seconds, per key name."""

    def __init__(self):
        self._hits: dict[str, deque] = {}
        self._lock = threading.Lock()  # requests run in parallel threads

    def check(self, name: str, limit: int, window: float = 60.0, now: float | None = None):
        now = time.monotonic() if now is None else now
        with self._lock:
            q = self._hits.setdefault(name, deque())
            while q and q[0] <= now - window:
                q.popleft()
            if len(q) >= limit:
                return False, int(q[0] + window - now) + 1  # seconds until a slot frees
            q.append(now)
            return True, 0


class Auth:
    def __init__(self, keys: list[ApiKey], on_event=None):
        self.keys = keys
        self.limiter = RateLimiter()
        self.on_event = on_event or (lambda outcome, client: None)

    def authenticate(
        self,
        credentials: HTTPAuthorizationCredentials | None,
        roles: set,
        rate_limited: bool = False,
    ) -> ApiKey:
        key = None
        if credentials is not None and credentials.scheme.lower() == "bearer":
            key = find_key(credentials.credentials, self.keys)

        if key is None:
            self.on_event("unauthorized", None)
            raise HTTPException(
                status_code=401,
                detail={"error": "invalid_or_missing_api_key"},
                headers={"WWW-Authenticate": "Bearer"},
            )

        if key.role not in roles:
            self.on_event("forbidden", key.name)
            raise HTTPException(status_code=403, detail={"error": "forbidden"})

        if rate_limited:
            allowed, retry_after = self.limiter.check(key.name, key.rate_limit_per_minute)
            if not allowed:
                self.on_event("rate_limited", key.name)
                raise HTTPException(
                    status_code=429,
                    detail={"error": "rate_limit_exceeded", "retry_after_seconds": retry_after},
                    headers={"Retry-After": str(retry_after)},
                )
        return key