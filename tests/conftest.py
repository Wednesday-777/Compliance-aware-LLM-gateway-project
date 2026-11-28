import json
import os
import tempfile

import pytest

# The environment must be set BEFORE any app module is imported.
_tmp = tempfile.mkdtemp()
os.environ["LLM_API_KEY"] = "test-key"
os.environ["LLM_MODEL"] = "test-model"
os.environ["LLM_BASE_URL"] = "http://localhost:9"
os.environ["AUDIT_DB_PATH"] = os.path.join(_tmp, "test_audit.db")
os.environ["API_KEYS_FILE"] = os.path.join(_tmp, "no_such_file.yaml")

from app.auth import generate_key, hash_key  # noqa: E402

_CLIENT_KEY = generate_key()
_ADMIN_KEY = generate_key()
os.environ["GATEWAY_API_KEYS"] = json.dumps(
    {
        "keys": [
            {
                "name": "test-client",
                "role": "client",
                "key_hash": hash_key(_CLIENT_KEY),
                "rate_limit_per_minute": 1000,
            },
            {
                "name": "test-admin",
                "role": "admin",
                "key_hash": hash_key(_ADMIN_KEY),
                "rate_limit_per_minute": 1000,
            },
        ]
    }
)


@pytest.fixture(scope="session")
def client_key():
    return _CLIENT_KEY


@pytest.fixture(scope="session")
def admin_key():
    return _ADMIN_KEY


@pytest.fixture()
def api(monkeypatch):
    """A test client with a fake LLM and a known policy."""
    from fastapi.testclient import TestClient

    import app.main as main
    from app.policy import Policy

    sent = []  # records exactly what the "LLM" receives

    def fake_llm(messages):
        sent.append(messages)
        return "mocked reply"

    monkeypatch.setattr(main, "ask_llm", fake_llm)
    monkeypatch.setattr(
        main,
        "policy",
        Policy(
            pii_default="redact",
            pii_actions={"AADHAAR": "block", "CREDIT_CARD": "block"},
            injection_enabled=True,
            injection_threshold=5,
            injection_action="block",
        ),
    )
    client = TestClient(main.app)
    client.sent = sent
    return client