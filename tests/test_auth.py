import pytest
from fastapi import HTTPException
from fastapi.security import HTTPAuthorizationCredentials

from app.auth import ApiKey, Auth, RateLimiter, find_key, generate_key, hash_key, load_keys


def creds(raw):
    return HTTPAuthorizationCredentials(scheme="Bearer", credentials=raw)


def make_auth(events=None):
    client_raw, admin_raw = generate_key(), generate_key()
    keys = [
        ApiKey("c", hash_key(client_raw), "client", 2),
        ApiKey("a", hash_key(admin_raw), "admin", 100),
    ]
    on_event = (lambda o, c: events.append((o, c))) if events is not None else None
    return Auth(keys, on_event), client_raw, admin_raw


def test_generated_keys_are_unique_and_prefixed():
    a, b = generate_key(), generate_key()
    assert a != b
    assert a.startswith("gw_") and len(a) > 30


def test_hash_is_stable_and_differs_from_key():
    raw = generate_key()
    assert hash_key(raw) == hash_key(raw)
    assert hash_key(raw) != raw
    assert len(hash_key(raw)) == 64


def test_find_key_matches_only_the_right_key():
    auth, client_raw, _ = make_auth()
    assert find_key(client_raw, auth.keys).name == "c"
    assert find_key("gw_wrong", auth.keys) is None


def test_missing_credentials_rejected():
    auth, _, _ = make_auth()
    with pytest.raises(HTTPException) as exc:
        auth.authenticate(None, roles={"client"})
    assert exc.value.status_code == 401


def test_wrong_key_rejected_and_logged():
    events = []
    auth, _, _ = make_auth(events)
    with pytest.raises(HTTPException) as exc:
        auth.authenticate(creds("gw_not_a_real_key"), roles={"client"})
    assert exc.value.status_code == 401
    assert events == [("unauthorized", None)]


def test_client_key_cannot_use_admin_routes():
    auth, client_raw, _ = make_auth()
    with pytest.raises(HTTPException) as exc:
        auth.authenticate(creds(client_raw), roles={"admin"})
    assert exc.value.status_code == 403


def test_valid_key_accepted():
    auth, client_raw, admin_raw = make_auth()
    assert auth.authenticate(creds(client_raw), roles={"client", "admin"}).name == "c"
    assert auth.authenticate(creds(admin_raw), roles={"admin"}).name == "a"


def test_rate_limit_enforced_with_retry_after():
    events = []
    auth, client_raw, _ = make_auth(events)
    roles = {"client", "admin"}
    auth.authenticate(creds(client_raw), roles, rate_limited=True)
    auth.authenticate(creds(client_raw), roles, rate_limited=True)
    with pytest.raises(HTTPException) as exc:
        auth.authenticate(creds(client_raw), roles, rate_limited=True)
    assert exc.value.status_code == 429
    assert int(exc.value.headers["Retry-After"]) >= 1
    assert events == [("rate_limited", "c")]


def test_limiter_window_expires():
    rl = RateLimiter()
    assert rl.check("k", 1, 60, now=0)[0]
    assert not rl.check("k", 1, 60, now=30)[0]
    assert rl.check("k", 1, 60, now=61)[0]


def test_limiter_is_per_key():
    rl = RateLimiter()
    assert rl.check("a", 1, 60, now=0)[0]
    assert rl.check("b", 1, 60, now=0)[0]
    assert not rl.check("a", 1, 60, now=1)[0]


GOOD_HASH = hash_key("gw_example")


def test_load_keys_reads_valid_file(tmp_path):
    f = tmp_path / "k.yaml"
    f.write_text(
        f'keys:\n  - name: demo\n    role: client\n    key_hash: "{GOOD_HASH}"\n'
        "    rate_limit_per_minute: 5\n"
    )
    keys = load_keys(f)
    assert len(keys) == 1
    assert keys[0].name == "demo"
    assert keys[0].rate_limit_per_minute == 5


def test_load_keys_rejects_bad_entries(tmp_path):
    f = tmp_path / "k.yaml"
    f.write_text(f'keys:\n  - name: demo\n    role: superuser\n    key_hash: "{GOOD_HASH}"\n')
    with pytest.raises(ValueError):
        load_keys(f)
    f.write_text('keys:\n  - name: demo\n    role: client\n    key_hash: "tooshort"\n')
    with pytest.raises(ValueError):
        load_keys(f)


def test_load_keys_requires_at_least_one_key(tmp_path):
    f = tmp_path / "k.yaml"
    f.write_text("keys: []\n")
    with pytest.raises(RuntimeError):
        load_keys(f)