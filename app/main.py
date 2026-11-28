import logging
import time
from dataclasses import asdict

from fastapi import Depends, FastAPI, HTTPException
from fastapi.responses import RedirectResponse
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic import BaseModel

from app import config
from app.audit import init_db, log_request, recent_entries, summary_stats
from app.auth import ApiKey, Auth, load_keys
from app.llm_client import ask_llm
from app.pipeline import process_message
from app.policy import load_policy


logger = logging.getLogger("gateway")

app = FastAPI(title="Compliance-Aware LLM Gateway")
policy = load_policy()  # fails at startup if policy.yaml is invalid
init_db()

@app.get("/health")
def health():
    return {"status": "ok"}  # stays open so hosting platforms can check it


@app.get("/", include_in_schema=False)
def root():
    return RedirectResponse(url="/docs")


def _record_auth_event(outcome: str, client: str | None) -> None:
    log_request(outcome=outcome, client=client)


auth = Auth(load_keys(), on_event=_record_auth_event)  # fails if no valid keys
bearer = HTTPBearer(auto_error=False)  # we send our own 401 so errors stay consistent


def require_client(
    credentials: HTTPAuthorizationCredentials | None = Depends(bearer),
) -> ApiKey:
    return auth.authenticate(credentials, roles={"client", "admin"}, rate_limited=True)


def require_admin(
    credentials: HTTPAuthorizationCredentials | None = Depends(bearer),
) -> ApiKey:
    return auth.authenticate(credentials, roles={"admin"})


class Message(BaseModel):
    role: str
    content: str


class ChatRequest(BaseModel):
    messages: list[Message]


@app.get("/health")
def health():
    return {"status": "ok"}  # stays open so hosting platforms can check it


@app.get("/policy")
def show_policy(_: ApiKey = Depends(require_admin)):
    return asdict(policy)


@app.get("/audit/recent")
def audit_recent(limit: int = 50, _: ApiKey = Depends(require_admin)):
    return recent_entries(min(max(limit, 1), 200))


@app.get("/audit/stats")
def audit_stats(_: ApiKey = Depends(require_admin)):
    return summary_stats()


@app.post("/v1/chat")
def chat(req: ChatRequest, key: ApiKey = Depends(require_client)):
    started = time.perf_counter()
    clean_messages = []
    redacted, allowed = set(), set()
    flagged = False
    max_score = 0
    rules = set()
    input_chars = sum(len(m.content) for m in req.messages)

    def audit(outcome: str, **extra) -> str:
        # Reads the variables above as they are now, so it logs the latest state
        return log_request(
            outcome=outcome,
            client=key.name,
            message_count=len(req.messages),
            input_chars=input_chars,
            latency_ms=int((time.perf_counter() - started) * 1000),
            model=config.LLM_MODEL,
            pii_redacted=redacted,
            pii_allowed=allowed,
            injection_score=max_score,
            injection_rules=rules,
            injection_flagged=flagged,
            **extra,
        )

    for m in req.messages:
        d = process_message(m.content, m.role, policy)
        max_score = max(max_score, d.injection_score)
        rules.update(d.injection_rules)

        if d.blocked:
            request_id = audit(
                "blocked",
                block_reason=d.block_reason,
                pii_blocked=d.block_details.get("types", []),
            )
            raise HTTPException(
                status_code=400,
                detail={"error": d.block_reason, "request_id": request_id, **d.block_details},
            )

        redacted.update(d.pii_redacted)
        allowed.update(d.pii_allowed)
        flagged = flagged or d.injection_flagged
        clean_messages.append({"role": m.role, "content": d.text})

    try:
        reply = ask_llm(clean_messages)
    except Exception:
        logger.exception("LLM call failed")
        request_id = audit("error")
        raise HTTPException(
            status_code=502,
            detail={"error": "llm_unavailable", "request_id": request_id},
        )

    request_id = audit("allowed")
    return {
        "reply": reply,
        "request_id": request_id,
        "pii_redacted": sorted(redacted),
        "injection_flagged": flagged,
    }