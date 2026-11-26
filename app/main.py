from dataclasses import asdict

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel

from app.llm_client import ask_llm
from app.pipeline import process_message
from app.policy import load_policy

app = FastAPI(title="Compliance-Aware LLM Gateway")
policy = load_policy()  # fails at startup if policy.yaml is invalid


class Message(BaseModel):
    role: str
    content: str


class ChatRequest(BaseModel):
    messages: list[Message]


@app.get("/health")
def health():
    return {"status": "ok"}


@app.get("/policy")
def show_policy():
    return asdict(policy)


@app.post("/v1/chat")
def chat(req: ChatRequest):
    clean_messages = []
    redacted = set()
    flagged = False

    for m in req.messages:
        d = process_message(m.content, m.role, policy)
        if d.blocked:
            raise HTTPException(
                status_code=400,
                detail={"error": d.block_reason, **d.block_details},
            )
        redacted.update(d.pii_redacted)
        flagged = flagged or d.injection_flagged
        clean_messages.append({"role": m.role, "content": d.text})

    reply = ask_llm(clean_messages)
    return {
        "reply": reply,
        "pii_redacted": sorted(redacted),
        "injection_flagged": flagged,
    }