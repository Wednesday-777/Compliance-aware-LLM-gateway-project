from app.pii import redact
from fastapi import FastAPI
from pydantic import BaseModel

from app.llm_client import ask_llm

app = FastAPI(title="Compliance-Aware LLM Gateway")


class Message(BaseModel):
    role: str
    content: str


class ChatRequest(BaseModel):
    messages: list[Message]


@app.get("/health")
def health():
    return {"status": "ok"}


@app.post("/v1/chat")
def chat(req: ChatRequest):
    clean_messages = []
    pii_types = []

    for m in req.messages:
        clean_text, findings = redact(m.content)
        pii_types.extend(f.type for f in findings)
        clean_messages.append({"role": m.role, "content": clean_text})

    reply = ask_llm(clean_messages)
    return {"reply": reply, "pii_redacted": sorted(set(pii_types))}