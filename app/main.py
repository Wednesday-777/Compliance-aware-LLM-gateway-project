from app.pii import redact
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from app.injection import check_injection

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
        # Only check user messages. System messages come from the developer.
        if m.role == "user":
            result = check_injection(m.content)
            if result.is_injection:
                raise HTTPException(
                    status_code=400,
                    detail={
                        "error": "prompt_injection_detected",
                        "score": result.score,
                        "rules": result.matched,
                    },
                )

        clean_text, findings = redact(m.content)
        pii_types.extend(f.type for f in findings)
        clean_messages.append({"role": m.role, "content": clean_text})

    reply = ask_llm(clean_messages)
    return {"reply": reply, "pii_redacted": sorted(set(pii_types))}