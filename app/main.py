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
    messages = [m.model_dump() for m in req.messages]
    reply = ask_llm(messages)
    return {"reply": reply}