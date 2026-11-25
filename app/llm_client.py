from openai import OpenAI
from app import config

client = OpenAI(api_key=config.LLM_API_KEY, base_url=config.LLM_BASE_URL)


def ask_llm(messages: list[dict]) -> str:
    response = client.chat.completions.create(
        model=config.LLM_MODEL,
        messages=messages,
    )
    return response.choices[0].message.content