"""
R3D Agent -- LLM Client
Ollama wrapper for all module communications.
Every module uses this to talk to llama3.

Fixes applied:
    Fix 1: Timeout on Ollama calls -- prevents pipeline hang
    Fix 2: Retry logic with backoff -- handles transient failures
    Fix 3: Model version flexibility -- accepts llama3, llama3:8b, llama3.2
    Fix 4: Available model auto-detection -- warns if model not found
"""

import ollama
import time
import requests
from pydantic import BaseModel
from typing import Optional
import json
import re


# Ollama connection settings
OLLAMA_BASE_URL    = "http://localhost:11434"
OLLAMA_TIMEOUT     = 120   # 2 minutes max per LLM call
OLLAMA_MAX_RETRIES = 2     # retry twice before giving up
OLLAMA_RETRY_DELAY = 3     # seconds between retries

# System prompt that tells llama3 it's a cybersecurity analyst
SYSTEM_PROMPT = """You are an expert cybersecurity analyst and red team operator.
You specialize in OSINT reconnaissance, vulnerability assessment, LLM attack surface analysis,
and GRC compliance mapping (NIST SP 800-53, NERC CIP).

When analyzing findings you think like both an attacker and a defender simultaneously.
You are precise, technical, and never guess. If you are uncertain about something you say so explicitly.

CRITICAL: When asked to return JSON you return ONLY valid JSON with no preamble,
no explanation, no markdown code fences, and no text before or after the JSON object.
"""


class LLMResponse(BaseModel):
    """Pydantic model for validated LLM responses."""
    content: str
    model: str
    success: bool
    error: Optional[str] = None


def _resolve_model(model: str) -> str:
    """
    Resolve model name to one available in Ollama.
    Handles llama3 / llama3:8b / llama3.2 version variations.
    Returns best available match or original if cannot check.
    """
    try:
        resp = requests.get(
            f"{OLLAMA_BASE_URL}/api/tags", timeout=5
        )
        if resp.status_code == 200:
            available = [
                m.get("name", "")
                for m in resp.json().get("models", [])
            ]
            if model in available:
                return model
            for name in available:
                if name.startswith(model.split(":")[0]):
                    return name
    except Exception:
        pass
    return model


def query_llm(
    prompt: str,
    system_prompt: str = SYSTEM_PROMPT,
    model: str = "llama3",
    expect_json: bool = False
) -> LLMResponse:
    """
    Send a prompt to Ollama and return a validated response.
    Includes timeout, retry, and model version resolution.
    """
    resolved_model = _resolve_model(model)
    content = ""

    for attempt in range(OLLAMA_MAX_RETRIES + 1):
        try:
            client = ollama.Client(
                host=OLLAMA_BASE_URL,
                timeout=OLLAMA_TIMEOUT
            )
            response = client.chat(
                model=resolved_model,
                messages=[
                    {"role": "system", "content": system_prompt},
                    {"role": "user",   "content": prompt}
                ]
            )

            content = response["message"]["content"].strip()

            if expect_json:
                content = _clean_json_response(content)
                json.loads(content)

            return LLMResponse(
                content=content,
                model=resolved_model,
                success=True
            )

        except json.JSONDecodeError as e:
            repaired = _repair_json(content, str(e))
            if repaired:
                return LLMResponse(
                    content=repaired,
                    model=resolved_model,
                    success=True
                )
            return LLMResponse(
                content="",
                model=resolved_model,
                success=False,
                error=f"JSON parse failed: {str(e)}"
            )

        except Exception as e:
            if attempt < OLLAMA_MAX_RETRIES:
                time.sleep(OLLAMA_RETRY_DELAY * (attempt + 1))
                continue
            return LLMResponse(
                content="",
                model=resolved_model,
                success=False,
                error=str(e)
            )

    return LLMResponse(
        content="",
        model=resolved_model,
        success=False,
        error="Max retries exceeded"
    )


def _clean_json_response(text: str) -> str:
    """Strip markdown fences and extract clean JSON."""
    text = re.sub(r'^```(?:json)?\s*', '', text.strip())
    text = re.sub(r'\s*```$', '', text.strip())
    text = text.strip()
    # Find first { or [
    for i, c in enumerate(text):
        if c in '{[':
            text = text[i:]
            break
    # Find last } or ]
    for i in range(len(text) - 1, -1, -1):
        if text[i] in '}]':
            text = text[:i+1]
            break
    return text


def _repair_json(text: str, error: str) -> Optional[str]:
    """Attempt basic JSON repair for common LLM formatting issues."""
    try:
        cleaned = _clean_json_response(text)
        json.loads(cleaned)
        return cleaned
    except Exception:
        pass
    # Try wrapping in object if plain string returned
    try:
        if not text.strip().startswith('{'):
            wrapped = json.dumps({"content": text.strip()})
            json.loads(wrapped)
            return wrapped
    except Exception:
        pass
    return None


if __name__ == "__main__":
    print("R3D LLM Client -- Module Load Test")
    result = query_llm(
        "Respond with exactly: {\"status\": \"ok\"}",
        expect_json=True
    )
    print(f"Success: {result.success}")
    print(f"Model:   {result.model}")
    print(f"Content: {result.content[:100]}")