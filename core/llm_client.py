
"""
R3D Agent — LLM Client
Ollama wrapper for all module communications.
Every module uses this to talk to llama3.
"""

import ollama
from pydantic import BaseModel
from typing import Optional
import json
import re


# System prompt that tells llama3 it's a cybersecurity analyst
# This fixes the "prompt injection is a medical term" problem we saw earlier
SYSTEM_PROMPT = """You are an expert cybersecurity analyst and red team operator.
You specialize in OSINT reconnaissance, vulnerability assessment, LLM attack surface analysis,
and GRC compliance mapping (NIST SP 800-53, NERC CIP).

When analyzing findings you think like both an attacker and a defender simultaneously.
You are precise, technical, and never guess. If you are uncertain about something you say so explicitly.

CRITICAL: When asked to return JSON you return ONLY valid JSON with no preamble,
no explanation, no markdown code fences, and no text before or after the JSON object.
When asked for analysis or explanation you provide detailed, technically precise accounts
with full reasoning — never truncate findings or summarize when detail is available.
"""


class LLMResponse(BaseModel):
    """Pydantic model for validated LLM responses."""
    content: str
    model: str
    success: bool
    error: Optional[str] = None


def query_llm(
    prompt: str,
    system_prompt: str = SYSTEM_PROMPT,
    model: str = "llama3",
    expect_json: bool = False
) -> LLMResponse:
    """
    Send a prompt to Ollama and return a validated response.

    Args:
        prompt: The user prompt to send
        system_prompt: Override the default system prompt if needed
        model: Which Ollama model to use (default: llama3)
        expect_json: If True, validates and cleans JSON response

    Returns:
        LLMResponse with content and success status
    """
    try:
        response = ollama.chat(
            model=model,
            messages=[
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": prompt}
            ]
        )

        content = response["message"]["content"].strip()

        # If we expect JSON clean up any accidental formatting
        if expect_json:
            content = _clean_json_response(content)
            # Validate it actually parses
            json.loads(content)

        return LLMResponse(
            content=content,
            model=model,
            success=True
        )

    except json.JSONDecodeError as e:
        # JSON validation failed — try repair
        repaired = _repair_json(content, str(e))
        if repaired:
            return LLMResponse(content=repaired, model=model, success=True)
        return LLMResponse(
            content="",
            model=model,
            success=False,
            error=f"JSON parse failed: {str(e)}"
        )

    except Exception as e:
        return LLMResponse(
            content="",
            model=model,
            success=False,
            error=str(e)
        )


def _clean_json_response(text: str) -> str:
    """
    Strip markdown fences and extract clean JSON.
    LLMs sometimes wrap JSON in ```json ... ``` even when told not to.
    """
    # Remove markdown code fences
    text = re.sub(r"```json\s*", "", text)
    text = re.sub(r"```\s*", "", text)
    text = text.strip()

    # Find the first { and last } to extract just the JSON object
    start = text.find("{")
    end = text.rfind("}") + 1
    if start != -1 and end > start:
        return text[start:end]

    return text


def _repair_json(content: str, error: str) -> Optional[str]:
    """
    Attempt to repair malformed JSON by sending a targeted fix prompt.
    Called automatically when JSON validation fails.
    """
    repair_prompt = f"""The following JSON has an error: {error}

Please fix it and return ONLY the corrected JSON object with no other text:

{content}"""

    try:
        response = ollama.chat(
            model="llama3",
            messages=[
                {"role": "system", "content": "You are a JSON repair specialist. Return only valid JSON, nothing else."},
                {"role": "user", "content": repair_prompt}
            ]
        )
        repaired = response["message"]["content"].strip()
        repaired = _clean_json_response(repaired)
        json.loads(repaired)  # Validate the repair worked
        return repaired
    except Exception:
        return None


def test_connection() -> bool:
    """
    Quick test to verify Ollama is running and llama3 is available.
    Called at R3D startup before any modules run.
    """
    response = query_llm(
        prompt="Respond with exactly this JSON: {\"status\": \"ready\", \"model\": \"llama3\"}",
        expect_json=True
    )
    return response.success


if __name__ == "__main__":
    # Quick test when run directly
    from rich.console import Console
    console = Console()

    console.print("[bold green]Testing R3D LLM Client...[/bold green]")

    if test_connection():
        console.print("[green]✓ Ollama connection successful[/green]")
        console.print("[green]✓ llama3 responding[/green]")
        console.print("[green]✓ JSON validation working[/green]")
    else:
        console.print("[red]✗ Connection failed — is Ollama running?[/red]")
        console.print("[yellow]Run: ollama serve[/yellow]")