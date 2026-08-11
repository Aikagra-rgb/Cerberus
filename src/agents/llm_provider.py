"""
Cerberus Multi-Agent Pipeline — LLM Provider Abstraction
=========================================================
Provides a unified interface for calling LLMs via NVIDIA NIM
(OpenAI-compatible endpoint). Routes different model assignments
to the correct API key based on the model family.

Model Assignments:
  - DeepSeek V4 Pro  -> Triage, Research, Guardrail agents  (deep reasoning)
  - NVIDIA Nemotron  -> Remediation agent                   (strict code generation)
"""

import json
import os
import re

from dotenv import load_dotenv
from openai import OpenAI

load_dotenv()

# ── NVIDIA NIM Configuration ─────────────────────────────────────────────────
_NVIDIA_BASE_URL = os.getenv("NVIDIA_BASE_URL", "https://integrate.api.nvidia.com/v1")
_NEMOTRON_KEY    = os.getenv("NEMOTRON_API_KEY", "")
_DEEPSEEK_KEY    = os.getenv("DEEPSEEK_API_KEY", "")
_NEMOTRON_MODEL  = os.getenv("NEMOTRON_MODEL",   "nvidia/llama-3.1-nemotron-70b-instruct")
_DEEPSEEK_MODEL  = os.getenv("DEEPSEEK_MODEL",   "deepseek-ai/deepseek-v4-0324")
_TIMEOUT         = int(os.getenv("AGENT_TIMEOUT_SECONDS", "30"))

# ── OpenAI-compatible client builder ─────────────────────────────────────────
def _make_client(api_key: str) -> OpenAI:
    return OpenAI(base_url=_NVIDIA_BASE_URL, api_key=api_key)


def _nemotron_client() -> OpenAI:
    return _make_client(_NEMOTRON_KEY)


def _deepseek_client() -> OpenAI:
    return _make_client(_DEEPSEEK_KEY)


# ── Core call function ────────────────────────────────────────────────────────
def call_llm(
    system_prompt: str,
    user_prompt: str,
    model_family: str = "deepseek",   # "deepseek" | "nemotron"
    temperature: float = 0.2,
    max_tokens: int = 1024,
    json_mode: bool = False,
) -> str:
    """
    Calls the appropriate NVIDIA NIM-hosted model and returns the response text.
    Falls back gracefully if the API is unavailable.
    """
    if model_family == "nemotron":
        client = _nemotron_client()
        model  = _NEMOTRON_MODEL
        api_key = _NEMOTRON_KEY
    else:
        client = _deepseek_client()
        model  = _DEEPSEEK_MODEL
        api_key = _DEEPSEEK_KEY

    if not api_key:
        raise RuntimeError(
            f"No API key configured for model_family='{model_family}'. "
            "Set NEMOTRON_API_KEY or DEEPSEEK_API_KEY in your .env file."
        )

    messages = [
        {"role": "system", "content": system_prompt},
        {"role": "user",   "content": user_prompt},
    ]

    kwargs: dict = dict(
        model=model,
        messages=messages,
        temperature=temperature,
        max_tokens=max_tokens,
    )
    if json_mode:
        kwargs["response_format"] = {"type": "json_object"}

    try:
        response = client.chat.completions.create(**kwargs)
        return response.choices[0].message.content or ""
    except Exception as exc:
        raise RuntimeError(f"LLM call failed ({model_family}): {exc}") from exc


def call_llm_json(
    system_prompt: str,
    user_prompt: str,
    model_family: str = "deepseek",
    temperature: float = 0.1,
    max_tokens: int = 1024,
) -> dict:
    """
    Calls the LLM and parses the result as JSON. Includes fallback regex extraction.
    """
    raw = call_llm(
        system_prompt=system_prompt,
        user_prompt=user_prompt,
        model_family=model_family,
        temperature=temperature,
        max_tokens=max_tokens,
        json_mode=True,
    )
    try:
        return json.loads(raw)
    except json.JSONDecodeError:
        # Extract first JSON block from markdown-wrapped responses
        match = re.search(r"\{.*\}", raw, re.DOTALL)
        if match:
            try:
                return json.loads(match.group())
            except json.JSONDecodeError:
                pass
        return {"raw_output": raw, "parse_error": True}
