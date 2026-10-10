"""LLM entry point with an offline switch and pluggable providers (see ``providers.py``).

The default provider is Anthropic through the official ``anthropic`` SDK: requests go to
``client.beta.messages.create`` with the server-side refusal fallback (``fallbacks="default"``),
so a safety-classifier decline on the primary model is re-served by a fallback model inside the
same call. ``NIMBUS_LLM_PROVIDER`` selects ``openai`` (any OpenAI-compatible endpoint, including a
local one) or ``bedrock`` instead. ``NIMBUS_OFFLINE=1`` disables every provider.
"""
from __future__ import annotations

import re
from typing import Optional

from .providers import DEFAULT_MODEL, FALLBACK_BETA, Completion, Provider, model_name, offline, provider_from_env  # noqa: F401

_client = None
_override: Optional[Provider] = None


def _get_client():
    global _client
    if _client is None:
        import anthropic

        _client = anthropic.Anthropic()
    return _client


def set_provider(p: Optional[Provider]) -> None:
    """Install a provider for this process (tests, eval, embedding apps); None restores env selection."""
    global _override
    _override = p


def current_provider() -> Optional[Provider]:
    if _override is not None:
        # offline still blocks anything that would leave the machine
        if offline() and getattr(_override, "network", True):
            return None
        return _override
    try:
        return provider_from_env()
    except ValueError:
        return None


def llm_available() -> bool:
    return current_provider() is not None


def complete_ex(system: str, prompt: str, max_tokens: int = 16000, effort: str = "medium") -> Optional[Completion]:
    """Return the provider's Completion (text + token usage), or None offline / on failure."""
    p = current_provider()
    if p is None:
        return None
    return p.complete(system, prompt, max_tokens=max_tokens, effort=effort)


def complete(system: str, prompt: str, max_tokens: int = 16000, effort: str = "medium") -> Optional[str]:
    """Return the model's text, or None when offline / on any API failure (callers fall back)."""
    c = complete_ex(system, prompt, max_tokens=max_tokens, effort=effort)
    return c.text if c else None


_FENCE = re.compile(r"```[a-zA-Z0-9_+-]*\n(.*?)```", re.S)


def extract_code(text: str) -> str:
    """First fenced code block, or the text itself."""
    m = _FENCE.search(text or "")
    return (m.group(1) if m else (text or "")).strip() + "\n"
