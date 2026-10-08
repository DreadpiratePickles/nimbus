"""Minimal Anthropic wrapper with an offline switch.

Uses the official ``anthropic`` SDK. Requests go to ``client.beta.messages.create`` with the
server-side refusal fallback (``fallbacks="default"``) enabled, so a safety-classifier decline on
the primary model is re-served by a fallback model inside the same call. Thinking is adaptive by
default on Claude Opus 5.5; depth is controlled with ``output_config.effort``.
"""
from __future__ import annotations

import os
import re
import sys
from typing import Optional

DEFAULT_MODEL = "claude-opus-5-5"
FALLBACK_BETA = "server-side-fallback-2026-07-01"


def model_name() -> str:
    return os.environ.get("NIMBUS_MODEL") or DEFAULT_MODEL


def llm_available() -> bool:
    if os.environ.get("NIMBUS_OFFLINE", "").lower() in ("1", "true", "yes"):
        return False
    if not os.environ.get("ANTHROPIC_API_KEY"):
        return False
    try:
        import anthropic  # noqa: F401
    except ImportError:
        return False
    return True


_client = None


def _get_client():
    global _client
    if _client is None:
        import anthropic

        _client = anthropic.Anthropic()
    return _client


def complete(system: str, prompt: str, max_tokens: int = 16000, effort: str = "medium") -> Optional[str]:
    """Return the model's text, or None when offline / on any API failure (callers fall back)."""
    if not llm_available():
        return None
    import anthropic

    try:
        resp = _get_client().beta.messages.create(
            model=model_name(),
            max_tokens=max_tokens,
            system=system,
            messages=[{"role": "user", "content": prompt}],
            output_config={"effort": effort},
            betas=[FALLBACK_BETA],
            fallbacks="default",
        )
    except anthropic.BadRequestError as exc:
        print(f"nimbus.ai: request rejected ({exc.status_code}); using offline fallback", file=sys.stderr)
        return None
    except anthropic.RateLimitError:
        print("nimbus.ai: rate limited; using offline fallback", file=sys.stderr)
        return None
    except anthropic.APIStatusError as exc:
        print(f"nimbus.ai: API error {exc.status_code}; using offline fallback", file=sys.stderr)
        return None
    except anthropic.APIConnectionError:
        print("nimbus.ai: cannot reach the Anthropic API; using offline fallback", file=sys.stderr)
        return None
    if resp.stop_reason == "refusal":
        return None
    text = "".join(getattr(b, "text", "") for b in resp.content if getattr(b, "type", "") == "text").strip()
    return text or None


_FENCE = re.compile(r"```[a-zA-Z0-9_+-]*\n(.*?)```", re.S)


def extract_code(text: str) -> str:
    """First fenced code block, or the text itself."""
    m = _FENCE.search(text or "")
    return (m.group(1) if m else (text or "")).strip() + "\n"
