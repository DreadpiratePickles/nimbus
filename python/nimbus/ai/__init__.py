"""AI features (explanations, fixes, copilot, policy generation).

Every function works offline with rule-based fallbacks. A model is used when a provider is configured
(``providers.py``: ``NIMBUS_LLM_PROVIDER`` = anthropic (default, needs ``ANTHROPIC_API_KEY``) | openai
(any OpenAI-compatible endpoint, incl. local, ``NIMBUS_LLM_BASE_URL``) | bedrock | none) and
``NIMBUS_OFFLINE`` is not set. Model: ``NIMBUS_MODEL`` or ``claude-opus-5-5``. Guardrails, outbound
minimisation and redaction: ``guardrails.py``, ``redact.py``; what leaves the machine: docs/data-flow.md.
"""
from .llm import DEFAULT_MODEL, llm_available  # noqa: F401
