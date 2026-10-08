"""AI features (explanations, fixes, copilot, policy generation).

Every function works offline with rule-based fallbacks; when ``ANTHROPIC_API_KEY`` is set (and
``NIMBUS_OFFLINE`` is not) the Anthropic API is used. Model: ``NIMBUS_MODEL`` or ``claude-opus-5-5``.
"""
from .llm import DEFAULT_MODEL, llm_available  # noqa: F401
