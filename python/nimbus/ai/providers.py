"""BYO-LLM providers (plan AI2). One small interface, three real back ends and a scripted one.

``NIMBUS_LLM_PROVIDER`` picks the back end (default ``anthropic``):

* ``anthropic`` - the official ``anthropic`` SDK (``ANTHROPIC_API_KEY``), unchanged request shape.
* ``openai`` - any OpenAI-compatible ``/chat/completions`` endpoint (``NIMBUS_LLM_BASE_URL``,
  optional ``NIMBUS_LLM_API_KEY``): Ollama, vLLM, llama.cpp, LM Studio, a gateway. A loopback
  endpoint keeps every byte on the machine and is the recommended default for sensitive estates.
* ``bedrock`` - Amazon Bedrock ``converse`` via boto3 (``AWS_REGION``; standard AWS credentials).
* ``none`` - no model; the copilot stays in its offline rule-based mode.

``NIMBUS_MODEL`` names the model for every back end. ``NIMBUS_OFFLINE=1`` disables all of them.
``CLOUD_POSTURE_NO_NETWORK=1`` disables every provider that leaves the machine, so only an
OpenAI-compatible endpoint on a loopback address remains usable. Every ``complete`` returns
``None`` on any failure so callers fall back to offline behaviour.
"""
from __future__ import annotations

import ipaddress
import os
import sys
from dataclasses import dataclass
from typing import Any, Callable, Optional, Sequence, Union
from urllib.parse import urlparse

DEFAULT_MODEL = "claude-opus-5-5"
FALLBACK_BETA = "server-side-fallback-2026-07-01"


@dataclass(frozen=True)
class Completion:
    text: str
    input_tokens: int = 0
    output_tokens: int = 0
    provider: str = ""
    model: str = ""


def _truthy(name: str) -> bool:
    return os.environ.get(name, "").strip().lower() in ("1", "true", "yes")


def offline() -> bool:
    return _truthy("NIMBUS_OFFLINE")


def no_network() -> bool:
    return _truthy("CLOUD_POSTURE_NO_NETWORK")


def model_name() -> str:
    return os.environ.get("NIMBUS_MODEL") or DEFAULT_MODEL


class Provider:
    name = "provider"
    network = True  # sends data off the machine

    def available(self) -> bool:
        return True

    def complete(self, system: str, prompt: str, max_tokens: int = 16000, effort: str = "medium") -> Optional[Completion]:
        raise NotImplementedError


class AnthropicProvider(Provider):
    """The original path: ``client.beta.messages.create`` with the server-side refusal fallback."""

    name = "anthropic"

    def __init__(self, model: Optional[str] = None):
        self.model = model or model_name()

    def available(self) -> bool:
        if not os.environ.get("ANTHROPIC_API_KEY"):
            return False
        try:
            import anthropic  # noqa: F401
        except ImportError:
            return False
        return True

    def complete(self, system, prompt, max_tokens=16000, effort="medium"):
        from . import llm

        try:
            import anthropic
        except ImportError:
            return None
        try:
            resp = llm._get_client().beta.messages.create(
                model=self.model, max_tokens=max_tokens, system=system,
                messages=[{"role": "user", "content": prompt}],
                output_config={"effort": effort}, betas=[FALLBACK_BETA], fallbacks="default",
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
        if getattr(resp, "stop_reason", None) == "refusal":
            return None
        text = "".join(getattr(b, "text", "") for b in resp.content if getattr(b, "type", "") == "text").strip()
        if not text:
            return None
        usage = getattr(resp, "usage", None)
        return Completion(text=text, input_tokens=int(getattr(usage, "input_tokens", 0) or 0),
                          output_tokens=int(getattr(usage, "output_tokens", 0) or 0), provider=self.name, model=self.model)


def is_loopback(url: str) -> bool:
    host = (urlparse(url).hostname or "").strip("[]")
    if host == "localhost":
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


class OpenAICompatibleProvider(Provider):
    name = "openai"

    def __init__(self, base_url: str, model: Optional[str] = None, api_key: Optional[str] = None, transport: Any = None,
                 timeout: float = 120.0):
        self.base_url = base_url.rstrip("/")
        self.model = model or model_name()
        self.api_key = api_key
        self.transport = transport
        self.timeout = timeout
        self.local = is_loopback(self.base_url)
        self.network = not self.local

    def complete(self, system, prompt, max_tokens=16000, effort="medium"):
        import httpx

        headers = {"content-type": "application/json"}
        if self.api_key:
            headers["authorization"] = f"Bearer {self.api_key}"
        body = {"model": self.model, "max_tokens": max_tokens,
                "messages": [{"role": "system", "content": system}, {"role": "user", "content": prompt}]}
        try:
            with httpx.Client(transport=self.transport, timeout=self.timeout) as c:
                r = c.post(f"{self.base_url}/chat/completions", json=body, headers=headers)
            r.raise_for_status()
            data = r.json()
            text = (data["choices"][0]["message"].get("content") or "").strip()
        except Exception as exc:  # any transport/shape error -> offline fallback
            print(f"nimbus.ai: OpenAI-compatible endpoint failed ({type(exc).__name__}); using offline fallback", file=sys.stderr)
            return None
        if not text:
            return None
        usage = data.get("usage") or {}
        return Completion(text=text, input_tokens=int(usage.get("prompt_tokens", 0) or 0),
                          output_tokens=int(usage.get("completion_tokens", 0) or 0), provider=self.name, model=self.model)


class BedrockProvider(Provider):
    name = "bedrock"

    def __init__(self, model: Optional[str] = None, region: Optional[str] = None, client: Any = None):
        self.model = model or model_name()
        self.region = region or os.environ.get("AWS_REGION") or os.environ.get("AWS_DEFAULT_REGION")
        self._client = client

    def available(self) -> bool:
        if self._client is not None:
            return True
        try:
            import boto3  # noqa: F401
        except ImportError:
            return False
        return bool(self.region)

    def client(self):
        if self._client is None:
            import boto3

            self._client = boto3.client("bedrock-runtime", region_name=self.region)
        return self._client

    def complete(self, system, prompt, max_tokens=16000, effort="medium"):
        try:
            resp = self.client().converse(modelId=self.model, system=[{"text": system}],
                                          messages=[{"role": "user", "content": [{"text": prompt}]}],
                                          inferenceConfig={"maxTokens": max_tokens})
            parts = resp["output"]["message"]["content"]
            text = "".join(p.get("text", "") for p in parts).strip()
        except Exception as exc:
            print(f"nimbus.ai: Bedrock call failed ({type(exc).__name__}); using offline fallback", file=sys.stderr)
            return None
        if not text:
            return None
        usage = resp.get("usage") or {}
        return Completion(text=text, input_tokens=int(usage.get("inputTokens", 0) or 0),
                          output_tokens=int(usage.get("outputTokens", 0) or 0), provider=self.name, model=self.model)


Responder = Callable[[str, str], str]


class ScriptedProvider(Provider):
    """Deterministic provider for tests and the eval suite: a list of replies or a function of
    (system, prompt). Records every call. Makes no network call, so offline mode allows it."""

    name = "scripted"
    network = False

    def __init__(self, responder: Union[Responder, Sequence[str]]):
        if callable(responder):
            self.responder = responder
        else:
            replies = list(responder)
            self.responder = lambda s, p: replies.pop(0) if replies else ""
        self.calls: list[tuple[str, str]] = []

    def complete(self, system, prompt, max_tokens=16000, effort="medium"):
        self.calls.append((system, prompt))
        text = self.responder(system, prompt)
        if not text:
            return None
        return Completion(text=text, input_tokens=max(1, len(system + prompt) // 4), output_tokens=max(1, len(text) // 4),
                          provider=self.name, model="scripted")


PROVIDERS = ("anthropic", "openai", "bedrock", "none")


def provider_from_env() -> Optional[Provider]:
    """The configured provider, or None when offline / unconfigured / blocked by no-network."""
    if offline():
        return None
    name = (os.environ.get("NIMBUS_LLM_PROVIDER") or "anthropic").strip().lower()
    if name not in PROVIDERS:
        raise ValueError(f"NIMBUS_LLM_PROVIDER={name!r}: expected one of {', '.join(PROVIDERS)}")
    p: Optional[Provider]
    if name == "none":
        return None
    if name == "anthropic":
        p = AnthropicProvider()
    elif name == "openai":
        base = os.environ.get("NIMBUS_LLM_BASE_URL", "")
        if not base:
            return None
        p = OpenAICompatibleProvider(base, api_key=os.environ.get("NIMBUS_LLM_API_KEY") or None)
    else:
        p = BedrockProvider()
    if no_network() and p.network:
        return None
    return p if p.available() else None
