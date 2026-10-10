"""BYO-LLM provider abstraction (plan AI2): Anthropic (existing SDK path), OpenAI-compatible
(incl. a local endpoint) and Bedrock, selected by NIMBUS_LLM_PROVIDER; offline unchanged."""
from __future__ import annotations

import json
from types import SimpleNamespace

import httpx
import pytest

from nimbus.ai import llm
from nimbus.ai.providers import (AnthropicProvider, BedrockProvider, Completion, OpenAICompatibleProvider, ScriptedProvider,
                                 provider_from_env)


@pytest.fixture(autouse=True)
def _reset():
    llm.set_provider(None)
    yield
    llm.set_provider(None)


def test_offline_disables_every_network_provider(monkeypatch):
    monkeypatch.setenv("ANTHROPIC_API_KEY", "k")
    for name in ("anthropic", "openai", "bedrock"):
        monkeypatch.setenv("NIMBUS_LLM_PROVIDER", name)
        monkeypatch.setenv("NIMBUS_LLM_BASE_URL", "http://127.0.0.1:11434/v1")
        assert provider_from_env() is None  # NIMBUS_OFFLINE=1 from conftest
        assert not llm.llm_available() and llm.complete("s", "p") is None


def test_selection_from_env(monkeypatch):
    monkeypatch.delenv("NIMBUS_OFFLINE", raising=False)
    monkeypatch.delenv("CLOUD_POSTURE_NO_NETWORK", raising=False)
    monkeypatch.setenv("ANTHROPIC_API_KEY", "k")
    monkeypatch.delenv("NIMBUS_LLM_PROVIDER", raising=False)
    assert isinstance(provider_from_env(), AnthropicProvider)
    monkeypatch.setenv("NIMBUS_LLM_PROVIDER", "openai")
    monkeypatch.setenv("NIMBUS_LLM_BASE_URL", "http://localhost:8080/v1")
    monkeypatch.setenv("NIMBUS_MODEL", "llama3.1")
    p = provider_from_env()
    assert isinstance(p, OpenAICompatibleProvider) and p.model == "llama3.1" and p.local
    monkeypatch.delenv("NIMBUS_LLM_BASE_URL")
    assert provider_from_env() is None  # openai-compatible needs an endpoint
    monkeypatch.setenv("NIMBUS_LLM_PROVIDER", "bedrock")
    monkeypatch.setenv("AWS_REGION", "us-east-1")
    assert isinstance(provider_from_env(), BedrockProvider)
    monkeypatch.setenv("NIMBUS_LLM_PROVIDER", "none")
    assert provider_from_env() is None
    monkeypatch.setenv("NIMBUS_LLM_PROVIDER", "carrier-pigeon")
    with pytest.raises(ValueError):
        provider_from_env()


def test_no_network_allows_only_a_loopback_endpoint(monkeypatch):
    monkeypatch.delenv("NIMBUS_OFFLINE", raising=False)
    monkeypatch.setenv("CLOUD_POSTURE_NO_NETWORK", "1")
    monkeypatch.setenv("ANTHROPIC_API_KEY", "k")
    monkeypatch.setenv("NIMBUS_LLM_PROVIDER", "anthropic")
    assert provider_from_env() is None
    monkeypatch.setenv("NIMBUS_LLM_PROVIDER", "openai")
    monkeypatch.setenv("NIMBUS_LLM_BASE_URL", "https://api.example.com/v1")
    assert provider_from_env() is None
    monkeypatch.setenv("NIMBUS_LLM_BASE_URL", "http://127.0.0.1:11434/v1")
    assert isinstance(provider_from_env(), OpenAICompatibleProvider)


def test_openai_compatible_request_shape():
    seen = {}

    def handler(req: httpx.Request) -> httpx.Response:
        seen["url"] = str(req.url)
        seen["auth"] = req.headers.get("authorization")
        seen["body"] = json.loads(req.content)
        return httpx.Response(200, json={"choices": [{"message": {"content": "hello"}, "finish_reason": "stop"}],
                                         "usage": {"prompt_tokens": 12, "completion_tokens": 3}})

    p = OpenAICompatibleProvider("http://localhost:11434/v1/", "qwen2.5", api_key="sk-x", transport=httpx.MockTransport(handler))
    c = p.complete("sys", "user prompt", max_tokens=100)
    assert c == Completion(text="hello", input_tokens=12, output_tokens=3, provider="openai", model="qwen2.5")
    assert seen["url"] == "http://localhost:11434/v1/chat/completions" and seen["auth"] == "Bearer sk-x"
    assert seen["body"]["messages"] == [{"role": "system", "content": "sys"}, {"role": "user", "content": "user prompt"}]
    assert seen["body"]["max_tokens"] == 100 and seen["body"]["model"] == "qwen2.5"
    # errors degrade to None (callers fall back offline)
    bad = OpenAICompatibleProvider("http://localhost:1/v1", "m", transport=httpx.MockTransport(lambda r: httpx.Response(500)))
    assert bad.complete("s", "p") is None


def test_bedrock_converse_shape():
    calls = []

    class FakeBedrock:
        def converse(self, **kw):
            calls.append(kw)
            return {"output": {"message": {"content": [{"text": "from bedrock"}]}}, "stopReason": "end_turn",
                    "usage": {"inputTokens": 7, "outputTokens": 2}}

    p = BedrockProvider("anthropic.claude-opus-5-5", region="us-east-1", client=FakeBedrock())
    c = p.complete("sys", "q", max_tokens=50)
    assert c.text == "from bedrock" and c.input_tokens == 7 and c.provider == "bedrock"
    assert calls[0]["system"] == [{"text": "sys"}] and calls[0]["messages"][0]["content"] == [{"text": "q"}]
    assert calls[0]["inferenceConfig"]["maxTokens"] == 50


def test_anthropic_provider_keeps_the_sdk_path(monkeypatch):
    calls = []

    class FakeMessages:
        def create(self, **kw):
            calls.append(kw)
            return SimpleNamespace(stop_reason="end_turn", content=[SimpleNamespace(type="text", text="ok")],
                                   usage=SimpleNamespace(input_tokens=5, output_tokens=1))

    monkeypatch.setattr(llm, "_get_client", lambda: SimpleNamespace(beta=SimpleNamespace(messages=FakeMessages())))
    c = AnthropicProvider("claude-opus-5-5").complete("s", "p", max_tokens=10, effort="low")
    assert c.text == "ok" and c.input_tokens == 5
    assert calls[0]["fallbacks"] == "default" and calls[0]["output_config"] == {"effort": "low"}


def test_scripted_provider_records_and_is_allowed_offline():
    p = ScriptedProvider(["a", "b"])
    llm.set_provider(p)
    assert llm.llm_available()  # a scripted provider makes no network call, so offline mode allows it
    assert llm.complete("s1", "p1") == "a" and llm.complete("s2", "p2") == "b"
    assert p.calls == [("s1", "p1"), ("s2", "p2")]
