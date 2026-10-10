"""Recorded copilot eval suite (plan AI2): >= 20 questions with the SQL a model produced and the
expected answer facts, replayed through each provider class with fake transports."""
from __future__ import annotations

import json
from types import SimpleNamespace

import httpx
import pytest

from nimbus.ai import llm
from nimbus.ai.evals import CASES, recorded_responder, run_eval
from nimbus.ai.providers import AnthropicProvider, BedrockProvider, OpenAICompatibleProvider, ScriptedProvider


@pytest.fixture(autouse=True)
def _reset():
    llm.set_provider(None)
    yield
    llm.set_provider(None)


def test_suite_size_and_shape():
    assert len(CASES) >= 20
    for c in CASES:
        assert c["question"] and c["sql"].lstrip().upper().startswith(("SELECT", "WITH")) and c["expect"]


def test_eval_scripted_provider(seeded):
    report = run_eval(seeded, ScriptedProvider(recorded_responder()))
    assert report["failed"] == [], report["failed"]
    assert report["passed"] == len(CASES)


def test_eval_offline_rule_mode(seeded):
    report = run_eval(seeded, None)
    offline_cases = [c for c in CASES if c.get("offline_intent")]
    assert len(offline_cases) >= 12
    assert report["failed"] == [], report["failed"]


def _anthropic(monkeypatch):
    resp = recorded_responder()

    class FakeMessages:
        def create(self, **kw):
            text = resp(kw["system"], kw["messages"][0]["content"])
            return SimpleNamespace(stop_reason="end_turn", content=[SimpleNamespace(type="text", text=text)],
                                   usage=SimpleNamespace(input_tokens=100, output_tokens=20))

    monkeypatch.setattr(llm, "_get_client", lambda: SimpleNamespace(beta=SimpleNamespace(messages=FakeMessages())))
    return _Online(AnthropicProvider("claude-opus-5-5"))


def _openai_local():
    resp = recorded_responder()

    def handler(req):
        body = json.loads(req.content)
        text = resp(body["messages"][0]["content"], body["messages"][1]["content"])
        return httpx.Response(200, json={"choices": [{"message": {"content": text}}], "usage": {"prompt_tokens": 1, "completion_tokens": 1}})

    return _Online(OpenAICompatibleProvider("http://127.0.0.1:11434/v1", "llama3.1", transport=httpx.MockTransport(handler)))


def _bedrock():
    resp = recorded_responder()

    class FakeBedrock:
        def converse(self, **kw):
            return {"output": {"message": {"content": [{"text": resp(kw["system"][0]["text"], kw["messages"][0]["content"][0]["text"])}]}},
                    "usage": {"inputTokens": 1, "outputTokens": 1}}

    return _Online(BedrockProvider("anthropic.claude-opus-5-5", region="us-east-1", client=FakeBedrock()))


class _Online:
    """Wraps a network provider so the offline test environment lets it run (transport is fake)."""

    def __init__(self, inner):
        self.inner, self.network = inner, False

    def available(self):
        return True

    def complete(self, *a, **kw):
        return self.inner.complete(*a, **kw)


@pytest.mark.parametrize("make", ["anthropic", "openai_local", "bedrock"])
def test_eval_each_provider(seeded, monkeypatch, make):
    p = {"anthropic": lambda: _anthropic(monkeypatch), "openai_local": _openai_local, "bedrock": _bedrock}[make]()
    report = run_eval(seeded, p)
    assert report["failed"] == [], report["failed"]
