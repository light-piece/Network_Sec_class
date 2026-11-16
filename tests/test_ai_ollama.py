"""Ollama provider (backend/ai/ollama.py) against a fake HTTP server. No network."""
import json

import httpx
import pytest

from backend.ai.interface import AIUnavailable, Feedback, IncidentFacts, InvalidRecommendation
from backend.ai.models import AIRecommendation
from backend.ai.ollama import OllamaProvider, reachable
from backend.fake_lab import baseline_rules
from backend.lab_types import LabAddresses

FACTS = IncidentFacts(source_ip="10.10.10.10", target_ip="10.10.30.10", target_port=5432, matched_rule="rule-14",
                      policy="Only the company app (10.10.20.10) may reach the database (10.10.30.10:5432).")
RULES = baseline_rules(LabAddresses())
GOOD = {"actions": [{"action": "set_rule_verdict", "rule_id": "rule-14", "verdict": "drop"}],
        "summary": "Deny rule-14.", "change": "rule-14 becomes drop.", "affects": "Employees -> db.",
        "unaffected": "Employees -> app, app -> db.", "what_changed": ""}


def chat_reply(content):
    return httpx.Response(200, json={"model": "qwen3:4b", "message": {"role": "assistant", "content": content},
                                     "done": True})


class Server:
    """Records requests and answers with the given handler."""

    def __init__(self, handler):
        self.handler = handler
        self.requests = []

    def __call__(self, request):
        body = json.loads(request.content) if request.content else None
        self.requests.append((request.method, str(request.url), body))
        return self.handler(request, body)


def provider(handler, timeout=120):
    srv = Server(handler)
    return OllamaProvider("http://ollama.test:11434/", "qwen3:4b", timeout, transport=httpx.MockTransport(srv)), srv


def test_good_json_and_request_shape():
    p, srv = provider(lambda req, body: chat_reply(json.dumps(GOOD)))
    rec = p.recommend(FACTS, RULES, None, 1)
    assert isinstance(rec, AIRecommendation) and rec.actions[0].verdict == "drop"
    assert p.model_name == "qwen3:4b via Ollama"
    method, url, body = srv.requests[0]
    assert method == "POST" and url == "http://ollama.test:11434/api/chat"
    assert body["model"] == "qwen3:4b" and body["stream"] is False and body["think"] is False
    assert body["options"] == {"temperature": 0.2, "num_ctx": 4096}
    assert body["format"] == AIRecommendation.model_json_schema()
    system, user = body["messages"]
    assert system["role"] == "system" and user["role"] == "user"
    for needle in ("Only the company app", "FIRST rule that matches", "set_rule_verdict", "delete_rule",
                   "narrow_source", "add_deny", "JSON"):
        assert needle in system["content"]
    for needle in ("1. rule-10", "2. rule-12", "3. rule-14", "10.10.10.10", "default deny"):
        assert needle in user["content"]
    assert "/no_think" not in user["content"]


def test_feedback_is_in_the_prompt():
    p, srv = provider(lambda req, body: chat_reply(json.dumps(GOOD)))
    p.recommend(FACTS, RULES, Feedback("failed", 1, "“Company application still works” failed: HTTP 500"), 2)
    user = srv.requests[0][2]["messages"][1]["content"]
    assert "FAILED verification" in user and "HTTP 500" in user and "Version 1" in user
    p.recommend(FACTS, RULES, Feedback("rejected", 2), 3)
    assert "REJECTED version 2" in srv.requests[1][2]["messages"][1]["content"]


def test_temp_block_not_listed_in_prompt():
    from backend.fake_lab import FakeLab
    lab = FakeLab()
    lab.block_on()
    p, srv = provider(lambda req, body: chat_reply(json.dumps(GOOD)))
    p.recommend(FACTS, lab.rules(), None, 1)
    assert "temp-block" not in srv.requests[0][2]["messages"][1]["content"]


def test_code_fenced_json_is_accepted():
    p, _ = provider(lambda req, body: chat_reply("```json\n" + json.dumps(GOOD) + "\n```"))
    assert p.recommend(FACTS, RULES, None, 1).actions[0].rule_id == "rule-14"


@pytest.mark.parametrize("content", ["not json at all", "{\"actions\": [", ""])
def test_bad_json_is_invalid(content):
    p, _ = provider(lambda req, body: chat_reply(content))
    with pytest.raises(InvalidRecommendation):
        p.recommend(FACTS, RULES, None, 1)


@pytest.mark.parametrize("data", [
    {**GOOD, "actions": []},
    {**GOOD, "actions": [{"action": "run_shell", "cmd": "nft flush ruleset"}]},
    {**GOOD, "actions": [{"action": "delete_rule", "rule_id": "rule-14; reboot"}]},
    {**GOOD, "commands": ["nft flush ruleset"]},
    {k: v for k, v in GOOD.items() if k != "summary"},
    [GOOD],
])
def test_schema_invalid_is_invalid(data):
    p, _ = provider(lambda req, body: chat_reply(json.dumps(data)))
    with pytest.raises(InvalidRecommendation, match="schema"):
        p.recommend(FACTS, RULES, None, 1)


def test_reply_without_message_is_invalid():
    p, _ = provider(lambda req, body: httpx.Response(200, json={"done": True}))
    with pytest.raises(InvalidRecommendation):
        p.recommend(FACTS, RULES, None, 1)


def test_timeout_is_unavailable():
    def handler(req, body):
        raise httpx.ReadTimeout("timed out", request=req)
    p, _ = provider(handler, timeout=7)
    with pytest.raises(AIUnavailable, match="within 7 s"):
        p.recommend(FACTS, RULES, None, 1)


def test_connection_refused_is_unavailable():
    def handler(req, body):
        raise httpx.ConnectError("[Errno 111] Connection refused", request=req)
    p, _ = provider(handler)
    with pytest.raises(AIUnavailable, match="Cannot reach Ollama at http://ollama.test:11434"):
        p.recommend(FACTS, RULES, None, 1)


def test_real_connection_refused_is_unavailable():
    # Port 9 on localhost: nothing listens there; no external network involved.
    p = OllamaProvider("http://127.0.0.1:9", "qwen3:4b", 2)
    with pytest.raises(AIUnavailable):
        p.recommend(FACTS, RULES, None, 1)


def test_think_rejected_falls_back_to_no_think():
    def handler(req, body):
        if "think" in body:
            return httpx.Response(400, json={"error": "invalid option provided: think"})
        return chat_reply(json.dumps(GOOD))
    p, srv = provider(handler)
    rec = p.recommend(FACTS, RULES, None, 1)
    assert rec.actions[0].verdict == "drop"
    assert len(srv.requests) == 2
    retry = srv.requests[1][2]
    assert "think" not in retry and retry["messages"][1]["content"].endswith(" /no_think")
    # Remembered for the next call: one request, no think field.
    p.recommend(FACTS, RULES, None, 1)
    assert len(srv.requests) == 3 and "think" not in srv.requests[2][2]


def test_other_http_errors_are_unavailable():
    p, srv = provider(lambda req, body: httpx.Response(404, json={"error": "model 'qwen3:4b' not found"}))
    with pytest.raises(AIUnavailable, match="ollama pull qwen3:4b"):
        p.recommend(FACTS, RULES, None, 1)
    p, srv = provider(lambda req, body: httpx.Response(500, json={"error": "out of memory"}))
    with pytest.raises(AIUnavailable, match="out of memory"):
        p.recommend(FACTS, RULES, None, 1)
    assert len(srv.requests) == 1  # a 400/500 without "think" is not retried


def test_reachable():
    ok = httpx.MockTransport(lambda req: httpx.Response(200, json={"models": []})
                             if req.url.path == "/api/tags" else httpx.Response(404))
    assert reachable("http://ollama.test:11434/", transport=ok)
    down = httpx.MockTransport(lambda req: (_ for _ in ()).throw(httpx.ConnectError("refused", request=req)))
    assert not reachable("http://ollama.test:11434", transport=down)
    assert not reachable("http://ollama.test:11434", transport=httpx.MockTransport(lambda req: httpx.Response(500)))
