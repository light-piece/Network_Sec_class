"""Real AI provider: a local model served by Ollama (``AI_MODE=ollama``), milestone 2C.

One non-streaming ``POST {url}/api/chat`` with structured output (plan 5.6).
The model only chooses actions from the closed set in ``models.py``; its
output is parsed and schema-checked here, then lab-checked by ``validate.py``.
Nothing it returns is ever passed to a shell.
"""
from __future__ import annotations

import json
from typing import Any, Optional

import httpx
from pydantic import ValidationError

from backend.ai.interface import AIUnavailable, Feedback, IncidentFacts, InvalidRecommendation
from backend.ai.models import AIRecommendation, ollama_format_schema
from backend.lab_types import FirewallRule

TEMP_BLOCK = "temp-block"

SYSTEM_PROMPT = """\
You are a network security assistant. You fix ONE firewall misconfiguration in a small lab network.
You never write commands. You choose 1 to 3 actions from a fixed list, and the system applies them.

SECURITY POLICY
{policy}
The intended path is: employee workstation -> company application -> database.
Employees may use the company application. Only the company application may connect to the database.

HOW THE FIREWALL WORKS
- Rules are checked from top to bottom. The FIRST rule that matches decides (accept or drop).
- Traffic that matches no rule is dropped (default deny, shown to the administrator as rule #99).
- Replies to already-allowed connections are always accepted by a built-in first rule; you cannot change it.
- A temporary containment block is active right now. It is not in the rule list, you must not reference it,
  and it is removed before your fix is tested, so your fix must block the traffic on its own.
- Rule ids look like "rule-14". Use only rule ids from the list you are given.

YOUR GOAL
Block direct connections from the employee workstations to the database, while keeping BOTH of these working:
1. employees -> company application (the application's web port), and
2. company application -> database (the database port).
Prefer the smallest change that achieves this. A rule placed above another rule wins over it.

ALLOWED ACTIONS (applied in order, top to bottom)
- {{"action": "set_rule_verdict", "rule_id": "<existing rule id>", "verdict": "accept" | "drop"}}
    Change an existing rule's verdict.
- {{"action": "delete_rule", "rule_id": "<existing rule id>"}}
    Remove an existing rule. Its traffic then falls through to later rules or the default deny.
- {{"action": "narrow_source", "rule_id": "<existing rule id>", "source_cidr": "<smaller IPv4 network, e.g. 10.10.10.0/25>"}}
    Restrict an existing rule's source to a smaller network inside its current source.
- {{"action": "add_deny", "source_cidr": "<IPv4 network>", "dest_ip": "<app or database IP>", "dest_port": {app_port} | {db_port},
    "position": "top" | "before:<existing rule id>" | "after:<existing rule id>"}}
    Insert a new drop rule. Do not set rule_id; the system assigns it.
Each rule may be changed or deleted at most once. Every action must change something.

REPLY FORMAT
Reply with ONE JSON object and nothing else (no markdown, no explanations outside the JSON):
{{"actions": [...], "summary": "...", "change": "...", "affects": "...", "unaffected": "...", "what_changed": "..."}}
- summary: one sentence the administrator reads first.
- change: what changes in the firewall, in plain words, naming rule numbers.
- affects: who loses access because of the change.
- unaffected: who keeps access.
- what_changed: empty for a first recommendation; for a revised one, how it differs from the previous version.
Each text field is at most 400 characters. Write plain sentences, never commands.
"""


class OllamaProvider:
    def __init__(self, url: str, model: str, timeout: float = 120.0,
                 transport: Optional[httpx.BaseTransport] = None) -> None:
        self.url = url.rstrip("/")
        self.model = model
        self.timeout = float(timeout)
        self.model_name = f"{model} via Ollama"
        self._transport = transport
        self._think_supported = True  # set False once the server rejects the "think" field

    # ---- AIProvider --------------------------------------------------------
    def recommend(self, facts: IncidentFacts, rules: list[FirewallRule],
                  feedback: Optional[Feedback], attempt: int) -> AIRecommendation:
        system = build_system_prompt(facts, rules)
        user = build_user_message(facts, rules, feedback, attempt)

        response = self._chat(system, user, think=self._think_supported)
        if response.status_code == 400 and self._think_supported and "think" in response.text.lower():
            # Older Ollama: no "think" field. Drop it and ask the model not to think instead.
            self._think_supported = False
            response = self._chat(system, user, think=False)
        return parse_response(response, self.model, self.url)

    # ---- HTTP --------------------------------------------------------------
    def _chat(self, system: str, user: str, think: bool) -> httpx.Response:
        """``think=True`` sends ``"think": false``; otherwise ``/no_think`` is appended to the user message."""
        if not think:
            user = user + " /no_think"
        body: dict[str, Any] = {
            "model": self.model,
            "stream": False,
            "format": ollama_format_schema(),
            "options": {"temperature": 0.2, "num_ctx": 4096},
            "messages": [
                {"role": "system", "content": system},
                {"role": "user", "content": user},
            ],
        }
        if think:
            body["think"] = False
        try:
            with httpx.Client(transport=self._transport, timeout=self.timeout) as client:
                return client.post(f"{self.url}/api/chat", json=body)
        except httpx.TimeoutException:
            raise AIUnavailable(
                f"The AI model ({self.model}) at {self.url} did not answer within {self.timeout:g} s.") from None
        except httpx.HTTPError as e:
            raise AIUnavailable(f"Cannot reach Ollama at {self.url}: {_reason(e)}.") from None


def reachable(url: str, timeout: float = 3.0, transport: Optional[httpx.BaseTransport] = None) -> bool:
    """True if Ollama answers ``GET {url}/api/tags``."""
    try:
        with httpx.Client(transport=transport, timeout=timeout) as client:
            return client.get(f"{url.rstrip('/')}/api/tags").status_code == 200
    except httpx.HTTPError:
        return False


# ---------------------------------------------------------------------------
# Prompt building
# ---------------------------------------------------------------------------
def build_system_prompt(facts: IncidentFacts, rules: list[FirewallRule]) -> str:
    app_port, db_port = _ports(facts, rules)
    return SYSTEM_PROMPT.format(policy=facts.policy, app_port=app_port, db_port=db_port)


def build_user_message(facts: IncidentFacts, rules: list[FirewallRule],
                       feedback: Optional[Feedback], attempt: int) -> str:
    incident = {
        "event": "unauthorized direct connection to the database",
        "source_ip": facts.source_ip,
        "target_ip": facts.target_ip,
        "target_port": facts.target_port,
        "allowed_by_rule": facts.matched_rule,
    }
    lines = ["INCIDENT", json.dumps(incident), "",
             "CURRENT FIREWALL RULES (forward chain, checked top to bottom, first match wins):"]
    lines += format_rules(rules)
    lines.append("(no match) -> drop  [default deny, rule #99]")
    lines.append("")
    if feedback is None:
        lines.append("This is the first recommendation for this incident. Leave what_changed empty.")
    elif feedback.type == "rejected":
        lines.append(f"FEEDBACK: The administrator REJECTED version {feedback.version} of your recommendation "
                     "without applying it. Propose a DIFFERENT approach than that version, and explain the "
                     "difference in what_changed.")
    else:
        lines.append(f"FEEDBACK: Version {feedback.version} was applied and FAILED verification, then rolled back. "
                     "The firewall rules above are the current rules again.")
        if feedback.summary:
            lines.append(f"Failed check results: {feedback.summary}")
        lines.append("Propose a corrected recommendation that fixes this failure, and explain the difference "
                     "in what_changed.")
    lines.append("")
    lines.append("Reply with the JSON object only.")
    return "\n".join(lines)


def format_rules(rules: list[FirewallRule]) -> list[str]:
    out = []
    n = 0
    for r in rules:
        if r.rule_id == TEMP_BLOCK:
            continue
        n += 1
        src = r.src or "any"
        dst = r.dst or "any"
        port = f"tcp dport {r.dport}" if r.dport is not None else "any port"
        out.append(f"{n}. {r.rule_id}: src {src} -> dst {dst} {port} -> {r.verdict}")
    if not out:
        out.append("(no rules)")
    return out


def _ports(facts: IncidentFacts, rules: list[FirewallRule]) -> tuple[int, int]:
    db_port = facts.target_port
    other = sorted({r.dport for r in rules if r.dport and r.dport != db_port})
    return (other[0] if other else 8080), db_port


# ---------------------------------------------------------------------------
# Response parsing
# ---------------------------------------------------------------------------
def parse_response(response: httpx.Response, model: str, url: str) -> AIRecommendation:
    if response.status_code == 404 and "model" in response.text.lower():
        raise AIUnavailable(f"Ollama at {url} does not have the model '{model}'. Run: ollama pull {model}")
    if response.status_code >= 400:
        raise AIUnavailable(f"Ollama at {url} returned HTTP {response.status_code}: {_detail(response)}")
    try:
        content = response.json()["message"]["content"]
    except (ValueError, KeyError, TypeError):
        raise InvalidRecommendation("The AI server's reply had no message content.") from None
    if not isinstance(content, str) or not content.strip():
        raise InvalidRecommendation("The AI returned an empty answer.")
    try:
        data = json.loads(_strip_fences(content))
    except json.JSONDecodeError as e:
        raise InvalidRecommendation(f"The AI did not return valid JSON ({e.msg} at position {e.pos}).") from None
    try:
        return AIRecommendation.model_validate(data)
    except ValidationError as e:
        raise InvalidRecommendation(f"The AI's answer does not match the recommendation schema: {_short(e)}") from None


def _strip_fences(text: str) -> str:
    t = text.strip()
    if t.startswith("```"):
        t = t.split("\n", 1)[1] if "\n" in t else ""
        if t.rstrip().endswith("```"):
            t = t.rstrip()[:-3]
    return t.strip()


def _short(e: ValidationError) -> str:
    parts = []
    for err in e.errors()[:3]:
        loc = ".".join(str(x) for x in err.get("loc", ()))
        parts.append(f"{loc}: {err.get('msg')}" if loc else str(err.get("msg")))
    more = len(e.errors()) - 3
    return "; ".join(parts) + (f" (+{more} more)" if more > 0 else "")


def _detail(response: httpx.Response) -> str:
    try:
        err = response.json().get("error")
        if err:
            return str(err)[:200]
    except (ValueError, AttributeError):
        pass
    return response.text[:200] or response.reason_phrase


def _reason(e: httpx.HTTPError) -> str:
    if isinstance(e, httpx.ConnectError):
        return "connection refused or host unreachable"
    return type(e).__name__


__all__ = ["OllamaProvider", "reachable", "build_system_prompt", "build_user_message", "parse_response"]
