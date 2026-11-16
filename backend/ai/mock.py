"""Deterministic mock AI (``AI_MODE=mock``), milestone 2C.

Only the AI is mocked: the actions it returns are applied to the real lab and
really verified. The four recommendations match ``dashboard/js/mock-service.js``
(``good``, ``alt``, ``flawed``, ``fixed``), with the lab's real addresses.

Scenario A: first call -> ``good`` (set rule-14 to drop); after feedback -> ``alt`` (delete rule-14).
Scenario B: first call -> ``flawed`` (delete rule-14 + deny 10.0.0.0/8 before rule-12, breaks the app);
            after feedback -> ``fixed`` (delete rule-14 + deny the employee network after rule-12).
"""
from __future__ import annotations

from ipaddress import ip_address, ip_network
from typing import Optional

from backend.ai.interface import Feedback, IncidentFacts, InvalidRecommendation
from backend.ai.models import AIRecommendation
from backend.ai.validate import assign_rule_ids
from backend.lab_types import FirewallRule, LabAddresses

SEQUENCES = {"A": ("good", "alt"), "B": ("flawed", "fixed")}
BROAD_SOURCE = "10.0.0.0/8"  # the deliberate mistake in scenario B


class MockProvider:
    def __init__(self, scenario: str = "A") -> None:
        scenario = (scenario or "A").strip().upper()
        if scenario not in SEQUENCES:
            raise ValueError(f"MOCK_AI_SCENARIO must be A or B, not {scenario!r}")
        self.scenario = scenario
        self.model_name = f"Mock AI (scenario {scenario})"

    def recommend(self, facts: IncidentFacts, rules: list[FirewallRule],
                  feedback: Optional[Feedback], attempt: int) -> AIRecommendation:
        first, second = SEQUENCES[self.scenario]
        key = first if feedback is None and attempt <= 1 else second
        return _build(key, _Facts(facts, rules))


class _Facts:
    """Addresses and rule numbers the display text needs, read from the incident and rules."""

    def __init__(self, facts: IncidentFacts, rules: list[FirewallRule]) -> None:
        d = LabAddresses()
        self.rules = rules
        self.db_ip = facts.target_ip
        self.db_port = facts.target_port
        self.employee_ip = facts.source_ip
        self.matched = facts.matched_rule
        matched = _find(rules, facts.matched_rule)
        self.employee_net = (matched.src if matched and matched.src
                             else str(ip_network(f"{facts.source_ip}/24", strict=False)))
        # The application's own database rule: allow <app> -> db:port, not the matched rule.
        app_rule = next((r for r in rules
                         if r.rule_id not in (facts.matched_rule, "temp-block") and r.verdict == "accept"
                         and r.dst == self.db_ip and r.dport == self.db_port and r.src), None)
        self.app_db_rule = app_rule.rule_id if app_rule else "rule-12"
        self.app_ip = str(ip_network(app_rule.src, strict=False).network_address) if app_rule else d.app_ip
        # Employees' rule to the application: allow <employee net> -> app.
        emp_app = next((r for r in rules
                        if r.verdict == "accept" and r.dst == self.app_ip and r.src
                        and ip_address(self.employee_ip) in ip_network(r.src, strict=False)), None)
        self.emp_app_rule = emp_app.rule_id if emp_app else "rule-10"


def _find(rules: list[FirewallRule], rule_id: str) -> Optional[FirewallRule]:
    return next((r for r in rules if r.rule_id == rule_id), None)


def _n(rule_id: str) -> str:
    """'rule-14' -> '#14' (the dashboard's display number)."""
    return "#" + rule_id.split("-", 1)[1] if rule_id.startswith("rule-") else rule_id


def _build(key: str, f: _Facts) -> AIRecommendation:
    m, r10, r12 = _n(f.matched), _n(f.emp_app_rule), _n(f.app_db_rule)
    port = f"tcp/{f.db_port}"
    db = f"database {f.db_ip}"
    emp = f"employee network {f.employee_net}"

    if key == "good":
        data = dict(
            actions=[{"action": "set_rule_verdict", "rule_id": f.matched, "verdict": "drop"}],
            summary=f"Replace rule {m} with a rule that denies direct database connections from the employee network.",
            change=f"Rule {m} changes from “allow {emp} → {db}” to “deny {emp} → {db}” ({port}).",
            affects=f"Direct database connections from every host on the employee network ({f.employee_net}), including {f.employee_ip}.",
            unaffected=f"Employees using the company application (rule {r10}), and the application’s own database connection (rule {r12}).",
            what_changed="",
        )
    elif key == "alt":
        data = dict(
            actions=[{"action": "delete_rule", "rule_id": f.matched}],
            summary=f"Delete rule {m} and let the existing default-deny rule block direct database connections.",
            change=f"Rule {m} (allow {emp} → {db}) is deleted. No rule is added.",
            affects=f"Direct database connections from every host on the employee network ({f.employee_net}), including {f.employee_ip}.",
            unaffected=f"Employees using the company application (rule {r10}), and the application’s own database connection (rule {r12}).",
            what_changed=f"Instead of changing rule {m} to deny, this version only deletes rule {m} and relies on the existing default-deny rule #99.",
        )
    elif key == "flawed":
        actions = [{"action": "delete_rule", "rule_id": f.matched},
                   {"action": "add_deny", "source_cidr": BROAD_SOURCE, "dest_ip": f.db_ip,
                    "dest_port": f.db_port, "position": f"before:{f.app_db_rule}"}]
        new = _n(_new_id(actions, f, fallback="rule-11"))
        data = dict(
            actions=actions,
            summary=f"Delete rule {m} and add a broad rule that stops every internal address from connecting to the database directly.",
            change=f"Delete rule {m}. Insert rule {new}: deny {BROAD_SOURCE} → {db} ({port}).",
            affects=f"Database connections from every internal address in {BROAD_SOURCE}.",
            unaffected=f"Employees using the company application (rule {r10}).",
            what_changed="",
        )
    else:  # fixed
        actions = [{"action": "delete_rule", "rule_id": f.matched},
                   {"action": "add_deny", "source_cidr": f.employee_net, "dest_ip": f.db_ip,
                    "dest_port": f.db_port, "position": f"after:{f.app_db_rule}"}]
        new = _n(_new_id(actions, f, fallback="rule-13"))
        data = dict(
            actions=actions,
            summary=f"Delete rule {m} and deny direct database connections from the employee network only, placed after the application’s allow rule.",
            change=f"Delete rule {m}. Insert rule {new}: deny {emp} → {db} ({port}), below rule {r12}.",
            affects=f"Direct database connections from the employee network ({f.employee_net}) only, including {f.employee_ip}.",
            unaffected=f"The application server {f.app_ip} (matched first by rule {r12}) and every other internal segment.",
            what_changed=(f"The deny rule now covers only the employee network ({f.employee_net}) instead of all of {BROAD_SOURCE}, "
                          f"and it sits below the application’s allow rule {r12}, so the application server {f.app_ip} is allowed first."),
        )
    return AIRecommendation.model_validate(data)


def _new_id(actions: list[dict], f: _Facts, fallback: str) -> str:
    """The rule_id the validator will assign to the add_deny, so the text names it correctly."""
    try:
        parsed = AIRecommendation.model_validate(
            {"actions": actions, "summary": "x", "change": "x", "affects": "x", "unaffected": "x"}).actions
        return assign_rule_ids(parsed, f.rules)[-1] or fallback
    except InvalidRecommendation:
        return fallback


__all__ = ["MockProvider"]
