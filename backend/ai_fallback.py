"""TEMPORARY stand-ins for agent C's code (backend/ai/factory.py and backend/ai/validate.py).

Used only when those modules are missing, so the backend starts and its tests
run on the ``backend`` branch before the AI branch is merged.
DELETE THIS FILE during integration (milestone 3), once C's code is on main.
"""
from __future__ import annotations

import re
from typing import Optional

from backend.ai.interface import Feedback, IncidentFacts, InvalidRecommendation
from backend.ai.models import AddDeny, AIRecommendation, DeleteRule
from backend.lab_types import FirewallRule, LabAddresses

_NUM = re.compile(r"^rule-(\d+)$")


def _num(rule_id: str) -> Optional[int]:
    m = _NUM.match(rule_id)
    return int(m.group(1)) if m else None


def standin_validate(rec: AIRecommendation, rules: list[FirewallRule],
                     addresses: LabAddresses) -> AIRecommendation:
    """Minimal stand-in: only gives each AddDeny a rule_id that sorts into its position
    (rule-11 for before:rule-12, rule-13 for after:rule-12). No other lab checks."""
    rec = rec.model_copy(deep=True)
    order = [r.rule_id for r in rules]
    for act in rec.actions:
        if isinstance(act, DeleteRule):
            order = [x for x in order if x != act.rule_id]
            continue
        if not isinstance(act, AddDeny):
            continue
        if act.position == "top":
            idx = 0
        else:
            where, ref = act.position.split(":", 1)
            if ref not in order:
                raise InvalidRecommendation(f"position refers to missing rule {ref}")
            idx = order.index(ref) + (0 if where == "before" else 1)
        prev = next((n for n in (_num(x) for x in reversed(order[:idx])) if n is not None), 0)
        nxt = next((n for n in (_num(x) for x in order[idx:]) if n is not None), 1000)
        used = {_num(x) for x in order}
        free = [n for n in range(prev + 1, nxt) if n not in used]
        if not free:
            raise InvalidRecommendation(f"no free rule number for position {act.position}")
        n = free[0] if act.position.startswith("after:") else free[-1]
        act.rule_id = f"rule-{n}"
        order.insert(idx, act.rule_id)
    return rec


# ---- stand-in AI provider (same four cases as dashboard/js/mock-service.js) --------
def _library(a: LabAddresses) -> dict[str, dict]:
    return {
        "good": {
            "actions": [{"action": "set_rule_verdict", "rule_id": "rule-14", "verdict": "drop"}],
            "summary": "Change rule 14 so it denies direct database connections from the employee network.",
            "change": "Rule 14 changes from allow to deny (employee network → database, tcp/5432).",
            "affects": f"Direct database connections from the employee network ({a.employee_net}).",
            "unaffected": "Employees using the company application (rule 10) and the application's database connection (rule 12).",
        },
        "alt": {
            "actions": [{"action": "delete_rule", "rule_id": "rule-14"}],
            "summary": "Delete rule 14 and let the default-deny policy block direct database connections.",
            "change": "Rule 14 (allow employee network → database) is deleted. No rule is added.",
            "affects": f"Direct database connections from the employee network ({a.employee_net}).",
            "unaffected": "Employees using the company application (rule 10) and the application's database connection (rule 12).",
            "what_changed": "Instead of changing rule 14 to deny, this version deletes it and relies on the default deny.",
        },
        "flawed": {
            "actions": [{"action": "delete_rule", "rule_id": "rule-14"},
                        {"action": "add_deny", "source_cidr": "10.0.0.0/8", "dest_ip": a.db_ip,
                         "dest_port": a.db_port, "position": "before:rule-12"}],
            "summary": "Delete rule 14 and add a broad rule that stops every internal address from reaching the database.",
            "change": "Delete rule 14. Insert rule 11: deny 10.0.0.0/8 → database (tcp/5432).",
            "affects": "Database connections from every internal address in 10.0.0.0/8.",
            "unaffected": "Employees using the company application (rule 10).",
        },
        "fixed": {
            "actions": [{"action": "delete_rule", "rule_id": "rule-14"},
                        {"action": "add_deny", "source_cidr": a.employee_net, "dest_ip": a.db_ip,
                         "dest_port": a.db_port, "position": "after:rule-12"}],
            "summary": "Delete rule 14 and deny database connections from the employee network only, below the application's allow rule.",
            "change": f"Delete rule 14. Insert rule 13: deny {a.employee_net} → database (tcp/5432), below rule 12.",
            "affects": f"Direct database connections from the employee network ({a.employee_net}) only.",
            "unaffected": "The application server (matched first by rule 12).",
            "what_changed": "The deny rule now covers only the employee network instead of 10.0.0.0/8, and sits below rule 12.",
        },
    }


SEQUENCES = {"A": ["good", "alt"], "B": ["flawed", "fixed"]}


class StandInProvider:
    """Deterministic stand-in AI. Clearly labelled so nobody mistakes it for agent C's mock."""

    def __init__(self, scenario: str = "A", addresses: Optional[LabAddresses] = None) -> None:
        self.scenario = scenario if scenario in SEQUENCES else "A"
        self.addresses = addresses or LabAddresses()
        self.model_name = f"Stand-in AI (backend fallback, scenario {self.scenario})"

    def recommend(self, facts: IncidentFacts, rules: list[FirewallRule],
                  feedback: Optional[Feedback], attempt: int) -> AIRecommendation:
        seq = SEQUENCES[self.scenario]
        key = seq[min(max(attempt, 1) - 1, len(seq) - 1)]
        return AIRecommendation.model_validate(_library(self.addresses)[key])
