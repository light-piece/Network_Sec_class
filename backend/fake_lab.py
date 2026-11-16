"""In-memory fake of the lab, for testing the backend without Linux.

It keeps an ordered rule list and evaluates traffic first-match, like the
real nftables chain, so recommendations really pass or fail:
- set rule-14 to drop        -> attacker blocked, app works
- add_deny 10.0.0.0/8 at top -> attacker blocked, app BROKEN (scenario B's first fix)

The real ``lab.Lab`` must behave the same way for the same inputs.
"""
from __future__ import annotations

import copy
import json
from ipaddress import ip_address, ip_network
from typing import Optional

from backend.ai.models import Action, AddDeny, DeleteRule, NarrowSource, SetRuleVerdict
from backend.lab_types import (
    AttackResult,
    CheckOutcome,
    FirewallRule,
    LabAddresses,
    LabError,
    LabHealth,
)

TEMP_BLOCK = "temp-block"


def baseline_rules(a: LabAddresses) -> list[FirewallRule]:
    """The deliberately vulnerable baseline (matches lab/baseline.nft)."""
    return [
        FirewallRule("rule-10", "accept", a.employee_net, a.app_ip, a.app_port),
        FirewallRule("rule-12", "accept", a.app_ip, a.db_ip, a.db_port),
        FirewallRule("rule-14", "accept", a.employee_net, a.db_ip, a.db_port, counter=0),
    ]


def _matches(rule: FirewallRule, src: str, dst: str, dport: int) -> bool:
    if rule.src and ip_address(src) not in ip_network(rule.src, strict=False):
        return False
    if rule.dst and ip_address(dst) != ip_address(rule.dst):
        return False
    if rule.dport is not None and rule.dport != dport:
        return False
    return True


class FakeLab:
    def __init__(self, addresses: Optional[LabAddresses] = None) -> None:
        self.addresses = addresses or LabAddresses()
        self._rules = baseline_rules(self.addresses)
        self.up = True

    # ---- inspection -------------------------------------------------------
    def health(self) -> LabHealth:
        return LabHealth(up=self.up, app_ok=self.up, db_ok=self.up, detail="fake lab")

    def rules(self) -> list[FirewallRule]:
        return copy.deepcopy(self._rules)

    def rule14_counter(self) -> int:
        r = self._find("rule-14")
        return (r.counter or 0) if r else 0

    def evaluate(self, src: str, dst: str, dport: int, count: bool = False) -> tuple[str, str]:
        """First matching rule wins; default policy is drop. Returns (verdict, rule_id)."""
        for r in self._rules:
            if _matches(r, src, dst, dport):
                if count and r.counter is not None:
                    r.counter += 1
                return r.verdict, r.rule_id
        return "drop", "default"

    # ---- temporary block ---------------------------------------------------
    def block_on(self) -> FirewallRule:
        a = self.addresses
        existing = self._find(TEMP_BLOCK)
        if existing:
            return copy.deepcopy(existing)
        rule = FirewallRule(TEMP_BLOCK, "drop", a.employee_ip, a.db_ip, a.db_port)
        self._rules.insert(0, rule)
        return copy.deepcopy(rule)

    def block_off(self) -> None:
        self._rules = [r for r in self._rules if r.rule_id != TEMP_BLOCK]

    def block_active(self) -> bool:
        return self._find(TEMP_BLOCK) is not None

    # ---- corrections -------------------------------------------------------
    def render(self, actions: list[Action]) -> list[str]:
        """Display-only text. The real lab returns the exact nft commands."""
        out = []
        for act in actions:
            if isinstance(act, SetRuleVerdict):
                out.append(f"(fake) set {act.rule_id} verdict {act.verdict}")
            elif isinstance(act, DeleteRule):
                out.append(f"(fake) delete {act.rule_id}")
            elif isinstance(act, NarrowSource):
                out.append(f"(fake) set {act.rule_id} source {act.source_cidr}")
            elif isinstance(act, AddDeny):
                out.append(f"(fake) add {act.rule_id} drop {act.source_cidr} -> {act.dest_ip}:{act.dest_port} at {act.position}")
        return out

    def apply(self, actions: list[Action]) -> None:
        for act in actions:
            if isinstance(act, SetRuleVerdict):
                self._require(act.rule_id).verdict = act.verdict
            elif isinstance(act, DeleteRule):
                self._require(act.rule_id)
                self._rules = [r for r in self._rules if r.rule_id != act.rule_id]
            elif isinstance(act, NarrowSource):
                self._require(act.rule_id).src = str(act.source_cidr)
            elif isinstance(act, AddDeny):
                if not act.rule_id:
                    raise LabError("add_deny needs a rule_id assigned by the validator")
                new = FirewallRule(act.rule_id, "drop", str(act.source_cidr), str(act.dest_ip), act.dest_port)
                self._rules.insert(self._index_for(act.position), new)
            else:  # pragma: no cover
                raise LabError(f"unknown action {act!r}")

    def snapshot(self) -> str:
        return json.dumps([r.__dict__ for r in self._rules])

    def restore(self, snapshot: str) -> None:
        self._rules = [FirewallRule(**d) for d in json.loads(snapshot)]

    # ---- checks ------------------------------------------------------------
    def check_unauthorized_blocked(self) -> CheckOutcome:
        a = self.addresses
        verdict, rid = self.evaluate(a.employee_ip, a.db_ip, a.db_port)
        blocked = verdict == "drop"
        return CheckOutcome(
            passed=blocked,
            command=f"pg_isready -h {a.db_ip} -p {a.db_port} (from employee)",
            exit_code=2 if blocked else 0,
            output=f"{'no response' if blocked else 'accepting connections'} · matched {rid}",
            duration_ms=3000 if blocked else 15,
        )

    def check_legitimate_app(self) -> CheckOutcome:
        a = self.addresses
        v1, r1 = self.evaluate(a.employee_ip, a.app_ip, a.app_port)
        v2, r2 = self.evaluate(a.app_ip, a.db_ip, a.db_port)
        ok = v1 == "accept" and v2 == "accept"
        if v1 != "accept":
            out = f"employee → app blocked by {r1}"
        elif v2 != "accept":
            out = f"HTTP 500 · app → db blocked by {r2}"
        else:
            out = "HTTP 200 · 25 records"
        return CheckOutcome(passed=ok, command=f"curl http://{a.app_ip}:{a.app_port}/api/records",
                            exit_code=0 if ok else 22, output=out, duration_ms=120 if ok else 5000)

    # ---- demo --------------------------------------------------------------
    def run_attack(self) -> AttackResult:
        a = self.addresses
        verdict, rid = self.evaluate(a.employee_ip, a.db_ip, a.db_port, count=True)
        return AttackResult(reached=verdict == "accept",
                            command=f"connect {a.employee_ip} → {a.db_ip}:{a.db_port}",
                            output=f"matched {rid}")

    def reset(self) -> None:
        self._rules = baseline_rules(self.addresses)

    # ---- helpers -----------------------------------------------------------
    def _find(self, rule_id: str) -> Optional[FirewallRule]:
        return next((r for r in self._rules if r.rule_id == rule_id), None)

    def _require(self, rule_id: str) -> FirewallRule:
        r = self._find(rule_id)
        if r is None:
            raise LabError(f"rule {rule_id} not found")
        return r

    def _index_for(self, position: str) -> int:
        if position == "top":
            return 0
        where, rule_id = position.split(":", 1)
        idx = next((i for i, r in enumerate(self._rules) if r.rule_id == rule_id), None)
        if idx is None:
            raise LabError(f"position refers to missing rule {rule_id}")
        return idx if where == "before" else idx + 1
