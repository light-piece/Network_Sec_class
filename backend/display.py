"""Turn lab data into the dashboard's display shapes.

- Rule rows and before/after lists (a dry run of the actions on a FakeLab copy).
- CheckResult detail/evidence text from a CheckOutcome.
- Containment and policy rule text.

Nothing here touches the real lab except through the arguments it is given.
"""
from __future__ import annotations

import copy
import re
from ipaddress import ip_network
from typing import Optional

from backend.ai.models import Action
from backend.fake_lab import FakeLab
from backend.lab_types import CheckOutcome, FirewallRule, LabAddresses
from backend.models import CheckResult, Rule

TEMP_BLOCK = "temp-block"
TEMP_BLOCK_NUM = "T-1"
DEFAULT_DENY = Rule(num="99", action="deny", src="any", dst="any", port="any",
                    note="Default deny", change="unchanged")

CHECK_NAMES = {
    "unauthorized_blocked": "Attacker path blocked",
    "legitimate_app": "Company application still works",
}


# ---- dry run --------------------------------------------------------------------
def fake_lab_from_rules(rules: list[FirewallRule], addresses: LabAddresses) -> FakeLab:
    """A FakeLab holding a copy of ``rules`` (no edits to fake_lab.py needed)."""
    lab = FakeLab(addresses)
    lab._rules = copy.deepcopy(rules)
    return lab


def dry_run(rules: list[FirewallRule], actions: list[Action], addresses: LabAddresses) -> list[FirewallRule]:
    """Apply ``actions`` to a copy of ``rules``. Raises LabError if an action does not fit."""
    lab = fake_lab_from_rules(rules, addresses)
    lab.apply(actions)
    return lab.rules()


# ---- names ------------------------------------------------------------------------
def rule_num(rule_id: str) -> str:
    if rule_id == TEMP_BLOCK:
        return TEMP_BLOCK_NUM
    m = re.fullmatch(r"rule-(\d+)", rule_id)
    return m.group(1) if m else rule_id


def verdict_word(verdict: str) -> str:
    return "allow" if verdict == "accept" else "deny"


def place_name(value: Optional[str], a: LabAddresses) -> str:
    """Readable name for a rule's src/dst (CIDR or single IP)."""
    if not value:
        return "any"
    try:
        net = ip_network(value, strict=False)
    except ValueError:
        return value
    names = [
        (a.employee_net, "Employee network"),
        (a.employee_ip, "Employee workstation"),
        (a.app_ip, "Company app"),
        (a.db_ip, "Company database"),
        (a.app_net, "Application network"),
        (a.db_net, "Database network"),
    ]
    for addr, name in names:
        if net == ip_network(addr, strict=False):
            return name
    return str(net) if net.prefixlen < 32 else str(net.network_address)


def port_text(dport: Optional[int]) -> str:
    return f"tcp/{dport}" if dport is not None else "any"


def _note(r: FirewallRule, a: LabAddresses) -> str:
    if r.rule_id == TEMP_BLOCK:
        return "Temporary block"
    if r.rule_id == "rule-10" and r.verdict == "accept":
        return "Employees use the application"
    if r.rule_id == "rule-12" and r.verdict == "accept":
        return "Application uses the database"
    if r.rule_id == "rule-14" and r.verdict == "accept":
        return "Misconfigured"
    if r.verdict == "drop" and r.dst == a.db_ip:
        return "Blocks direct database access"
    return ""


def _key(r: FirewallRule) -> tuple:
    src = str(ip_network(r.src, strict=False)) if r.src else None
    dst = str(ip_network(r.dst, strict=False)) if r.dst else None
    return (r.rule_id, r.verdict, src, dst, r.dport)


def rule_row(r: FirewallRule, a: LabAddresses, change: str = "unchanged", note: Optional[str] = None) -> Rule:
    return Rule(num=rule_num(r.rule_id), action=verdict_word(r.verdict),
                src=place_name(r.src, a), dst=place_name(r.dst, a), port=port_text(r.dport),
                note=_note(r, a) if note is None else note, change=change)


def rule_text(r: FirewallRule) -> str:
    """'deny 10.10.10.10 → 10.10.30.10 tcp/5432' (raw addresses, like the contract)."""
    return f"{verdict_word(r.verdict)} {r.src or 'any'} → {r.dst or 'any'} {port_text(r.dport)}"


def before_after(rules: list[FirewallRule], actions: list[Action], a: LabAddresses,
                 include_temp_block: bool = False) -> tuple[list[Rule], list[Rule]]:
    """Display rows for the current rules and for the rules after the actions (dry run).

    The temporary block is hidden by default: it is lifted before verification,
    so it is not part of the permanent change the administrator approves.
    Raises LabError if the actions do not apply to ``rules``.
    """
    after_rules = dry_run(rules, actions, a)
    if not include_temp_block:
        rules = [r for r in rules if r.rule_id != TEMP_BLOCK]
        after_rules = [r for r in after_rules if r.rule_id != TEMP_BLOCK]
    before_keys = {_key(r) for r in rules}
    after_keys = {_key(r) for r in after_rules}
    before = [rule_row(r, a, "unchanged" if _key(r) in after_keys else "removed") for r in rules]
    after = []
    for r in after_rules:
        if _key(r) in before_keys:
            after.append(rule_row(r, a, "unchanged"))
        else:
            after.append(rule_row(r, a, "added", note="New"))
    return before + [DEFAULT_DENY], after + [DEFAULT_DENY]


# ---- checks -------------------------------------------------------------------------
def evidence_text(o: CheckOutcome) -> str:
    out = " ".join(o.output.split()) or "(no output)"
    return f"{o.command} → exit {o.exit_code} · {out} · {o.duration_ms} ms"


def check_result(check_id: str, o: CheckOutcome, source_name: str) -> CheckResult:
    if check_id == "unauthorized_blocked":
        detail = (f"The direct connection from {source_name} to the database was refused."
                  if o.passed else
                  f"{source_name} could still connect to the database directly.")
    else:
        detail = ("The company application returned records normally."
                  if o.passed else
                  "The company application could not return records from the database.")
    return CheckResult(id=check_id, status="passed" if o.passed else "failed",
                       detail=detail, evidence=evidence_text(o))


def fail_detail(check_id: str, o: CheckOutcome, version: int, source_name: str) -> str:
    """Explanation stored on the recommendation after a failed check."""
    out = " ".join(o.output.split()) or "no output"
    if check_id == "legitimate_app":
        return (f"With version {version} applied, the company application could not serve records "
                f"({out}). The change also blocks the application's legitimate path to the database.")
    return (f"With version {version} applied, {source_name} could still reach the database directly "
            f"({out}). The change does not block the unauthorized path.")
