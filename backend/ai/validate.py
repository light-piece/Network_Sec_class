"""Lab-specific validation of an AI recommendation (milestone 2C).

``models.py`` already checks types and formats. This module checks the
recommendation against the *current* lab: rule IDs exist, addresses are
inside the lab, positions make sense, and every action really changes
something. It also assigns each ``add_deny`` a new ``rule_id`` that sorts
into its position (``before:rule-12`` -> ``rule-11``, ``after:rule-12`` ->
``rule-13``, ``top`` -> one below the first rule).

Nothing here runs commands. ``backend/lab.py`` turns validated actions into
fixed nftables templates.
"""
from __future__ import annotations

import re
from ipaddress import IPv4Address, IPv4Network, ip_network
from typing import Optional

from pydantic import ValidationError

from backend.ai.interface import InvalidRecommendation
from backend.ai.models import (
    Action,
    AddDeny,
    AIRecommendation,
    DeleteRule,
    NarrowSource,
    SetRuleVerdict,
)
from backend.lab_types import FirewallRule, LabAddresses

TEMP_BLOCK = "temp-block"
MIN_RULE_NUM = 1
MAX_RULE_NUM = 999
_RULE_RE = re.compile(r"^rule-(\d{1,3})$")


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------
def validate(rec: AIRecommendation, rules: list[FirewallRule], addresses: LabAddresses) -> AIRecommendation:
    """Return a validated copy of ``rec`` with every AddDeny given a rule_id.

    ``rules`` is the current forward chain in order (``lab.rules()``), which
    may include ``temp-block`` while containment is on. Raises
    ``InvalidRecommendation`` with a message the administrator can read.
    The input is never mutated.
    """
    # Re-run the schema on a JSON round trip: this also rejects objects built
    # with model_construct() that skipped validation, and gives us a deep copy.
    try:
        rec = AIRecommendation.model_validate(rec.model_dump(mode="json", warnings=False))
    except ValidationError as e:
        raise InvalidRecommendation(f"The AI recommendation does not match the schema: {_short_errors(e)}") from None

    lab = _LabRanges(addresses)
    working = [_copy_rule(r) for r in rules if r.rule_id != TEMP_BLOCK]
    original = [_copy_rule(r) for r in working]
    known_ids = {r.rule_id for r in rules}
    taken = {_num(r.rule_id) for r in rules if _num(r.rule_id) is not None}
    touched: set[str] = set()
    out: list[Action] = []

    for i, act in enumerate(rec.actions, start=1):
        where = f"Action {i} ({act.action})"
        if isinstance(act, (SetRuleVerdict, DeleteRule, NarrowSource)):
            target = _existing(act.rule_id, working, known_ids, touched, where)
            if isinstance(act, SetRuleVerdict):
                if target.verdict == act.verdict:
                    raise InvalidRecommendation(f"{where}: {act.rule_id} is already '{act.verdict}', so this changes nothing.")
                target.verdict = act.verdict
            elif isinstance(act, DeleteRule):
                working.remove(target)
            else:
                _check_narrow(act, target, lab, where)
                target.src = str(act.source_cidr)
            touched.add(act.rule_id)
            out.append(act)
        elif isinstance(act, AddDeny):
            lab.check_source(act.source_cidr, where)
            lab.check_destination(act.dest_ip, act.dest_port, where)
            index, num = _place(act.position, working, taken, where)
            rule_id = f"rule-{num}"
            taken.add(num)
            working.insert(index, FirewallRule(rule_id, "drop", str(act.source_cidr), str(act.dest_ip), act.dest_port))
            out.append(act.model_copy(update={"rule_id": rule_id}))
        else:  # pragma: no cover - the schema only allows the four actions
            raise InvalidRecommendation(f"{where}: unknown action.")

    if _same(working, original):
        raise InvalidRecommendation("The AI recommendation does not change the firewall.")

    return rec.model_copy(update={"actions": out})


def assign_rule_ids(actions: list[Action], rules: list[FirewallRule]) -> list[Optional[str]]:
    """The rule_id each action would get (AddDeny) or touches (others), without lab range checks.

    Used by the mock AI to name new rules in its display text consistently
    with ``validate``. Raises ``InvalidRecommendation`` if a position is impossible.
    """
    working = [_copy_rule(r) for r in rules if r.rule_id != TEMP_BLOCK]
    taken = {_num(r.rule_id) for r in rules if _num(r.rule_id) is not None}
    ids: list[Optional[str]] = []
    for i, act in enumerate(actions, start=1):
        if isinstance(act, AddDeny):
            index, num = _place(act.position, working, taken, f"Action {i} (add_deny)")
            taken.add(num)
            working.insert(index, FirewallRule(f"rule-{num}", "drop"))
            ids.append(f"rule-{num}")
        else:
            if isinstance(act, DeleteRule):
                working = [r for r in working if r.rule_id != act.rule_id]
            ids.append(getattr(act, "rule_id", None))
    return ids


# ---------------------------------------------------------------------------
# Address checks
# ---------------------------------------------------------------------------
class _LabRanges:
    """The lab's networks and services, from LabAddresses."""

    def __init__(self, a: LabAddresses) -> None:
        self.nets = [ip_network(n, strict=False) for n in (a.employee_net, a.app_net, a.db_net)]
        # The private block that holds the lab ("internal" addresses). A source
        # wider than a lab network is allowed only inside this block, and only if
        # it covers at least one lab network (e.g. 10.10.0.0/16 or 10.0.0.0/8).
        self.internal = next((b for b in _PRIVATE_BLOCKS if all(n.subnet_of(b) for n in self.nets)), None)
        self.services = {IPv4Address(a.app_ip): a.app_port, IPv4Address(a.db_ip): a.db_port}
        self.names = {IPv4Address(a.app_ip): "company app", IPv4Address(a.db_ip): "database"}

    def check_source(self, cidr: IPv4Network, where: str) -> None:
        if any(cidr.subnet_of(n) for n in self.nets):
            return
        if self.internal is not None and cidr.subnet_of(self.internal) and any(n.subnet_of(cidr) for n in self.nets):
            return
        allowed = ", ".join(str(n) for n in self.nets)
        raise InvalidRecommendation(
            f"{where}: source {cidr} is outside the lab. Use one of the lab networks ({allowed}), "
            f"an address inside them, or an internal range that contains them.")

    def check_destination(self, ip: IPv4Address, port: int, where: str) -> None:
        if ip not in self.services:
            listed = ", ".join(f"{self.names[k]} {k}" for k in self.services)
            raise InvalidRecommendation(f"{where}: destination {ip} is not a lab service ({listed}).")
        if self.services[ip] != port:
            raise InvalidRecommendation(
                f"{where}: the {self.names[ip]} {ip} listens on port {self.services[ip]}, not {port}.")


_PRIVATE_BLOCKS = [ip_network("10.0.0.0/8"), ip_network("172.16.0.0/12"), ip_network("192.168.0.0/16")]


def _check_narrow(act: NarrowSource, target: FirewallRule, lab: _LabRanges, where: str) -> None:
    lab.check_source(act.source_cidr, where)
    if target.src is None:
        return
    current = ip_network(target.src, strict=False)
    if act.source_cidr == current:
        raise InvalidRecommendation(f"{where}: {act.rule_id} already has source {current}, so this changes nothing.")
    if not act.source_cidr.subnet_of(current):
        raise InvalidRecommendation(
            f"{where}: {act.source_cidr} is not inside {act.rule_id}'s current source {current}; "
            "narrow_source can only make a source smaller.")


# ---------------------------------------------------------------------------
# Rule lookup and numbering
# ---------------------------------------------------------------------------
def _existing(rule_id: str, working: list[FirewallRule], known: set[str], touched: set[str], where: str) -> FirewallRule:
    if rule_id == TEMP_BLOCK:
        raise InvalidRecommendation(f"{where}: the temporary block cannot be changed by a recommendation.")
    if rule_id in touched:
        raise InvalidRecommendation(f"{where}: {rule_id} is changed more than once in the same recommendation.")
    for r in working:
        if r.rule_id == rule_id:
            return r
    if rule_id in known:  # pragma: no cover - only reachable via touched, kept for clarity
        raise InvalidRecommendation(f"{where}: {rule_id} was already removed earlier in this recommendation.")
    raise InvalidRecommendation(f"{where}: rule {rule_id} does not exist in the lab firewall.")


def _place(position: str, working: list[FirewallRule], taken: set[int], where: str) -> tuple[int, int]:
    """Return (insert index in ``working``, new rule number) for a position."""
    if position == "top":
        index = 0
        upper = _num_at(working, 0)
        lower = MIN_RULE_NUM - 1
        prefer_high = True
    else:
        side, ref = position.split(":", 1)
        idx = next((k for k, r in enumerate(working) if r.rule_id == ref), None)
        if idx is None:
            raise InvalidRecommendation(f"{where}: position '{position}' refers to {ref}, which is not in the firewall.")
        if side == "before":
            index = idx
            lower = _num_at(working, idx - 1) if idx > 0 else MIN_RULE_NUM - 1
            upper = _num_at(working, idx)
            prefer_high = True
        else:
            index = idx + 1
            lower = _num_at(working, idx)
            upper = _num_at(working, idx + 1) if idx + 1 < len(working) else MAX_RULE_NUM + 1
            prefer_high = False
    if upper is None:
        upper = MAX_RULE_NUM + 1
    if lower is None:
        lower = MIN_RULE_NUM - 1
    candidates = range(upper - 1, lower, -1) if prefer_high else range(lower + 1, upper)
    for n in candidates:
        if MIN_RULE_NUM <= n <= MAX_RULE_NUM and n not in taken:
            return index, n
    raise InvalidRecommendation(f"{where}: no free rule number fits at position '{position}'.")


def _num(rule_id: str) -> Optional[int]:
    m = _RULE_RE.match(rule_id)
    return int(m.group(1)) if m else None


def _num_at(working: list[FirewallRule], i: int) -> Optional[int]:
    return _num(working[i].rule_id) if 0 <= i < len(working) else None


def _copy_rule(r: FirewallRule) -> FirewallRule:
    return FirewallRule(r.rule_id, r.verdict, r.src, r.dst, r.dport, r.counter)


def _same(a: list[FirewallRule], b: list[FirewallRule]) -> bool:
    key = lambda r: (r.rule_id, r.verdict, r.src, r.dst, r.dport)  # noqa: E731
    return [key(r) for r in a] == [key(r) for r in b]


def _short_errors(e: ValidationError) -> str:
    parts = []
    for err in e.errors()[:3]:
        loc = ".".join(str(x) for x in err.get("loc", ()))
        parts.append(f"{loc}: {err.get('msg')}" if loc else str(err.get("msg")))
    return "; ".join(parts)


__all__ = ["validate", "assign_rule_ids"]
