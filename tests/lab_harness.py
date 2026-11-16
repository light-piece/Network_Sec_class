"""Drives the REAL lab (backend.lab.Lab) through docs/LAB_INTERFACE.md.

Run as root from the repo root, with the lab up (tests/integration.sh does this):
    .venv/bin/python -m tests.lab_harness

Checks the expected-outcomes table, the temporary block, snapshot/restore,
reset, the rule-14 counter, render() templates and the all-or-nothing apply,
and compares every rule list with the reference FakeLab. Stops at the first
failure with a clear message (exit 1). Not collected by pytest.
"""
from __future__ import annotations

import json
import re
import sys
import time
from ipaddress import ip_network

from pydantic import TypeAdapter

from backend.ai.models import Action
from backend.fake_lab import FakeLab
from backend.lab import Lab
from backend.lab_types import FirewallRule, LabError

ACTIONS = TypeAdapter(list[Action])
STEP = 0


def step(title: str) -> None:
    global STEP
    STEP += 1
    print(f"--- harness {STEP}: {title}", flush=True)


def fail(msg: str) -> None:
    print(f"HARNESS FAILED: {msg}", flush=True)
    sys.exit(1)


def expect(cond: bool, msg: str) -> None:
    if not cond:
        fail(msg)


def acts(*items: dict) -> list:
    return ACTIONS.validate_python(list(items))


def norm(rules: list[FirewallRule]) -> list[tuple]:
    """Comparable form: addresses normalised (nft prints a /32 as a bare IP)."""
    def n(x):
        return str(ip_network(x, strict=False)) if x else None
    return [(r.rule_id, r.verdict, n(r.src), n(r.dst), r.dport) for r in rules]


def outcomes(lab: Lab) -> tuple[bool, bool]:
    u, a = lab.check_unauthorized_blocked(), lab.check_legitimate_app()
    print(f"      unauthorized_blocked={u.passed} [{u.output}] · legitimate_app={a.passed} [{a.output}]", flush=True)
    return u.passed, a.passed


def raw_chain_comments(lab: Lab) -> list[str]:
    return [r.comment or "" for r in lab._chain()]  # noqa: SLF001 - test needs the real order incl. est


def raw_handles(lab: Lab) -> str:
    return json.dumps([(r.handle, r.comment) for r in lab._chain()])  # noqa: SLF001


A = "10.10.30.10"
CASES = [
    ("set_rule_verdict rule-14 drop",
     [{"action": "set_rule_verdict", "rule_id": "rule-14", "verdict": "drop"}], (True, True),
     [r"^nft replace rule inet lab forward handle \d+ ip saddr 10\.10\.10\.0/24 ip daddr 10\.10\.30\.10 "
      r"tcp dport 5432 counter drop comment \"rule-14\"$"]),
    ("delete_rule rule-14",
     [{"action": "delete_rule", "rule_id": "rule-14"}], (True, True),
     [r"^nft delete rule inet lab forward handle \d+$"]),
    ("delete_rule rule-14 + add_deny 10.0.0.0/8 before:rule-12 (too broad)",
     [{"action": "delete_rule", "rule_id": "rule-14"},
      {"action": "add_deny", "source_cidr": "10.0.0.0/8", "dest_ip": A, "dest_port": 5432,
       "position": "before:rule-12", "rule_id": "rule-11"}], (True, False),
     [r"^nft delete rule inet lab forward handle \d+$",
      r"^nft insert rule inet lab forward position \d+ ip saddr 10\.0\.0\.0/8 ip daddr 10\.10\.30\.10 "
      r"tcp dport 5432 drop comment \"rule-11\"$"]),
    ("delete_rule rule-14 + add_deny 10.10.10.0/24 after:rule-12",
     [{"action": "delete_rule", "rule_id": "rule-14"},
      {"action": "add_deny", "source_cidr": "10.10.10.0/24", "dest_ip": A, "dest_port": 5432,
       "position": "after:rule-12", "rule_id": "rule-13"}], (True, True),
     [r"^nft delete rule inet lab forward handle \d+$",
      r"^nft add rule inet lab forward position \d+ ip saddr 10\.10\.10\.0/24 ip daddr 10\.10\.30\.10 "
      r"tcp dport 5432 drop comment \"rule-13\"$"]),
    # Beyond the table: the other templates.
    ("narrow_source rule-14 to 10.10.10.128/25 (attacker outside)",
     [{"action": "narrow_source", "rule_id": "rule-14", "source_cidr": "10.10.10.128/25"}], (True, True),
     [r"^nft replace rule inet lab forward handle \d+ ip saddr 10\.10\.10\.128/25 ip daddr 10\.10\.30\.10 "
      r"tcp dport 5432 counter accept comment \"rule-14\"$"]),
    ("add_deny 10.10.10.10/32 at top",
     [{"action": "add_deny", "source_cidr": "10.10.10.10/32", "dest_ip": A, "dest_port": 5432,
       "position": "top", "rule_id": "rule-9"}], (True, True),
     [r"^nft insert rule inet lab forward position \d+ ip saddr 10\.10\.10\.10/32 ip daddr 10\.10\.30\.10 "
      r"tcp dport 5432 drop comment \"rule-9\"$"]),
    ("add_deny 10.10.10.0/24 -> app:8080 before:rule-10 (breaks the app)",
     [{"action": "add_deny", "source_cidr": "10.10.10.0/24", "dest_ip": "10.10.20.10", "dest_port": 8080,
       "position": "before:rule-10", "rule_id": "rule-8"}], (False, False),
     [r"^nft insert rule inet lab forward position \d+ .*tcp dport 8080 drop comment \"rule-8\"$"]),
]


def main() -> None:
    lab = Lab.from_env()
    fake_baseline = FakeLab(lab.addresses)
    t_start = time.monotonic()

    step("health")
    h = lab.health()
    expect(h.up and h.app_ok and h.db_ok, f"lab not healthy: {h}")

    step("reset -> baseline rules, counter 0, no temp-block, est first")
    lab.reset()
    expect(norm(lab.rules()) == norm(fake_baseline.rules()),
           f"baseline rules differ from FakeLab:\n real {norm(lab.rules())}\n fake {norm(fake_baseline.rules())}")
    expect(lab.rule14_counter() == 0, f"counter after reset is {lab.rule14_counter()}, want 0")
    expect(not lab.block_active(), "temp-block present after reset")
    expect(raw_chain_comments(lab)[0] == "est", f"est is not first: {raw_chain_comments(lab)}")

    step("baseline is vulnerable (unauthorized fails, app passes)")
    expect(outcomes(lab) == (False, True), "baseline outcomes wrong, want (False, True)")

    step("attack reaches the db and adds exactly 1 to the rule-14 counter")
    c0 = lab.rule14_counter()
    atk = lab.run_attack()
    print(f"      {atk.output}")
    expect(atk.reached, f"attack did not reach the db on the baseline: {atk}")
    c1 = lab.rule14_counter()
    expect(c1 == c0 + 1, f"rule-14 counter went {c0} -> {c1}, want +1")

    step("temp-block on (twice): above est, attacker blocked, app ok, counter unchanged")
    b = lab.block_on()
    lab.block_on()
    expect(b.rule_id == "temp-block" and b.verdict == "drop", f"block_on returned {b}")
    comments = raw_chain_comments(lab)
    expect(comments.count("temp-block") == 1, f"temp-block count != 1: {comments}")
    expect(comments[:2] == ["temp-block", "est"], f"temp-block not directly above est: {comments}")
    expect(lab.rules()[0].rule_id == "temp-block", "rules() does not list temp-block first")
    expect(lab.block_active(), "block_active() is False after block_on")
    expect(outcomes(lab) == (True, True), "with temp-block want (True, True)")
    c2 = lab.rule14_counter()
    atk = lab.run_attack()
    expect(not atk.reached, f"attack reached the db through temp-block: {atk}")
    expect(lab.rule14_counter() == c2, "rule-14 counted while temp-block was on")

    step("temp-block off (twice) -> vulnerable again")
    lab.block_off()
    lab.block_off()
    expect(not lab.block_active(), "temp-block still present after block_off")
    expect(outcomes(lab) == (False, True), "after block_off want (False, True)")

    for title, items, expected, patterns in CASES:
        step(f"actions: {title} -> want {expected}")
        lab.reset()
        actions = acts(*items)
        snap = lab.snapshot()
        handles_before = raw_handles(lab)
        cmds = lab.render(actions)
        for c in cmds:
            print(f"      {c}")
        expect(raw_handles(lab) == handles_before and lab.snapshot() == snap, "render() changed the firewall")
        expect(len(cmds) == len(patterns), f"render gave {len(cmds)} commands, want {len(patterns)}")
        for c, p in zip(cmds, patterns):
            expect(re.match(p, c) is not None, f"rendered command does not match template:\n {c}\n {p}")
        lab.apply(actions)
        fake = FakeLab(lab.addresses)
        fake.apply(actions)
        expect(norm(lab.rules()) == norm(fake.rules()),
               f"rules differ from FakeLab:\n real {norm(lab.rules())}\n fake {norm(fake.rules())}")
        got = outcomes(lab)
        expect(got == expected, f"outcomes {got}, want {expected}")
        expect(raw_chain_comments(lab)[0] == "est", "est is no longer first")
        step(f"restore snapshot after: {title}")
        lab.restore(snap)
        expect(lab.snapshot() == snap, "restore() did not reproduce the snapshot")
        expect(norm(lab.rules()) == norm(fake_baseline.rules()), "restore did not bring back the baseline rules")
        expect(outcomes(lab) == (False, True), "after restore want (False, True)")

    step("backend flow, scenario B: block, apply wrong fix, lift block, fail, re-block, roll back")
    lab.reset()
    lab.block_on()
    backup = lab.snapshot()
    lab.apply(acts(*CASES[2][1]))
    lab.block_off()
    expect(outcomes(lab) == (True, False), "wrong fix should break the app")
    lab.block_on()
    lab.restore(backup)
    expect(lab.snapshot() == backup and lab.block_active(), "rollback did not restore the contained state")
    expect(outcomes(lab) == (True, True), "contained state after rollback want (True, True)")
    step("backend flow, scenario B retry: correct fix, lift block, both pass")
    lab.apply(acts(*CASES[0][1]))
    lab.block_off()
    expect(outcomes(lab) == (True, True), "correct fix want (True, True)")
    expect(not lab.run_attack().reached, "attacker reached the db after the fix")

    step("apply is all-or-nothing and errors are LabError")
    lab.reset()
    snap = lab.snapshot()
    for bad in (
        [{"action": "delete_rule", "rule_id": "rule-14"}, {"action": "delete_rule", "rule_id": "rule-99"}],
        [{"action": "add_deny", "source_cidr": "10.10.10.0/24", "dest_ip": A, "dest_port": 5432, "position": "top"}],
        [{"action": "add_deny", "source_cidr": "10.10.10.0/24", "dest_ip": A, "dest_port": 5432,
          "position": "after:rule-77", "rule_id": "rule-78"}],
        [{"action": "add_deny", "source_cidr": "10.10.10.0/24", "dest_ip": A, "dest_port": 5432,
          "position": "top", "rule_id": "rule-12"}],
    ):
        try:
            lab.apply(acts(*bad))
        except LabError as exc:
            print(f"      LabError: {exc}")
        else:
            fail(f"apply({bad}) did not raise LabError")
        expect(lab.snapshot() == snap, f"firewall changed after a failed apply({bad})")
    try:
        lab.restore("table ip nat { }")
    except LabError:
        pass
    else:
        fail("restore() accepted a snapshot of another table")

    step("final reset -> baseline, counter 0")
    lab.block_on()
    lab.apply(acts({"action": "delete_rule", "rule_id": "rule-14"}))
    lab.reset()
    expect(norm(lab.rules()) == norm(fake_baseline.rules()), "reset did not restore the baseline")
    expect(lab.rule14_counter() == 0 and not lab.block_active(), "reset left a counter or temp-block")
    expect(outcomes(lab) == (False, True), "after reset want (False, True)")
    lab.reset()

    print(f"HARNESS PASSED ({STEP} steps, {time.monotonic() - t_start:.0f} s)", flush=True)


if __name__ == "__main__":
    try:
        main()
    except LabError as exc:
        fail(f"unexpected LabError: {exc}")
