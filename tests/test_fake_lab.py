"""The fake lab must produce the expected-outcomes table in docs/LAB_INTERFACE.md."""
import pytest
from pydantic import TypeAdapter

from backend.ai.models import Action
from backend.fake_lab import FakeLab

A = TypeAdapter(list[Action])


def acts(*items):
    return A.validate_python(list(items))


def outcomes(lab):
    return lab.check_unauthorized_blocked().passed, lab.check_legitimate_app().passed


def test_baseline_is_vulnerable():
    lab = FakeLab()
    assert outcomes(lab) == (False, True)
    assert lab.run_attack().reached
    assert lab.rule14_counter() == 1


def test_temp_block_stops_attacker_only():
    lab = FakeLab()
    lab.block_on()
    lab.block_on()  # idempotent
    assert sum(r.rule_id == "temp-block" for r in lab.rules()) == 1
    assert outcomes(lab) == (True, True)
    assert not lab.run_attack().reached
    lab.block_off()
    assert not lab.block_active()


@pytest.mark.parametrize("actions,expected", [
    ([{"action": "set_rule_verdict", "rule_id": "rule-14", "verdict": "drop"}], (True, True)),
    ([{"action": "delete_rule", "rule_id": "rule-14"}], (True, True)),
    ([{"action": "delete_rule", "rule_id": "rule-14"},
      {"action": "add_deny", "source_cidr": "10.0.0.0/8", "dest_ip": "10.10.30.10", "dest_port": 5432,
       "position": "before:rule-12", "rule_id": "rule-11"}], (True, False)),
    ([{"action": "delete_rule", "rule_id": "rule-14"},
      {"action": "add_deny", "source_cidr": "10.10.10.0/24", "dest_ip": "10.10.30.10", "dest_port": 5432,
       "position": "after:rule-12", "rule_id": "rule-13"}], (True, True)),
])
def test_expected_outcomes(actions, expected):
    lab = FakeLab()
    lab.apply(acts(*actions))
    assert outcomes(lab) == expected


def test_snapshot_restore_round_trip():
    lab = FakeLab()
    snap = lab.snapshot()
    lab.apply(acts({"action": "delete_rule", "rule_id": "rule-14"}))
    assert outcomes(lab) == (True, True)
    lab.restore(snap)
    assert outcomes(lab) == (False, True)


def test_reset_restores_baseline():
    lab = FakeLab()
    lab.block_on()
    lab.apply(acts({"action": "set_rule_verdict", "rule_id": "rule-14", "verdict": "drop"}))
    lab.reset()
    assert outcomes(lab) == (False, True)
    assert not lab.block_active()
