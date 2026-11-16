"""Static validation of the AI recommendation schema (runs anywhere)."""
import json

import pytest
from pydantic import TypeAdapter, ValidationError

from backend.ai.models import AIRecommendation, Action, AddDeny, ollama_format_schema

TEXT = dict(summary="s", change="c", affects="a", unaffected="u")


def rec(*actions, **extra):
    return AIRecommendation.model_validate({"actions": list(actions), **TEXT, **extra})


def test_correct_fix_is_valid():
    r = rec({"action": "set_rule_verdict", "rule_id": "rule-14", "verdict": "drop"})
    assert r.actions[0].verdict == "drop"


def test_two_step_fix_is_valid():
    r = rec({"action": "delete_rule", "rule_id": "rule-14"},
            {"action": "add_deny", "source_cidr": "10.10.10.0/24", "dest_ip": "10.10.30.10",
             "dest_port": 5432, "position": "after:rule-12"})
    assert isinstance(r.actions[1], AddDeny)


@pytest.mark.parametrize("bad", [
    {"action": "run_shell", "cmd": "rm -rf /"},
    {"action": "delete_rule", "rule_id": "rule-14; nft flush ruleset"},
    {"action": "delete_rule", "rule_id": "$(reboot)"},
    {"action": "set_rule_verdict", "rule_id": "rule-14", "verdict": "jump evil"},
    {"action": "add_deny", "source_cidr": "10.10.10.0/24", "dest_ip": "10.10.30.10", "dest_port": 22, "position": "top"},
    {"action": "add_deny", "source_cidr": "not-a-cidr", "dest_ip": "10.10.30.10", "dest_port": 5432, "position": "top"},
    {"action": "add_deny", "source_cidr": "10.10.10.0/24", "dest_ip": "10.10.30.10", "dest_port": 5432, "position": "bottom; flush"},
    {"action": "delete_rule", "rule_id": "rule-14", "extra": "field"},
])
def test_bad_actions_rejected(bad):
    with pytest.raises(ValidationError):
        rec(bad)


def test_action_count_limits():
    with pytest.raises(ValidationError):
        rec()
    many = [{"action": "delete_rule", "rule_id": f"rule-{n}"} for n in (10, 12, 14, 15)]
    with pytest.raises(ValidationError):
        rec(*many)


def test_unknown_top_level_field_rejected():
    with pytest.raises(ValidationError):
        rec({"action": "delete_rule", "rule_id": "rule-14"}, commands=["nft flush ruleset"])


def test_schema_is_json_serialisable():
    schema = ollama_format_schema()
    assert "actions" in json.dumps(schema)


def test_action_adapter_discriminates():
    a = TypeAdapter(Action).validate_python({"action": "delete_rule", "rule_id": "rule-14"})
    assert a.action == "delete_rule"
