"""Lab validation of AI recommendations (backend/ai/validate.py) and the mock AI. Runs anywhere."""
import pytest
from pydantic import ValidationError

from backend.ai.interface import Feedback, IncidentFacts, InvalidRecommendation
from backend.ai.mock import MockProvider
from backend.ai.models import AddDeny, AIRecommendation, DeleteRule
from backend.ai.validate import validate
from backend.fake_lab import FakeLab, baseline_rules
from backend.lab_types import FirewallRule, LabAddresses

ADDR = LabAddresses()
TEXT = dict(summary="s", change="c", affects="a", unaffected="u")
FACTS = IncidentFacts(source_ip="10.10.10.10", target_ip="10.10.30.10", target_port=5432, matched_rule="rule-14",
                      policy="Only the company app (10.10.20.10) may reach the database (10.10.30.10:5432).")


def rec(*actions, **extra):
    return AIRecommendation.model_validate({"actions": list(actions), **TEXT, **extra})


def base():
    return baseline_rules(ADDR)


def with_block():
    lab = FakeLab()
    lab.block_on()
    return lab.rules()


def deny(src="10.10.10.0/24", dst="10.10.30.10", port=5432, position="after:rule-12", **kw):
    return {"action": "add_deny", "source_cidr": src, "dest_ip": dst, "dest_port": port, "position": position, **kw}


def ids(r):
    return [a.rule_id for a in r.actions]


# ---- accepted ---------------------------------------------------------------
@pytest.mark.parametrize("actions", [
    [{"action": "set_rule_verdict", "rule_id": "rule-14", "verdict": "drop"}],
    [{"action": "delete_rule", "rule_id": "rule-14"}],
    [{"action": "narrow_source", "rule_id": "rule-14", "source_cidr": "10.10.10.128/25"}],
    [{"action": "delete_rule", "rule_id": "rule-14"}, deny()],
    [deny(position="top")],
    [deny(src="10.10.10.10/32", position="top")],
    [deny(src="10.10.0.0/16", position="before:rule-12")],
    [deny(src="10.0.0.0/8", position="before:rule-12")],
    [deny(src="10.10.10.0/24", dst="10.10.20.10", port=8080, position="top")],
])
def test_valid_recommendations_accepted(actions):
    out = validate(rec(*actions), base(), ADDR)
    assert len(out.actions) == len(actions)
    for a in out.actions:
        assert a.rule_id


def test_valid_with_temp_block_present():
    out = validate(rec({"action": "set_rule_verdict", "rule_id": "rule-14", "verdict": "drop"}), with_block(), ADDR)
    assert ids(out) == ["rule-14"]


# ---- rule-id assignment -----------------------------------------------------
@pytest.mark.parametrize("position,expected", [
    ("before:rule-12", "rule-11"),
    ("after:rule-12", "rule-13"),
    ("before:rule-10", "rule-9"),
    ("top", "rule-9"),
    ("after:rule-14", "rule-15"),
])
def test_add_deny_rule_ids_sort_into_position(position, expected):
    out = validate(rec(deny(position=position)), base(), ADDR)
    assert out.actions[0].rule_id == expected


def test_top_ignores_temp_block():
    assert validate(rec(deny(position="top")), with_block(), ADDR).actions[0].rule_id == "rule-9"


def test_rule_id_from_model_is_overwritten():
    out = validate(rec(deny(position="before:rule-12", rule_id="rule-500")), base(), ADDR)
    assert out.actions[0].rule_id == "rule-11"


def test_taken_numbers_are_skipped():
    rules = [FirewallRule("rule-10", "accept", "10.10.10.0/24", "10.10.20.10", 8080),
             FirewallRule("rule-11", "accept", "10.10.20.10", "10.10.30.10", 5432),
             FirewallRule("rule-14", "accept", "10.10.10.0/24", "10.10.30.10", 5432)]
    out = validate(rec(deny(position="before:rule-14")), rules, ADDR)
    assert out.actions[0].rule_id == "rule-13"
    out = validate(rec(deny(position="after:rule-11"), deny(src="10.10.10.10/32", position="before:rule-14")), rules, ADDR)
    assert ids(out) == ["rule-12", "rule-13"]


def test_two_adds_never_collide():
    out = validate(rec({"action": "delete_rule", "rule_id": "rule-14"}, deny(position="after:rule-12"),
                       deny(src="10.10.10.10/32", position="after:rule-10")), base(), ADDR)
    assert ids(out) == ["rule-14", "rule-13", "rule-11"]


def test_same_gap_twice_is_rejected_not_collided():
    with pytest.raises(InvalidRecommendation, match="no free rule number"):
        validate(rec({"action": "delete_rule", "rule_id": "rule-14"}, deny(position="after:rule-12"),
                     deny(src="10.10.10.10/32", position="after:rule-12")), base(), ADDR)


def test_deleted_number_not_reused():
    rules = base()[:2] + [FirewallRule("rule-13", "accept", "10.10.20.10", "10.10.20.10", 8080)] + base()[2:]
    out = validate(rec({"action": "delete_rule", "rule_id": "rule-14"}, deny(position="after:rule-13")), rules, ADDR)
    assert ids(out) == ["rule-14", "rule-15"]


def test_no_free_number_is_rejected():
    rules = [FirewallRule("rule-11", "accept", "10.10.10.0/24", "10.10.20.10", 8080),
             FirewallRule("rule-12", "accept", "10.10.20.10", "10.10.30.10", 5432)]
    with pytest.raises(InvalidRecommendation, match="no free rule number"):
        validate(rec(deny(position="before:rule-12")), rules, ADDR)


def test_input_is_not_mutated():
    original = rec({"action": "delete_rule", "rule_id": "rule-14"}, deny())
    before = original.model_dump()
    rules = base()
    out = validate(original, rules, ADDR)
    assert original.model_dump() == before
    assert original.actions[1].rule_id is None
    assert out is not original and out.actions[1].rule_id == "rule-13"
    assert rules == base()


# ---- rejected ---------------------------------------------------------------
@pytest.mark.parametrize("actions,match", [
    ([{"action": "delete_rule", "rule_id": "rule-99"}], "does not exist"),
    ([{"action": "set_rule_verdict", "rule_id": "rule-15", "verdict": "drop"}], "does not exist"),
    ([{"action": "set_rule_verdict", "rule_id": "rule-14", "verdict": "accept"}], "changes nothing"),
    ([{"action": "narrow_source", "rule_id": "rule-14", "source_cidr": "10.10.10.0/24"}], "changes nothing"),
    ([{"action": "narrow_source", "rule_id": "rule-14", "source_cidr": "10.10.0.0/16"}], "not inside"),
    ([{"action": "narrow_source", "rule_id": "rule-14", "source_cidr": "10.10.20.0/24"}], "not inside"),
    ([{"action": "delete_rule", "rule_id": "rule-14"}, {"action": "delete_rule", "rule_id": "rule-14"}], "more than once"),
    ([{"action": "set_rule_verdict", "rule_id": "rule-14", "verdict": "drop"},
      {"action": "delete_rule", "rule_id": "rule-14"}], "more than once"),
    ([{"action": "delete_rule", "rule_id": "rule-12"}, deny(position="after:rule-12")], "not in the firewall"),
    ([deny(position="before:rule-13")], "not in the firewall"),
    ([deny(src="192.168.1.0/24")], "outside the lab"),
    ([deny(src="0.0.0.0/0")], "outside the lab"),
    ([deny(src="10.10.40.0/24")], "outside the lab"),
    ([deny(src="172.16.0.0/12")], "outside the lab"),
    ([deny(dst="10.10.30.11")], "not a lab service"),
    ([deny(dst="8.8.8.8")], "not a lab service"),
    ([deny(dst="10.10.30.10", port=8080)], "listens on port 5432"),
    ([deny(dst="10.10.20.10", port=5432)], "listens on port 8080"),
])
def test_invalid_recommendations_rejected(actions, match):
    with pytest.raises(InvalidRecommendation, match=match):
        validate(rec(*actions), base(), ADDR)


def test_temp_block_cannot_be_touched():
    r = AIRecommendation.model_construct(actions=[DeleteRule.model_construct(action="delete_rule", rule_id="temp-block")],
                                         **TEXT, what_changed="")
    with pytest.raises(InvalidRecommendation):
        validate(r, with_block(), ADDR)


def test_bypassing_schema_with_model_construct_is_caught():
    bad = AddDeny.model_construct(action="add_deny", source_cidr="10.10.10.0/24; nft flush ruleset",
                                  dest_ip="10.10.30.10", dest_port=5432, position="top", rule_id=None)
    r = AIRecommendation.model_construct(actions=[bad], **TEXT, what_changed="")
    with pytest.raises(InvalidRecommendation, match="schema"):
        validate(r, base(), ADDR)


SHELL = ["rule-14; nft flush ruleset", "$(reboot)", "`id`", "rule-14 && rm -rf /", "rule-14|sh",
         "10.10.10.0/24; rm -rf /", "after:rule-12; reboot", "top\nflush ruleset", "../../etc/passwd"]


@pytest.mark.parametrize("s", SHELL)
def test_shell_looking_strings_never_pass(s):
    candidates = [
        {"action": "delete_rule", "rule_id": s},
        {"action": "set_rule_verdict", "rule_id": "rule-14", "verdict": s},
        {"action": "narrow_source", "rule_id": "rule-14", "source_cidr": s},
        deny(src=s), deny(dst=s), deny(position=s), deny(rule_id=s),
    ]
    for c in candidates:
        with pytest.raises((ValidationError, InvalidRecommendation)):
            validate(rec(c), base(), ADDR)
        # Same strings smuggled past the schema with model_construct.
        with pytest.raises(InvalidRecommendation):
            validate(AIRecommendation.model_construct(actions=[_construct(c)], **TEXT, what_changed=""), base(), ADDR)


def _construct(d):
    from backend.ai.models import NarrowSource, SetRuleVerdict
    cls = {"delete_rule": DeleteRule, "set_rule_verdict": SetRuleVerdict,
           "narrow_source": NarrowSource, "add_deny": AddDeny}[d["action"]]
    return cls.model_construct(**d)


def test_validated_actions_only_contain_typed_values():
    out = validate(rec({"action": "delete_rule", "rule_id": "rule-14"}, deny()), base(), ADDR)
    lab = FakeLab()
    assert lab.render(out.actions) == ["(fake) delete rule-14",
                                       "(fake) add rule-13 drop 10.10.10.0/24 -> 10.10.30.10:5432 at after:rule-12"]


# ---- mock AI ----------------------------------------------------------------
def _run(lab, r):
    v = validate(r, lab.rules(), lab.addresses)
    lab.apply(v.actions)
    return lab.check_unauthorized_blocked().passed, lab.check_legitimate_app().passed


def test_mock_scenario_a_sequence():
    p = MockProvider("A")
    assert p.model_name == "Mock AI (scenario A)"
    good = p.recommend(FACTS, base(), None, 1)
    assert [a.model_dump(exclude_none=True) for a in good.actions] == [
        {"action": "set_rule_verdict", "rule_id": "rule-14", "verdict": "drop"}]
    assert good.what_changed == ""
    alt = p.recommend(FACTS, base(), Feedback("rejected", 1), 2)
    assert [a.model_dump(exclude_none=True) for a in alt.actions] == [{"action": "delete_rule", "rule_id": "rule-14"}]
    assert "#99" in alt.what_changed
    # deterministic
    assert p.recommend(FACTS, base(), None, 1) == good


def test_mock_scenario_b_sequence():
    p = MockProvider("b")
    assert p.model_name == "Mock AI (scenario B)"
    flawed = p.recommend(FACTS, base(), None, 1)
    assert flawed.actions[0].rule_id == "rule-14"
    assert str(flawed.actions[1].source_cidr) == "10.0.0.0/8" and flawed.actions[1].position == "before:rule-12"
    assert "rule #11" in flawed.change
    fixed = p.recommend(FACTS, base(), Feedback("failed", 1, "“Company application still works” failed: …"), 2)
    assert str(fixed.actions[1].source_cidr) == "10.10.10.0/24" and fixed.actions[1].position == "after:rule-12"
    assert "rule #13" in fixed.change and "10.0.0.0/8" in fixed.what_changed


def test_mock_text_uses_lab_addresses():
    for sc in "AB":
        p = MockProvider(sc)
        for fb, att in ((None, 1), (Feedback("failed", 1, "x"), 2)):
            r = p.recommend(FACTS, base(), fb, att)
            text = " ".join([r.summary, r.change, r.affects, r.unaffected, r.what_changed])
            assert "10.20.0" not in text and "WS-FIN" not in text and "DB-PRIMARY" not in text
            assert "10.10.30.10" in r.change


@pytest.mark.parametrize("scenario,feedback,attempt,expected", [
    ("A", None, 1, (True, True)),                                # good
    ("A", Feedback("rejected", 1), 2, (True, True)),            # alt
    ("B", None, 1, (True, False)),                               # flawed breaks the app
    ("B", Feedback("failed", 1, "app failed"), 2, (True, True)),  # fixed
])
def test_mock_recommendations_give_expected_outcomes(scenario, feedback, attempt, expected):
    lab = FakeLab()
    r = MockProvider(scenario).recommend(FACTS, lab.rules(), feedback, attempt)
    assert _run(lab, r) == expected


def test_mock_recommendations_validate_with_containment_on():
    """The backend asks for a recommendation while the temporary block is on."""
    for sc in "AB":
        lab = FakeLab()
        lab.block_on()
        r = MockProvider(sc).recommend(FACTS, lab.rules(), None, 1)
        v = validate(r, lab.rules(), lab.addresses)
        lab.apply(v.actions)
        lab.block_off()
        assert lab.check_unauthorized_blocked().passed


def test_mock_rejects_unknown_scenario():
    with pytest.raises(ValueError):
        MockProvider("C")


def test_factory():
    from backend.ai.factory import get_provider
    from backend.ai.ollama import OllamaProvider
    assert get_provider("mock", "B", "http://x:11434", "qwen3:4b", 120).model_name == "Mock AI (scenario B)"
    p = get_provider("ollama", "A", "http://x:11434/", "qwen3:4b", 30)
    assert isinstance(p, OllamaProvider) and p.model_name == "qwen3:4b via Ollama" and p.timeout == 30
    with pytest.raises(ValueError):
        get_provider("gpt", "A", "", "", 1)
