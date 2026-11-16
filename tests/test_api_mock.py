"""API tests against FakeLab and a fixed stand-in AI (no Linux, no Ollama).

Flows follow the call order in dashboard/js/workflow.js; every response is
checked against the shapes in docs/API_CONTRACT.md.
"""
from __future__ import annotations

import re
import threading
import time

import pytest
from fastapi.testclient import TestClient
from pydantic import ValidationError

from backend.ai.interface import AIUnavailable, InvalidRecommendation
from backend.ai.models import AIRecommendation
from backend.config import Settings
from backend.fake_lab import FakeLab
from backend.lab_types import LabError
from backend.main import create_app

CHECKS = ["unauthorized_blocked", "legitimate_app"]
TEXT = dict(summary="s", change="c", affects="a", unaffected="u")

# The dashboard's four mock recommendations (mock-service.js REC_LIBRARY), as AI actions.
LIBRARY = {
    "good": [{"action": "set_rule_verdict", "rule_id": "rule-14", "verdict": "drop"}],
    "alt": [{"action": "delete_rule", "rule_id": "rule-14"}],
    "flawed": [{"action": "delete_rule", "rule_id": "rule-14"},
               {"action": "add_deny", "source_cidr": "10.0.0.0/8", "dest_ip": "10.10.30.10",
                "dest_port": 5432, "position": "before:rule-12"}],
    "fixed": [{"action": "delete_rule", "rule_id": "rule-14"},
              {"action": "add_deny", "source_cidr": "10.10.10.0/24", "dest_ip": "10.10.30.10",
               "dest_port": 5432, "position": "after:rule-12"}],
}


def ai_rec(key: str) -> AIRecommendation:
    return AIRecommendation.model_validate({
        "actions": LIBRARY[key], "summary": f"{key} summary", "change": f"{key} change",
        "affects": "Employee network", "unaffected": "Company app",
        "what_changed": "" if key in ("good", "flawed") else f"{key} differs",
    })


class FixedAI:
    """Returns the given items in order (the last one repeats). Items are library keys or exceptions."""

    def __init__(self, *items, name="Mock AI (test)"):
        self.items = list(items)
        self.model_name = name
        self.calls = []

    def recommend(self, facts, rules, feedback, attempt):
        self.calls.append((feedback, attempt))
        item = self.items[min(len(self.calls) - 1, len(self.items) - 1)]
        if isinstance(item, Exception):
            raise item
        return ai_rec(item)


def settings(**kw) -> Settings:
    base = dict(_env_file=None, LAB_MODE="fake", AI_MODE="mock", POLL_INTERVAL_SECONDS=0.02,
                LONGPOLL_TIMEOUT_SECONDS=3)
    base.update(kw)
    return Settings(**base)


@pytest.fixture
def make_client():
    clients = []

    def _make(*items, lab=None, **kw):
        s = settings(**kw)
        lab = lab or FakeLab(s.lab_addresses())
        ai = FixedAI(*items)
        client = TestClient(create_app(settings=s, lab=lab, provider=ai))
        client.__enter__()
        clients.append(client)
        client.lab, client.ai = lab, ai
        return client

    yield _make
    for c in clients:
        c.__exit__(None, None, None)


# ---- shape checks (docs/API_CONTRACT.md) ------------------------------------------------
def keys(obj, expected):
    assert set(obj) == set(expected), f"keys {sorted(obj)} != {sorted(expected)}"


def check_host(h):
    keys(h, ["name", "role", "ip", "segment"])
    assert all(isinstance(v, str) for v in h.values())


def check_incident(inc):
    keys(inc, ["id", "detectedAt", "source", "target", "app", "connection", "policy"])
    assert re.fullmatch(r"INC-\d{4}-\d{4}", inc["id"])
    assert isinstance(inc["detectedAt"], int) and inc["detectedAt"] > 1_600_000_000_000
    for h in ("source", "target", "app"):
        check_host(inc[h])
    assert inc["source"] == {"name": "Employee workstation", "role": "Employee workstation",
                             "ip": "10.10.10.10", "segment": "Employee network 10.10.10.0/24"}
    assert inc["target"]["name"] == "Company database" and inc["target"]["ip"] == "10.10.30.10"
    assert inc["app"]["name"] == "Company app" and inc["app"]["ip"] == "10.10.20.10"
    keys(inc["connection"], ["protocol", "srcPort", "dstPort", "service", "observedBy"])
    assert inc["connection"]["protocol"] == "TCP" and inc["connection"]["srcPort"] is None
    assert inc["connection"]["dstPort"] == 5432 and inc["connection"]["service"] == "PostgreSQL"
    assert inc["connection"]["observedBy"] == "Firewall rule counter (rule-14)"
    assert inc["policy"] == {"ruleId": "14", "ruleText": "allow 10.10.10.0/24 → 10.10.30.10 tcp/5432",
                             "intendedPath": "Employee → company application → database"}


def check_containment_active(c):
    assert c == {"status": "active", "ruleId": "T-1", "ruleText": "deny 10.10.10.10 → 10.10.30.10 tcp/5432"}


def check_rule(r):
    keys(r, ["num", "action", "src", "dst", "port", "note", "change"])
    assert all(isinstance(v, str) for v in r.values())
    assert r["action"] in ("allow", "deny")
    assert r["change"] in ("unchanged", "added", "removed")


def check_rec(rec, version, feedback=None):
    keys(rec, ["id", "version", "model", "summary", "change", "affects", "unaffected", "before", "after",
               "commands", "whatChanged", "revisedBecause", "previousVersion", "previousFailure", "failDetail"])
    assert rec["id"] == f"REC-{version}" and rec["version"] == version
    for k in ("model", "summary", "change", "affects", "unaffected", "whatChanged"):
        assert isinstance(rec[k], str)
    assert rec["model"] == "Mock AI (test)"
    for r in rec["before"] + rec["after"]:
        check_rule(r)
    assert rec["before"][-1] == rec["after"][-1] == {
        "num": "99", "action": "deny", "src": "any", "dst": "any", "port": "any",
        "note": "Default deny", "change": "unchanged"}
    assert all(r["change"] != "added" for r in rec["before"])
    assert all(r["change"] != "removed" for r in rec["after"])
    assert isinstance(rec["commands"], list) and rec["commands"] and all(isinstance(c, str) for c in rec["commands"])
    assert rec["failDetail"] is None
    if feedback is None:
        assert rec["whatChanged"] == ""
        assert rec["revisedBecause"] is None and rec["previousVersion"] is None and rec["previousFailure"] is None
    else:
        assert rec["revisedBecause"] == feedback["type"]
        assert rec["previousVersion"] == feedback["version"]
        assert rec["previousFailure"] == (feedback.get("summary") if feedback["type"] == "failed" else None)


def check_result(r, check_id, status):
    keys(r, ["id", "status", "detail", "evidence"])
    assert r["id"] == check_id and r["status"] == status
    assert isinstance(r["detail"], str) and r["detail"]
    assert isinstance(r["evidence"], str) and r["evidence"]


def check_error(resp, status):
    assert resp.status_code == status, resp.text
    body = resp.json()
    keys(body, ["detail"])
    assert isinstance(body["detail"], str) and body["detail"]
    return body["detail"]


def nums(rows):
    return [r["num"] for r in rows]


# ---- flow helpers (same calls, same order as workflow.js) ------------------------------
def start(c):
    """Run attack, then workflow.start(): getActiveIncident -> activateContainment -> requestRecommendation."""
    attack = c.post("/api/lab/attack")
    assert attack.status_code == 200 and attack.json() == {"started": True, "reached": True}
    r = c.get("/api/incidents/active")
    assert r.status_code == 200, r.text
    inc = r.json()
    check_incident(inc)
    r = c.post(f"/api/incidents/{inc['id']}/containment")
    assert r.status_code == 200
    check_containment_active(r.json())
    r = c.post(f"/api/incidents/{inc['id']}/recommendations", json={"feedback": None})
    assert r.status_code == 200, r.text
    rec = r.json()
    check_rec(rec, 1)
    return inc["id"], rec


def approve_and_verify(c, inc_id, rec):
    """workflow.approve(): decision -> correction -> lift containment -> both checks."""
    r = c.post(f"/api/recommendations/{rec['id']}/decision", json={"decision": "approved"})
    assert r.status_code == 200 and r.json() == {"recId": rec["id"], "decision": "approved"}
    r = c.post(f"/api/incidents/{inc_id}/corrections", json={"recommendationId": rec["id"]})
    assert r.status_code == 200 and r.json() == {"status": "applied", "recId": rec["id"]}
    r = c.delete(f"/api/incidents/{inc_id}/containment")
    assert r.status_code == 200 and r.json() == {"status": "lifted"}
    results = {}
    for check_id in CHECKS:
        r = c.post(f"/api/incidents/{inc_id}/verifications/{check_id}", json={"recommendationId": rec["id"]})
        assert r.status_code == 200, r.text
        results[check_id] = r.json()
    return results


def recover(c, inc_id, rec):
    """Failure path: restoreContainment -> rollbackCorrection."""
    r = c.post(f"/api/incidents/{inc_id}/containment")
    assert r.status_code == 200
    check_containment_active(r.json())
    r = c.post(f"/api/incidents/{inc_id}/corrections/{rec['id']}/rollback")
    assert r.status_code == 200 and r.json() == {"status": "rolled_back", "recId": rec["id"]}


# ---- scenarios ---------------------------------------------------------------------------
def test_scenario_a_fix_works(make_client):
    c = make_client("good", "alt")
    inc_id, rec = start(c)
    assert nums(rec["before"]) == ["10", "12", "14", "99"]
    assert [r["change"] for r in rec["before"]] == ["unchanged", "unchanged", "removed", "unchanged"]
    assert rec["before"][2] == {"num": "14", "action": "allow", "src": "Employee network", "dst": "Company database",
                                "port": "tcp/5432", "note": "Misconfigured", "change": "removed"}
    assert rec["before"][0]["dst"] == "Company app" and rec["before"][1]["src"] == "Company app"
    assert nums(rec["after"]) == ["10", "12", "14", "99"]
    assert rec["after"][2]["action"] == "deny" and rec["after"][2]["change"] == "added"

    results = approve_and_verify(c, inc_id, rec)
    check_result(results["unauthorized_blocked"], "unauthorized_blocked", "passed")
    check_result(results["legitimate_app"], "legitimate_app", "passed")
    assert "pg_isready" in results["unauthorized_blocked"]["evidence"]
    assert "HTTP 200" in results["legitimate_app"]["evidence"]

    # Resolved: no longer the active incident; permanent fix in place, no temp block.
    assert c.get("/api/status").json()["incident"] is None
    assert not c.lab.block_active()
    assert [r.rule_id for r in c.lab.rules()] == ["rule-10", "rule-12", "rule-14"]
    assert c.lab.rules()[2].verdict == "drop"


def test_scenario_b_first_fix_fails_then_fixed(make_client):
    c = make_client("flawed", "fixed")
    inc_id, rec1 = start(c)
    assert nums(rec1["after"]) == ["10", "11", "12", "99"]
    added = rec1["after"][1]
    assert added == {"num": "11", "action": "deny", "src": "10.0.0.0/8", "dst": "Company database",
                     "port": "tcp/5432", "note": "New", "change": "added"}

    results = approve_and_verify(c, inc_id, rec1)
    check_result(results["unauthorized_blocked"], "unauthorized_blocked", "passed")
    check_result(results["legitimate_app"], "legitimate_app", "failed")
    assert "rule-11" in results["legitimate_app"]["evidence"]

    # failDetail is set on the stored recommendation.
    st = c.app.state.workflow.incidents[inc_id]
    fail_detail = st.recs["REC-1"].rec.fail_detail
    assert fail_detail and "version 1" in fail_detail and "rule-11" in fail_detail
    assert st.status == "open"

    recover(c, inc_id, rec1)
    assert c.lab.block_active()
    assert [r.rule_id for r in c.lab.rules()] == ["temp-block", "rule-10", "rule-12", "rule-14"]

    summary = "“Company application still works” failed: " + fail_detail
    fb = {"type": "failed", "version": 1, "summary": summary}
    r = c.post(f"/api/incidents/{inc_id}/recommendations", json={"feedback": fb})
    assert r.status_code == 200, r.text
    rec2 = r.json()
    check_rec(rec2, 2, fb)
    assert rec2["whatChanged"] == "fixed differs"
    assert nums(rec2["after"]) == ["10", "12", "13", "99"]
    assert rec2["after"][2]["src"] == "Employee network" and rec2["after"][2]["change"] == "added"
    # The AI received the feedback and the attempt number.
    fb_seen, attempt = c.ai.calls[-1]
    assert attempt == 2 and fb_seen.type == "failed" and fb_seen.version == 1 and fb_seen.summary == summary

    results = approve_and_verify(c, inc_id, rec2)
    assert all(results[k]["status"] == "passed" for k in CHECKS)
    assert c.get("/api/status").json()["incident"] is None


def test_reject_path(make_client):
    c = make_client("good", "alt")
    inc_id, rec1 = start(c)
    r = c.post(f"/api/recommendations/{rec1['id']}/decision", json={"decision": "rejected"})
    assert r.status_code == 200 and r.json() == {"recId": "REC-1", "decision": "rejected"}
    # A rejected recommendation cannot be applied.
    check_error(c.post(f"/api/incidents/{inc_id}/corrections", json={"recommendationId": "REC-1"}), 409)

    fb = {"type": "rejected", "version": 1}
    r = c.post(f"/api/incidents/{inc_id}/recommendations", json={"feedback": fb})
    assert r.status_code == 200
    rec2 = r.json()
    check_rec(rec2, 2, fb)
    assert rec2["whatChanged"] == "alt differs"
    assert nums(rec2["after"]) == ["10", "12", "99"]
    assert c.ai.calls[-1][0].type == "rejected"

    results = approve_and_verify(c, inc_id, rec2)
    assert all(results[k]["status"] == "passed" for k in CHECKS)


# ---- long-poll ---------------------------------------------------------------------------
def test_long_poll_404_when_nothing_happens(make_client):
    c = make_client("good", LONGPOLL_TIMEOUT_SECONDS=0.3)
    t0 = time.monotonic()
    detail = check_error(c.get("/api/incidents/active"), 404)
    assert detail == "No unauthorized connection detected."
    assert time.monotonic() - t0 >= 0.25


def test_long_poll_returns_when_attack_happens_during_wait(make_client):
    c = make_client("good", LONGPOLL_TIMEOUT_SECONDS=5)
    out = {}
    t = threading.Thread(target=lambda: out.setdefault("r", c.get("/api/incidents/active")))
    t.start()
    time.sleep(0.2)
    assert c.post("/api/lab/attack").status_code == 200
    t.join(5)
    assert out["r"].status_code == 200
    check_incident(out["r"].json())


def test_counter_already_raised_at_startup_is_not_an_incident(make_client):
    lab = FakeLab()
    lab.run_attack()  # e.g. setup_lab.sh's self-check
    c = make_client("good", lab=lab, LONGPOLL_TIMEOUT_SECONDS=0.2)
    check_error(c.get("/api/incidents/active"), 404)


def test_second_attack_while_open_keeps_one_incident(make_client):
    c = make_client("good")
    inc_id, _ = start(c)
    c.delete(f"/api/incidents/{inc_id}/containment")
    assert c.post("/api/lab/attack").json()["reached"] is True
    time.sleep(0.1)
    assert c.get("/api/incidents/active").json()["id"] == inc_id
    assert len(c.app.state.workflow.incidents) == 1


# ---- 409 / 404 / 502 / 500 --------------------------------------------------------------
def test_conflicts(make_client):
    c = make_client("good", "alt")
    inc_id, rec = start(c)
    # Not approved yet.
    check_error(c.post(f"/api/incidents/{inc_id}/corrections", json={"recommendationId": "REC-1"}), 409)
    # Never applied: rollback and verification are conflicts.
    check_error(c.post(f"/api/incidents/{inc_id}/corrections/REC-1/rollback"), 409)
    check_error(c.post(f"/api/incidents/{inc_id}/verifications/legitimate_app",
                       json={"recommendationId": "REC-1"}), 409)
    c.post("/api/recommendations/REC-1/decision", json={"decision": "approved"})
    assert c.post(f"/api/incidents/{inc_id}/corrections", json={"recommendationId": "REC-1"}).status_code == 200
    # Already applied.
    check_error(c.post(f"/api/incidents/{inc_id}/corrections", json={"recommendationId": "REC-1"}), 409)
    # New recommendation while one is applied.
    check_error(c.post(f"/api/incidents/{inc_id}/recommendations", json={"feedback": None}), 409)
    # Changing the decision of an applied recommendation.
    check_error(c.post("/api/recommendations/REC-1/decision", json={"decision": "rejected"}), 409)
    # Rollback is fine and idempotent.
    for _ in range(2):
        r = c.post(f"/api/incidents/{inc_id}/corrections/REC-1/rollback")
        assert r.json() == {"status": "rolled_back", "recId": "REC-1"}


def test_not_found(make_client):
    c = make_client("good")
    inc_id, _ = start(c)
    check_error(c.post("/api/incidents/INC-1999-0001/containment"), 404)
    check_error(c.delete("/api/incidents/INC-1999-0001/containment"), 404)
    check_error(c.post("/api/incidents/INC-1999-0001/recommendations", json={"feedback": None}), 404)
    check_error(c.post("/api/recommendations/REC-9/decision", json={"decision": "approved"}), 404)
    check_error(c.post(f"/api/incidents/{inc_id}/corrections", json={"recommendationId": "REC-9"}), 404)
    check_error(c.post(f"/api/incidents/{inc_id}/corrections/REC-9/rollback"), 404)
    check_error(c.post(f"/api/incidents/{inc_id}/verifications/port_scan", json={"recommendationId": "REC-1"}), 404)
    check_error(c.post(f"/api/incidents/{inc_id}/verifications/legitimate_app",
                       json={"recommendationId": "REC-9"}), 404)


def test_invalid_bodies_are_422(make_client):
    c = make_client("good")
    inc_id, _ = start(c)
    assert c.post("/api/recommendations/REC-1/decision", json={"decision": "maybe"}).status_code == 422
    assert c.post(f"/api/incidents/{inc_id}/corrections", json={}).status_code == 422
    assert c.post(f"/api/incidents/{inc_id}/recommendations",
                  json={"feedback": {"type": "bored", "version": 1}}).status_code == 422


def test_containment_is_idempotent(make_client):
    c = make_client("good")
    inc_id, _ = start(c)
    check_containment_active(c.post(f"/api/incidents/{inc_id}/containment").json())
    assert sum(r.rule_id == "temp-block" for r in c.lab.rules()) == 1
    for _ in range(2):
        assert c.delete(f"/api/incidents/{inc_id}/containment").json() == {"status": "lifted"}
    assert not c.lab.block_active()


def test_502_when_ai_unavailable(make_client):
    c = make_client(AIUnavailable("Ollama at http://x:11434 did not answer within 120 s."))
    c.post("/api/lab/attack")
    inc_id = c.get("/api/incidents/active").json()["id"]
    detail = check_error(c.post(f"/api/incidents/{inc_id}/recommendations", json={"feedback": None}), 502)
    assert "did not answer" in detail
    assert len(c.ai.calls) == 1  # no retry on unavailability
    assert c.app.state.workflow.incidents[inc_id].recs == {}


def test_invalid_recommendation_retried_once(make_client):
    c = make_client(InvalidRecommendation("bad JSON"), "good")
    c.post("/api/lab/attack")
    inc_id = c.get("/api/incidents/active").json()["id"]
    r = c.post(f"/api/incidents/{inc_id}/recommendations", json={"feedback": None})
    assert r.status_code == 200
    check_rec(r.json(), 1)
    assert len(c.ai.calls) == 2


def test_502_when_invalid_twice(make_client):
    c = make_client(InvalidRecommendation("rule-77 does not exist"))
    c.post("/api/lab/attack")
    inc_id = c.get("/api/incidents/active").json()["id"]
    detail = check_error(c.post(f"/api/incidents/{inc_id}/recommendations", json={"feedback": None}), 502)
    assert "invalid" in detail and "rule-77" in detail
    assert len(c.ai.calls) == 2


def test_502_when_actions_do_not_fit_the_firewall(make_client):
    c = make_client("alt")
    c.post("/api/lab/attack")
    inc_id = c.get("/api/incidents/active").json()["id"]
    c.lab.apply(ai_rec("alt").actions)  # rule-14 is already gone, so deleting it again fails the dry run
    check_error(c.post(f"/api/incidents/{inc_id}/recommendations", json={"feedback": None}), 502)


def test_max_attempts(make_client):
    c = make_client("good", "alt", MAX_ATTEMPTS=2)
    inc_id, rec1 = start(c)
    c.post("/api/recommendations/REC-1/decision", json={"decision": "rejected"})
    r = c.post(f"/api/incidents/{inc_id}/recommendations", json={"feedback": {"type": "rejected", "version": 1}})
    assert r.status_code == 200
    c.post("/api/recommendations/REC-2/decision", json={"decision": "rejected"})
    detail = check_error(c.post(f"/api/incidents/{inc_id}/recommendations",
                                json={"feedback": {"type": "rejected", "version": 2}}), 409)
    assert "maximum" in detail
    assert len(c.ai.calls) == 2


class BrokenApplyLab(FakeLab):
    def apply(self, actions):
        super().apply(actions[:1])
        raise LabError("nft: Could not process rule: No such file or directory")


def test_500_when_lab_command_fails_and_table_is_restored(make_client):
    lab = BrokenApplyLab()
    c = make_client("flawed", lab=lab)
    inc_id, rec = start(c)
    c.post("/api/recommendations/REC-1/decision", json={"decision": "approved"})
    detail = check_error(c.post(f"/api/incidents/{inc_id}/corrections", json={"recommendationId": "REC-1"}), 500)
    assert "Could not process rule" in detail
    assert [r.rule_id for r in lab.rules()] == ["temp-block", "rule-10", "rule-12", "rule-14"]


# ---- status / attack / reset / static ------------------------------------------------------
def test_status(make_client):
    c = make_client("good")
    r = c.get("/api/status")
    assert r.status_code == 200
    body = r.json()
    keys(body, ["backend", "lab", "app", "database", "aiMode", "aiModel", "aiReachable", "incident"])
    assert body == {"backend": "ok", "lab": "up", "app": "ok", "database": "ok", "aiMode": "mock",
                    "aiModel": "Mock AI (test)", "aiReachable": True, "incident": None}
    inc_id, _ = start(c)
    assert c.get("/api/status").json()["incident"] == inc_id
    c.lab.up = False
    body = c.get("/api/status").json()
    assert (body["lab"], body["app"], body["database"]) == ("down", "error", "error")


def test_attack_blocked_while_contained(make_client):
    c = make_client("good")
    inc_id, _ = start(c)
    assert c.post("/api/lab/attack").json() == {"started": True, "reached": False}


def test_reset_clears_state(make_client):
    c = make_client("flawed")
    inc_id, rec = start(c)
    c.post("/api/recommendations/REC-1/decision", json={"decision": "approved"})
    c.post(f"/api/incidents/{inc_id}/corrections", json={"recommendationId": "REC-1"})
    r = c.post("/api/lab/reset")
    assert r.status_code == 200 and r.json() == {"status": "reset"}
    assert c.get("/api/status").json()["incident"] is None
    assert c.app.state.workflow.incidents == {}
    assert [r.rule_id for r in c.lab.rules()] == ["rule-10", "rule-12", "rule-14"]
    assert c.lab.rule14_counter() == 0
    check_error(c.post(f"/api/incidents/{inc_id}/containment"), 404)
    check_error(c.post("/api/recommendations/REC-1/decision", json={"decision": "approved"}), 404)
    # The next attack opens a new incident, and REC numbering starts again.
    inc2, rec2 = start(c)
    assert inc2 != inc_id and rec2["id"] == "REC-1"


def test_static_dashboard(make_client):
    c = make_client("good")
    r = c.get("/")
    assert r.status_code == 200 and "text/html" in r.headers["content-type"]
    assert "Threat Containment Console" in r.text
    assert c.get("/css/styles.css").status_code == 200
    for name in ("api-service.js", "workflow.js", "config.js"):
        assert c.get(f"/js/{name}").status_code == 200


# ---- config ----------------------------------------------------------------------------------
def test_settings_defaults_and_validation():
    s = Settings(_env_file=None)
    assert (s.APP_PORT, s.AI_MODE, s.MOCK_AI_SCENARIO, s.MAX_ATTEMPTS, s.LAB_MODE) == (8000, "mock", "A", 3, "real")
    a = s.lab_addresses()
    assert (a.app_net, a.db_net, a.app_port, a.db_port) == ("10.10.20.0/24", "10.10.30.0/24", 8080, 5432)
    assert s.DASHBOARD_DIR.joinpath("index.html").is_file()
    for bad in ({"EMPLOYEE_IP": "10.10.20.5"}, {"AI_MODE": "gpt"}, {"DB_IP": "not-an-ip"},
                {"MAX_ATTEMPTS": 0}, {"LAB_MODE": "virtual"}, {"OLLAMA_URL": "ftp://x"}):
        with pytest.raises(ValidationError):
            Settings(_env_file=None, **bad)


def test_settings_read_env(monkeypatch):
    monkeypatch.setenv("MOCK_AI_SCENARIO", "b")
    monkeypatch.setenv("POLL_INTERVAL_SECONDS", "0.5")
    monkeypatch.setenv("DB_IP", "10.10.31.10")
    s = Settings(_env_file=None)
    assert s.MOCK_AI_SCENARIO == "B" and s.POLL_INTERVAL_SECONDS == 0.5
    assert s.lab_addresses().db_net == "10.10.31.0/24"
