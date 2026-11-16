"""Incident workflow: in-memory state and the logic behind every API endpoint.

Concurrency:
- The lab is blocking and not concurrency-safe. Every lab call goes through
  ``Workflow.lab_call``: it runs in a worker thread and holds ``lab_lock``
  (one ``threading.Lock`` for ALL lab access: requests, detector, status).
- State-changing operations also hold ``op_lock`` (an asyncio lock), so two
  requests never interleave halfway through e.g. snapshot + apply.
"""
from __future__ import annotations

import asyncio
import logging
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Callable, Optional

from backend import display
from backend.ai.interface import AIUnavailable, Feedback as AIFeedback, IncidentFacts, InvalidRecommendation
from backend.ai.models import Action
from backend.config import Settings
from backend.lab_types import FirewallRule, LabError
from backend.models import (
    CHECK_IDS,
    CheckResult,
    Connection,
    Containment,
    ContainmentLifted,
    CorrectionResponse,
    DecisionResponse,
    Feedback,
    Host,
    Incident,
    Policy,
    Recommendation,
    RollbackResponse,
)

log = logging.getLogger("backend.workflow")

MATCHED_RULE = "rule-14"


class ApiError(Exception):
    """Raised by the workflow; main.py turns it into ``{"detail": message}`` with ``status``."""

    def __init__(self, status: int, detail: str) -> None:
        super().__init__(detail)
        self.status = status
        self.detail = detail


@dataclass
class RecState:
    rec: Recommendation
    actions: list[Action]
    decision: Optional[str] = None          # "approved" | "rejected"
    snapshot: Optional[str] = None          # lab snapshot taken right before apply
    applied: bool = False                   # currently applied (not rolled back)
    checks: dict[str, str] = field(default_factory=dict)   # check id -> "passed"/"failed"


@dataclass
class IncidentState:
    incident: Incident
    status: str = "open"                    # "open" | "resolved"
    recs: dict[str, RecState] = field(default_factory=dict)

    def applied(self) -> Optional[RecState]:
        return next((r for r in self.recs.values() if r.applied), None)


def _load_validate() -> Callable:
    """Agent C's validator, or the backend's stand-in if it is not merged yet."""
    try:
        from backend.ai.validate import validate  # type: ignore[import-not-found]
        return validate
    except ModuleNotFoundError as e:
        if e.name != "backend.ai.validate":
            raise
        from backend.ai_fallback import standin_validate
        log.warning("backend.ai.validate not found: using the backend's stand-in validator (ai_fallback.py)")
        return standin_validate


class Workflow:
    def __init__(self, lab: Any, provider: Any, settings: Settings,
                 validate: Optional[Callable] = None) -> None:
        self.lab = lab
        self.provider = provider
        self.settings = settings
        self.addresses = settings.lab_addresses()
        self.validate = validate or _load_validate()
        self.lab_lock = threading.Lock()
        self.incidents: dict[str, IncidentState] = {}
        self.current_id: Optional[str] = None
        self.last_counter: Optional[int] = None
        self._seq = 0
        self.bind_loop()

    def bind_loop(self) -> None:
        """(Re)create asyncio primitives; called at app startup so they belong to the running loop."""
        self.op_lock = asyncio.Lock()
        self._incident_event = asyncio.Event()

    # ---- lab access -------------------------------------------------------------
    def _locked(self, fn: Callable, *args):
        with self.lab_lock:
            try:
                return fn(*args)
            except LabError:
                raise
            except Exception as e:  # NotImplementedError, OSError, ... -> readable LabError
                raise LabError(f"Lab call {getattr(fn, '__name__', fn)} failed: {e}") from e

    async def lab_call(self, fn: Callable, *args):
        return await asyncio.to_thread(self._locked, fn, *args)

    # ---- lookups ----------------------------------------------------------------
    def active(self) -> Optional[IncidentState]:
        st = self.incidents.get(self.current_id) if self.current_id else None
        return st if st and st.status == "open" else None

    def _incident(self, incident_id: str) -> IncidentState:
        st = self.incidents.get(incident_id)
        if st is None:
            raise ApiError(404, f"Unknown incident {incident_id}.")
        return st

    def _rec(self, st: IncidentState, rec_id: str) -> RecState:
        rs = st.recs.get(rec_id)
        if rs is None:
            raise ApiError(404, f"Unknown recommendation {rec_id} for incident {st.incident.id}.")
        return rs

    def _find_rec(self, rec_id: str) -> RecState:
        """Recommendation IDs are per incident; look in the current incident first."""
        order = ([self.current_id] if self.current_id else []) + list(reversed(self.incidents))
        for inc_id in order:
            st = self.incidents.get(inc_id)
            if st and rec_id in st.recs:
                return st.recs[rec_id]
        raise ApiError(404, f"Unknown recommendation {rec_id}.")

    # ---- detection ----------------------------------------------------------------
    async def poll_counter(self) -> Optional[Incident]:
        """Read the rule-14 counter once; open an incident if it rose and none is open.
        The first reading only sets the baseline (setup self-checks also hit rule-14)."""
        async with self.op_lock:
            value = await self.lab_call(self.lab.rule14_counter)
            last, self.last_counter = self.last_counter, value
            if last is None or value <= last or self.active() is not None:
                return None
            return await self._open_incident()

    async def _open_incident(self) -> Incident:
        rules = await self.lab_call(self.lab.rules)
        r14 = next((r for r in rules if r.rule_id == MATCHED_RULE), None)
        a, s = self.addresses, self.settings
        rule_text = display.rule_text(r14) if r14 else \
            f"allow {a.employee_net} → {a.db_ip} tcp/{a.db_port}"
        self._seq += 1
        year = datetime.now(timezone.utc).year
        inc = Incident(
            id=f"INC-{year}-{self._seq:04d}",
            detected_at=int(time.time() * 1000),
            source=Host(name=s.EMPLOYEE_HOST_NAME, role="Employee workstation", ip=a.employee_ip,
                        segment=f"Employee network {a.employee_net}"),
            target=Host(name=s.DB_HOST_NAME, role="Company database", ip=a.db_ip,
                        segment=f"Database network {a.db_net}"),
            app=Host(name=s.APP_HOST_NAME, role="Company application", ip=a.app_ip,
                     segment=f"Application network {a.app_net}"),
            connection=Connection(protocol="TCP", src_port=None, dst_port=a.db_port, service="PostgreSQL",
                                  observed_by=f"Firewall rule counter ({MATCHED_RULE})"),
            policy=Policy(rule_id=display.rule_num(MATCHED_RULE), rule_text=rule_text,
                          intended_path="Employee → company application → database"),
        )
        self.incidents[inc.id] = IncidentState(incident=inc)
        self.current_id = inc.id
        log.info("Incident %s opened (rule-14 counter rose to %s)", inc.id, self.last_counter)
        self._incident_event.set()
        self._incident_event = asyncio.Event()
        return inc

    async def wait_for_active(self, timeout: float) -> Optional[Incident]:
        loop = asyncio.get_running_loop()
        deadline = loop.time() + timeout
        while True:
            st = self.active()
            if st:
                return st.incident
            remaining = deadline - loop.time()
            if remaining <= 0:
                return None
            ev = self._incident_event
            try:
                await asyncio.wait_for(ev.wait(), remaining)
            except asyncio.TimeoutError:
                pass

    # ---- containment ------------------------------------------------------------------
    async def containment_on(self, incident_id: str) -> Containment:
        async with self.op_lock:
            self._incident(incident_id)
            rule: FirewallRule = await self.lab_call(self.lab.block_on)
            return Containment(status="active", rule_id=display.rule_num(rule.rule_id),
                               rule_text=display.rule_text(rule))

    async def containment_off(self, incident_id: str) -> ContainmentLifted:
        async with self.op_lock:
            self._incident(incident_id)
            await self.lab_call(self.lab.block_off)
            return ContainmentLifted()

    # ---- recommendations ----------------------------------------------------------------
    def _facts(self) -> IncidentFacts:
        a = self.addresses
        return IncidentFacts(
            source_ip=a.employee_ip, target_ip=a.db_ip, target_port=a.db_port, matched_rule=MATCHED_RULE,
            policy=(f"Only the company app ({a.app_ip}) may reach the database ({a.db_ip}:{a.db_port}). "
                    f"Employees ({a.employee_net}) reach the app on port {a.app_port} only."),
        )

    async def recommend(self, incident_id: str, feedback: Optional[Feedback]) -> Recommendation:
        async with self.op_lock:
            st = self._incident(incident_id)
            if st.status != "open":
                raise ApiError(409, f"Incident {incident_id} is already resolved.")
            if len(st.recs) >= self.settings.MAX_ATTEMPTS:
                raise ApiError(409, f"The maximum of {self.settings.MAX_ATTEMPTS} recommendation attempts "
                                    f"for incident {incident_id} has been reached. Reset the lab to start again.")
            applied = st.applied()
            if applied:
                raise ApiError(409, f"Version {applied.rec.version} is still applied. Roll it back first.")

            rules = await self.lab_call(self.lab.rules)
            facts = self._facts()
            fb = AIFeedback(type=feedback.type, version=feedback.version, summary=feedback.summary) \
                if feedback else None
            attempt = len(st.recs) + 1

            ai_rec = before = after = None
            last_error: Optional[Exception] = None
            for _ in range(2):  # one retry on an invalid recommendation
                try:
                    raw = await asyncio.to_thread(self.provider.recommend, facts, rules, fb, attempt)
                    ai_rec = self.validate(raw, rules, self.addresses)
                    try:
                        before, after = display.before_after(rules, list(ai_rec.actions), self.addresses)
                    except LabError as e:
                        raise InvalidRecommendation(f"The actions do not fit the current firewall: {e}") from e
                    break
                except InvalidRecommendation as e:
                    log.warning("Invalid AI recommendation (attempt %s): %s", attempt, e)
                    last_error, ai_rec = e, None
                except AIUnavailable as e:
                    raise ApiError(502, f"The AI is unavailable: {e}") from e
            if ai_rec is None:
                raise ApiError(502, f"The AI returned an invalid recommendation twice: {last_error}")

            actions = list(ai_rec.actions)
            commands = await self.lab_call(self.lab.render, actions)
            rec = Recommendation(
                id=f"REC-{attempt}", version=attempt, model=self.provider.model_name,
                summary=ai_rec.summary, change=ai_rec.change, affects=ai_rec.affects,
                unaffected=ai_rec.unaffected, before=before, after=after, commands=list(commands),
                what_changed=ai_rec.what_changed if attempt > 1 else "",
                revised_because=feedback.type if feedback else None,
                previous_version=feedback.version if feedback else None,
                previous_failure=feedback.summary if feedback and feedback.type == "failed" else None,
                fail_detail=None,
            )
            st.recs[rec.id] = RecState(rec=rec, actions=actions)
            return rec

    async def decide(self, rec_id: str, decision: str) -> DecisionResponse:
        async with self.op_lock:
            rs = self._find_rec(rec_id)
            if rs.applied and decision != rs.decision:
                raise ApiError(409, f"Version {rs.rec.version} is already applied; roll it back first.")
            rs.decision = decision
            return DecisionResponse(rec_id=rec_id, decision=decision)

    # ---- corrections ----------------------------------------------------------------------
    async def apply(self, incident_id: str, rec_id: str) -> CorrectionResponse:
        async with self.op_lock:
            st = self._incident(incident_id)
            rs = self._rec(st, rec_id)
            if rs.decision != "approved":
                raise ApiError(409, f"Version {rs.rec.version} has not been approved.")
            current = st.applied()
            if current:
                raise ApiError(409, f"Version {current.rec.version} is already applied.")
            snapshot = await self.lab_call(self.lab.snapshot)
            try:
                await self.lab_call(self.lab.apply, rs.actions)
            except LabError:
                try:
                    await self.lab_call(self.lab.restore, snapshot)
                except LabError:
                    log.exception("Restore after a failed apply also failed")
                raise
            rs.snapshot, rs.applied, rs.checks = snapshot, True, {}
            return CorrectionResponse(rec_id=rec_id)

    async def rollback(self, incident_id: str, rec_id: str) -> RollbackResponse:
        async with self.op_lock:
            st = self._incident(incident_id)
            rs = self._rec(st, rec_id)
            if rs.snapshot is None:
                raise ApiError(409, f"Version {rs.rec.version} was never applied, so there is nothing to roll back.")
            if rs.applied:
                await self.lab_call(self.lab.restore, rs.snapshot)
                rs.applied = False
                if st.status == "resolved":
                    st.status = "open"
            return RollbackResponse(rec_id=rec_id)

    # ---- verification ---------------------------------------------------------------------
    async def verify(self, incident_id: str, check_id: str, rec_id: Optional[str]) -> CheckResult:
        if check_id not in CHECK_IDS:
            raise ApiError(404, f"Unknown check {check_id}. Valid checks: {', '.join(CHECK_IDS)}.")
        async with self.op_lock:
            st = self._incident(incident_id)
            if rec_id is None:
                if not st.recs:
                    raise ApiError(404, "No recommendation to verify.")
                rec_id = list(st.recs)[-1]
            rs = self._rec(st, rec_id)
            if not rs.applied:
                raise ApiError(409, f"Version {rs.rec.version} is not applied, so it cannot be verified.")
            fn = self.lab.check_unauthorized_blocked if check_id == "unauthorized_blocked" \
                else self.lab.check_legitimate_app
            outcome = await self.lab_call(fn)
            name = st.incident.source.name
            result = display.check_result(check_id, outcome, name)
            rs.checks[check_id] = result.status
            if not outcome.passed:
                text = display.fail_detail(check_id, outcome, rs.rec.version, name)
                prev = rs.rec.fail_detail
                rs.rec.fail_detail = f"{prev} {text}" if prev and text not in prev else (prev or text)
            elif all(rs.checks.get(c) == "passed" for c in CHECK_IDS):
                st.status = "resolved"
                log.info("Incident %s resolved by %s", st.incident.id, rec_id)
            return result

    # ---- lab controls -----------------------------------------------------------------------
    async def attack(self):
        return await self.lab_call(self.lab.run_attack)

    async def reset(self) -> None:
        async with self.op_lock:
            await self.lab_call(self.lab.reset)
            self.incidents.clear()
            self.current_id = None
            self.last_counter = await self.lab_call(self.lab.rule14_counter)
