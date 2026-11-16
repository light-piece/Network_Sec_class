"""API models, exactly the shapes in docs/API_CONTRACT.md.

Python attributes are snake_case; JSON uses camelCase aliases. FastAPI
serializes responses by alias, and request bodies accept either spelling.
"""
from __future__ import annotations

from typing import Literal, Optional

from pydantic import BaseModel, ConfigDict
from pydantic.alias_generators import to_camel

CHECK_IDS = ("unauthorized_blocked", "legitimate_app")
CheckId = Literal["unauthorized_blocked", "legitimate_app"]


class ApiModel(BaseModel):
    model_config = ConfigDict(alias_generator=to_camel, populate_by_name=True)

    def to_json(self) -> dict:
        return self.model_dump(mode="json", by_alias=True)


# ---- incident -----------------------------------------------------------------
class Host(ApiModel):
    name: str
    role: str
    ip: str
    segment: str


class Connection(ApiModel):
    protocol: str = "TCP"
    src_port: Optional[int] = None
    dst_port: int
    service: str
    observed_by: str


class Policy(ApiModel):
    rule_id: str
    rule_text: str
    intended_path: str


class Incident(ApiModel):
    id: str
    detected_at: int
    source: Host
    target: Host
    app: Host
    connection: Connection
    policy: Policy


# ---- containment ----------------------------------------------------------------
class Containment(ApiModel):
    status: Literal["active", "lifted"]
    rule_id: Optional[str] = None
    rule_text: Optional[str] = None


class ContainmentLifted(ApiModel):
    status: Literal["lifted"] = "lifted"


# ---- recommendation -------------------------------------------------------------
class Rule(ApiModel):
    num: str
    action: Literal["allow", "deny"]
    src: str
    dst: str
    port: str
    note: str
    change: Literal["unchanged", "added", "removed"]


class Recommendation(ApiModel):
    id: str
    version: int
    model: str
    summary: str
    change: str
    affects: str
    unaffected: str
    before: list[Rule]
    after: list[Rule]
    commands: list[str]
    what_changed: str = ""
    revised_because: Optional[Literal["rejected", "failed"]] = None
    previous_version: Optional[int] = None
    previous_failure: Optional[str] = None
    fail_detail: Optional[str] = None


class Feedback(ApiModel):
    type: Literal["rejected", "failed"]
    version: int
    summary: Optional[str] = None


class RecommendationRequest(ApiModel):
    feedback: Optional[Feedback] = None


class DecisionRequest(ApiModel):
    decision: Literal["approved", "rejected"]


class DecisionResponse(ApiModel):
    rec_id: str
    decision: Literal["approved", "rejected"]


class CorrectionRequest(ApiModel):
    recommendation_id: str


class CorrectionResponse(ApiModel):
    status: Literal["applied"] = "applied"
    rec_id: str


class RollbackResponse(ApiModel):
    status: Literal["rolled_back"] = "rolled_back"
    rec_id: str


class VerificationRequest(ApiModel):
    # Optional so a bodyless call still works; the dashboard always sends it.
    recommendation_id: Optional[str] = None


class CheckResult(ApiModel):
    id: CheckId
    status: Literal["passed", "failed"]
    detail: str
    evidence: str


# ---- real-mode extras -------------------------------------------------------------
class Status(ApiModel):
    backend: Literal["ok"] = "ok"
    lab: Literal["up", "down", "error"]
    app: Literal["ok", "error"]
    database: Literal["ok", "error"]
    ai_mode: str
    ai_model: str
    ai_reachable: bool
    incident: Optional[str] = None


class AttackResponse(ApiModel):
    started: bool = True
    reached: bool


class ResetResponse(ApiModel):
    status: Literal["reset"] = "reset"
