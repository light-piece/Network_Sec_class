"""FastAPI app: the API in docs/API_CONTRACT.md under /api, plus the dashboard at /.

Run (from the repo root):
    uvicorn backend.main:app --host "$APP_HOST" --port "$APP_PORT"

Tests build their own app with ``create_app(settings=..., lab=..., provider=...)``.
"""
from __future__ import annotations

import logging
from contextlib import asynccontextmanager
from typing import Any, Optional

import httpx
from fastapi import APIRouter, Body, FastAPI, Request
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles

from backend.config import Settings, load_settings
from backend.detection import Detector
from backend.lab_types import LabError
from backend.models import (
    AttackResponse,
    CheckResult,
    Containment,
    ContainmentLifted,
    CorrectionRequest,
    CorrectionResponse,
    DecisionRequest,
    DecisionResponse,
    Incident,
    Recommendation,
    RecommendationRequest,
    ResetResponse,
    RollbackResponse,
    Status,
    VerificationRequest,
)
from backend.workflow import ApiError, Workflow

log = logging.getLogger("backend")


# ---- lab and AI selection --------------------------------------------------------------
def make_lab(settings: Settings) -> Any:
    addresses = settings.lab_addresses()
    if settings.LAB_MODE == "fake":
        from backend.fake_lab import FakeLab
        return FakeLab(addresses)
    from backend.lab import Lab  # real lab, Linux only; imported lazily
    return Lab(addresses, router_ns=settings.NS_ROUTER, employee_ns=settings.NS_EMPLOYEE,
               app_ns=settings.NS_APP, db_ns=settings.NS_DB)


def make_provider(settings: Settings) -> Any:
    """Agent C's provider factory, or the clearly-labelled stand-in if it is not merged yet."""
    try:
        from backend.ai.factory import get_provider  # type: ignore[import-not-found]
    except ModuleNotFoundError as e:
        if e.name != "backend.ai.factory":
            raise
        from backend.ai_fallback import StandInProvider
        log.warning("backend.ai.factory not found: using the backend's STAND-IN AI (ai_fallback.py), "
                    "not the real mock or Ollama")
        return StandInProvider(settings.MOCK_AI_SCENARIO, settings.lab_addresses())
    return get_provider(settings.AI_MODE, settings.MOCK_AI_SCENARIO, settings.OLLAMA_URL,
                        settings.OLLAMA_MODEL, settings.OLLAMA_TIMEOUT)


async def ai_reachable(settings: Settings) -> bool:
    if settings.AI_MODE != "ollama":
        return True
    try:
        async with httpx.AsyncClient(timeout=3) as client:
            r = await client.get(f"{settings.OLLAMA_URL}/api/tags")
            return r.status_code == 200
    except httpx.HTTPError:
        return False


# ---- app ---------------------------------------------------------------------------------
def create_app(settings: Optional[Settings] = None, lab: Any = None, provider: Any = None,
               validate: Any = None) -> FastAPI:
    settings = settings or load_settings()
    logging.basicConfig(level=settings.LOG_LEVEL, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    logging.getLogger("backend").setLevel(settings.LOG_LEVEL)

    lab = lab if lab is not None else make_lab(settings)
    provider = provider if provider is not None else make_provider(settings)
    wf = Workflow(lab, provider, settings, validate=validate)
    detector = Detector(wf, settings.POLL_INTERVAL_SECONDS)

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        wf.bind_loop()
        detector.start()
        log.info("Backend started: LAB_MODE=%s, AI=%s", settings.LAB_MODE, provider.model_name)
        try:
            yield
        finally:
            await detector.stop()

    app = FastAPI(title="Threat Containment Console API", lifespan=lifespan)
    app.state.settings, app.state.workflow, app.state.detector = settings, wf, detector

    @app.exception_handler(ApiError)
    async def _api_error(request: Request, exc: ApiError):
        return JSONResponse(status_code=exc.status, content={"detail": exc.detail})

    @app.exception_handler(LabError)
    async def _lab_error(request: Request, exc: LabError):
        log.error("Lab command failed: %s", exc)
        return JSONResponse(status_code=500, content={"detail": f"Lab command failed: {exc}"})

    api = APIRouter(prefix="/api")

    @api.get("/incidents/active", response_model=Incident)
    async def get_active_incident():
        inc = await wf.wait_for_active(settings.LONGPOLL_TIMEOUT_SECONDS)
        if inc is None:
            raise ApiError(404, "No unauthorized connection detected.")
        return inc

    @api.post("/incidents/{incident_id}/containment", response_model=Containment)
    async def activate_containment(incident_id: str):
        return await wf.containment_on(incident_id)

    @api.delete("/incidents/{incident_id}/containment", response_model=ContainmentLifted)
    async def lift_containment(incident_id: str):
        return await wf.containment_off(incident_id)

    @api.post("/incidents/{incident_id}/recommendations", response_model=Recommendation)
    async def request_recommendation(incident_id: str,
                                     body: Optional[RecommendationRequest] = Body(default=None)):
        return await wf.recommend(incident_id, body.feedback if body else None)

    @api.post("/recommendations/{rec_id}/decision", response_model=DecisionResponse)
    async def submit_decision(rec_id: str, body: DecisionRequest):
        return await wf.decide(rec_id, body.decision)

    @api.post("/incidents/{incident_id}/corrections", response_model=CorrectionResponse)
    async def apply_correction(incident_id: str, body: CorrectionRequest):
        return await wf.apply(incident_id, body.recommendation_id)

    @api.post("/incidents/{incident_id}/corrections/{rec_id}/rollback", response_model=RollbackResponse)
    async def rollback_correction(incident_id: str, rec_id: str):
        return await wf.rollback(incident_id, rec_id)

    @api.post("/incidents/{incident_id}/verifications/{check_id}", response_model=CheckResult)
    async def run_check(incident_id: str, check_id: str,
                        body: Optional[VerificationRequest] = Body(default=None)):
        return await wf.verify(incident_id, check_id, body.recommendation_id if body else None)

    @api.get("/status", response_model=Status)
    async def status():
        try:
            h = await wf.lab_call(lab.health)
            lab_s, app_s, db_s = ("up" if h.up else "down"), ("ok" if h.app_ok else "error"), \
                ("ok" if h.db_ok else "error")
        except LabError as e:
            log.warning("Lab health check failed: %s", e)
            lab_s, app_s, db_s = "error", "error", "error"
        active = wf.active()
        return Status(lab=lab_s, app=app_s, database=db_s, ai_mode=settings.AI_MODE,
                      ai_model=provider.model_name, ai_reachable=await ai_reachable(settings),
                      incident=active.incident.id if active else None)

    @api.post("/lab/attack", response_model=AttackResponse)
    async def lab_attack():
        result = await wf.attack()
        return AttackResponse(started=True, reached=result.reached)

    @api.post("/lab/reset", response_model=ResetResponse)
    async def lab_reset():
        await wf.reset()
        return ResetResponse()

    app.include_router(api)

    if settings.DASHBOARD_DIR.is_dir():
        app.mount("/", StaticFiles(directory=settings.DASHBOARD_DIR, html=True), name="dashboard")
    else:
        log.warning("DASHBOARD_DIR %s not found: dashboard not served", settings.DASHBOARD_DIR)
    return app


app = create_app()
