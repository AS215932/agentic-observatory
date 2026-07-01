from __future__ import annotations

import asyncio
import secrets
from collections.abc import AsyncIterator, Awaitable, Callable
from contextlib import asynccontextmanager
from datetime import UTC, datetime, timedelta
from typing import Any, cast
from urllib.parse import urlparse

import uvicorn
from fastapi import FastAPI, HTTPException, Request, Response, status
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from agentic_observatory.analysis import build_change_impact_report, report_to_dict
from agentic_observatory.clients import CollectorClient, GitHubClient, NOCClient
from agentic_observatory.config import Settings, get_settings
from agentic_observatory.db import ObservatoryStore
from agentic_observatory.domain import (
    LOOP_DESCRIPTORS,
    extract_change_keys,
    normalize_loop_snapshots,
)
from agentic_observatory.security import (
    CSRF_COOKIE,
    clear_session_cookie,
    current_session,
    login_csrf_token,
    make_session,
    require_session,
    session_csrf_token,
    set_session_cookie,
    validate_login_csrf,
    validate_session_csrf,
    verify_password,
)

templates = Jinja2Templates(directory="agentic_observatory/templates")

TERMINAL_CASE_STATUSES = frozenset({"resolved", "closed", "expired", "linked", "split", "merged"})
ACTIONABLE_CASE_STATUSES = frozenset(
    {
        "blocked",
        "failed",
        "handoff_in_progress",
        "handoff_requested",
        "needs_human",
        "waiting_approval",
    }
)
LIVE_CASE_STATUSES = (
    "open",
    "triaged",
    "context_requested",
    "handoff_requested",
    "handoff_in_progress",
    "verification_pending",
    "blocked",
    "failed",
    "needs_human",
    "investigating",
    "waiting_approval",
    "recovered_pending",
    "candidate_event",
    "active_event",
    "investigating_event",
    "monitoring_recovery",
    "stabilized",
)


def _http_url(value: Any) -> str:
    url = str(value or "").strip()
    if not url:
        return ""
    parsed = urlparse(url)
    if parsed.scheme.lower() not in {"http", "https"} or not parsed.netloc:
        return ""
    return url


templates.env.filters["http_url"] = _http_url


def _settings(request: Request) -> Settings:
    return cast(Settings, request.app.state.settings)


def _store(request: Request) -> ObservatoryStore:
    return cast(ObservatoryStore, request.app.state.store)


def _collector(request: Request) -> CollectorClient:
    return cast(CollectorClient, request.app.state.collector)


def _noc(request: Request) -> NOCClient:
    return cast(NOCClient, request.app.state.noc)


def _github(request: Request) -> GitHubClient:
    return cast(GitHubClient, request.app.state.github)


def template_context(request: Request, **kwargs: Any) -> dict[str, Any]:
    settings = _settings(request)
    session = current_session(request, settings)
    allowed_actions = settings.allowed_actions()
    context = {
        "request": request,
        "settings": settings,
        "session": session,
        "csrf_token": session_csrf_token(session, settings) if session else "",
        "enabled_actions": allowed_actions,
        "actions_enabled": bool(allowed_actions),
    }
    context.update(kwargs)
    return context


def render(request: Request, template_name: str, **kwargs: Any) -> Response:
    return templates.TemplateResponse(request, template_name, template_context(request, **kwargs))


def _parse_timestamp(value: Any) -> datetime | None:
    text = str(value or "").strip()
    if not text:
        return None
    if text.endswith("Z"):
        text = f"{text[:-1]}+00:00"
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        return parsed.replace(tzinfo=UTC)
    return parsed.astimezone(UTC)


def _case_is_recent(case: dict[str, Any], *, now: datetime, max_age_hours: float) -> bool:
    if max_age_hours <= 0:
        return True
    timestamp = _parse_timestamp(_timestamp_value(case, "updated_at", "opened_at", "resolved_at"))
    if timestamp is None:
        return True
    return now - timestamp <= timedelta(hours=max_age_hours)


def _case_is_live(case: dict[str, Any], *, now: datetime, max_age_hours: float) -> bool:
    status = str(case.get("status") or "").lower()
    if status in TERMINAL_CASE_STATUSES:
        return False
    if status in ACTIONABLE_CASE_STATUSES:
        return True
    return _case_is_recent(case, now=now, max_age_hours=max_age_hours)


def _timestamp_value(item: dict[str, Any], *keys: str) -> str:
    for key in keys:
        value = str(item.get(key) or "")
        if value:
            return value
    return ""


def _sort_by_recent(items: list[dict[str, Any]], *keys: str) -> list[dict[str, Any]]:
    return sorted(items, key=lambda item: _timestamp_value(item, *keys), reverse=True)


async def _case_list(request: Request, *, scope: str = "live", status: str | None = None, limit: int = 100) -> list[dict[str, Any]]:
    if status or scope == "all":
        return await _noc(request).cases(status=status, limit=limit)
    settings = _settings(request)
    now = datetime.now(UTC)
    case_batches = await asyncio.gather(
        *(_noc(request).cases(status=case_status, limit=limit) for case_status in LIVE_CASE_STATUSES)
    )
    cases: list[dict[str, Any]] = []
    seen: set[str] = set()
    for batch in case_batches:
        for case in batch:
            case_id = str(case.get("case_id") or "")
            if case_id and case_id in seen:
                continue
            if _case_is_live(case, now=now, max_age_hours=settings.live_case_max_age_hours):
                cases.append(case)
                if case_id:
                    seen.add(case_id)
    return _sort_by_recent(cases, "updated_at", "opened_at", "resolved_at")[:limit]


async def _artifacts_for_cases(request: Request, cases: list[dict[str, Any]]) -> list[dict[str, Any]]:
    artifacts: list[dict[str, Any]] = []
    for case in cases:
        case_id = str(case.get("case_id") or "")
        if not case_id:
            continue
        for artifact in await _noc(request).knowledge_artifacts(case_id):
            enriched = dict(artifact)
            enriched["_case_status"] = case.get("status", "")
            enriched["_case_updated_at"] = case.get("updated_at", "")
            enriched["_case_opened_at"] = case.get("opened_at", "")
            enriched["_case_resolved_at"] = case.get("resolved_at", "")
            artifacts.append(enriched)
    return _sort_by_recent(artifacts, "created_at", "_case_updated_at", "_case_opened_at")


async def _handoffs_for_cases(request: Request, cases: list[dict[str, Any]]) -> list[dict[str, Any]]:
    handoffs: list[dict[str, Any]] = []
    for case in cases:
        case_id = str(case.get("case_id") or "")
        if case_id:
            handoffs.extend(await _noc(request).handoffs(case_id))
    return _sort_by_recent(handoffs, "updated_at", "created_at")


async def _verification_objectives_for_cases(request: Request, cases: list[dict[str, Any]]) -> list[dict[str, Any]]:
    objectives: list[dict[str, Any]] = []
    for case in cases:
        case_id = str(case.get("case_id") or "")
        if case_id:
            objectives.extend(await _noc(request).verification_objectives(case_id))
    return _sort_by_recent(objectives, "next_check_at", "last_checked_at")


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    settings = get_settings()
    store = ObservatoryStore(settings.database_url)
    await store.init()
    app.state.settings = settings
    app.state.store = store
    app.state.collector = CollectorClient(settings.collector_base_url, timeout=settings.request_timeout_seconds)
    app.state.noc = NOCClient(settings.noc_base_url, settings.noc_loop_console_secret, timeout=settings.request_timeout_seconds)
    app.state.github = GitHubClient(settings.github_token, timeout=settings.request_timeout_seconds)
    try:
        yield
    finally:
        await store.close()


def create_app(settings: Settings | None = None, store: ObservatoryStore | None = None) -> FastAPI:
    app = FastAPI(title="AS215932 Agentic Observatory", lifespan=lifespan if settings is None else None)
    if settings is not None:
        app.state.settings = settings
        app.state.store = store or ObservatoryStore(settings.database_url)
        app.state.collector = CollectorClient(settings.collector_base_url, timeout=settings.request_timeout_seconds)
        app.state.noc = NOCClient(settings.noc_base_url, settings.noc_loop_console_secret, timeout=settings.request_timeout_seconds)
        app.state.github = GitHubClient(settings.github_token, timeout=settings.request_timeout_seconds)
    app.mount("/static", StaticFiles(directory="agentic_observatory/static"), name="static")

    @app.middleware("http")
    async def security_headers(request: Request, call_next: Callable[[Request], Awaitable[Response]]) -> Response:
        response = await call_next(request)
        response.headers.setdefault("X-Frame-Options", "DENY")
        response.headers.setdefault("X-Content-Type-Options", "nosniff")
        response.headers.setdefault("Referrer-Policy", "same-origin")
        response.headers.setdefault("Content-Security-Policy", "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:")
        return response

    @app.get("/healthz")
    async def healthz() -> dict[str, Any]:
        return {"status": "ok", "service": "agentic-observatory"}

    @app.get("/login", response_class=HTMLResponse)
    async def login_form(request: Request) -> Response:
        settings_obj = _settings(request)
        seed = request.cookies.get(CSRF_COOKIE) or secrets.token_urlsafe(24)
        context = template_context(request, csrf_token=login_csrf_token(seed, settings_obj))
        response = templates.TemplateResponse(request, "login.html", context)
        response.set_cookie(
            CSRF_COOKIE,
            seed,
            max_age=settings_obj.session_ttl_seconds,
            httponly=True,
            secure=settings_obj.environment != "development",
            samesite="strict",
        )
        return response

    @app.post("/login")
    async def login(request: Request) -> Response:
        form = await request.form()
        settings_obj = _settings(request)
        validate_login_csrf(request, str(form.get("csrf_token") or ""), settings_obj)
        username = str(form.get("username") or "")
        password = str(form.get("password") or "")
        if username != settings_obj.operator_username or not verify_password(password, settings_obj.operator_password_hash):
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials")
        cookie_value, _session = make_session(username, settings_obj)
        response = RedirectResponse("/", status_code=status.HTTP_303_SEE_OTHER)
        set_session_cookie(response, cookie_value, settings_obj)
        return response

    @app.post("/logout")
    async def logout(request: Request) -> Response:
        session = require_session(request, _settings(request))
        await validate_session_csrf(request, session, _settings(request))
        response = RedirectResponse("/login", status_code=status.HTTP_303_SEE_OTHER)
        clear_session_cookie(response)
        return response

    @app.get("/", response_class=HTMLResponse)
    async def index(request: Request) -> Response:
        require_session(request, _settings(request))
        loops = normalize_loop_snapshots(await _collector(request).loops())
        cases = await _case_list(request, limit=10)
        runs = await _collector(request).runs(limit=10)
        audit = await _store(request).recent_audit(limit=10)
        return render(request, "index.html", loops=loops, cases=cases, runs=runs, audit=audit)

    @app.get("/loops", response_class=HTMLResponse)
    async def loops(request: Request) -> Response:
        require_session(request, _settings(request))
        return render(request, "loops.html", loops=normalize_loop_snapshots(await _collector(request).loops()))

    @app.get("/loops/{loop_id}", response_class=HTMLResponse)
    async def loop_detail(loop_id: str, request: Request) -> Response:
        require_session(request, _settings(request))
        loops = normalize_loop_snapshots(await _collector(request).loops())
        loop = next((item for item in loops if item["loop_id"] == loop_id), None)
        if loop is None:
            raise HTTPException(status_code=404, detail="Loop not found")
        runs = [run for run in await _collector(request).runs(limit=100) if run.get("loop_id") in {loop_id, loop.get("trace_graph_id"), loop_id.replace("-", "_")} or run.get("graph_id") == loop_id]
        return render(request, "loop_detail.html", loop=loop, runs=runs)

    @app.get("/cases", response_class=HTMLResponse)
    async def cases(request: Request, status_filter: str | None = None, scope: str = "live") -> Response:
        require_session(request, _settings(request))
        case_list = await _case_list(request, scope=scope, status=status_filter, limit=100)
        return render(request, "cases.html", cases=case_list, scope=scope, status_filter=status_filter)

    @app.get("/cases/{case_id}", response_class=HTMLResponse)
    async def case_detail(case_id: str, request: Request) -> Response:
        require_session(request, _settings(request))
        detail = await _noc(request).case_detail(case_id)
        return render(request, "case_detail.html", detail=detail, case_id=case_id)

    @app.get("/handoffs", response_class=HTMLResponse)
    async def handoffs(request: Request, scope: str = "live") -> Response:
        require_session(request, _settings(request))
        cases = await _case_list(request, scope=scope, limit=100)
        return render(request, "handoffs.html", handoffs=await _handoffs_for_cases(request, cases), scope=scope)

    @app.get("/runs", response_class=HTMLResponse)
    async def runs(request: Request) -> Response:
        require_session(request, _settings(request))
        return render(request, "runs.html", runs=await _collector(request).runs(limit=100))

    @app.get("/runs/{run_id}", response_class=HTMLResponse)
    async def run_detail(run_id: str, request: Request) -> Response:
        require_session(request, _settings(request))
        return render(
            request,
            "run_detail.html",
            run=await _collector(request).run(run_id),
            events=await _collector(request).run_events(run_id),
            run_id=run_id,
        )

    @app.get("/knowledge", response_class=HTMLResponse)
    async def knowledge(request: Request, scope: str = "live") -> Response:
        require_session(request, _settings(request))
        cases = await _case_list(request, scope=scope, limit=100)
        return render(request, "knowledge.html", artifacts=await _artifacts_for_cases(request, cases), scope=scope)

    @app.get("/knowledge/artifacts/{artifact_id}", response_class=HTMLResponse)
    async def knowledge_artifact(artifact_id: str, request: Request) -> Response:
        require_session(request, _settings(request))
        artifacts = await _artifacts_for_cases(request, await _case_list(request, scope="all", limit=100))
        artifact = next((item for item in artifacts if str(item.get("artifact_id")) == artifact_id), None)
        if artifact is None:
            raise HTTPException(status_code=404, detail="Artifact not found")
        return render(request, "artifact_detail.html", artifact=artifact)

    @app.get("/verification", response_class=HTMLResponse)
    async def verification(request: Request, scope: str = "live") -> Response:
        require_session(request, _settings(request))
        cases = await _case_list(request, scope=scope, limit=100)
        return render(request, "verification.html", objectives=await _verification_objectives_for_cases(request, cases), scope=scope)

    @app.get("/changes", response_class=HTMLResponse)
    async def changes(request: Request) -> Response:
        require_session(request, _settings(request))
        runs = await _collector(request).runs(limit=100)
        actions = await _collector(request).actions(limit=100)
        keys = extract_change_keys(runs, actions)
        return render(request, "changes.html", change_keys=keys, runs=runs, actions=actions)

    @app.get("/changes/{change_key:path}", response_class=HTMLResponse)
    async def change_detail(change_key: str, request: Request) -> Response:
        require_session(request, _settings(request))
        report = report_to_dict(build_change_impact_report(change_key))
        return render(request, "change_detail.html", change_key=change_key, report=report)

    @app.get("/analysis", response_class=HTMLResponse)
    async def analysis_page(request: Request) -> Response:
        require_session(request, _settings(request))
        keys = extract_change_keys(await _collector(request).runs(limit=100), await _collector(request).actions(limit=100))
        reports = [report_to_dict(build_change_impact_report(key)) for key in keys[:25]]
        return render(request, "analysis.html", reports=reports)

    async def post_noc_action(
        request: Request,
        *,
        action: str,
        target_type: str,
        target_id: str,
        noc_path: str,
        body: dict[str, Any],
    ) -> Response:
        settings_obj = _settings(request)
        session = require_session(request, settings_obj)
        await validate_session_csrf(request, session, settings_obj)
        if not settings_obj.action_allowed(action):
            raise HTTPException(status_code=403, detail=f"Observatory action '{action}' is not enabled")
        idempotency_key = str(body.get("idempotency_key") or secrets.token_urlsafe(12))
        scope = f"{action}:{target_type}:{target_id}"
        existing = await _store(request).get_idempotency(scope, idempotency_key)
        if existing is not None:
            return RedirectResponse(existing.get("redirect", "/"), status_code=status.HTTP_303_SEE_OTHER)
        body = {**body, "actor_id": session.actor_id, "idempotency_key": idempotency_key}
        result = await _noc(request).post_action(noc_path, body)
        await _store(request).audit(
            actor_id=session.actor_id,
            action=action,
            target_type=target_type,
            target_id=target_id,
            idempotency_key=idempotency_key,
            status=str(result.get("status") or "ok"),
            payload={"noc_path": noc_path, "body": {k: v for k, v in body.items() if k != "csrf_token"}, "result": result},
        )
        redirect_to = f"/cases/{body.get('case_id', target_id)}" if target_type == "case" else request.headers.get("referer", "/")
        await _store(request).record_idempotency(scope=scope, key=idempotency_key, actor_id=session.actor_id, result={"redirect": redirect_to, "result": result})
        return RedirectResponse(redirect_to, status_code=status.HTTP_303_SEE_OTHER)

    @app.post("/actions/cases/{case_id}/feedback")
    async def action_feedback(case_id: str, request: Request) -> Response:
        form = await request.form()
        return await post_noc_action(
            request,
            action="feedback",
            target_type="case",
            target_id=case_id,
            noc_path=f"/loop-console/v1/cases/{case_id}/feedback",
            body={"case_id": case_id, "feedback_type": "operator_note", "comment": str(form.get("comment") or ""), "idempotency_key": str(form.get("idempotency_key") or "")},
        )

    @app.post("/actions/cases/{case_id}/ack")
    async def action_ack(case_id: str, request: Request) -> Response:
        form = await request.form()
        return await post_noc_action(request, action="ack", target_type="case", target_id=case_id, noc_path=f"/loop-console/v1/cases/{case_id}/ack", body={"case_id": case_id, "idempotency_key": str(form.get("idempotency_key") or "")})

    @app.post("/actions/cases/{case_id}/suppress")
    async def action_suppress(case_id: str, request: Request) -> Response:
        form = await request.form()
        return await post_noc_action(request, action="suppress", target_type="case", target_id=case_id, noc_path=f"/loop-console/v1/cases/{case_id}/suppress", body={"case_id": case_id, "reason": str(form.get("reason") or ""), "ttl_seconds": int(str(form.get("ttl_seconds") or "3600")), "idempotency_key": str(form.get("idempotency_key") or "")})

    @app.post("/actions/knowledge-artifacts/{artifact_id}/review")
    async def action_artifact_review(artifact_id: str, request: Request) -> Response:
        form = await request.form()
        return await post_noc_action(request, action="artifact_review", target_type="knowledge_artifact", target_id=artifact_id, noc_path=f"/loop-console/v1/knowledge-artifacts/{artifact_id}/review", body={"review_status": str(form.get("review_status") or "pending"), "comment": str(form.get("comment") or ""), "idempotency_key": str(form.get("idempotency_key") or "")})

    @app.post("/actions/verification-objectives/{objective_id}/result")
    async def action_verification_result(objective_id: str, request: Request) -> Response:
        form = await request.form()
        return await post_noc_action(request, action="verification_result", target_type="verification_objective", target_id=objective_id, noc_path=f"/loop-console/v1/verification-objectives/{objective_id}/result", body={"status": str(form.get("status") or "pending"), "evidence_ref": str(form.get("evidence_ref") or ""), "failure_reason": str(form.get("failure_reason") or ""), "idempotency_key": str(form.get("idempotency_key") or "")})

    @app.get("/api/loops/topology")
    async def api_topology(request: Request) -> JSONResponse:
        require_session(request, _settings(request))
        topology = await _collector(request).topology()
        if not topology.get("nodes"):
            topology = {"nodes": LOOP_DESCRIPTORS, "edges": []}
        return JSONResponse(topology)

    @app.get("/api/cases/{case_id}/timeline")
    async def api_case_timeline(case_id: str, request: Request) -> JSONResponse:
        require_session(request, _settings(request))
        return JSONResponse({"case_id": case_id, "timeline": await _noc(request).case_timeline(case_id)})

    @app.get("/api/runs/{run_id}/replay")
    async def api_run_replay(run_id: str, request: Request) -> JSONResponse:
        require_session(request, _settings(request))
        return JSONResponse({"run_id": run_id, "events": await _collector(request).run_events(run_id)})

    @app.get("/api/changes/{change_key:path}/impact")
    async def api_change_impact(change_key: str, request: Request) -> JSONResponse:
        require_session(request, _settings(request))
        return JSONResponse(report_to_dict(build_change_impact_report(change_key)))

    return app


app = create_app()


def main() -> None:
    settings = get_settings()
    uvicorn.run("agentic_observatory.app:app", host=settings.host, port=settings.port)
