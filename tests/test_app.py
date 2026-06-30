from __future__ import annotations

import asyncio
import re
from pathlib import Path
from typing import Any

from fastapi.testclient import TestClient

from agentic_observatory.app import create_app
from agentic_observatory.config import Settings


class FakeCollector:
    async def loops(self) -> list[dict[str, Any]]:
        return [{"loop_id": "engineering-loop", "status": "active", "event_count": 3}]

    async def runs(self, limit: int = 50) -> list[dict[str, Any]]:
        return [{"run_id": "run-1", "loop_id": "engineering-loop", "status": "succeeded", "summary": "ran", "change_id": "chg-1"}]

    async def run(self, run_id: str) -> dict[str, Any]:
        return {"run_id": run_id, "status": "succeeded"}

    async def run_events(self, run_id: str) -> list[dict[str, Any]]:
        return [{"event_type": "loop_node", "summary": "node", "run_id": run_id}]

    async def actions(self, limit: int = 100) -> list[dict[str, Any]]:
        return [{"change_id": "chg-1", "event_type": "tool_call"}]

    async def topology(self) -> dict[str, Any]:
        return {"nodes": [{"loop_id": "engineering-loop", "display_name": "Engineering"}], "edges": []}

    async def daily_metrics(self) -> list[dict[str, Any]]:
        return []


class FakeNOC:
    def __init__(self) -> None:
        self.posts: list[tuple[str, dict[str, Any]]] = []

    async def cases(self, *, status: str | None = None, limit: int = 100) -> list[dict[str, Any]]:
        return [{"case_id": "case-1", "case_number": "NOC-1", "status": status or "open", "severity": "LOW", "title": "BGP"}]

    async def case_detail(self, case_id: str) -> dict[str, Any]:
        return {"case": {"case_id": case_id, "case_number": "NOC-1", "status": "open", "title": "BGP"}, "timeline": [{"event_type": "case_opened", "summary": "opened"}], "handoffs": [], "verification_objectives": [], "knowledge_artifacts": []}

    async def case_timeline(self, case_id: str) -> list[dict[str, Any]]:
        return [{"event_type": "case_opened", "summary": case_id}]

    async def handoffs(self, case_id: str | None = None) -> list[dict[str, Any]]:
        return [{"handoff_id": "handoff-1", "case_id": "case-1", "target_loop": "engineering", "status": "requested", "objective": "fix"}]

    async def verification_objectives(self, case_id: str) -> list[dict[str, Any]]:
        return [{"objective_id": "obj-1", "case_id": case_id, "handoff_id": "handoff-1", "status": "pending", "consecutive_pass_count": 0, "required_consecutive_passes": 3}]

    async def knowledge_artifacts(self, case_id: str) -> list[dict[str, Any]]:
        return [{"artifact_id": "art-1", "case_id": case_id, "artifact_type": "runbook", "review_status": "pending", "summary": "candidate"}]

    async def post_action(self, path: str, body: dict[str, Any]) -> dict[str, Any]:
        self.posts.append((path, body))
        return {"status": "ok", "path": path}


def _app(tmp_path: Path, *, actions: bool = False, enabled_actions: str | None = None):
    if enabled_actions is None:
        enabled_actions = "feedback,ack,suppress,artifact_review,verification_result" if actions else ""
    settings = Settings(
        environment="development",
        database_url=f"sqlite+aiosqlite:///{tmp_path / 'obs.db'}",
        session_secret="session-secret-for-tests",
        csrf_secret="csrf-secret-for-tests",
        operator_username="operator",
        operator_password_hash="secret",
        actions_enabled=actions,
        read_only=not actions,
        enabled_actions=enabled_actions,
    )
    app = create_app(settings)
    asyncio.run(app.state.store.init())
    fake_noc = FakeNOC()
    app.state.collector = FakeCollector()
    app.state.noc = fake_noc
    return app, fake_noc


def _login(client: TestClient) -> str:
    response = client.get("/login")
    token = re.search(r'name="csrf_token"\s+value="([a-f0-9]+)"', response.text)
    assert token is not None
    login = client.post("/login", data={"username": "operator", "password": "secret", "csrf_token": token.group(1)}, follow_redirects=False)
    assert login.status_code == 303
    index = client.get("/")
    assert index.status_code == 200
    csrf = re.search(r'name="csrf_token"\s+value="([a-f0-9]+)"', index.text)
    assert csrf is not None
    return csrf.group(1)


def test_pages_render_without_javascript(tmp_path: Path) -> None:
    app, _noc = _app(tmp_path)
    with TestClient(app) as client:
        _login(client)
        for path in ["/", "/loops", "/cases", "/cases/case-1", "/handoffs", "/verification", "/knowledge", "/runs", "/runs/run-1", "/changes", "/analysis"]:
            response = client.get(path)
            assert response.status_code == 200, path
            assert "<table" in response.text or "North Star" in response.text


def test_actions_require_csrf_and_are_idempotent(tmp_path: Path) -> None:
    app, noc = _app(tmp_path, actions=True)
    with TestClient(app) as client:
        csrf = _login(client)
        denied = client.post("/actions/cases/case-1/ack", data={"idempotency_key": "ack-1"})
        assert denied.status_code == 403
        first = client.post("/actions/cases/case-1/ack", data={"csrf_token": csrf, "idempotency_key": "ack-1"}, follow_redirects=False)
        second = client.post("/actions/cases/case-1/ack", data={"csrf_token": csrf, "idempotency_key": "ack-1"}, follow_redirects=False)
        assert first.status_code == 303
        assert second.status_code == 303
        assert len(noc.posts) == 1
        assert noc.posts[0][1]["actor_id"] == "operator"


def test_staged_actions_allowlist_gates_each_action(tmp_path: Path) -> None:
    app, noc = _app(tmp_path, actions=True, enabled_actions="feedback,ack")
    with TestClient(app) as client:
        csrf = _login(client)
        # Allowlisted actions proceed.
        allowed = client.post(
            "/actions/cases/case-1/ack",
            data={"csrf_token": csrf, "idempotency_key": "ack-staged"},
            follow_redirects=False,
        )
        assert allowed.status_code == 303
        # A known action left off the allowlist is rejected even with a valid CSRF token.
        denied = client.post(
            "/actions/cases/case-1/suppress",
            data={"csrf_token": csrf, "idempotency_key": "suppress-1", "reason": "noise"},
            follow_redirects=False,
        )
        assert denied.status_code == 403
        assert [path for path, _ in noc.posts] == ["/loop-console/v1/cases/case-1/ack"]


def test_case_detail_hides_unallowlisted_action_forms(tmp_path: Path) -> None:
    app, _noc = _app(tmp_path, actions=True, enabled_actions="feedback")
    with TestClient(app) as client:
        _login(client)
        body = client.get("/cases/case-1").text
        assert "/actions/cases/case-1/feedback" in body
        assert "/actions/cases/case-1/ack" not in body
