from __future__ import annotations

import asyncio
import re
from pathlib import Path
from typing import Any

import httpx
import pytest
from agent_core.contracts import (
    ApprovalRecord,
    CaseProjection,
    HandoffEnvelope,
    HandoffRecord,
)
from fastapi.testclient import TestClient

from agentic_observatory.app import create_app
from agentic_observatory.config import Settings
from agentic_observatory.coordination import ObservatoryCoordinator
from agentic_observatory.github_auth import GitHubOAuthClient, GitHubOAuthError
from agentic_observatory.security import (
    make_oauth_state,
    make_session,
    parse_oauth_state,
    session_csrf_token,
)


def _settings(tmp_path: Path, **overrides: Any) -> Settings:
    values: dict[str, Any] = {
        "environment": "development",
        "database_url": f"sqlite+aiosqlite:///{tmp_path / 'obs.db'}",
        "session_secret": "session-secret-for-tests",
        "csrf_secret": "csrf-secret-for-tests",
        "operator_username": "operator",
        "operator_password_hash": "secret",
        "knowledge_export_db_path": str(tmp_path / "missing.sqlite"),
    }
    values.update(overrides)
    return Settings(**values)


def _oauth_transport(*, owner: bool = False, two_factor: bool = True) -> httpx.MockTransport:
    def handler(request: httpx.Request) -> httpx.Response:
        path = request.url.path
        if path == "/login/oauth/access_token":
            return httpx.Response(200, json={"access_token": "ephemeral-token"})
        expected_token = (
            "Bearer org-policy-token"
            if path == "/orgs/AS215932"
            else "Bearer ephemeral-token"
        )
        assert request.headers["Authorization"] == expected_token
        if path == "/user":
            return httpx.Response(200, json={"id": 42, "login": "zelda"})
        if path == "/user/memberships/orgs/AS215932":
            return httpx.Response(
                200,
                json={"state": "active", "role": "admin" if owner else "member"},
            )
        if path == "/orgs/AS215932":
            return httpx.Response(
                200, json={"two_factor_requirement_enabled": two_factor}
            )
        if path == "/orgs/AS215932/teams/ops/memberships/zelda" and not owner:
            return httpx.Response(200, json={"state": "active", "role": "member"})
        return httpx.Response(404)

    return httpx.MockTransport(handler)


@pytest.mark.asyncio
async def test_github_oauth_maps_ops_and_owner_roles_and_requires_2fa(tmp_path: Path) -> None:
    settings = _settings(
        tmp_path,
        github_oauth_client_id="client",
        github_oauth_client_secret="secret",
        github_oauth_policy_token="org-policy-token",
    )
    operator = await GitHubOAuthClient(
        settings, transport=_oauth_transport()
    ).authenticate(code="code", code_verifier="verifier")
    senior = await GitHubOAuthClient(
        settings, transport=_oauth_transport(owner=True)
    ).authenticate(code="code", code_verifier="verifier")

    assert (operator.user_id, operator.login, operator.role) == (42, "zelda", "operator")
    assert senior.role == "senior"

    with pytest.raises(GitHubOAuthError, match="two-factor"):
        await GitHubOAuthClient(
            settings, transport=_oauth_transport(two_factor=False)
        ).authenticate(code="code", code_verifier="verifier")


def test_oauth_state_is_signed_scoped_and_one_callback_state(tmp_path: Path) -> None:
    settings = _settings(tmp_path)
    state, _verifier, cookie = make_oauth_state(settings)

    assert parse_oauth_state(cookie, state, settings)
    assert parse_oauth_state(cookie, "attacker-state", settings) is None
    assert parse_oauth_state(cookie + "tampered", state, settings) is None


class _FakeCoordinatorClient:
    def __init__(self) -> None:
        self.case_projection = CaseProjection(
            case_id="soc-case-1",
            owner_loop="soc",
            status="open",
            severity="HIGH",
            title="SOC posture drift",
            summary="Sanitized central projection",
        )
        envelope = HandoffEnvelope(
            source_loop="soc",
            target_loop="soc",
            capability="soc.active_probe.rt2",
            case_id="soc-case-1",
            intent="Verify the owned TLS endpoint",
            risk_level="high",
            approval_tier="senior",
            payload={
                "probe_kind": "tls_handshake",
                "targets": ["web.as215932.net"],
                "ports": [443],
            },
            idempotency_key="observatory-coordinator-test",
        )
        self.record = HandoffRecord(envelope=envelope, status="awaiting_approval")
        self.approval_records: list[ApprovalRecord] = []

    async def loops(self) -> list[dict[str, Any]]:
        return [{"loop_id": "soc", "display_name": "SOC Agent", "status": "active"}]

    async def cases(self, **filters: Any) -> list[CaseProjection]:
        if filters.get("status") and filters["status"] != self.case_projection.status:
            return []
        return [self.case_projection]

    async def case(self, case_id: str) -> CaseProjection:
        assert case_id == self.case_projection.case_id
        return self.case_projection

    async def handoffs(self, **filters: Any) -> list[HandoffRecord]:
        if filters.get("case_id") and filters["case_id"] != self.record.envelope.case_id:
            return []
        return [self.record]

    async def handoff(self, handoff_id: str) -> HandoffRecord:
        assert handoff_id == self.record.envelope.handoff_id
        return self.record

    async def handoff_events(self, handoff_id: str) -> list[dict[str, Any]]:
        assert handoff_id == self.record.envelope.handoff_id
        return [
            {
                "event_type": "approval_requested",
                "summary": "senior approval required",
                "created_at": "2026-07-11T12:00:00Z",
            }
        ]

    async def approvals(self, **_filters: Any) -> list[HandoffRecord]:
        return [self.record]

    async def approve(self, approval: ApprovalRecord) -> HandoffRecord:
        self.approval_records.append(approval)
        self.record = self.record.model_copy(
            update={"status": "queued", "approval": approval}
        )
        return self.record


def _csrf_from_login(client: TestClient) -> str:
    login_form = client.get("/login")
    token = re.search(r'name="csrf_token"\s+value="([a-f0-9]+)"', login_form.text)
    assert token
    response = client.post(
        "/login",
        data={"username": "operator", "password": "secret", "csrf_token": token.group(1)},
        follow_redirects=False,
    )
    assert response.status_code == 303
    index = client.get("/cases")
    csrf = re.search(r'name="csrf_token"\s+value="([a-f0-9]+)"', index.text)
    assert csrf
    return csrf.group(1)


def test_central_cases_handoffs_and_role_gated_approval(tmp_path: Path) -> None:
    settings = _settings(
        tmp_path,
        actions_enabled=True,
        read_only=False,
        enabled_actions="handoff_approval",
    )
    app = create_app(settings)
    asyncio.run(app.state.store.init())
    fake = _FakeCoordinatorClient()
    app.state.coordinator = ObservatoryCoordinator(fake, settings)  # type: ignore[arg-type]

    with TestClient(app) as client:
        operator_csrf = _csrf_from_login(client)
        cases = client.get("/cases").text
        handoffs = client.get("/handoffs").text
        approvals = client.get("/approvals").text
        assert "SOC posture drift" in cases
        assert "soc.active_probe.rt2" in handoffs
        assert fake.record.envelope.scope_hash in approvals
        assert "web.as215932.net" in approvals

        denied = client.post(
            f"/actions/handoffs/{fake.record.envelope.handoff_id}/decision",
            data={
                "csrf_token": operator_csrf,
                "scope_hash": fake.record.envelope.scope_hash,
                "decision": "approved",
                "rationale": "operator attempted senior scope",
            },
        )
        assert denied.status_code == 403

        cookie, senior = make_session(
            "github:7",
            settings,
            actor_login="owner",
            role="senior",
            auth_method="github",
        )
        client.cookies.set("obs_session", cookie)
        approved = client.post(
            f"/actions/handoffs/{fake.record.envelope.handoff_id}/decision",
            data={
                "csrf_token": session_csrf_token(senior, settings),
                "scope_hash": fake.record.envelope.scope_hash,
                "decision": "approved",
                "rationale": "bounded owned endpoint and exact scope reviewed",
                "idempotency_key": "senior-approval-1",
            },
            follow_redirects=False,
        )
        assert approved.status_code == 303
        assert fake.approval_records[0].approver_id == "github:7"
        assert fake.approval_records[0].approver_role == "senior"
        assert fake.approval_records[0].scope_hash == fake.record.envelope.scope_hash
