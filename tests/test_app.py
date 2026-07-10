from __future__ import annotations

import asyncio
import json
import re
import sqlite3
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from fastapi import FastAPI
from fastapi.testclient import TestClient

from agentic_observatory.app import _case_is_live, create_app
from agentic_observatory.config import Settings


class FakeCollector:
    async def loops(self) -> list[dict[str, Any]]:
        return [{"loop_id": "engineering-loop", "status": "active", "event_count": 3}]

    async def runs(self, limit: int = 50) -> list[dict[str, Any]]:
        return [
            {
                "run_id": "run-1",
                "loop_id": "engineering-loop",
                "status": "succeeded",
                "summary": "ran",
                "change_id": "chg-1",
            }
        ]

    async def run(self, run_id: str) -> dict[str, Any]:
        return {"run_id": run_id, "status": "succeeded"}

    async def run_events(self, run_id: str) -> list[dict[str, Any]]:
        return [{"event_type": "loop_node", "summary": "node", "run_id": run_id}]

    async def actions(self, limit: int = 100) -> list[dict[str, Any]]:
        return [{"change_id": "chg-1", "event_type": "tool_call"}]

    async def topology(self) -> dict[str, Any]:
        return {
            "nodes": [{"loop_id": "engineering-loop", "display_name": "Engineering"}],
            "edges": [],
        }

    async def daily_metrics(self) -> list[dict[str, Any]]:
        return []


class FakeNOC:
    def __init__(self) -> None:
        self.posts: list[tuple[str, dict[str, Any]]] = []
        self.case_rows = [
            {
                "case_id": "case-1",
                "case_number": "NOC-1",
                "status": "open",
                "severity": "LOW",
                "title": "BGP",
                "opened_at": "2026-06-30T08:00:00+00:00",
                "updated_at": "2026-06-30T09:00:00+00:00",
            },
            {
                "case_id": "case-old",
                "case_number": "NOC-OLD",
                "status": "resolved",
                "severity": "LOW",
                "title": "Old solved case",
                "opened_at": "2026-06-01T08:00:00+00:00",
                "updated_at": "2026-06-01T09:00:00+00:00",
                "resolved_at": "2026-06-01T09:00:00+00:00",
            },
        ]

    async def cases(self, *, status: str | None = None, limit: int = 100) -> list[dict[str, Any]]:
        rows = [dict(case) for case in self.case_rows]
        if status:
            rows = [case for case in rows if case["status"] == status]
        return rows[:limit]

    async def case_detail(self, case_id: str) -> dict[str, Any]:
        case = next(
            (case for case in self.case_rows if case["case_id"] == case_id), self.case_rows[0]
        )
        return {
            "case": dict(case),
            "counts": {
                "timeline": 1,
                "handoffs": 1,
                "verification_objectives": 1,
                "knowledge_artifacts": 1,
                "outcomes": 1,
            },
            "timeline_limit": 200,
            "timeline": [{"event_type": "case_opened", "summary": "opened"}],
            "handoffs": [
                {
                    "handoff_id": f"handoff-{case_id}",
                    "case_id": case_id,
                    "target_loop": "engineering",
                    "status": "requested",
                    "objective": "fix",
                    "acceptance_criteria": ["service stays healthy"],
                    "updated_at": "2026-06-30T10:00:00+00:00",
                    "payload": {"raw_evidence": "hidden"},
                }
            ],
            "verification_objectives": [
                {
                    "objective_id": "obj-1",
                    "case_id": case_id,
                    "status": "pending",
                    "name": "health check",
                    "consecutive_pass_count": 0,
                    "required_consecutive_passes": 3,
                    "payload": {"raw_probe": "hidden"},
                }
            ],
            "knowledge_artifacts": [
                {
                    "artifact_id": f"art-{case_id}",
                    "case_id": case_id,
                    "artifact_type": "runbook",
                    "review_status": "pending",
                    "summary": "candidate",
                    "created_at": "2026-06-30T10:00:00+00:00",
                    "payload": {"raw_document": "hidden"},
                }
            ],
            "outcomes": [
                {
                    "outcome_id": "outcome-1",
                    "proposed_action": "review",
                    "final_score": {"useful": 0.8},
                    "created_at": "2026-06-30T10:00:00+00:00",
                    "payload": {"raw_outcome": "hidden"},
                }
            ],
        }

    async def case_timeline(self, case_id: str) -> list[dict[str, Any]]:
        return [{"event_type": "case_opened", "summary": case_id}]

    async def handoffs(self, case_id: str | None = None) -> list[dict[str, Any]]:
        case_id = case_id or "case-1"
        return [
            {
                "handoff_id": f"handoff-{case_id}",
                "case_id": case_id,
                "target_loop": "engineering",
                "status": "requested",
                "objective": "fix",
                "created_at": "2026-06-30T10:00:00+00:00",
            }
        ]

    async def verification_objectives(self, case_id: str) -> list[dict[str, Any]]:
        return [
            {
                "objective_id": "obj-1",
                "case_id": case_id,
                "handoff_id": "handoff-1",
                "status": "pending",
                "consecutive_pass_count": 0,
                "required_consecutive_passes": 3,
            }
        ]

    async def knowledge_artifacts(self, case_id: str) -> list[dict[str, Any]]:
        created_at = (
            "2026-06-30T10:00:00+00:00" if case_id == "case-1" else "2026-06-01T10:00:00+00:00"
        )
        return [
            {
                "artifact_id": f"art-{case_id}",
                "case_id": case_id,
                "artifact_type": "runbook",
                "review_status": "pending",
                "summary": "candidate",
                "created_at": created_at,
            }
        ]

    async def post_action(self, path: str, body: dict[str, Any]) -> dict[str, Any]:
        self.posts.append((path, body))
        return {"status": "ok", "path": path}


def _app(
    tmp_path: Path,
    *,
    actions: bool = False,
    enabled_actions: str | None = None,
    live_case_max_age_hours: float = 24 * 365 * 10,
    knowledge_export_db_path: str | None = None,
) -> tuple[FastAPI, FakeNOC]:
    if enabled_actions is None:
        enabled_actions = (
            "feedback,ack,suppress,artifact_review,verification_result" if actions else ""
        )
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
        live_case_max_age_hours=live_case_max_age_hours,
        knowledge_export_db_path=knowledge_export_db_path or str(tmp_path / "missing-knowledge.sqlite"),
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
    login = client.post(
        "/login",
        data={"username": "operator", "password": "secret", "csrf_token": token.group(1)},
        follow_redirects=False,
    )
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
        for path in [
            "/",
            "/loops",
            "/cases",
            "/cases/case-1",
            "/handoffs",
            "/verification",
            "/knowledge",
            "/cross-loop",
            "/runs",
            "/runs/run-1",
            "/changes",
            "/analysis",
        ]:
            response = client.get(path)
            assert response.status_code == 200, path
            assert "<table" in response.text or "North Star" in response.text


def test_actions_require_csrf_and_are_idempotent(tmp_path: Path) -> None:
    app, noc = _app(tmp_path, actions=True)
    with TestClient(app) as client:
        csrf = _login(client)
        denied = client.post("/actions/cases/case-1/ack", data={"idempotency_key": "ack-1"})
        assert denied.status_code == 403
        first = client.post(
            "/actions/cases/case-1/ack",
            data={"csrf_token": csrf, "idempotency_key": "ack-1"},
            follow_redirects=False,
        )
        second = client.post(
            "/actions/cases/case-1/ack",
            data={"csrf_token": csrf, "idempotency_key": "ack-1"},
            follow_redirects=False,
        )
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


def test_case_detail_renders_projected_records_without_raw_json(tmp_path: Path) -> None:
    app, _noc = _app(tmp_path)
    with TestClient(app) as client:
        _login(client)
        body = client.get("/cases/case-1").text
        assert "<pre>" not in body
        assert "handoff-case-1" in body
        assert "health check" in body
        assert "candidate" in body
        assert "raw_evidence" not in body
        assert "raw_probe" not in body
        assert "raw_document" not in body
        assert "raw_outcome" not in body


def test_insight_contract_accepts_all_observatory_display_actions() -> None:
    from agent_core.contracts import InsightDecisionRecord  # type: ignore[import-untyped]

    for action in ["notify", "question", "draft", "stay_silent"]:
        record = InsightDecisionRecord.model_validate(
                {
                    "insight_id": f"ins_observatory_{action}",
                    "loop": "noc",
                "fingerprint": f"observatory-{action}",
                "sampling_class": "surfaced",
                "candidate_type": "display_fixture",
                "candidate_source": "agentic_observatory:test",
                "support_facts": ["contract action renders as displayable state"],
                "evidence_refs": [{"kind": "fixture", "ref": f"observatory:{action}"}],
                "action_selected": action,
                "why_now": "Fixture validates Observatory can depend on the released action space.",
                "policy_version": "observatory-insight.fixture",
            }
        )
        assert record.action_selected == action


def test_case_detail_only_links_safe_issue_urls(tmp_path: Path) -> None:
    app, noc = _app(tmp_path)
    noc.case_rows[0]["issue_url"] = "javascript:alert(1)"
    with TestClient(app) as client:
        _login(client)
        unsafe_body = client.get("/cases/case-1").text
        assert "javascript:alert(1)" in unsafe_body
        assert 'href="javascript:alert(1)"' not in unsafe_body

    noc.case_rows[0]["issue_url"] = "https://github.com/AS215932/noc-agent/issues/1"
    with TestClient(app) as client:
        _login(client)
        safe_body = client.get("/cases/case-1").text
        assert 'href="https://github.com/AS215932/noc-agent/issues/1"' in safe_body


def test_cases_default_to_live_scope_with_history_escape_hatch(tmp_path: Path) -> None:
    app, _noc = _app(tmp_path)
    with TestClient(app) as client:
        _login(client)
        live = client.get("/cases").text
        assert "NOC-1" in live
        assert "NOC-OLD" not in live
        assert "2026-06-30T09:00:00+00:00" in live

        history = client.get("/cases?scope=all").text
        assert "NOC-1" in history
        assert "NOC-OLD" in history

        resolved = client.get("/cases?status_filter=resolved").text
        assert "NOC-OLD" in resolved
        assert "NOC-1" not in resolved


def test_live_scope_queries_non_terminal_cases_when_history_fills_first_page(
    tmp_path: Path,
) -> None:
    app, noc = _app(tmp_path)
    noc.case_rows = [
        {
            "case_id": f"case-old-{index}",
            "case_number": f"NOC-OLD-{index}",
            "status": "resolved",
            "severity": "LOW",
            "title": "Old solved case",
            "opened_at": "2026-06-01T08:00:00+00:00",
            "updated_at": "2026-06-01T09:00:00+00:00",
            "resolved_at": "2026-06-01T09:00:00+00:00",
        }
        for index in range(101)
    ] + [
        {
            "case_id": "case-live",
            "case_number": "NOC-LIVE",
            "status": "open",
            "severity": "LOW",
            "title": "Current case",
            "opened_at": "2026-06-30T08:00:00+00:00",
            "updated_at": "2026-06-30T09:00:00+00:00",
        }
    ]
    with TestClient(app) as client:
        _login(client)
        body = client.get("/cases").text
        assert "NOC-LIVE" in body
        assert "NOC-OLD-0" not in body


def test_live_scope_hides_stale_non_action_cases(tmp_path: Path) -> None:
    app, noc = _app(tmp_path, live_case_max_age_hours=24)
    noc.case_rows = [
        {
            "case_id": "case-stale",
            "case_number": "NOC-STALE",
            "status": "investigating",
            "severity": "LOW",
            "title": "Stale solved case",
            "opened_at": "2020-01-01T00:00:00+00:00",
            "updated_at": "2020-01-01T00:00:00+00:00",
        },
        {
            "case_id": "case-action",
            "case_number": "NOC-ACTION",
            "status": "handoff_requested",
            "severity": "HIGH",
            "title": "Needs operator action",
            "opened_at": "2020-01-01T00:00:00+00:00",
            "updated_at": "2020-01-01T00:00:00+00:00",
        },
    ]
    with TestClient(app) as client:
        _login(client)
        live = client.get("/cases").text
        assert "NOC-STALE" not in live
        assert "NOC-ACTION" in live

        history = client.get("/cases?scope=all").text
        assert "NOC-STALE" in history
        assert "NOC-ACTION" in history


def test_case_live_freshness_uses_latest_case_timestamp() -> None:
    now = datetime(2026, 7, 1, tzinfo=UTC)
    assert _case_is_live(
        {"status": "investigating", "updated_at": "2026-06-30T12:00:00+00:00"},
        now=now,
        max_age_hours=24,
    )
    assert not _case_is_live(
        {"status": "investigating", "updated_at": "2026-06-29T12:00:00+00:00"},
        now=now,
        max_age_hours=24,
    )
    assert _case_is_live(
        {"status": "handoff_requested", "updated_at": "2026-06-29T12:00:00+00:00"},
        now=now,
        max_age_hours=24,
    )


def test_knowledge_page_shows_timestamps_and_hides_resolved_case_artifacts_by_default(
    tmp_path: Path,
) -> None:
    app, _noc = _app(tmp_path)
    with TestClient(app) as client:
        _login(client)
        live = client.get("/knowledge").text
        assert "art-case-1" in live
        assert "art-case-old" not in live
        assert "2026-06-30T10:00:00+00:00" in live
        assert "2026-06-30T09:00:00+00:00" in live

        history = client.get("/knowledge?scope=all").text
        assert "art-case-1" in history
        assert "art-case-old" in history


def test_aggregate_pages_default_to_live_cases(tmp_path: Path) -> None:
    app, _noc = _app(tmp_path)
    with TestClient(app) as client:
        _login(client)
        handoffs = client.get("/handoffs").text
        assert "handoff-case-1" in handoffs
        assert "handoff-case-old" not in handoffs
        assert "handoff-case-old" in client.get("/handoffs?scope=all").text

        verification = client.get("/verification").text
        assert "case-1" in verification
        assert "case-old" not in verification
        assert "case-old" in client.get("/verification?scope=all").text


def test_cross_loop_timelines_group_knowledge_decision_memory(tmp_path: Path) -> None:
    db_path = tmp_path / "knowledge.sqlite"
    _write_loop_decision_db(db_path)
    app, _noc = _app(tmp_path, knowledge_export_db_path=str(db_path))
    with TestClient(app) as client:
        _login(client)
        body = client.get("/cross-loop").text
        assert "shared-fp" in body
        assert "soc" in body
        assert "stay_silent" in body
        assert "missing evidence: soc" in body

        response = client.get("/api/cross-loop/timelines?fingerprint=shared-fp")
        assert response.status_code == 200
        payload = response.json()
        timeline = payload["timelines"][0]
        assert timeline["fingerprint"] == "shared-fp"
        assert timeline["owner_loop"] == "soc"
        assert timeline["speak_loop"] is None
        assert timeline["silent_loops"] == ["soc"]
        assert timeline["missing_evidence_loops"] == ["soc"]
        assert timeline["shadow_mode"] is True
        assert timeline["suppression_applied"] is False


def _write_loop_decision_db(path: Path) -> None:
    conn = sqlite3.connect(path)
    try:
        conn.execute(
            """
            CREATE TABLE loop_decision_envelopes (
              envelope_id TEXT PRIMARY KEY,
              loop TEXT NOT NULL,
              created_at TEXT NOT NULL,
              fingerprint TEXT NOT NULL,
              decision TEXT NOT NULL,
              insight_id TEXT,
              case_id TEXT,
              meta_case_id TEXT,
              evidence_refs_json TEXT NOT NULL DEFAULT '[]',
              proposed_action_json TEXT NOT NULL DEFAULT '{}',
              human_outcome_json TEXT NOT NULL DEFAULT '{}',
              governance_json TEXT NOT NULL DEFAULT '{}',
              body_json TEXT NOT NULL
            )
            """
        )
        rows: list[dict[str, Any]] = [
            {
                "envelope_id": "env-noc",
                "loop": "noc",
                "created_at": "2026-07-02T10:00:00+00:00",
                "fingerprint": "shared-fp",
                "decision": "notify",
                "case_id": "case-noc",
                "evidence_refs_json": [{"kind": "fixture", "ref": "noc:evidence"}],
                "proposed_action_json": {"type": "ticket", "summary": "Open NOC case"},
                "governance_json": {"approval_tier": "operator", "sensitivity_class": "internal"},
                "body_json": {
                    "input_event": {"event_type": "alert", "source": "noc:test"},
                    "retrieved_context": [{"kind": "fixture", "ref": "knowledge:noc"}],
                },
            },
            {
                "envelope_id": "env-soc",
                "loop": "soc",
                "created_at": "2026-07-02T10:01:00+00:00",
                "fingerprint": "shared-fp",
                "decision": "stay_silent",
                "case_id": "case-soc",
                "evidence_refs_json": [],
                "proposed_action_json": {"type": "control_drift", "summary": "Security posture drift"},
                "governance_json": {"approval_tier": "senior", "sensitivity_class": "sensitive"},
                "body_json": {
                    "input_event": {"event_type": "control_drift", "source": "soc:test"},
                    "retrieved_context": [],
                },
            },
        ]
        for row in rows:
            conn.execute(
                """
                INSERT INTO loop_decision_envelopes (
                    envelope_id, loop, created_at, fingerprint, decision, insight_id,
                    case_id, meta_case_id, evidence_refs_json, proposed_action_json,
                    human_outcome_json, governance_json, body_json
                )
                VALUES (?, ?, ?, ?, ?, NULL, ?, NULL, ?, ?, '{}', ?, ?)
                """,
                (
                    row["envelope_id"],
                    row["loop"],
                    row["created_at"],
                    row["fingerprint"],
                    row["decision"],
                    row["case_id"],
                    json.dumps(row["evidence_refs_json"]),
                    json.dumps(row["proposed_action_json"]),
                    json.dumps(row["governance_json"]),
                    json.dumps(row["body_json"]),
                ),
            )
        conn.commit()
    finally:
        conn.close()


# --- insight inbox -----------------------------------------------------------


def _insight_decision(insight_id: str, *, sampling: str = "surfaced", action: str = "notify") -> dict[str, Any]:
    return {
        "record_type": "decision",
        "loop": "noc",
        "received_at": "2026-07-10T12:00:00+00:00",
        "record": {
            "insight_id": insight_id,
            "loop": "noc",
            "created_at": "2026-07-10T11:59:00+00:00",
            "fingerprint": f"fp-{insight_id}",
            "sampling_class": sampling,
            "candidate_type": "hotspot",
            "candidate_source": "proactive_scanner:disk_fill",
            "action_selected": action,
            "why_now": "disk trending toward full",
            "support_facts": ["disk free 5%"],
            "evidence_refs": [
                {"kind": "okf_concept", "ref": "curated/lessons/disk-retention", "authority": "A1"},
                {"kind": "telemetry_probe", "ref": "node_filesystem_avail"},
            ],
            "expected_utility": {"total": 0.4},
            "interruption_cost": {"total": 0.25},
            "budget_context": {"gate_reason": "within budget"},
        },
    }


class FakeInsightCollector(FakeCollector):
    def __init__(self) -> None:
        self.items: list[dict[str, Any]] = [
            _insight_decision("ins-surfaced"),
            _insight_decision("ins-withheld", sampling="withheld_logged", action="stay_silent"),
        ]
        self.posted: list[tuple[dict[str, Any], str]] = []

    async def insights(self, *, loop: str | None = None, record_type: str | None = None, since: str | None = None, limit: int = 200) -> list[dict[str, Any]]:
        return list(self.items)

    async def post_trace_event(self, event: dict[str, Any], *, token: str = "") -> dict[str, Any]:
        self.posted.append((event, token))
        return {"status": "stored", "event_id": "ev-1"}


def _insight_app(tmp_path: Path, *, actions: bool = False, enabled_actions: str | None = None) -> tuple[FastAPI, FakeInsightCollector]:
    app, _noc = _app(tmp_path, actions=actions, enabled_actions=enabled_actions)
    fake = FakeInsightCollector()
    app.state.collector = fake
    return app, fake


def test_insights_page_shows_withheld_by_default(tmp_path: Path) -> None:
    app, _fake = _insight_app(tmp_path)
    with TestClient(app) as client:
        _login(client)
        page = client.get("/insights")
        assert page.status_code == 200
        assert "ins-surfaced" in page.text
        assert "ins-withheld" in page.text
        assert "withheld_logged" in page.text

        sampled = client.get("/insights", params={"sample": "withheld"})
        assert "ins-withheld" in sampled.text
        assert "ins-surfaced" not in sampled.text


def test_insight_detail_renders_and_hides_label_form_when_disabled(tmp_path: Path) -> None:
    app, _fake = _insight_app(tmp_path)
    with TestClient(app) as client:
        _login(client)
        page = client.get("/insights/ins-surfaced")
        assert page.status_code == 200
        assert "curated/lessons/disk-retention" in page.text
        assert "Label this decision" not in page.text
        assert client.get("/insights/ins-missing").status_code == 404


def test_insight_label_action_gated_posts_contract_valid_label(tmp_path: Path) -> None:
    app, fake = _insight_app(tmp_path, actions=True, enabled_actions="insight_label")
    with TestClient(app) as client:
        csrf = _login(client)
        response = client.post(
            "/actions/insights/ins-surfaced/label",
            data={
                "csrf_token": csrf,
                "disposition": "accept",
                "comment": "good call",
                "idempotency_key": "idem-1",
            },
            follow_redirects=False,
        )
        assert response.status_code == 303
        assert len(fake.posted) == 1
        event, _token = fake.posted[0]
        assert event["event_type"] == "insight_label"
        label = event["payload"]["insight_label"]
        from agent_core.contracts import InsightLabel

        validated = InsightLabel.model_validate(label)
        assert validated.reference_action == "notify"
        assert validated.feedback["disposition"] == "accept"
        # affirming the insight affirms its OKF citations as gold evidence
        assert [ref.ref for ref in validated.evidence_refs] == ["curated/lessons/disk-retention"]

        # idempotent double-post does not re-send
        again = client.post(
            "/actions/insights/ins-surfaced/label",
            data={"csrf_token": csrf, "disposition": "accept", "idempotency_key": "idem-1"},
            follow_redirects=False,
        )
        assert again.status_code == 303
        assert len(fake.posted) == 1


def test_insight_label_dismiss_maps_to_stay_silent_reference(tmp_path: Path) -> None:
    app, fake = _insight_app(tmp_path, actions=True, enabled_actions="insight_label")
    with TestClient(app) as client:
        csrf = _login(client)
        client.post(
            "/actions/insights/ins-surfaced/label",
            data={"csrf_token": csrf, "disposition": "dismiss", "idempotency_key": "idem-2"},
            follow_redirects=False,
        )
        label = fake.posted[0][0]["payload"]["insight_label"]
        assert label["reference_action"] == "stay_silent"
        assert label["evidence_refs"] == []


def test_insight_label_action_denied_when_not_enabled(tmp_path: Path) -> None:
    app, fake = _insight_app(tmp_path, actions=True, enabled_actions="feedback")
    with TestClient(app) as client:
        csrf = _login(client)
        response = client.post(
            "/actions/insights/ins-surfaced/label",
            data={"csrf_token": csrf, "disposition": "accept"},
            follow_redirects=False,
        )
        assert response.status_code == 403
        assert fake.posted == []
