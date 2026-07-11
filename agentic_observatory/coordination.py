"""Organization-wide Observatory view over the LHP-v2 coordinator."""

from __future__ import annotations

import asyncio
from collections import Counter
from datetime import UTC, datetime, timedelta
from typing import Any

from agent_core.contracts import ApprovalRecord, HandoffRecord
from agent_core.coordination import CoordinatorClient, CoordinatorError, LoopRequestSigner

from agentic_observatory.config import Settings

_SCOPE_PAYLOAD_KEYS = frozenset(
    {
        "probe_kind",
        "targets",
        "ports",
        "max_concurrency",
        "requests_per_second_per_target",
        "max_requests",
        "max_duration_seconds",
        "repository",
        "event_type",
        "producer",
        "subject",
        "status",
        "authority_tier",
    }
)
_SCOPE_CONSTRAINT_KEYS = frozenset(
    {
        "allowed_repository",
        "allowed_paths",
        "draft_pr_only",
        "production_mutation",
        "mutating_tools",
        "human_review_required",
        "direct_a1_a2_write",
        "no_raw_logs",
        "no_secrets",
        "max_result_bytes",
    }
)


class ObservatoryCoordinator:
    def __init__(self, client: CoordinatorClient | None, settings: Settings) -> None:
        self.client = client
        self.settings = settings

    @classmethod
    def from_settings(cls, settings: Settings) -> ObservatoryCoordinator:
        client: CoordinatorClient | None = None
        if settings.coordinator_available:
            client = CoordinatorClient(
                str(settings.coordinator_base_url),
                signer=LoopRequestSigner(
                    loop_id="observatory",
                    key_id=settings.coordinator_key_id,
                    secret=settings.coordinator_secret,
                ),
                timeout=settings.request_timeout_seconds,
            )
        return cls(client, settings)

    @property
    def available(self) -> bool:
        return self.client is not None

    def _client(self) -> CoordinatorClient:
        if self.client is None:
            raise CoordinatorError("coordinator is not configured")
        return self.client

    async def loops(self) -> list[dict[str, Any]]:
        return await self._client().loops()

    async def cases(self, **filters: Any) -> list[dict[str, Any]]:
        rows = await self._client().cases(**filters)
        return [row.model_dump(mode="json") for row in rows]

    async def handoffs(self, **filters: Any) -> list[dict[str, Any]]:
        records = await self._client().handoffs(**filters)
        return [handoff_row(record) for record in records]

    async def handoff(self, handoff_id: str) -> HandoffRecord:
        return await self._client().handoff(handoff_id)

    async def approvals(self) -> list[dict[str, Any]]:
        records = await self._client().approvals()
        return [handoff_row(record) for record in records]

    async def case_detail(self, case_id: str) -> dict[str, Any]:
        client = self._client()
        case = (await client.case(case_id)).model_dump(mode="json")
        records = await client.handoffs(case_id=case_id, limit=100)
        event_batches = await asyncio.gather(
            *(client.handoff_events(record.envelope.handoff_id) for record in records)
        )
        timeline = sorted(
            [event for batch in event_batches for event in batch],
            key=lambda event: str(event.get("created_at") or ""),
            reverse=True,
        )
        handoffs = [handoff_row(record) for record in records]
        objectives: list[dict[str, Any]] = []
        artifacts: list[dict[str, Any]] = []
        outcomes: list[dict[str, Any]] = []
        for record in records:
            if record.verification is not None:
                verification = record.verification
                objectives.append(
                    {
                        "objective_id": verification.verification_id,
                        "handoff_id": record.envelope.handoff_id,
                        "name": record.envelope.capability,
                        "status": verification.verdict,
                        "consecutive_pass_count": verification.consecutive_passes,
                        "required_consecutive_passes": verification.required_consecutive_passes,
                        "last_checked_at": verification.verified_at.isoformat(),
                        "evidence_ref": verification.summary,
                    }
                )
            elif record.status in {"result_submitted", "verification_pending"}:
                objectives.append(
                    {
                        "objective_id": f"verify:{record.envelope.handoff_id}",
                        "handoff_id": record.envelope.handoff_id,
                        "name": record.envelope.capability,
                        "status": "pending",
                        "consecutive_pass_count": 0,
                        "required_consecutive_passes": 1,
                    }
                )
            if record.result is None:
                continue
            outcomes.append(
                {
                    "outcome_id": record.result.result_id,
                    "action_taken": record.result.outcome,
                    "final_score": record.result.summary,
                    "created_at": record.result.completed_at.isoformat(),
                }
            )
            for ref in record.result.artifact_refs:
                artifacts.append(
                    {
                        "artifact_id": ref.ref,
                        "case_id": case_id,
                        "artifact_type": ref.kind or "handoff_artifact",
                        "review_status": ref.review_status or "",
                        "summary": record.result.summary,
                        "created_at": record.result.completed_at.isoformat(),
                    }
                )
        return {
            "case": case,
            "counts": {
                "timeline": len(timeline),
                "handoffs": len(handoffs),
                "verification_objectives": len(objectives),
                "knowledge_artifacts": len(artifacts),
                "outcomes": len(outcomes),
            },
            "timeline_limit": 200,
            "timeline": timeline[:200],
            "handoffs": handoffs,
            "verification_objectives": objectives,
            "knowledge_artifacts": artifacts,
            "outcomes": outcomes,
        }

    async def decide(
        self,
        record: HandoffRecord,
        *,
        decision: str,
        actor_id: str,
        actor_login: str,
        actor_role: str,
        rationale: str,
    ) -> HandoffRecord:
        if decision not in {"approved", "rejected"}:
            raise ValueError("unsupported approval decision")
        expires_at = datetime.now(UTC) + timedelta(
            seconds=max(60, min(self.settings.approval_ttl_seconds, 24 * 60 * 60))
        )
        return await self._client().approve(
            ApprovalRecord(
                handoff_id=record.envelope.handoff_id,
                scope_hash=record.envelope.scope_hash,
                decision=decision,  # type: ignore[arg-type]
                approver_id=actor_id,
                approver_login=actor_login,
                approver_role=actor_role,  # type: ignore[arg-type]
                rationale=rationale,
                expires_at=expires_at,
            )
        )

    async def cancel(self, handoff_id: str, reason: str) -> HandoffRecord:
        return await self._client().cancel(handoff_id, reason)

    async def topology(self) -> dict[str, Any]:
        loops, records = await asyncio.gather(
            self.loops(), self._client().handoffs(limit=500)
        )
        counts = Counter(
            (record.envelope.source_loop, record.envelope.target_loop)
            for record in records
        )
        capabilities: dict[tuple[str, str], set[str]] = {}
        for record in records:
            key = (record.envelope.source_loop, record.envelope.target_loop)
            capabilities.setdefault(key, set()).add(record.envelope.capability)
        return {
            "nodes": loops,
            "edges": [
                {
                    "source": source,
                    "target": target,
                    "handoff_count": count,
                    "capabilities": sorted(capabilities[(source, target)]),
                }
                for (source, target), count in sorted(counts.items())
            ],
        }


def handoff_row(record: HandoffRecord) -> dict[str, Any]:
    envelope = record.envelope
    approved_scope = {
        **{
            key: value
            for key, value in envelope.payload.items()
            if key in _SCOPE_PAYLOAD_KEYS
        },
        **{
            key: value
            for key, value in envelope.constraints.items()
            if key in _SCOPE_CONSTRAINT_KEYS
        },
    }
    return {
        "handoff_id": envelope.handoff_id,
        "case_id": envelope.case_id,
        "source_loop": envelope.source_loop,
        "target_loop": envelope.target_loop,
        "capability": envelope.capability,
        "intent": envelope.intent,
        "objective": envelope.intent or envelope.summary,
        "summary": envelope.summary,
        "risk_level": envelope.risk_level,
        "approval_tier": envelope.approval_tier,
        "scope_hash": envelope.scope_hash,
        "approved_scope": approved_scope,
        "status": record.status,
        "claim_owner": record.claim_owner,
        "lease_expires_at": (
            record.lease_expires_at.isoformat() if record.lease_expires_at else ""
        ),
        "created_at": envelope.created_at.isoformat(),
        "updated_at": record.updated_at.isoformat(),
        "approval": record.approval.model_dump(mode="json") if record.approval else {},
        "result_summary": record.result.summary if record.result else "",
        "artifact_refs": (
            [
                {
                    "ref": ref.ref,
                    "kind": ref.kind or "handoff_artifact",
                    "authority": ref.authority or "",
                    "review_status": ref.review_status or "",
                }
                for ref in record.result.artifact_refs
            ]
            if record.result
            else []
        ),
        "verification_verdict": (
            record.verification.verdict if record.verification else ""
        ),
        "verification_summary": (
            record.verification.summary if record.verification else ""
        ),
        "consecutive_passes": (
            record.verification.consecutive_passes if record.verification else 0
        ),
        "required_consecutive_passes": (
            record.verification.required_consecutive_passes
            if record.verification
            else 1
        ),
        "verified_at": (
            record.verification.verified_at.isoformat() if record.verification else ""
        ),
    }
