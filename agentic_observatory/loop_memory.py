from __future__ import annotations

import json
import sqlite3
from collections import defaultdict
from pathlib import Path
from typing import Any

from agent_core.arbiter import arbitrate_cross_loop_event  # type: ignore[import-untyped]

LOOP_ORDER = ("soc", "noc", "engineering", "knowledge")


class KnowledgeLoopMemory:
    def __init__(self, db_path: str | Path | None) -> None:
        self.db_path = _coerce_db_path(db_path)

    def status(self) -> dict[str, Any]:
        if self.db_path is None:
            return {
                "configured": False,
                "available": False,
                "path": "",
                "reason": "OBSERVATORY_KNOWLEDGE_EXPORT_DB_PATH is not configured.",
            }
        if not self.db_path.exists():
            return {
                "configured": True,
                "available": False,
                "path": str(self.db_path),
                "reason": "Knowledge export database does not exist.",
            }
        try:
            available = self._has_loop_decision_table()
        except sqlite3.Error as exc:
            return {
                "configured": True,
                "available": False,
                "path": str(self.db_path),
                "reason": str(exc),
            }
        return {
            "configured": True,
            "available": available,
            "path": str(self.db_path),
            "reason": "" if available else "Knowledge export lacks loop_decision_envelopes.",
        }

    def timelines(self, *, fingerprint: str | None = None, limit: int = 100) -> list[dict[str, Any]]:
        if not self.status()["available"]:
            return []
        return build_cross_loop_timelines(self._rows(fingerprint=fingerprint, limit=limit))

    def _has_loop_decision_table(self) -> bool:
        if self.db_path is None:
            return False
        conn = sqlite3.connect(self.db_path)
        try:
            row = conn.execute(
                """
                SELECT 1
                FROM sqlite_master
                WHERE type = 'table' AND name = 'loop_decision_envelopes'
                """
            ).fetchone()
            return row is not None
        finally:
            conn.close()

    def _rows(self, *, fingerprint: str | None, limit: int) -> list[dict[str, Any]]:
        if self.db_path is None:
            return []
        clauses = ["fingerprint != ''"]
        params: list[Any] = []
        if fingerprint:
            clauses = ["fingerprint = ?"]
            params.append(fingerprint)
        params.append(max(1, min(limit, 500)))
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        try:
            rows = conn.execute(
                f"""
                SELECT envelope_id, loop, created_at, fingerprint, decision, insight_id,
                       case_id, meta_case_id, evidence_refs_json, proposed_action_json,
                       human_outcome_json, governance_json, body_json
                FROM loop_decision_envelopes
                WHERE {' AND '.join(clauses)}
                ORDER BY created_at DESC, envelope_id ASC
                LIMIT ?
                """,
                params,
            ).fetchall()
        finally:
            conn.close()
        return [_decode_row(row) for row in rows]


def build_cross_loop_timelines(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    by_fingerprint: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for row in rows:
        fingerprint = str(row.get("fingerprint") or "")
        if fingerprint:
            by_fingerprint[fingerprint].append(row)

    timelines = [
        _build_timeline(fingerprint, grouped)
        for fingerprint, grouped in by_fingerprint.items()
    ]
    return sorted(timelines, key=lambda item: str(item.get("updated_at") or ""), reverse=True)


def _build_timeline(fingerprint: str, rows: list[dict[str, Any]]) -> dict[str, Any]:
    ordered = sorted(rows, key=lambda item: str(item.get("created_at") or ""), reverse=True)
    evidence_refs = []
    for row in ordered:
        evidence_refs.extend(_as_list(row.get("evidence_refs")))
    arbiter_decision = arbitrate_cross_loop_event(
        event_fingerprint=fingerprint,
        candidates=[_arbiter_candidate(row) for row in ordered],
        evidence_refs=evidence_refs,
    ).model_dump(mode="json")
    speaking_loops = _ordered_unique(
        str(row.get("loop") or "")
        for row in ordered
        if str(row.get("decision") or "") != "stay_silent"
    )
    silent_loops = _ordered_unique(
        str(row.get("loop") or "")
        for row in ordered
        if str(row.get("decision") or "") == "stay_silent"
    )
    missing_evidence_loops = _ordered_unique(
        str(row.get("loop") or "")
        for row in ordered
        if not _as_list(row.get("evidence_refs"))
    )
    decisions = _ordered_unique(str(row.get("decision") or "") for row in ordered)
    return {
        "fingerprint": fingerprint,
        "updated_at": str(ordered[0].get("created_at") or "") if ordered else "",
        "record_count": len(ordered),
        "loops": _ordered_unique(str(row.get("loop") or "") for row in ordered),
        "decisions": decisions,
        "owner_loop": arbiter_decision.get("owner_loop"),
        "speak_loop": arbiter_decision.get("speak_loop"),
        "selected_action": arbiter_decision.get("selected_action"),
        "case_ids": arbiter_decision.get("related_case_ids", []),
        "silent_loops": silent_loops,
        "speaking_loops": speaking_loops,
        "missing_evidence_loops": missing_evidence_loops,
        "duplicate_speech": len(speaking_loops) > 1,
        "disagreement": len(decisions) > 1 or len(speaking_loops) > 1,
        "shadow_mode": True,
        "suppression_applied": False,
        "arbiter_decision": arbiter_decision,
        "records": [_display_record(row) for row in ordered],
    }


def _decode_row(row: sqlite3.Row) -> dict[str, Any]:
    result = dict(row)
    for key in (
        "evidence_refs_json",
        "proposed_action_json",
        "human_outcome_json",
        "governance_json",
        "body_json",
    ):
        output_key = key.removesuffix("_json")
        result[output_key] = _json_value(result.pop(key), [] if key == "evidence_refs_json" else {})
    return result


def _display_record(row: dict[str, Any]) -> dict[str, Any]:
    body = _as_dict(row.get("body"))
    governance = _as_dict(row.get("governance"))
    return {
        "envelope_id": row.get("envelope_id", ""),
        "loop": row.get("loop", ""),
        "created_at": row.get("created_at", ""),
        "decision": row.get("decision", ""),
        "case_id": row.get("case_id", ""),
        "meta_case_id": row.get("meta_case_id", ""),
        "insight_id": row.get("insight_id", ""),
        "evidence_count": len(_as_list(row.get("evidence_refs"))),
        "context_count": len(_as_list(body.get("retrieved_context"))),
        "proposed_action": _proposed_action_label(row.get("proposed_action")),
        "approval_tier": governance.get("approval_tier", ""),
        "sensitivity_class": governance.get("sensitivity_class", ""),
        "never_learn": governance.get("never_learn", False),
    }


def _arbiter_candidate(row: dict[str, Any]) -> dict[str, Any]:
    body = _as_dict(row.get("body"))
    input_event = _as_dict(body.get("input_event"))
    proposed = _as_dict(row.get("proposed_action"))
    return {
        "loop": row.get("loop"),
        "action_selected": row.get("decision"),
        "case_id": row.get("case_id") or body.get("case_id"),
        "meta_case_id": row.get("meta_case_id") or body.get("meta_case_id"),
        "candidate_type": _first_text(
            body.get("candidate_type"),
            input_event.get("type"),
            input_event.get("event_type"),
            proposed.get("type"),
        ),
        "candidate_source": _first_text(
            body.get("candidate_source"),
            input_event.get("source"),
            body.get("policy_version"),
        ),
        "why_now": _first_text(body.get("why_now"), proposed.get("summary"), proposed.get("description")),
        "proposed_action": proposed,
    }


def _coerce_db_path(value: str | Path | None) -> Path | None:
    text = str(value or "").strip()
    if not text:
        return None
    if text.startswith("sqlite:///"):
        text = text.removeprefix("sqlite:///")
    return Path(text).expanduser()


def _json_value(value: Any, default: Any) -> Any:
    if value is None:
        return default
    try:
        return json.loads(str(value))
    except json.JSONDecodeError:
        return default


def _as_dict(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _as_list(value: Any) -> list[Any]:
    return value if isinstance(value, list) else []


def _first_text(*values: Any) -> str:
    for value in values:
        text = str(value or "").strip()
        if text:
            return text
    return ""


def _ordered_unique(values: Any) -> list[str]:
    seen: set[str] = set()
    ordered: list[str] = []
    for value in values:
        text = str(value or "")
        if not text or text in seen:
            continue
        seen.add(text)
        ordered.append(text)
    return sorted(ordered, key=_loop_key)


def _loop_key(value: str) -> tuple[int, str]:
    try:
        return (LOOP_ORDER.index(value), value)
    except ValueError:
        return (len(LOOP_ORDER), value)


def _proposed_action_label(value: Any) -> str:
    proposed = _as_dict(value)
    return _first_text(
        proposed.get("summary"),
        proposed.get("description"),
        proposed.get("action"),
        proposed.get("type"),
    )
