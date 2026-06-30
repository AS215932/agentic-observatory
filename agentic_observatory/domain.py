from __future__ import annotations

from typing import Any

LOOP_DESCRIPTORS: list[dict[str, Any]] = [
    {
        "loop_id": "engineering-loop",
        "display_name": "Engineering Loop",
        "kind": "engineering",
        "status": "active",
        "service_name": "hyrule-engineering-loop.timer",
        "host": "loop",
        "capabilities": ["code review", "PR publication", "LHP handoff handling"],
    },
    {
        "loop_id": "noc-agent",
        "display_name": "NOC Agent",
        "kind": "noc",
        "status": "active",
        "service_name": "noc-agent.service",
        "host": "noc",
        "capabilities": ["CaseService", "LHP-v1", "operator approval", "verification"],
    },
    {
        "loop_id": "knowledge",
        "display_name": "Knowledge Loop",
        "kind": "knowledge",
        "status": "active",
        "service_name": "hyrule-knowledge-loop.timer",
        "host": "loop",
        "capabilities": ["context packs", "knowledge artifacts", "learning ledger"],
    },
    {
        "loop_id": "hyperliquid-wave-supervisor",
        "display_name": "Hyperliquid Wave Supervisor",
        "kind": "other",
        "status": "idle",
        "service_name": "hyperliquid-trading-agent.service",
        "host": "trading",
        "capabilities": ["engine readiness observation", "LHP handoff rendering", "agent-core traces", "wave-gated verification"],
    },
    {
        "loop_id": "soc-loop",
        "display_name": "SOC Loop",
        "kind": "soc",
        "status": "disabled",
        "service_name": "future-soc-loop",
        "host": "future",
        "capabilities": ["placeholder", "security triage"],
    },
]


def normalize_loop_snapshots(collector_loops: list[dict[str, Any]]) -> list[dict[str, Any]]:
    by_id = {str(item.get("loop_id") or item.get("graph_id") or item.get("id")): item for item in collector_loops}
    rendered: list[dict[str, Any]] = []
    for descriptor in LOOP_DESCRIPTORS:
        live = by_id.get(descriptor["loop_id"]) or by_id.get(descriptor.get("trace_graph_id", "")) or {}
        rendered.append(
            {
                **descriptor,
                "status": live.get("status") or descriptor["status"],
                "active_run_id": live.get("active_run_id") or live.get("run_id") or "",
                "recent_action_count": live.get("recent_action_count") or live.get("event_count") or 0,
                "last_event_at": live.get("last_event_at") or live.get("received_at") or "",
                "summary": live.get("summary") or descriptor.get("description") or "",
            }
        )
    return rendered


def case_title(case: dict[str, Any]) -> str:
    return str(case.get("title") or case.get("summary") or case.get("case_id") or "case")


def extract_change_keys(runs: list[dict[str, Any]], actions: list[dict[str, Any]]) -> list[str]:
    keys: set[str] = set()
    for item in [*runs, *actions]:
        for key_name in ("change_id", "commit_sha"):
            value = item.get(key_name)
            if value:
                keys.add(str(value))
        repo = item.get("repository")
        pr_number = item.get("pr_number")
        if repo and pr_number:
            keys.add(f"{repo}#{pr_number}")
    return sorted(keys)
