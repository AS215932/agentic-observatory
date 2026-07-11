from __future__ import annotations

from typing import Any

LOOP_DESCRIPTORS: list[dict[str, Any]] = [
    {
        "loop_id": "engineering",
        "trace_graph_id": "engineering-loop",
        "display_name": "Engineering Loop",
        "kind": "engineering",
        "status": "active",
        "service_name": "hyrule-engineering-loop.timer",
        "host": "loop",
        "capabilities": ["engineering.repository.analyze", "engineering.draft_pr"],
    },
    {
        "loop_id": "noc",
        "trace_graph_id": "noc-agent",
        "display_name": "NOC Agent",
        "kind": "noc",
        "status": "active",
        "service_name": "noc-agent.service",
        "host": "noc",
        "capabilities": ["noc.network_snapshot.read", "noc.network_change.prepare", "noc.verify"],
    },
    {
        "loop_id": "knowledge",
        "display_name": "Knowledge Loop",
        "kind": "knowledge",
        "status": "active",
        "service_name": "hyrule-knowledge-loop.timer",
        "host": "loop",
        "capabilities": ["knowledge.context.resolve", "knowledge.gap.analyze", "knowledge.learning.proposal"],
    },
    {
        "loop_id": "soc",
        "trace_graph_id": "soc-loop",
        "display_name": "SOC Agent",
        "kind": "soc",
        "status": "active",
        "service_name": "soc-agent.service",
        "host": "soc",
        "capabilities": ["security.triage", "security.attack_path", "security.verify", "soc.active_probe.rt2"],
    },
]


def normalize_loop_snapshots(
    collector_loops: list[dict[str, Any]],
    coordinator_loops: list[dict[str, Any]] | None = None,
) -> list[dict[str, Any]]:
    by_id = {str(item.get("loop_id") or item.get("graph_id") or item.get("id")): item for item in collector_loops}
    coordinated = {
        str(item.get("loop_id") or ""): item for item in coordinator_loops or []
    }
    rendered: list[dict[str, Any]] = []
    for descriptor in LOOP_DESCRIPTORS:
        live = by_id.get(descriptor["loop_id"]) or by_id.get(descriptor.get("trace_graph_id", "")) or {}
        registration = coordinated.get(descriptor["loop_id"], {})
        rendered.append(
            {
                **descriptor,
                **{
                    key: value
                    for key, value in registration.items()
                    if value is not None and value != ""
                },
                "status": registration.get("status") or live.get("status") or descriptor["status"],
                "active_run_id": live.get("active_run_id") or live.get("run_id") or "",
                "recent_action_count": live.get("recent_action_count") or live.get("event_count") or 0,
                "last_event_at": registration.get("last_heartbeat_at") or live.get("last_event_at") or live.get("received_at") or "",
                "summary": registration.get("summary") or live.get("summary") or descriptor.get("description") or "",
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
