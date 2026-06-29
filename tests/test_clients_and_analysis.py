from __future__ import annotations

from agentic_observatory.analysis import build_change_impact_report
from agentic_observatory.clients import build_loop_signature


def test_loop_console_signature_is_deterministic() -> None:
    first = build_loop_signature(secret="shared", method="get", path="/loop-console/v1/health", timestamp="2026-01-01T00:00:00Z", body={})
    second = build_loop_signature(secret="shared", method="GET", path="/loop-console/v1/health", timestamp="2026-01-01T00:00:00Z", body={})
    assert first == second
    assert len(first) == 64


def test_balanced_scorecard_better_and_safety_regression() -> None:
    better = build_change_impact_report(
        "chg-good",
        {
            "baseline_cycle_time": 20,
            "observed_cycle_time": 10,
            "baseline_ci_pass_rate": 0.8,
            "observed_ci_pass_rate": 0.95,
            "baseline_rollback_rate": 0.02,
            "observed_rollback_rate": 0.02,
        },
    )
    assert better.verdict == "better"
    worse = build_change_impact_report(
        "chg-bad",
        {
            "baseline_cycle_time": 10,
            "observed_cycle_time": 8,
            "baseline_rollback_rate": 0.01,
            "observed_rollback_rate": 0.20,
        },
    )
    assert worse.verdict == "worse"
