from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Literal

Verdict = Literal["better", "worse", "mixed", "inconclusive"]
Direction = Literal["higher_is_better", "lower_is_better", "neutral"]


@dataclass(frozen=True)
class Metric:
    name: str
    baseline: float | None
    observed: float | None
    direction: Direction = "higher_is_better"
    weight: float = 1.0


@dataclass(frozen=True)
class ComponentScore:
    component: str
    score_delta: float
    verdict: Verdict
    metrics: list[Metric]


@dataclass(frozen=True)
class ChangeImpactReport:
    change_key: str
    verdict: Verdict
    total_delta: float
    components: list[ComponentScore]
    summary: str


def metric_delta(metric: Metric) -> float | None:
    if metric.baseline is None or metric.observed is None:
        return None
    if metric.baseline == 0:
        raw = 1.0 if metric.observed > 0 else 0.0
    else:
        raw = (metric.observed - metric.baseline) / abs(metric.baseline)
    if metric.direction == "lower_is_better":
        raw = -raw
    if metric.direction == "neutral":
        raw = 0.0
    return max(-25.0, min(25.0, raw * 100.0 * metric.weight))


def component_score(component: str, metrics: list[Metric]) -> ComponentScore:
    deltas = [delta for metric in metrics if (delta := metric_delta(metric)) is not None]
    if not deltas:
        return ComponentScore(component, 0.0, "inconclusive", metrics)
    score = sum(deltas) / max(1, len(deltas))
    if score >= 5:
        verdict: Verdict = "better"
    elif score <= -5:
        verdict = "worse"
    else:
        verdict = "inconclusive"
    return ComponentScore(component, round(score, 2), verdict, metrics)


def verdict_for_components(components: list[ComponentScore]) -> Verdict:
    if not components or all(component.verdict == "inconclusive" for component in components):
        return "inconclusive"
    total = sum(component.score_delta for component in components)
    safety = next((component for component in components if component.component == "safety"), None)
    positive = any(component.score_delta >= 5 for component in components)
    negative = any(component.score_delta <= -5 for component in components)
    if safety and safety.score_delta <= -10:
        return "worse"
    if positive and negative:
        return "mixed"
    if total >= 5 and (safety is None or safety.score_delta >= 0):
        return "better"
    if total <= -5:
        return "worse"
    return "inconclusive"


def build_change_impact_report(change_key: str, metrics: dict[str, Any] | None = None) -> ChangeImpactReport:
    data = metrics or {}
    components = [
        component_score(
            "speed",
            [
                Metric("cycle_time_minutes", data.get("baseline_cycle_time"), data.get("observed_cycle_time"), "lower_is_better"),
                Metric("handoff_latency_minutes", data.get("baseline_handoff_latency"), data.get("observed_handoff_latency"), "lower_is_better"),
            ],
        ),
        component_score(
            "quality",
            [
                Metric("ci_pass_rate", data.get("baseline_ci_pass_rate"), data.get("observed_ci_pass_rate")),
                Metric("verification_pass_rate", data.get("baseline_verification_pass_rate"), data.get("observed_verification_pass_rate")),
            ],
        ),
        component_score(
            "autonomy",
            [Metric("manual_retry_rate", data.get("baseline_manual_retry_rate"), data.get("observed_manual_retry_rate"), "lower_is_better")],
        ),
        component_score(
            "cost",
            [Metric("usd_per_success", data.get("baseline_usd_per_success"), data.get("observed_usd_per_success"), "lower_is_better")],
        ),
        component_score(
            "safety",
            [
                Metric("rollback_rate", data.get("baseline_rollback_rate"), data.get("observed_rollback_rate"), "lower_is_better", weight=1.5),
                Metric("invalid_transition_count", data.get("baseline_invalid_transitions"), data.get("observed_invalid_transitions"), "lower_is_better", weight=1.5),
            ],
        ),
    ]
    verdict = verdict_for_components(components)
    total = round(sum(component.score_delta for component in components), 2)
    return ChangeImpactReport(
        change_key=change_key,
        verdict=verdict,
        total_delta=total,
        components=components,
        summary=f"{change_key}: {verdict} ({total:+.1f} score delta)",
    )


def report_to_dict(report: ChangeImpactReport) -> dict[str, Any]:
    return {
        "change_key": report.change_key,
        "verdict": report.verdict,
        "total_delta": report.total_delta,
        "summary": report.summary,
        "components": [
            {
                "component": component.component,
                "score_delta": component.score_delta,
                "verdict": component.verdict,
                "metrics": [metric.__dict__ for metric in component.metrics],
            }
            for component in report.components
        ],
    }
