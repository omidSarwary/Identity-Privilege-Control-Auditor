"""Risk scoring helpers for the identity and privilege audit model."""

from __future__ import annotations

from collections import Counter, defaultdict
from typing import Any, Iterable

from src.analysis.risk_rules import RISK_ORDER, RiskLevel


def summarize_findings(findings: Iterable[dict[str, Any]]) -> dict[str, Any]:
    """Summarize findings by identity and preserve the highest risk level.

    Expects an iterable of finding dictionaries and returns a structure with
    per-risk counts plus identity summaries. The highest severity wins for each
    identity because the final report should highlight the most urgent issue.
    """
    summary: dict[str, dict[str, Any]] = defaultdict(
        lambda: {"identity": "", "risk_level": RiskLevel.LOW.value, "findings": []}
    )
    counts = Counter({level.value: 0 for level in RiskLevel})

    for finding in findings:
        identity = str(finding.get("identity", "unknown"))
        risk_level = str(finding.get("risk_level", RiskLevel.LOW.value))
        # Unknown or malformed risk levels are treated as LOW so the summary can
        # continue safely instead of failing on unexpected input.
        if risk_level not in {level.value for level in RiskLevel}:
            risk_level = RiskLevel.LOW.value
        summary_entry = summary[identity]
        summary_entry["identity"] = identity
        summary_entry["findings"].append(finding)
        counts[risk_level] += 1

        current_level = RiskLevel(summary_entry["risk_level"])
        incoming_level = RiskLevel(risk_level)
        if RISK_ORDER[incoming_level] > RISK_ORDER[current_level]:
            summary_entry["risk_level"] = incoming_level.value

    return {
        "counts": {level.value: counts[level.value] for level in RiskLevel},
        "identities": list(summary.values()),
    }
