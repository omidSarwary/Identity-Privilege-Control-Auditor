"""Text report generation helpers."""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Mapping, Sequence

from src.core.paths import PROJECT_ROOT


REPORT_FILE_NAME = "final_identity_risk_report.txt"
EXECUTIVE_SUMMARY_FILE_NAME = "executive_summary.txt"


def _resolve_output_root(output_root: Path | None) -> Path:
    """Resolve the directory that should receive report artifacts.

    The report writer supports tests and production runs by allowing an
    alternate root directory. When no root is provided, the project root is
    used so the final artifacts land in the expected repo folders.
    """
    return output_root if output_root is not None else PROJECT_ROOT


def _format_run_date(run_id: str | None) -> str:
    """Convert the run identifier into a human-readable UTC date string."""
    if not run_id:
        return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    try:
        return datetime.strptime(run_id, "%Y%m%d-%H%M%S").replace(tzinfo=timezone.utc).strftime(
            "%Y-%m-%d %H:%M:%S UTC"
        )
    except ValueError:
        return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")


def _is_fallback_used(data_quality: Mapping[str, Any] | None) -> bool:
    """Determine whether the analysis had to continue with partial evidence."""
    if not data_quality:
        return False
    if data_quality.get("errors"):
        return True
    return any(not source.get("loaded", False) or not source.get("valid", False) for source in data_quality.get("sources", {}).values())


def _source_lines(data_sources: Mapping[str, Mapping[str, Any]] | None) -> list[str]:
    """Format the source inventory so the report shows what evidence was used."""
    lines: list[str] = []
    for name, details in (data_sources or {}).items():
        status = "loaded" if details.get("loaded") else "missing"
        valid = "valid" if details.get("valid") else "needs review"
        path = details.get("path") or "n/a"
        lines.append(f"- {name}: {status}, {valid}, path={path}")
    return lines


def _group_findings_by_level(findings: Sequence[Mapping[str, Any]] | None) -> dict[str, list[Mapping[str, Any]]]:
    """Group findings by risk level so the report sections stay readable."""
    grouped = {"CRITICAL": [], "HIGH": [], "MEDIUM": [], "LOW": []}
    for finding in findings or []:
        level = str(finding.get("risk_level", "LOW")).upper()
        if level not in grouped:
            level = "LOW"
        grouped[level].append(finding)
    return grouped


def _format_finding(finding: Mapping[str, Any]) -> str:
    """Render one finding in a compact, report-friendly style."""
    return (
        f"- Identity: {finding.get('identity', 'unknown')}\n"
        f"  Finding: {finding.get('finding', 'n/a')}\n"
        f"  Reason: {finding.get('reason', 'n/a')}\n"
        f"  Source: {finding.get('source', 'n/a')}\n"
        f"  Recommended follow-up: {finding.get('recommended_action', 'n/a')}"
    )


def _format_level_section(title: str, findings: Sequence[Mapping[str, Any]]) -> str:
    """Render one risk-level section for the main report."""
    if not findings:
        return f"{title}\n- None observed.\n"
    body = "\n\n".join(_format_finding(finding) for finding in findings)
    return f"{title}\n{body}\n"


def _identity_rows(summary_identities: Sequence[Mapping[str, Any]] | None) -> list[str]:
    """Build rows for the identity risk table."""
    rows: list[str] = []
    for entry in summary_identities or []:
        findings = list(entry.get("findings", []))
        sources = sorted({str(finding.get("source", "n/a")) for finding in findings})
        rows.append(
            f"- {entry.get('identity', 'unknown')} | risk={entry.get('risk_level', 'LOW')} | "
            f"findings={len(findings)} | sources={', '.join(sources) if sources else 'n/a'}"
        )
    return rows


def _select_policy_findings(findings: Sequence[Mapping[str, Any]] | None) -> list[Mapping[str, Any]]:
    """Pick policy-related findings for the dedicated report section."""
    selected: list[Mapping[str, Any]] = []
    for finding in findings or []:
        source = str(finding.get("source", "")).lower()
        text = f"{finding.get('finding', '')} {finding.get('reason', '')}".lower()
        if "policy" in source or "policy" in text or "firewall" in text or "ssh" in text:
            selected.append(finding)
    return selected


def _select_event_findings(findings: Sequence[Mapping[str, Any]] | None) -> list[Mapping[str, Any]]:
    """Pick event and log correlation findings for the dedicated section."""
    selected: list[Mapping[str, Any]] = []
    for finding in findings or []:
        source = str(finding.get("source", "")).lower()
        text = f"{finding.get('finding', '')} {finding.get('reason', '')}".lower()
        if source in {"events", "auth.log"} or "failed login" in text or "authentication" in text:
            selected.append(finding)
    return selected


def _recommended_follow_up(findings: Sequence[Mapping[str, Any]] | None) -> list[str]:
    """Collect unique follow-up actions so the report stays actionable."""
    actions: list[str] = []
    for finding in findings or []:
        action = str(finding.get("recommended_action", "")).strip()
        if action and action not in actions:
            actions.append(action)
    return actions


def _limitations_section(data_quality: Mapping[str, Any] | None) -> str:
    """Summarize data-quality limitations in plain language."""
    if not data_quality:
        return "11. Limitations\nNo data-quality limitations were recorded.\n"

    lines: list[str] = ["11. Limitations"]
    warnings = list(data_quality.get("warnings", []))
    errors = list(data_quality.get("errors", []))
    if warnings:
        lines.append("Warnings:")
        lines.extend(f"- {warning}" for warning in warnings)
    if errors:
        lines.append("Errors:")
        lines.extend(f"- {error}" for error in errors)
    if not warnings and not errors:
        lines.append("- No data-quality limitations were recorded.")
    return "\n".join(lines) + "\n"


def build_text_report(analysis_result: Mapping[str, Any]) -> str:
    """Build the full human-readable identity risk report.

    Expects the structured analysis result returned by the risk engine and
    returns a formatted text string. The function does not write files; it only
    prepares the report body so the writer layer can persist it.
    """
    run_id = str(analysis_result.get("run_id", "unknown"))
    mode = str(analysis_result.get("mode", "test"))
    data_sources = analysis_result.get("data_sources", {})
    data_quality = analysis_result.get("data_quality", {})
    findings = list(analysis_result.get("findings", []))
    summary = analysis_result.get("summary", {})
    summary_identities = summary.get("identities", []) if isinstance(summary, Mapping) else []
    grouped_findings = _group_findings_by_level(findings)

    lines = [
        "NORDSEC IDENTITY & PRIVILEGE CONTROL AUDIT REPORT",
        f"Run ID: {run_id}",
        f"Date: {_format_run_date(run_id)}",
        f"Mode: {mode}",
        f"Platform selected: {mode}",
        "Data sources used:",
        *(_source_lines(data_sources) or ["- None"]),
        f"Fallback used: {'Yes' if _is_fallback_used(data_quality) else 'No'}",
        "",
        "1. Executive Summary",
        f"Total findings: {len(findings)}",
        f"Critical: {summary.get('counts', {}).get('CRITICAL', 0)}",
        f"High: {summary.get('counts', {}).get('HIGH', 0)}",
        f"Medium: {summary.get('counts', {}).get('MEDIUM', 0)}",
        f"Low: {summary.get('counts', {}).get('LOW', 0)}",
        "",
        "2. Data Quality Summary",
    ]

    if data_quality.get("warnings"):
        lines.append("Warnings:")
        lines.extend(f"- {warning}" for warning in data_quality.get("warnings", []))
    else:
        lines.append("- No warnings recorded.")
    if data_quality.get("errors"):
        lines.append("Errors:")
        lines.extend(f"- {error}" for error in data_quality.get("errors", []))
    else:
        lines.append("- No errors recorded.")

    lines.extend(
        [
            "",
            _format_level_section("3. Critical Findings", grouped_findings["CRITICAL"]),
            _format_level_section("4. High Findings", grouped_findings["HIGH"]),
            _format_level_section("5. Medium Findings", grouped_findings["MEDIUM"]),
            _format_level_section("6. Low Findings", grouped_findings["LOW"]),
            "7. Identity Risk Table",
            *(_identity_rows(summary_identities) or ["- No identity summaries available."]),
            "",
            "8. Policy Deviations",
            *(
                [_format_finding(finding) for finding in _select_policy_findings(findings)] or ["- None observed."]
            ),
            "",
            "9. Log/Event Correlations",
            *(
                [_format_finding(finding) for finding in _select_event_findings(findings)] or ["- None observed."]
            ),
            "",
            "10. Recommended Follow-up",
            *(_recommended_follow_up(findings) or ["- No follow-up actions required."]),
            "",
            _limitations_section(data_quality).strip(),
        ]
    )

    return "\n".join(lines).replace("\n\n\n", "\n\n").rstrip() + "\n"


def build_executive_summary(analysis_result: Mapping[str, Any]) -> str:
    """Build the short executive summary companion report."""
    summary = analysis_result.get("summary", {}) if isinstance(analysis_result, Mapping) else {}
    counts = summary.get("counts", {}) if isinstance(summary, Mapping) else {}
    findings = list(analysis_result.get("findings", []))

    lines = [
        "NORDSEC IDENTITY & PRIVILEGE CONTROL EXECUTIVE SUMMARY",
        f"Run ID: {analysis_result.get('run_id', 'unknown')}",
        f"Mode: {analysis_result.get('mode', 'test')}",
        f"Total findings: {len(findings)}",
        f"Critical: {counts.get('CRITICAL', 0)}",
        f"High: {counts.get('HIGH', 0)}",
        f"Medium: {counts.get('MEDIUM', 0)}",
        f"Low: {counts.get('LOW', 0)}",
    ]

    top_findings = [finding for finding in findings if str(finding.get("risk_level", "")).upper() in {"CRITICAL", "HIGH"}]
    if top_findings:
        lines.append("")
        lines.append("Top findings:")
        for finding in top_findings[:5]:
            lines.append(f"- {finding.get('identity', 'unknown')}: {finding.get('finding', 'n/a')}")

    return "\n".join(lines).rstrip() + "\n"


def write_text_report(analysis_result: Mapping[str, Any], output_root: Path | None = None) -> Path:
    """Write the main text report to disk and return its path."""
    root = _resolve_output_root(output_root)
    report_path = root / "reports" / REPORT_FILE_NAME
    report_path.parent.mkdir(parents=True, exist_ok=True)
    report_path.write_text(build_text_report(analysis_result), encoding="utf-8")
    return report_path


def write_executive_summary(analysis_result: Mapping[str, Any], output_root: Path | None = None) -> Path:
    """Write the executive summary companion file and return its path."""
    root = _resolve_output_root(output_root)
    summary_path = root / "reports" / EXECUTIVE_SUMMARY_FILE_NAME
    summary_path.parent.mkdir(parents=True, exist_ok=True)
    summary_path.write_text(build_executive_summary(analysis_result), encoding="utf-8")
    return summary_path
