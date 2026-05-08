"""JSON report generation helpers."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Mapping

from src.core.paths import PROJECT_ROOT


REPORT_FILE_NAME = "final_identity_risk_report.json"


def _resolve_output_root(output_root: Path | None) -> Path:
    """Resolve the directory that should receive report artifacts."""
    return output_root if output_root is not None else PROJECT_ROOT


def build_json_report_payload(analysis_result: Mapping[str, Any]) -> dict[str, Any]:
    """Build the JSON payload for the final report.

    The JSON report stays deliberately compact so it remains easy to parse in
    later automation steps and in the final project hand-in.
    """
    fallback_used = analysis_result.get("fallback_used")
    return {
        "run_id": analysis_result.get("run_id", "unknown"),
        "mode": analysis_result.get("mode", "test"),
        "selected_platform": analysis_result.get("selected_platform"),
        "fallback_used": bool(fallback_used) if fallback_used is not None else None,
        "fallback_reason": analysis_result.get("fallback_reason"),
        "summary": analysis_result.get("summary", {}),
        "findings": analysis_result.get("findings", []),
    }


def write_json_report(analysis_result: Mapping[str, Any], output_root: Path | None = None) -> Path:
    """Write the machine-readable report to disk and return its path."""
    root = _resolve_output_root(output_root)
    report_path = root / "reports" / REPORT_FILE_NAME
    report_path.parent.mkdir(parents=True, exist_ok=True)
    report_path.write_text(
        json.dumps(build_json_report_payload(analysis_result), indent=2, sort_keys=True),
        encoding="utf-8",
    )
    return report_path
