"""Alert export helpers for downstream integrations."""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any, Mapping

from src.core.paths import PROJECT_ROOT


LOGGER = logging.getLogger("nordsec.ipca.reporting.alert_writer")
ALERTS_FILE_NAME = "alerts.json"
CRITICAL_ALERTS_LOG_NAME = "critical_alerts.log"


def _resolve_output_root(output_root: Path | None) -> Path:
    """Resolve the directory that should receive alert artifacts."""
    return output_root if output_root is not None else PROJECT_ROOT


def _critical_findings(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Return only the critical findings for the critical alert log."""
    return [finding for finding in findings if str(finding.get("risk_level", "")).upper() == "CRITICAL"]


def write_alert_outputs(analysis_result: Mapping[str, Any], output_root: Path | None = None) -> dict[str, Path]:
    """Write alert artifacts and return their paths.

    Expects the analysis result from the risk engine and writes a machine-
    readable alert bundle plus a human-readable critical alert log. This layer
    does not make risk decisions; it only exports findings that already exist.
    """
    root = _resolve_output_root(output_root)
    alerts_dir = root / "data" / "alerts"
    logs_dir = root / "logs"
    alerts_dir.mkdir(parents=True, exist_ok=True)
    logs_dir.mkdir(parents=True, exist_ok=True)

    findings = list(analysis_result.get("findings", []))
    alerts_path = alerts_dir / ALERTS_FILE_NAME
    critical_log_path = logs_dir / CRITICAL_ALERTS_LOG_NAME

    alerts_payload = {
        "run_id": analysis_result.get("run_id", "unknown"),
        "mode": analysis_result.get("mode", "test"),
        "alert_count": len(findings),
        "alerts": findings,
    }
    alerts_path.write_text(json.dumps(alerts_payload, indent=2, sort_keys=True), encoding="utf-8")

    critical_findings = _critical_findings(findings)
    if critical_findings:
        log_lines = []
        for finding in critical_findings:
            log_lines.append(
                " | ".join(
                    [
                        str(finding.get("risk_level", "CRITICAL")),
                        str(finding.get("identity", "unknown")),
                        str(finding.get("finding", "n/a")),
                        str(finding.get("source", "n/a")),
                        str(finding.get("reason", "n/a")),
                    ]
                )
            )
        critical_log_path.write_text("\n".join(log_lines) + "\n", encoding="utf-8")
    else:
        critical_log_path.write_text("No critical findings.\n", encoding="utf-8")

    LOGGER.info("Wrote %s alerts and %s critical findings", len(findings), len(critical_findings))
    return {"alerts_json": alerts_path, "critical_alerts_log": critical_log_path}
