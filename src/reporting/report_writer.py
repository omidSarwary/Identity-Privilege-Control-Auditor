"""Report writing helpers for text and JSON outputs."""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any, Mapping

from src.reporting.alert_writer import write_alert_outputs
from src.reporting.json_report import write_json_report
from src.reporting.text_report import write_executive_summary, write_text_report


LOGGER = logging.getLogger("nordsec.ipca.reporting.report_writer")


def write_reports(analysis_result: Mapping[str, Any], output_root: Path | None = None) -> dict[str, Path]:
    """Write all report and alert artifacts for one analysis result.

    Expects the structured output of the risk engine and an optional output
    root. The function returns a dictionary of artifact paths so callers can log
    or verify the generated files without re-reading the filesystem.
    """
    text_report_path = write_text_report(analysis_result, output_root=output_root)
    executive_summary_path = write_executive_summary(analysis_result, output_root=output_root)
    json_report_path = write_json_report(analysis_result, output_root=output_root)
    alert_paths = write_alert_outputs(analysis_result, output_root=output_root)

    artifact_paths = {
        "text_report": text_report_path,
        "executive_summary": executive_summary_path,
        "json_report": json_report_path,
        **alert_paths,
    }
    LOGGER.info("Wrote report artifacts: %s", ", ".join(f"{key}={value}" for key, value in artifact_paths.items()))
    return artifact_paths
