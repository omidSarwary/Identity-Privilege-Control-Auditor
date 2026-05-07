"""Tests for report and alert output generation."""

from __future__ import annotations

import json
from pathlib import Path

from src.analysis.identity_risk_engine import run_identity_risk_engine
from src.reporting.report_writer import write_reports


MOCKDATA_DIR = Path(__file__).resolve().parents[1] / "mockdata"
PROJECT_ROOT = Path(__file__).resolve().parents[2]
CONFIG_BASELINES_DIR = PROJECT_ROOT / "config" / "baselines"


def _build_analysis_result() -> dict[str, object]:
    """Build a realistic analysis result from the anonymous mock dataset."""
    return run_identity_risk_engine(
        mode="test",
        data_paths={
            "mockdata": MOCKDATA_DIR,
            "baselines": CONFIG_BASELINES_DIR,
        },
    )


def test_report_files_are_created_from_analysis_result(tmp_path) -> None:
    """The writer should create every required artifact for one analysis run.

    This protects the final output path contract used by the project report
    workflow and ensures the report layer stays decoupled from the engine.
    """
    analysis_result = _build_analysis_result()

    artifacts = write_reports(analysis_result, output_root=tmp_path)

    assert artifacts["text_report"].exists()
    assert artifacts["executive_summary"].exists()
    assert artifacts["json_report"].exists()
    assert artifacts["alerts_json"].exists()
    assert artifacts["critical_alerts_log"].exists()


def test_json_report_is_valid_json(tmp_path) -> None:
    """The JSON report should be machine-readable and preserve core fields.

    The report must remain valid JSON because later automation can parse it
    without relying on the text report.
    """
    analysis_result = _build_analysis_result()

    artifacts = write_reports(analysis_result, output_root=tmp_path)
    payload = json.loads(artifacts["json_report"].read_text(encoding="utf-8"))

    assert payload["run_id"] == analysis_result["run_id"]
    assert payload["mode"] == analysis_result["mode"]
    assert "summary" in payload
    assert "findings" in payload


def test_critical_findings_are_written_to_critical_alert_log(tmp_path) -> None:
    """Critical findings should be exported to the dedicated alert log.

    This verifies that the alert layer preserves the most urgent findings in a
    separate location that can be reviewed quickly.
    """
    analysis_result = _build_analysis_result()

    artifacts = write_reports(analysis_result, output_root=tmp_path)
    critical_log = artifacts["critical_alerts_log"].read_text(encoding="utf-8")

    assert "CRITICAL" in critical_log
    assert "disabled account" in critical_log.lower()
