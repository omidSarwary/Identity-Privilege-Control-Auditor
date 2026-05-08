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


def _report_ready_result(*, fallback_used: bool, fallback_reason: str) -> dict[str, object]:
    """Build a report-ready analysis result with explicit fallback metadata."""
    analysis_result = _build_analysis_result()
    analysis_result["fallback_used"] = fallback_used
    analysis_result["fallback_reason"] = fallback_reason
    return analysis_result


def _platform_report_result(selected_platform: str) -> dict[str, object]:
    """Build report data with an explicit selected platform."""
    analysis_result = _report_ready_result(fallback_used=False, fallback_reason="collector output complete")
    analysis_result["mode"] = "test" if selected_platform == "test" else "production"
    analysis_result["selected_platform"] = selected_platform
    return analysis_result


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


def test_reports_show_fallback_used_when_metadata_is_true(tmp_path) -> None:
    """Report output should reflect that fallback was used in the run."""
    analysis_result = _report_ready_result(fallback_used=True, fallback_reason="mockdata used")

    artifacts = write_reports(analysis_result, output_root=tmp_path)
    text_report = artifacts["text_report"].read_text(encoding="utf-8")
    payload = json.loads(artifacts["json_report"].read_text(encoding="utf-8"))

    assert "Fallback used: Yes" in text_report
    assert payload["fallback_used"] is True
    assert payload["fallback_reason"] == "mockdata used"


def test_reports_show_fallback_used_when_metadata_is_false(tmp_path) -> None:
    """Report output should reflect when fallback was not needed."""
    analysis_result = _report_ready_result(fallback_used=False, fallback_reason="collector output complete")

    artifacts = write_reports(analysis_result, output_root=tmp_path)
    text_report = artifacts["text_report"].read_text(encoding="utf-8")
    payload = json.loads(artifacts["json_report"].read_text(encoding="utf-8"))

    assert "Fallback used: No" in text_report
    assert payload["fallback_used"] is False
    assert payload["fallback_reason"] == "collector output complete"


def test_text_and_json_reports_include_windows_selected_platform(tmp_path) -> None:
    """Production report metadata should distinguish platform from mode."""
    analysis_result = _platform_report_result("windows")

    artifacts = write_reports(analysis_result, output_root=tmp_path)
    text_report = artifacts["text_report"].read_text(encoding="utf-8")
    payload = json.loads(artifacts["json_report"].read_text(encoding="utf-8"))

    assert "Mode: production" in text_report
    assert "Platform selected: windows" in text_report
    assert payload["mode"] == "production"
    assert payload["selected_platform"] == "windows"


def test_text_and_json_reports_include_linux_selected_platform(tmp_path) -> None:
    """Linux production reports should show the selected Linux platform."""
    analysis_result = _platform_report_result("linux")

    artifacts = write_reports(analysis_result, output_root=tmp_path)
    text_report = artifacts["text_report"].read_text(encoding="utf-8")
    payload = json.loads(artifacts["json_report"].read_text(encoding="utf-8"))

    assert "Platform selected: linux" in text_report
    assert payload["selected_platform"] == "linux"


def test_text_and_json_reports_include_test_selected_platform(tmp_path) -> None:
    """Test reports should keep selected platform explicit as test."""
    analysis_result = _platform_report_result("test")

    artifacts = write_reports(analysis_result, output_root=tmp_path)
    text_report = artifacts["text_report"].read_text(encoding="utf-8")
    payload = json.loads(artifacts["json_report"].read_text(encoding="utf-8"))

    assert "Platform selected: test" in text_report
    assert payload["selected_platform"] == "test"
