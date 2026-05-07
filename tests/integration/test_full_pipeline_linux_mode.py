"""Integration test for the full test-mode application pipeline."""

from __future__ import annotations

import json
from pathlib import Path

import app
from src.core.bootstrap import BootstrapStatus
from src.core.environment import EnvironmentStatus
from src.reporting.report_writer import write_reports


MOCKDATA_DIR = Path(__file__).resolve().parents[1] / "mockdata"


def _bootstrap_status() -> BootstrapStatus:
    """Build a healthy bootstrap result so the integration test can focus on the pipeline."""
    return BootstrapStatus(
        bootstrap_skipped=False,
        environment=EnvironmentStatus(
            python_ok=True,
            python_version="3.11.9",
            required_directories_ok=True,
            missing_directories=(),
            messages=(),
        ),
        requirements_file_present=True,
        requirements_file_nonempty=True,
        venv_active=True,
        messages=(),
    )


def test_test_mode_pipeline_uses_mockdata_and_writes_reports(monkeypatch, tmp_path) -> None:
    """Run the full read-only pipeline in ``--test`` mode and verify the outputs.

    The test keeps the application isolated by stubbing the bootstrap layer and
    redirecting report writes to a temporary directory. It then confirms that
    the fallback collector only used mock data and that the reporting layer
    produced the expected artifacts.
    """
    fixed_run_id = "20260507-120000"
    captured_fallback: dict[str, object] = {}

    real_fallback = app.collect_fallback_data

    def capture_fallback(mode: str) -> dict[str, object]:
        result = real_fallback(mode)
        captured_fallback["result"] = result
        return result

    monkeypatch.setattr(app, "create_run_id", lambda: fixed_run_id)
    monkeypatch.setattr(
        app,
        "load_app_config",
        lambda: {"project_name": "NordSec Identity & Privilege Control Auditor", "version": "0.2.0"},
    )
    monkeypatch.setattr(app, "bootstrap_project", lambda perform_full_checks=True: _bootstrap_status())
    monkeypatch.setattr(
        app,
        "collect_linux_data",
        lambda mode: (_ for _ in ()).throw(AssertionError("linux collector should not run in test mode")),
    )
    monkeypatch.setattr(
        app,
        "collect_windows_data",
        lambda mode: (_ for _ in ()).throw(AssertionError("windows collector should not run in test mode")),
    )
    monkeypatch.setattr(app, "collect_fallback_data", capture_fallback)
    monkeypatch.setattr(
        app,
        "write_reports",
        lambda analysis_result: write_reports(analysis_result, output_root=tmp_path),
    )
    monkeypatch.setattr(app, "print_message", lambda message: None)

    exit_code = app.main(["--test", "--no-bootstrap"], input_func=lambda _: "test")

    assert exit_code == 0

    fallback_result = captured_fallback["result"]
    assert fallback_result["searched_directories"] == [str(MOCKDATA_DIR)]
    assert fallback_result["no_data_found"] is False
    assert all(
        info["source_directory"].endswith("mockdata")
        for info in fallback_result["used_files"].values()
    )

    text_report = tmp_path / "reports" / "final_identity_risk_report.txt"
    json_report = tmp_path / "reports" / "final_identity_risk_report.json"
    executive_summary = tmp_path / "reports" / "executive_summary.txt"
    alerts_json = tmp_path / "data" / "alerts" / "alerts.json"
    critical_alerts_log = tmp_path / "logs" / "critical_alerts.log"

    assert text_report.exists()
    assert json_report.exists()
    assert executive_summary.exists()
    assert alerts_json.exists()
    assert critical_alerts_log.exists()

    payload = json.loads(json_report.read_text(encoding="utf-8"))
    assert payload["run_id"] == fixed_run_id
    assert payload["mode"] == "test"
    assert payload["findings"]
    assert payload["summary"]["counts"]["CRITICAL"] >= 1
