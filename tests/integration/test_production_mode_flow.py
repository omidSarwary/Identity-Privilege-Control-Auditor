"""Integration tests for the production-mode application flow."""

from __future__ import annotations

from pathlib import Path

import app
from src.core.bootstrap import BootstrapStatus
from src.core.environment import EnvironmentStatus
from src.reporting.report_writer import write_reports
import src.utils.safe_exit as safe_exit_module


def _bootstrap_status() -> BootstrapStatus:
    """Build a healthy bootstrap result so production flow tests stay focused."""
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


def _analysis_result(run_id: str, mode: str) -> dict[str, object]:
    """Build a minimal analysis result used by the production-mode tests."""
    return {
        "run_id": run_id,
        "mode": mode,
        "data_sources": {},
        "data_quality": {"valid": True, "warnings": [], "errors": [], "sources": {}},
        "findings": [],
        "summary": {"counts": {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}, "identities": []},
    }


def _report_paths(output_root: Path) -> dict[str, Path]:
    """Return the report paths generated under the temporary output root."""
    return {
        "text_report": output_root / "reports" / "final_identity_risk_report.txt",
        "executive_summary": output_root / "reports" / "executive_summary.txt",
        "json_report": output_root / "reports" / "final_identity_risk_report.json",
        "alerts_json": output_root / "data" / "alerts" / "alerts.json",
        "critical_alerts_log": output_root / "logs" / "critical_alerts.log",
    }


def test_linux_production_mode_shows_manual_windows_guidance_and_generates_reports(monkeypatch, tmp_path) -> None:
    """Linux production mode should explain manual Windows evidence handling.

    The application should route to the Linux collector, keep the flow read
    only, and still generate reports when the collector succeeds.
    """
    fixed_run_id = "20260507-130000"
    captured_messages: list[str] = []

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
        lambda mode, **kwargs: {
            "platform": "linux",
            "mode": mode,
            "success": True,
            "missing_outputs": [],
            "expected_outputs": {"linux_identity": "data/collected/linux_identity.json"},
            "command": {"returncode": 0},
        },
    )
    monkeypatch.setattr(
        app,
        "collect_windows_data",
        lambda mode, **kwargs: (_ for _ in ()).throw(AssertionError("windows collector should not run for linux production mode")),
    )
    monkeypatch.setattr(
        app,
        "collect_fallback_data",
        lambda mode, **kwargs: (_ for _ in ()).throw(AssertionError("fallback should not run when Linux collector succeeds")),
    )
    monkeypatch.setattr(app, "run_identity_risk_engine", lambda mode, data_paths, run_id: _analysis_result(run_id, mode))
    monkeypatch.setattr(app, "write_reports", lambda analysis_result: write_reports(analysis_result, output_root=tmp_path))
    monkeypatch.setattr(app, "print_message", lambda message: captured_messages.append(message))

    exit_code = app.main(["--mode", "linux", "--no-bootstrap"], input_func=lambda _: "linux")

    assert exit_code == 0
    assert any("Linux logs will be collected automatically" in message for message in captured_messages)
    assert any("Environment checks started." in message for message in captured_messages)
    assert any("Collecting Linux evidence." in message for message in captured_messages)
    assert any("Reports generated." in message for message in captured_messages)
    assert _report_paths(tmp_path)["json_report"].exists()


def test_windows_production_mode_shows_manual_linux_guidance_and_safe_exits(monkeypatch) -> None:
    """Windows production mode should explain manual Linux evidence handling.

    When the collector fails and fallback cannot find usable evidence, the app
    must exit cleanly without a traceback in the user-facing flow.
    """
    captured_messages: list[str] = []

    monkeypatch.setattr(app, "load_app_config", lambda: {"project_name": "NordSec Identity & Privilege Control Auditor", "version": "0.2.0"})
    monkeypatch.setattr(app, "bootstrap_project", lambda perform_full_checks=True: _bootstrap_status())
    monkeypatch.setattr(
        app,
        "collect_linux_data",
        lambda mode, **kwargs: (_ for _ in ()).throw(AssertionError("linux collector should not run for windows production mode")),
    )
    monkeypatch.setattr(
        app,
        "collect_windows_data",
        lambda mode, **kwargs: {
            "platform": "windows",
            "mode": mode,
            "success": False,
            "missing_outputs": ["windows_identity.csv"],
            "expected_outputs": {"windows_identity": "data/collected/windows_identity.csv"},
            "command": {"returncode": 1},
        },
    )
    monkeypatch.setattr(
        app,
        "collect_fallback_data",
        lambda mode, **kwargs: {
            "mode": mode,
            "fallback_activated": True,
            "fallback_reason": "no usable data",
            "used_files": {},
            "missing_files": ["windows_identity.csv"],
            "no_data_found": True,
            "searched_directories": [],
            "sources": {},
            "payloads": {},
        },
    )
    monkeypatch.setattr(app, "run_identity_risk_engine", lambda *args, **kwargs: (_ for _ in ()).throw(AssertionError("engine should not run when no data exists")))
    monkeypatch.setattr(app, "write_reports", lambda *args, **kwargs: (_ for _ in ()).throw(AssertionError("reports should not be written when no data exists")))
    monkeypatch.setattr(app, "print_message", lambda message: captured_messages.append(message))
    monkeypatch.setattr(safe_exit_module, "print_message", lambda message: captured_messages.append(message))

    exit_code = app.main(["--mode", "windows", "--no-bootstrap"], input_func=lambda _: "windows")

    assert exit_code == 1
    assert any("Windows logs will be collected automatically" in message for message in captured_messages)
    assert any("No valid evidence files were found." in message for message in captured_messages)


def test_windows_production_mode_prefers_collector_outputs_over_incoming(monkeypatch, tmp_path) -> None:
    """Fresh collector outputs should be passed explicitly to analysis."""
    fixed_run_id = "20260507-130001"
    captured_messages: list[str] = []
    captured_data_paths: dict[str, object] = {}
    incoming_dir = tmp_path / "data" / "incoming"
    collected_dir = tmp_path / "data" / "collected"
    incoming_dir.mkdir(parents=True)
    collected_dir.mkdir(parents=True)
    incoming_identity = incoming_dir / "windows_identity.csv"
    collected_identity = collected_dir / "windows_identity.csv"
    incoming_identity.write_text("stale", encoding="utf-8")
    collected_identity.write_text("fresh", encoding="utf-8")

    monkeypatch.setattr(app, "create_run_id", lambda: fixed_run_id)
    monkeypatch.setattr(
        app,
        "load_app_config",
        lambda: {
            "project_name": "NordSec Identity & Privilege Control Auditor",
            "version": "0.2.0",
            "paths": {"incoming": str(incoming_dir), "collected": str(collected_dir)},
        },
    )
    monkeypatch.setattr(app, "bootstrap_project", lambda perform_full_checks=True: _bootstrap_status())
    monkeypatch.setattr(
        app,
        "load_json_file",
        lambda path: {"paths": {"incoming": str(incoming_dir), "collected": str(collected_dir)}},
    )
    monkeypatch.setattr(
        app,
        "collect_linux_data",
        lambda mode, **kwargs: (_ for _ in ()).throw(AssertionError("linux collector should not run for windows production mode")),
    )
    monkeypatch.setattr(
        app,
        "collect_windows_data",
        lambda mode, **kwargs: {
            "platform": "windows",
            "mode": mode,
            "success": True,
            "missing_outputs": [],
            "expected_outputs": {"windows_identity": str(collected_identity)},
            "command": {"returncode": 0, "stderr_summary": ""},
            "reason": "completed successfully",
            "output_statuses": {
                "windows_identity": {"status": "collected", "reason": "output file created", "path": str(collected_identity)}
            },
        },
    )
    monkeypatch.setattr(
        app,
        "collect_fallback_data",
        lambda mode, **kwargs: (_ for _ in ()).throw(AssertionError("fallback should not run when collector outputs are usable")),
    )
    def _run_identity_risk_engine(mode, data_paths, run_id):
        captured_data_paths.update(data_paths)
        return _analysis_result(run_id, mode)

    monkeypatch.setattr(app, "run_identity_risk_engine", _run_identity_risk_engine)
    monkeypatch.setattr(app, "write_reports", lambda analysis_result: write_reports(analysis_result, output_root=tmp_path))
    monkeypatch.setattr(app, "print_message", lambda message: captured_messages.append(message))
    monkeypatch.setattr(safe_exit_module, "print_message", lambda message: captured_messages.append(message))

    exit_code = app.main(["--mode", "windows", "--no-bootstrap"], input_func=lambda _: "windows")

    assert exit_code == 0
    assert any("Fallback used: No." in message for message in captured_messages)
    assert captured_data_paths["windows_identity"] == str(collected_identity)
    assert _report_paths(tmp_path)["json_report"].exists()
