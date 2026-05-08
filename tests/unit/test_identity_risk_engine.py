"""Tests for evidence-source selection in the identity risk engine."""

from __future__ import annotations

import shutil
from pathlib import Path

from src.analysis.identity_risk_engine import load_analysis_inputs, run_identity_risk_engine


BASELINE_DIR = Path(__file__).resolve().parents[2] / "config" / "baselines"
MOCKDATA_DIR = Path(__file__).resolve().parents[1] / "mockdata"


def _write_minimal_windows_sources(directory: Path) -> dict[str, Path]:
    """Create valid Windows CSV sources for production engine tests."""
    directory.mkdir(parents=True, exist_ok=True)
    identity = directory / "windows_identity.csv"
    events = directory / "windows_events.csv"
    policy = directory / "windows_policy.csv"
    identity.write_text(
        "ComputerName,CollectionTime,Username,Enabled,IsLocalAdmin,LastLogon,Source\n"
        "WIN-PROD-01,2026-05-08T03:00:00Z,normal_user,True,False,2026-05-08T02:00:00Z,collector\n",
        encoding="utf-8",
    )
    events.write_text(
        "ComputerName,TimeCreated,EventId,TargetUserName,IpAddress,EventType\n",
        encoding="utf-8",
    )
    policy.write_text(
        "ComputerName,CheckName,Status,Value,RiskHint\n"
        "WIN-PROD-01,firewall_enabled,True,Enabled,Expected\n"
        "WIN-PROD-01,audit_policy_enabled,True,Enabled,Expected\n"
        "WIN-PROD-01,execution_policy,True,RemoteSigned,Expected\n",
        encoding="utf-8",
    )
    return {
        "windows_identity": identity,
        "windows_events": events,
        "windows_policy": policy,
    }


def _data_paths(tmp_path: Path, *, collected: Path, incoming: Path) -> dict[str, str]:
    """Build an isolated production path map with real baseline files."""
    logdata = tmp_path / "logdata"
    (logdata / "linux").mkdir(parents=True, exist_ok=True)
    (logdata / "windows").mkdir(parents=True, exist_ok=True)
    return {
        "collected": str(collected),
        "incoming": str(incoming),
        "logdata": str(logdata),
        "baselines": str(BASELINE_DIR),
    }


def test_production_ignores_test_mode_linux_json_evidence(tmp_path) -> None:
    """Production loading must reject JSON evidence marked as test-mode data."""
    collected = tmp_path / "data" / "collected"
    incoming = tmp_path / "data" / "incoming"
    collected.mkdir(parents=True)
    incoming.mkdir(parents=True)
    shutil.copyfile(MOCKDATA_DIR / "linux_identity.json", collected / "linux_identity.json")
    shutil.copyfile(MOCKDATA_DIR / "linux_policy.json", collected / "linux_policy.json")
    windows_sources = _write_minimal_windows_sources(collected)

    paths = _data_paths(tmp_path, collected=collected, incoming=incoming)
    paths.update({name: str(path) for name, path in windows_sources.items()})

    inputs = load_analysis_inputs("production", paths)

    assert inputs["linux_identity"] == {}
    assert inputs["linux_policy"] == {}
    assert inputs["data_sources"]["linux_identity"]["valid"] is False
    assert inputs["data_sources"]["linux_policy"]["valid"] is False
    warnings = "\n".join(inputs["data_quality"]["warnings"])
    assert "Linux evidence file ignored because it was collected in test mode during a production run" in warnings


def test_windows_production_excludes_old_collected_linux_files_from_findings(tmp_path) -> None:
    """Ignored Linux collector artifacts must not create Linux sudo findings."""
    collected = tmp_path / "data" / "collected"
    incoming = tmp_path / "data" / "incoming"
    collected.mkdir(parents=True)
    incoming.mkdir(parents=True)
    linux_identity = collected / "linux_identity.json"
    linux_policy = collected / "linux_policy.json"
    shutil.copyfile(MOCKDATA_DIR / "linux_identity.json", linux_identity)
    shutil.copyfile(MOCKDATA_DIR / "linux_policy.json", linux_policy)
    windows_sources = _write_minimal_windows_sources(collected)

    paths = _data_paths(tmp_path, collected=collected, incoming=incoming)
    paths.update({name: str(path) for name, path in windows_sources.items()})
    paths["excluded_paths"] = [str(linux_identity), str(linux_policy)]

    result = run_identity_risk_engine("production", paths, run_id="20260508-030000")

    finding_text = "\n".join(f"{finding.get('identity')} {finding.get('finding')}" for finding in result["findings"])
    assert "unauthorized_sudo" not in finding_text
    assert "Unapproved Linux sudo user" not in finding_text
    assert result["data_sources"]["linux_identity"]["loaded"] is False


def test_manual_production_linux_evidence_from_incoming_remains_supported(tmp_path) -> None:
    """Manual cross-platform evidence in data/incoming should still be usable."""
    collected = tmp_path / "data" / "collected"
    incoming = tmp_path / "data" / "incoming"
    collected.mkdir(parents=True)
    incoming.mkdir(parents=True)
    (incoming / "linux_identity.json").write_text(
        """
{
  "source": "linux",
  "host": "manual-linux",
  "collection_time": "2026-05-08T03:00:00Z",
  "mode": "production",
  "users": [
    {
      "username": "manual_sudo",
      "enabled": true,
      "privileges": ["sudo"],
      "is_inactive": false,
      "last_login": "2026-05-08T02:00:00Z"
    }
  ],
  "sudo_users": ["manual_sudo"],
  "auth_events": [],
  "policy": {
    "ssh_policy": {
      "permit_root_login": "no",
      "password_authentication": "no",
      "pubkey_authentication": "yes"
    }
  },
  "collector_status": {
    "success": true
  }
}
""".strip(),
        encoding="utf-8",
    )
    (incoming / "linux_policy.json").write_text(
        """
{
  "source": "linux",
  "host": "manual-linux",
  "collection_time": "2026-05-08T03:00:00Z",
  "mode": "production",
  "policy": {
        "ssh_policy": {
          "permit_root_login": "no",
          "password_authentication": "no",
          "pubkey_authentication": "yes"
        }
      }
    }
""".strip(),
        encoding="utf-8",
    )
    windows_sources = _write_minimal_windows_sources(collected)

    paths = _data_paths(tmp_path, collected=collected, incoming=incoming)
    paths.update({name: str(path) for name, path in windows_sources.items()})
    paths["selected_platform"] = "windows"
    paths["manual_cross_evidence_included"] = "true"
    paths["manual_cross_evidence_platform"] = "linux"

    inputs = load_analysis_inputs("production", paths)

    assert inputs["linux_identity"]["host"] == "manual-linux"
    assert inputs["data_sources"]["linux_identity"]["loaded"] is True
    assert inputs["data_sources"]["linux_identity"]["valid"] is True


def test_windows_scope_without_manual_linux_marks_linux_sources_not_selected(tmp_path) -> None:
    """Windows-only production scope should not treat missing Linux as an error."""
    collected = tmp_path / "data" / "collected"
    incoming = tmp_path / "data" / "incoming"
    collected.mkdir(parents=True)
    incoming.mkdir(parents=True)
    windows_sources = _write_minimal_windows_sources(collected)

    paths = _data_paths(tmp_path, collected=collected, incoming=incoming)
    paths.update({name: str(path) for name, path in windows_sources.items()})
    paths["selected_platform"] = "windows"
    paths["manual_cross_evidence_included"] = False
    paths["manual_cross_evidence_platform"] = "none"

    inputs = load_analysis_inputs("production", paths)

    assert inputs["linux_identity"] == {}
    assert inputs["data_sources"]["linux_identity"]["not_selected"] is True
    assert inputs["data_sources"]["linux_identity"]["valid"] is True
    assert not any("linux_identity" in error for error in inputs["data_quality"]["errors"])

    result = run_identity_risk_engine("production", paths, run_id="20260508-040000")
    finding_text = "\n".join(finding.get("reason", "") for finding in result["findings"])
    assert "Linux SSH policy data was expected but not supplied" not in finding_text


def test_linux_scope_without_manual_windows_marks_windows_sources_not_selected(tmp_path) -> None:
    """Linux-only production scope should not treat missing Windows as an error."""
    collected = tmp_path / "data" / "collected"
    incoming = tmp_path / "data" / "incoming"
    collected.mkdir(parents=True)
    incoming.mkdir(parents=True)
    shutil.copyfile(MOCKDATA_DIR / "linux_identity.json", incoming / "linux_identity.json")
    shutil.copyfile(MOCKDATA_DIR / "linux_policy.json", incoming / "linux_policy.json")

    paths = _data_paths(tmp_path, collected=collected, incoming=incoming)
    paths["selected_platform"] = "linux"
    paths["manual_cross_evidence_included"] = False
    paths["manual_cross_evidence_platform"] = "none"

    production_inputs = load_analysis_inputs("production", paths)
    assert production_inputs["windows_identity_rows"] == []
    assert production_inputs["data_sources"]["windows_identity"]["not_selected"] is True
    assert production_inputs["data_sources"]["windows_identity"]["valid"] is True
    assert not any("windows_identity" in error for error in production_inputs["data_quality"]["errors"])

    result = run_identity_risk_engine("production", paths, run_id="20260508-040001")
    finding_text = "\n".join(finding.get("reason", "") for finding in result["findings"])
    assert "Windows policy data was expected but not supplied" not in finding_text
