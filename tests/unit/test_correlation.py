"""Tests for identity, privilege, event, and policy correlation."""

from __future__ import annotations

from pathlib import Path

from src.analysis.anomaly_detection import detect_anomalies
from src.analysis.correlation import (
    correlate_events_to_identities,
    correlate_identity_privileges,
    correlate_policy_findings,
    normalize_identities,
)
from src.analysis.risk_rules import RiskLevel
from src.parsers.csv_loader import load_csv_file
from src.parsers.json_loader import load_json_file


MOCKDATA_DIR = Path(__file__).resolve().parents[1] / "mockdata"
PROJECT_ROOT = Path(__file__).resolve().parents[2]
CONFIG_BASELINES_DIR = PROJECT_ROOT / "config" / "baselines"


def _load_inputs() -> dict[str, object]:
    """Load the anonymous mock inputs used by the correlation tests.

    The helper keeps the test bodies small while still showing the full data
    path from mock files through parsers, correlation, and anomaly detection.
    """
    linux_identity = load_json_file(MOCKDATA_DIR / "linux_identity.json")
    linux_policy = load_json_file(MOCKDATA_DIR / "linux_policy.json")
    windows_identity_rows = load_csv_file(
        MOCKDATA_DIR / "windows_identity.csv",
        ["ComputerName", "CollectionTime", "Username", "Enabled", "IsLocalAdmin", "LastLogon", "Source"],
    )
    windows_events_rows = load_csv_file(
        MOCKDATA_DIR / "windows_events.csv",
        ["ComputerName", "TimeCreated", "EventId", "TargetUserName", "IpAddress", "EventType"],
    )
    windows_policy_rows = load_csv_file(
        MOCKDATA_DIR / "windows_policy.csv",
        ["ComputerName", "CheckName", "Status", "Value", "RiskHint"],
    )
    approved_linux_sudoers = load_csv_file(
        CONFIG_BASELINES_DIR / "approved_linux_sudoers.csv",
        ["username", "reason", "owner", "approved_until"],
    )
    approved_windows_admins = load_csv_file(
        CONFIG_BASELINES_DIR / "approved_windows_admins.csv",
        ["username", "reason", "owner", "approved_until"],
    )
    approved_service_accounts = load_csv_file(
        CONFIG_BASELINES_DIR / "approved_service_accounts.csv",
        ["username", "platform", "interactive_login_allowed", "owner"],
    )
    expected_policy_baseline = load_json_file(CONFIG_BASELINES_DIR / "expected_policy_baseline.json")

    normalized = normalize_identities(linux_identity, windows_identity_rows)
    privileged = correlate_identity_privileges(
        normalized,
        approved_linux_sudoers,
        approved_windows_admins,
        approved_service_accounts,
    )
    with_events = correlate_events_to_identities(privileged, linux_identity.get("auth_events", []), windows_events_rows)
    with_policy = correlate_policy_findings(
        with_events,
        linux_policy=linux_policy,
        windows_policy_rows=windows_policy_rows,
        expected_policy_baseline=expected_policy_baseline,
    )

    return {
        "records": with_policy,
        "linux_identity": linux_identity,
        "linux_policy": linux_policy,
        "windows_events_rows": windows_events_rows,
        "windows_policy_rows": windows_policy_rows,
        "approved_linux_sudoers": approved_linux_sudoers,
        "approved_windows_admins": approved_windows_admins,
        "approved_service_accounts": approved_service_accounts,
        "expected_policy_baseline": expected_policy_baseline,
    }


def _get_record(records: list[dict[str, object]], identity: str) -> dict[str, object]:
    """Return the normalized record for a specific identity.

    The tests use this helper to focus on one account at a time so each
    assertion clearly explains the correlation behavior being verified.
    """
    return next(record for record in records if record["identity"] == identity)


def test_linux_sudo_baseline_matches_correctly() -> None:
    """Approved Linux sudo users should be marked as baseline matches.

    This checks that approved privilege lists are respected before anomaly
    detection runs.
    """
    inputs = _load_inputs()
    record = _get_record(inputs["records"], "ops_backup")

    assert record["baseline_match"] is True
    assert "sudo" in record["privileges"]


def test_windows_admin_baseline_matches_correctly() -> None:
    """Approved Windows administrators should be marked as baseline matches.

    The Windows admin baseline is a separate trust source, so it must be
    matched independently of Linux sudo data.
    """
    inputs = _load_inputs()
    record = _get_record(inputs["records"], "adm_svc_win")

    assert record["baseline_match"] is True
    assert "local_admin" in record["privileges"]


def test_disabled_account_with_failed_login_is_critical() -> None:
    """A disabled account with failed logins should escalate to CRITICAL.

    This verifies the strongest identity anomaly: activity on an account that
    should not be active in the first place.
    """
    inputs = _load_inputs()
    focus_records = [_get_record(inputs["records"], "disabled_user")]

    findings = detect_anomalies(
        focus_records,
        approved_linux_sudoers=inputs["approved_linux_sudoers"],
        approved_windows_admins=inputs["approved_windows_admins"],
        approved_service_accounts=inputs["approved_service_accounts"],
    )

    disabled_finding = next(finding for finding in findings if finding["identity"] == "disabled_user")
    assert disabled_finding["risk_level"] == RiskLevel.CRITICAL.value
    assert "disabled account" in disabled_finding["finding"].lower()


def test_inactive_privileged_account_is_high() -> None:
    """A privileged account with no activity should be treated as high risk.

    This checks the standing-privilege scenario where access exists but use is
    not observed, which still matters for the report.
    """
    inputs = _load_inputs()
    focus_records = [_get_record(inputs["records"], "adm_svc_win")]

    findings = detect_anomalies(
        focus_records,
        approved_linux_sudoers=inputs["approved_linux_sudoers"],
        approved_windows_admins=inputs["approved_windows_admins"],
        approved_service_accounts=inputs["approved_service_accounts"],
    )

    inactive_finding = next(finding for finding in findings if finding["identity"] == "adm_svc_win")
    assert inactive_finding["risk_level"] == RiskLevel.HIGH.value
    assert "inactive account" in inactive_finding["finding"].lower()


def test_policy_deviation_is_detected() -> None:
    """Windows policy deviations should produce a readable anomaly finding.

    Policy mismatches must become findings so the report can explain control
    gaps separately from login activity.
    """
    inputs = _load_inputs()
    focus_records = [_get_record(inputs["records"], "normal_user")]

    findings = detect_anomalies(
        focus_records,
        windows_policy_rows=inputs["windows_policy_rows"],
        expected_policy_baseline=inputs["expected_policy_baseline"],
        approved_linux_sudoers=inputs["approved_linux_sudoers"],
        approved_windows_admins=inputs["approved_windows_admins"],
        approved_service_accounts=inputs["approved_service_accounts"],
    )

    policy_findings = [finding for finding in findings if finding["identity"] == "normal_user"]
    assert policy_findings
    assert any(
        finding["risk_level"] in {RiskLevel.HIGH.value, RiskLevel.MEDIUM.value}
        for finding in policy_findings
    )
    assert any(
        "policy" in finding["finding"].lower() or "firewall" in finding["finding"].lower()
        for finding in policy_findings
    )
