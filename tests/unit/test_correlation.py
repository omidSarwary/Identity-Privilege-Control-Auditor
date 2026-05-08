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
    """A privileged account with explicit inactivity evidence should be high risk.

    This protects the evidence rule that inactivity must come from collected
    identity data, not from an empty authentication event window.
    """
    inputs = _load_inputs()
    focus_records = [_get_record(inputs["records"], "svc_archive")]

    findings = detect_anomalies(
        focus_records,
        approved_linux_sudoers=inputs["approved_linux_sudoers"],
        approved_windows_admins=inputs["approved_windows_admins"],
        approved_service_accounts=inputs["approved_service_accounts"],
    )

    inactive_finding = next(
        finding
        for finding in findings
        if finding["identity"] == "svc_archive" and "inactive account" in finding["finding"].lower()
    )
    assert inactive_finding["risk_level"] == RiskLevel.HIGH.value
    assert "inactive account" in inactive_finding["finding"].lower()


def test_linux_active_sudo_without_auth_events_is_not_inactive() -> None:
    """No auth events in the bounded window must not imply inactivity."""
    linux_identity = {
        "users": [
            {
                "username": "active_sudo",
                "enabled": True,
                "privileges": ["sudo"],
                "is_inactive": False,
                "last_login": "2026-05-08T08:00:00Z",
            }
        ],
        "sudo_users": ["active_sudo"],
        "auth_events": [],
    }
    records = normalize_identities(linux_identity, [])
    records = correlate_identity_privileges(records, [], [], [])
    records = correlate_events_to_identities(records, linux_identity["auth_events"], [])

    findings = detect_anomalies(records, approved_linux_sudoers=[], approved_windows_admins=[], approved_service_accounts=[])

    assert not any("inactive account" in finding["finding"].lower() for finding in findings)


def test_linux_inactive_sudo_with_collected_evidence_is_high() -> None:
    """Explicit Linux inactivity evidence should still trigger the HIGH rule."""
    linux_identity = {
        "users": [
            {
                "username": "inactive_sudo",
                "enabled": True,
                "privileges": ["sudo"],
                "is_inactive": True,
                "last_login": "",
            }
        ],
        "sudo_users": ["inactive_sudo"],
        "auth_events": [],
    }
    records = normalize_identities(linux_identity, [])
    records = correlate_identity_privileges(records, [], [], [])
    records = correlate_events_to_identities(records, linux_identity["auth_events"], [])

    findings = detect_anomalies(records, approved_linux_sudoers=[], approved_windows_admins=[], approved_service_accounts=[])

    assert any(
        finding["identity"] == "inactive_sudo" and finding["finding"] == "Inactive account with privileges"
        for finding in findings
    )


def test_linux_inactivity_fields_are_preserved_by_normalization() -> None:
    """Linux last-login and inactivity evidence should survive normalization."""
    linux_identity = {
        "users": [
            {
                "username": "audit_user",
                "enabled": True,
                "privileges": ["sudo"],
                "is_inactive": False,
                "last_login": "Sat Feb 7 2026",
            }
        ],
        "sudo_users": [],
    }

    record = normalize_identities(linux_identity, [])[0]

    assert record["is_inactive"] is False
    assert record["last_login"] == "Sat Feb 7 2026"
    assert "sudo" in record["privileges"]


def test_linux_user_level_privileges_are_merged_without_sudo_users() -> None:
    """The Linux user-level privileges list should be enough to mark sudo."""
    linux_identity = {
        "users": [
            {
                "username": "row_sudo",
                "enabled": True,
                "privileges": ["sudo"],
                "is_inactive": False,
            }
        ],
        "sudo_users": [],
    }

    record = normalize_identities(linux_identity, [])[0]

    assert record["privileges"] == ["sudo"]


def test_service_account_baseline_does_not_approve_linux_sudo() -> None:
    """Service account approval must not suppress an unapproved sudo finding."""
    linux_identity = {
        "users": [{"username": "svc_backup", "enabled": True, "privileges": ["sudo"], "is_inactive": False}],
        "sudo_users": ["svc_backup"],
        "auth_events": [],
    }
    records = normalize_identities(linux_identity, [])
    records = correlate_identity_privileges(
        records,
        approved_linux_sudoers=[],
        approved_windows_admins=[],
        approved_service_accounts=[{"username": "svc_backup"}],
    )

    findings = detect_anomalies(records, approved_linux_sudoers=[], approved_windows_admins=[], approved_service_accounts=[{"username": "svc_backup"}])

    assert any(finding["finding"] == "Unapproved Linux sudo user" for finding in findings)


def test_service_account_baseline_does_not_approve_windows_admin() -> None:
    """Service account approval must not suppress an unapproved Windows admin finding."""
    rows = [
        {
            "Username": "svc_backup",
            "Enabled": "True",
            "IsLocalAdmin": "True",
            "LastLogon": "2026-05-08T09:00:00Z",
        }
    ]
    records = normalize_identities({}, rows)
    records = correlate_identity_privileges(
        records,
        approved_linux_sudoers=[],
        approved_windows_admins=[],
        approved_service_accounts=[{"username": "svc_backup"}],
    )

    findings = detect_anomalies(records, approved_linux_sudoers=[], approved_windows_admins=[], approved_service_accounts=[{"username": "svc_backup"}])

    assert any(finding["finding"] == "Unapproved Windows administrators member" for finding in findings)


def test_approved_privileged_baselines_still_suppress_unapproved_findings() -> None:
    """Approved sudo and Windows admin baselines should still suppress findings."""
    linux_identity = {
        "users": [{"username": "ops_backup", "enabled": True, "privileges": ["sudo"], "is_inactive": False}],
        "sudo_users": ["ops_backup"],
        "auth_events": [],
    }
    rows = [{"Username": "adm_svc_win", "Enabled": "True", "IsLocalAdmin": "True", "LastLogon": ""}]
    records = normalize_identities(linux_identity, rows)
    records = correlate_identity_privileges(
        records,
        approved_linux_sudoers=[{"username": "ops_backup"}],
        approved_windows_admins=[{"username": "adm_svc_win"}],
        approved_service_accounts=[],
    )

    findings = detect_anomalies(
        records,
        approved_linux_sudoers=[{"username": "ops_backup"}],
        approved_windows_admins=[{"username": "adm_svc_win"}],
        approved_service_accounts=[],
    )

    assert not any(finding["finding"] == "Unapproved Linux sudo user" for finding in findings)
    assert not any(finding["finding"] == "Unapproved Windows administrators member" for finding in findings)


def test_ssh_root_login_with_no_privileged_activity_does_not_claim_activity() -> None:
    """PermitRootLogin alone must not create a CRITICAL observed-activity finding."""
    linux_identity = {
        "users": [{"username": "sudo_user", "enabled": True, "privileges": ["sudo"], "is_inactive": False}],
        "sudo_users": ["sudo_user"],
        "auth_events": [],
    }
    linux_policy = {"policy": {"ssh_policy": {"permit_root_login": "yes", "password_authentication": "no", "pubkey_authentication": "yes"}}}
    records = normalize_identities(linux_identity, [])
    records = correlate_identity_privileges(records, [], [], [])
    records = correlate_events_to_identities(records, [], [])

    findings = detect_anomalies(records, linux_policy=linux_policy, approved_linux_sudoers=[])

    assert not any("privileged activity observed" in finding["finding"].lower() for finding in findings)


def test_windows_old_admin_last_logon_triggers_inactive_privileged_finding() -> None:
    """Old Windows LastLogon evidence should drive privileged inactivity findings."""
    rows = [{"Username": "old_admin", "Enabled": "True", "IsLocalAdmin": "True", "LastLogon": "2025-01-01T00:00:00Z"}]
    records = normalize_identities({}, rows)
    records = correlate_identity_privileges(records, approved_windows_admins=[{"username": "old_admin"}])

    findings = detect_anomalies(records, approved_windows_admins=[{"username": "old_admin"}])

    assert any(finding["identity"] == "old_admin" and finding["finding"] == "Inactive account with privileges" for finding in findings)


def test_windows_recent_admin_last_logon_does_not_trigger_inactivity() -> None:
    """Recent Windows LastLogon evidence must not be marked inactive."""
    rows = [{"Username": "recent_admin", "Enabled": "True", "IsLocalAdmin": "True", "LastLogon": "2026-05-08T09:00:00Z"}]
    records = normalize_identities({}, rows)
    records = correlate_identity_privileges(records, approved_windows_admins=[{"username": "recent_admin"}])

    findings = detect_anomalies(records, approved_windows_admins=[{"username": "recent_admin"}])

    assert not any(finding["identity"] == "recent_admin" and finding["finding"] == "Inactive account with privileges" for finding in findings)


def test_windows_missing_last_logon_does_not_infer_inactivity() -> None:
    """Missing LastLogon is unknown evidence, not proof of inactivity."""
    rows = [{"Username": "unknown_admin", "Enabled": "True", "IsLocalAdmin": "True", "LastLogon": ""}]
    records = normalize_identities({}, rows)
    records = correlate_identity_privileges(records, approved_windows_admins=[{"username": "unknown_admin"}])

    findings = detect_anomalies(records, approved_windows_admins=[{"username": "unknown_admin"}])

    assert not any(finding["identity"] == "unknown_admin" and finding["finding"] == "Inactive account with privileges" for finding in findings)


def test_windows_firewall_disabled_is_system_level_only() -> None:
    """Windows Firewall findings should be emitted once for the whole run.

    This protects against a misleading report where one normal user inherits a
    platform-wide firewall weakness as if it were a personal account failure.
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

    firewall_findings = [finding for finding in findings if "firewall" in finding["finding"].lower()]

    assert len(firewall_findings) == 1
    assert firewall_findings[0]["identity"] == "system_policy"
    assert firewall_findings[0]["risk_level"] == RiskLevel.HIGH.value
    assert not any(
        finding["identity"] == "normal_user" and finding["risk_level"] == RiskLevel.HIGH.value
        for finding in findings
    )


def test_multiple_failed_logins_from_same_ip_is_not_duplicated() -> None:
    """Repeated failures from the same IP should appear only once per run.

    The network source is a run-level signal, so it should not be multiplied
    by the number of identities in the dataset.
    """
    inputs = _load_inputs()

    findings = detect_anomalies(
        inputs["records"],
        approved_linux_sudoers=inputs["approved_linux_sudoers"],
        approved_windows_admins=inputs["approved_windows_admins"],
        approved_service_accounts=inputs["approved_service_accounts"],
    )

    ip_findings = [
        finding
        for finding in findings
        if finding["finding"] == "Multiple failed logins from the same IP address"
    ]

    assert len(ip_findings) == 1
    assert ip_findings[0]["identity"] == "10.0.0.25"
    assert ip_findings[0]["risk_level"] == RiskLevel.HIGH.value
