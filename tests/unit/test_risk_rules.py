"""Tests for the identity and privilege risk rules."""

from __future__ import annotations

from src.analysis.risk_rules import (
    RiskLevel,
    corrupt_critical_input_data,
    disabled_account_with_inactivity,
    inactive_account_with_privileges,
    missing_audit_policy,
    missing_log_source_but_other_data_exists,
    multiple_failed_logins_from_same_ip,
    normal_user_single_failed_logins,
    privileged_account_with_multiple_failed_logins,
    ssh_root_login_with_privileged_activity,
    unauthorized_linux_sudo_user,
    unauthorized_windows_admin,
    weak_ssh_policy,
    windows_firewall_disabled,
)
from src.analysis.scoring import summarize_findings


def test_critical_rule_for_disabled_account_with_activity() -> None:
    """Disabled accounts with authentication activity should be critical.

    This guards the highest-severity rule because a disabled account should not
    be successfully or repeatedly probed as though it were active.
    """
    finding = disabled_account_with_inactivity(
        {"username": "disabled_user", "enabled": False},
        [{"TargetUserName": "disabled_user", "event_type": "failed_login", "count": 2}],
        "auth.log",
    )

    assert finding is not None
    assert finding["risk_level"] == RiskLevel.CRITICAL.value


def test_high_rule_for_inactive_account_with_privileges() -> None:
    """Inactive privileged accounts should be high risk.

    Standing privilege without normal use is a control weakness even when the
    account is not actively failing logins.
    """
    finding = inactive_account_with_privileges(
        {"username": "inactive_priv", "is_inactive": True, "is_local_admin": True},
        "windows_identity.csv",
    )

    assert finding is not None
    assert finding["risk_level"] == RiskLevel.HIGH.value


def test_critical_rule_for_windows_admin_baseline_violation() -> None:
    """Unapproved Windows administrators members should be critical.

    Local admin membership changes the trust boundary on Windows, so the
    approved baseline must remain authoritative.
    """
    finding = unauthorized_windows_admin(
        {"username": "unauthorized_admin", "is_local_admin": True},
        approved_admins=["adm_svc_win"],
        source="approved_windows_admins.csv",
    )

    assert finding is not None
    assert finding["risk_level"] == RiskLevel.CRITICAL.value


def test_critical_rule_for_linux_sudo_baseline_violation() -> None:
    """Unapproved Linux sudo users should be critical.

    Sudo access is a high-impact privilege, so an account outside the approved
    list must be escalated immediately.
    """
    finding = unauthorized_linux_sudo_user(
        {"username": "unauthorized_sudo", "privileges": ["sudo"]},
        approved_sudoers=["ops_backup"],
        source="approved_linux_sudoers.csv",
    )

    assert finding is not None
    assert finding["risk_level"] == RiskLevel.CRITICAL.value


def test_critical_rule_for_privileged_account_multiple_failed_logins() -> None:
    """Privileged accounts with repeated failed logins should be critical.

    Repeated failures on a privileged account can indicate brute-force or
    password-spraying activity against a sensitive account.
    """
    finding = privileged_account_with_multiple_failed_logins(
        {"username": "svc_backup", "is_local_admin": True, "privileges": []},
        [{"TargetUserName": "svc_backup", "event_type": "failed_login", "count": 3}],
        "windows_events.csv",
    )

    assert finding is not None
    assert finding["risk_level"] == RiskLevel.CRITICAL.value


def test_critical_rule_for_ssh_root_login_with_privileged_activity() -> None:
    """Permitted SSH root login combined with privileged activity should be critical.

    Root SSH access weakens the host's security boundary, so privileged
    activity under that setting must remain CRITICAL.
    """
    finding = ssh_root_login_with_privileged_activity(
        {"ssh_policy": {"permit_root_login": "yes"}},
        privileged_activity_observed=True,
        source="linux_policy.json",
    )

    assert finding is not None
    assert finding["risk_level"] == RiskLevel.CRITICAL.value


def test_critical_rule_for_corrupt_critical_input_data() -> None:
    """Corrupt critical inputs should be critical findings.

    Corrupted input threatens the trustworthiness of the whole analysis, so it
    needs a critical finding even before business logic runs.
    """
    finding = corrupt_critical_input_data("linux_identity.json", "Invalid JSON payload")

    assert finding["risk_level"] == RiskLevel.CRITICAL.value


def test_medium_rule_for_weak_ssh_policy() -> None:
    """Weak SSH policy should be medium risk.

    The rule stays below CRITICAL because the policy is weak, but not yet tied
    to observed privileged activity.
    """
    finding = weak_ssh_policy(
        {"ssh_policy": {"permit_root_login": "yes", "password_authentication": "no", "pubkey_authentication": "yes"}},
        "linux_policy.json",
    )

    assert finding is not None
    assert finding["risk_level"] == RiskLevel.MEDIUM.value


def test_high_rule_for_multiple_failed_logins_from_same_ip() -> None:
    """Repeated failed logins from the same IP should be high risk.

    This protects the brute-force detection path where the source address is as
    important as the account being targeted.
    """
    finding = multiple_failed_logins_from_same_ip(
        [
            {"IpAddress": "10.0.0.25", "event_type": "failed_login", "count": 2},
            {"IpAddress": "10.0.0.40", "event_type": "successful_login", "count": 1},
        ],
        "windows_events.csv",
    )

    assert finding is not None
    assert finding["risk_level"] == RiskLevel.HIGH.value


def test_high_rule_for_missing_audit_policy() -> None:
    """Missing audit policy should be high risk.

    Audit visibility is a core control in the project, so missing data about it
    should not be treated as low impact.
    """
    finding = missing_audit_policy({}, "windows_policy.csv")

    assert finding is not None
    assert finding["risk_level"] == RiskLevel.HIGH.value


def test_high_rule_for_windows_firewall_disabled() -> None:
    """Disabled firewall where the control is readable should be high risk.

    The rule only triggers when the control can actually be read, which keeps
    the finding evidence-based rather than speculative.
    """
    finding = windows_firewall_disabled(
        [{"ComputerName": "WIN-TEST-01", "CheckName": "firewall_enabled", "Status": "False", "Value": "Disabled", "RiskHint": "Policy deviation"}],
        "windows_policy.csv",
    )

    assert finding is not None
    assert finding["risk_level"] == RiskLevel.HIGH.value


def test_low_rule_for_normal_user_single_failed_login() -> None:
    """A normal user with a single failed login should be low risk.

    This preserves signal without over-escalating harmless authentication
    noise from non-privileged accounts.
    """
    finding = normal_user_single_failed_logins(
        {"username": "normal_user", "is_local_admin": False, "privileges": []},
        [{"TargetUserName": "normal_user", "event_type": "failed_login", "count": 1}],
        "windows_events.csv",
    )

    assert finding is not None
    assert finding["risk_level"] == RiskLevel.LOW.value


def test_medium_rule_for_missing_log_source_but_other_data_exists() -> None:
    """Missing one log source while other data exists should be medium risk.

    The pipeline can still produce value, but the report must note the evidence
    gap so the reader understands the limitation.
    """
    finding = missing_log_source_but_other_data_exists(
        "logdata/linux/auth.log",
        "Linux log source missing but Windows and policy data are available.",
    )

    assert finding is not None
    assert finding["risk_level"] == RiskLevel.MEDIUM.value


def test_critical_prioritizes_over_other_levels() -> None:
    """Critical findings must dominate summary output for an identity.

    This checks the scoring contract: if one account accumulates mixed findings,
    the report must still surface the most urgent severity first.
    """
    findings = [
        {
            "risk_level": RiskLevel.LOW.value,
            "identity": "svc_backup",
            "finding": "Normal user with a single failed login",
            "reason": "One failed login event.",
            "source": "windows_events.csv",
            "recommended_action": "Monitor.",
        },
        {
            "risk_level": RiskLevel.HIGH.value,
            "identity": "svc_backup",
            "finding": "Inactive account with privileges",
            "reason": "Inactive privileged account.",
            "source": "windows_identity.csv",
            "recommended_action": "Review access.",
        },
        {
            "risk_level": RiskLevel.CRITICAL.value,
            "identity": "svc_backup",
            "finding": "Disabled account shows authentication activity",
            "reason": "Disabled account has recent activity.",
            "source": "auth.log",
            "recommended_action": "Investigate the activity.",
        },
    ]

    summary = summarize_findings(findings)
    identity_summary = next(item for item in summary["identities"] if item["identity"] == "svc_backup")

    assert identity_summary["risk_level"] == RiskLevel.CRITICAL.value
    assert summary["counts"][RiskLevel.CRITICAL.value] == 1
    assert summary["counts"][RiskLevel.HIGH.value] == 1
    assert summary["counts"][RiskLevel.LOW.value] == 1


def test_normal_user_without_deviation_returns_no_finding() -> None:
    """A normal user with no suspicious activity should not produce a finding.

    The pipeline should avoid noisy output for accounts that match the expected
    low-risk baseline.
    """
    finding = normal_user_single_failed_logins(
        {"username": "normal_user", "is_local_admin": False, "privileges": []},
        [],
        "windows_events.csv",
    )

    assert finding is None
