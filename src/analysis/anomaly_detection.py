"""Anomaly detection helpers for identity risk signals."""

from __future__ import annotations

import logging
from typing import Any, Mapping, Sequence

from src.analysis import scoring
from src.analysis.risk_rules import (
    RiskLevel,
    disabled_account_with_inactivity,
    inactive_account_with_privileges,
    missing_audit_policy,
    missing_log_source_but_other_data_exists,
    multiple_failed_logins_from_same_ip,
    normal_user_single_failed_logins,
    privileged_account_with_multiple_failed_logins,
    policy_deviation,
    ssh_root_login_with_privileged_activity,
    unauthorized_linux_sudo_user,
    unauthorized_windows_admin,
    weak_ssh_policy,
    windows_firewall_disabled,
)


LOGGER = logging.getLogger("nordsec.ipca.analysis.anomaly_detection")
RISK_SCORE_BY_LEVEL = {
    RiskLevel.CRITICAL.value: 90,
    RiskLevel.HIGH.value: 70,
    RiskLevel.MEDIUM.value: 40,
    RiskLevel.LOW.value: 10,
}


def _as_username_set(values: Sequence[Any] | None) -> set[str]:
    """Convert approved baseline rows into a set of usernames."""
    usernames: set[str] = set()
    for value in values or []:
        if isinstance(value, Mapping):
            username = value.get("username") or value.get("Username")
        else:
            username = value
        if username is not None:
            usernames.add(str(username))
    return usernames


def _apply_risk_summary(record: dict[str, Any], findings: list[dict[str, str]]) -> None:
    """Update the normalized record with the highest risk level seen for it.

    The summary keeps the identity-centric score aligned with the most severe
    finding so that later reporting can explain the final decision clearly.
    """
    if not findings:
        record["risk_score"] = RISK_SCORE_BY_LEVEL[RiskLevel.LOW.value]
        record["risk_level"] = RiskLevel.LOW.value
        record["reasons"] = list(record.get("reasons", []))
        return

    summary = scoring.summarize_findings(findings)
    identity_summary = next((entry for entry in summary["identities"] if entry["identity"] == record["identity"]), None)
    if identity_summary is None:
        return

    record["risk_level"] = identity_summary["risk_level"]
    record["risk_score"] = RISK_SCORE_BY_LEVEL[identity_summary["risk_level"]]
    record["reasons"] = [finding["reason"] for finding in identity_summary["findings"]]


def _copy_record(identity: Mapping[str, Any]) -> dict[str, Any]:
    """Return a mutable copy of a normalized identity record."""
    return dict(identity)


def detect_anomalies(
    normalized_identities: Sequence[Mapping[str, Any]] | None,
    *,
    linux_policy: Mapping[str, Any] | None = None,
    windows_policy_rows: Sequence[Mapping[str, Any]] | None = None,
    expected_policy_baseline: Mapping[str, Any] | None = None,
    approved_linux_sudoers: Sequence[Any] | None = None,
    approved_windows_admins: Sequence[Any] | None = None,
    approved_service_accounts: Sequence[Any] | None = None,
) -> list[dict[str, str]]:
    """Detect read-only anomalies from normalized records and policy context.

    The function expects normalized dictionaries produced by the correlation
    layer plus optional raw policy and baseline inputs. It returns findings and
    also updates the normalized records with their resulting risk summary.
    """
    LOGGER.info("Starting anomaly detection")

    findings: list[dict[str, str]] = []
    approved_linux = _as_username_set(approved_linux_sudoers)
    approved_windows = _as_username_set(approved_windows_admins)
    expected_ssh_policy = (expected_policy_baseline or {}).get("ssh_policy", {})
    expected_windows_policy = expected_policy_baseline or {}
    linux_policy_map = (linux_policy or {}).get("policy", linux_policy or {})

    for identity in normalized_identities or []:
        record = identity if isinstance(identity, dict) else _copy_record(identity)
        username = str(record.get("identity") or "unknown")
        privileges = {str(item).lower() for item in record.get("privileges", [])}
        events = list(record.get("events", []))
        baseline_match = bool(record.get("baseline_match", False))
        platforms = {str(item).lower() for item in record.get("platforms", [])}
        identity_findings: list[dict[str, str]] = []

        if not baseline_match and "windows" in platforms and "local_admin" in privileges:
            finding = unauthorized_windows_admin(
                {"username": username, "is_local_admin": True},
                approved_admins=approved_windows,
                source="windows_identity.csv",
            )
            if finding:
                finding["identity"] = username
                identity_findings.append(finding)

        if not baseline_match and "linux" in platforms and "sudo" in privileges:
            finding = unauthorized_linux_sudo_user(
                {"username": username, "privileges": ["sudo"]},
                approved_sudoers=approved_linux,
                source="approved_linux_sudoers.csv",
            )
            if finding:
                finding["identity"] = username
                identity_findings.append(finding)

        failed_logins = [
            event for event in events if str(event.get("event_type") or "").lower() == "failed_login"
        ]

        # A privileged account with no observed sign-in activity is treated as
        # inactive for reporting purposes because standing privilege without use
        # is an operational risk in the baseline model.
        if privileges and not failed_logins:
            finding = inactive_account_with_privileges(
                {
                    "username": username,
                    "is_inactive": True,
                    "is_local_admin": "local_admin" in privileges,
                    "privileges": list(privileges),
                },
                source="normalized_identities",
            )
            if finding:
                finding["identity"] = username
                identity_findings.append(finding)

        if record.get("status") == "disabled" and failed_logins:
            finding = disabled_account_with_inactivity(
                {"username": username, "enabled": False},
                failed_logins,
                source="events",
            )
            if finding:
                finding["identity"] = username
                identity_findings.append(finding)

        if len(failed_logins) == 1 and not privileges:
            finding = normal_user_single_failed_logins(
                {"username": username, "is_local_admin": False, "privileges": []},
                failed_logins,
                source="events",
            )
            if finding:
                finding["identity"] = username
                identity_findings.append(finding)

        if len(failed_logins) >= 2 and privileges:
            finding = privileged_account_with_multiple_failed_logins(
                {"username": username, "is_local_admin": "local_admin" in privileges, "privileges": list(privileges)},
                failed_logins,
                source="events",
            )
            if finding:
                finding["identity"] = username
                identity_findings.append(finding)

        # High-volume failures from one source are correlated separately from
        # the account record so the report can explain network-level patterns.
        ip_finding = multiple_failed_logins_from_same_ip(events, source="events")
        if ip_finding:
            findings.append(ip_finding)

        if "linux" in platforms and linux_policy_map:
            ssh_root_finding = ssh_root_login_with_privileged_activity(
                linux_policy_map,
                privileged_activity_observed=bool(privileges or events),
                source="linux_policy.json",
            )
            if ssh_root_finding:
                ssh_root_finding["identity"] = username
                identity_findings.append(ssh_root_finding)

            ssh_finding = weak_ssh_policy(linux_policy_map, source="linux_policy.json")
            if ssh_finding:
                ssh_finding["identity"] = username
                identity_findings.append(ssh_finding)

        if "windows" in platforms and windows_policy_rows:
            firewall_finding = windows_firewall_disabled(windows_policy_rows, source="windows_policy.csv")
            if firewall_finding:
                firewall_finding["identity"] = username
                identity_findings.append(firewall_finding)

            execution_rows = [
                row for row in windows_policy_rows if str(row.get("CheckName") or row.get("check_name") or "").lower() == "execution_policy"
            ]
            expected_execution = (expected_policy_baseline or {}).get("execution_policy", {}).get("powershell")
            if execution_rows and expected_execution:
                observed_execution = str(execution_rows[0].get("Value") or execution_rows[0].get("value") or "").strip().lower()
                if observed_execution != str(expected_execution).strip().lower():
                    execution_finding = policy_deviation(
                        username,
                        finding="Windows execution policy differs from the approved baseline",
                        reason="The readable Windows execution policy does not match the approved baseline.",
                        source="windows_policy.csv",
                    )
                    identity_findings.append(execution_finding)

            # Audit policy absence is treated as a separate control gap so that
            # the report can distinguish between a missing control and a weak one.
            audit_policy_rows = [
                row for row in windows_policy_rows if str(row.get("CheckName") or row.get("check_name") or "").lower() == "audit_policy_enabled"
            ]
            if not audit_policy_rows or str(audit_policy_rows[0].get("Status") or "").lower() not in {"true", "enabled", "on"}:
                audit_finding = missing_audit_policy({"audit_policy": None}, source="windows_policy.csv")
                audit_finding["identity"] = username
                identity_findings.append(audit_finding)

        if expected_windows_policy and "windows" in platforms and not windows_policy_rows:
            identity_findings.append(
                missing_log_source_but_other_data_exists(
                    source="correlation",
                    reason="Windows policy data was expected but not supplied for scoring.",
                    identity=username,
                )
            )

        if expected_ssh_policy and "linux" in platforms and not linux_policy:
            identity_findings.append(
                missing_log_source_but_other_data_exists(
                    source="correlation",
                    reason="Linux SSH policy data was expected but not supplied for scoring.",
                    identity=username,
                )
            )

        findings.extend(identity_findings)
        _apply_risk_summary(record, identity_findings)

    LOGGER.info("Completed anomaly detection")
    return findings
