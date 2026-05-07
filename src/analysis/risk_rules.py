"""Risk rule definitions for the identity and privilege audit model."""

from __future__ import annotations

from enum import Enum
from typing import Any, Mapping, Sequence


class RiskLevel(str, Enum):
    """Centralized risk levels used across the analysis layer."""

    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"


RISK_ORDER = {
    RiskLevel.CRITICAL: 4,
    RiskLevel.HIGH: 3,
    RiskLevel.MEDIUM: 2,
    RiskLevel.LOW: 1,
}


def create_finding(
    *,
    risk_level: RiskLevel,
    identity: str,
    finding: str,
    reason: str,
    source: str,
    recommended_action: str,
) -> dict[str, str]:
    """Build a normalized finding record for downstream reporting."""
    return {
        "risk_level": risk_level.value,
        "identity": identity,
        "finding": finding,
        "reason": reason,
        "source": source,
        "recommended_action": recommended_action,
    }


def _identity_name(record: Mapping[str, Any], default: str = "unknown") -> str:
    return str(record.get("username") or record.get("identity") or default)


def _is_truthy(value: Any) -> bool:
    if isinstance(value, str):
        return value.strip().lower() in {"true", "1", "yes", "enabled", "yes"}
    return bool(value)


def _count_failed_logins(events: Sequence[Mapping[str, Any]], username: str) -> int:
    count = 0
    for event in events:
        event_user = str(event.get("TargetUserName") or event.get("username") or "")
        event_type = str(event.get("event_type") or event.get("EventType") or "")
        if event_user == username and event_type.lower() == "failed_login":
            raw_count = event.get("count", 1)
            try:
                count += int(raw_count)
            except (TypeError, ValueError):
                count += 1
    return count


def disabled_account_with_inactivity(
    identity: Mapping[str, Any],
    auth_events: Sequence[Mapping[str, Any]],
    source: str,
) -> dict[str, str] | None:
    """Return a critical finding when a disabled account still has activity."""
    if _is_truthy(identity.get("enabled", True)):
        return None

    username = _identity_name(identity)
    if _count_failed_logins(auth_events, username) > 0:
        return create_finding(
            risk_level=RiskLevel.CRITICAL,
            identity=username,
            finding="Disabled account shows authentication activity",
            reason="A disabled account has recent login activity.",
            source=source,
            recommended_action="Review the account and investigate the source of the activity.",
        )
    return None


def unauthorized_windows_admin(
    identity: Mapping[str, Any],
    approved_admins: Sequence[str],
    source: str,
) -> dict[str, str] | None:
    """Return a critical finding for an unapproved Windows administrators member."""
    username = _identity_name(identity)
    if _is_truthy(identity.get("is_local_admin")) and username not in approved_admins:
        return create_finding(
            risk_level=RiskLevel.CRITICAL,
            identity=username,
            finding="Unapproved Windows administrators member",
            reason="The account is a local administrator but is not listed in the approved baseline.",
            source=source,
            recommended_action="Review local administrator membership against the approved baseline.",
        )
    return None


def unauthorized_linux_sudo_user(
    identity: Mapping[str, Any],
    approved_sudoers: Sequence[str],
    source: str,
) -> dict[str, str] | None:
    """Return a critical finding for an unapproved Linux sudo user."""
    username = _identity_name(identity)
    if "sudo" in {str(item).lower() for item in identity.get("privileges", [])} and username not in approved_sudoers:
        return create_finding(
            risk_level=RiskLevel.CRITICAL,
            identity=username,
            finding="Unapproved Linux sudo user",
            reason="The account has sudo privileges but is not listed in the approved baseline.",
            source=source,
            recommended_action="Review sudo access against the approved baseline.",
        )
    return None


def privileged_account_with_multiple_failed_logins(
    identity: Mapping[str, Any],
    auth_events: Sequence[Mapping[str, Any]],
    source: str,
    threshold: int = 2,
) -> dict[str, str] | None:
    """Return a critical finding for privileged accounts with repeated failed logins."""
    username = _identity_name(identity)
    is_privileged = _is_truthy(identity.get("is_local_admin")) or "sudo" in {
        str(item).lower() for item in identity.get("privileges", [])
    }
    if is_privileged and _count_failed_logins(auth_events, username) >= threshold:
        return create_finding(
            risk_level=RiskLevel.CRITICAL,
            identity=username,
            finding="Privileged account with repeated failed logins",
            reason="A privileged account has multiple failed login attempts.",
            source=source,
            recommended_action="Verify whether the activity is expected and investigate possible abuse.",
        )
    return None


def ssh_root_login_with_privileged_activity(
    policy: Mapping[str, Any],
    privileged_activity_observed: bool,
    source: str,
) -> dict[str, str] | None:
    """Return a critical finding when root SSH login is permitted and privileged activity is observed."""
    ssh_policy = policy.get("ssh_policy", {})
    if (
        isinstance(ssh_policy, Mapping)
        and str(ssh_policy.get("permit_root_login", "")).strip().lower() == "yes"
        and privileged_activity_observed
    ):
        return create_finding(
            risk_level=RiskLevel.CRITICAL,
            identity="root",
            finding="SSH root login permitted with privileged activity observed",
            reason="The SSH policy allows root login while privileged activity is present.",
            source=source,
            recommended_action="Disable root SSH login and review privileged activity.",
        )
    return None


def corrupt_critical_input_data(source: str, reason: str, identity: str = "unknown") -> dict[str, str]:
    """Return a critical finding for corrupt critical input data."""
    return create_finding(
        risk_level=RiskLevel.CRITICAL,
        identity=identity,
        finding="Corrupt critical input data",
        reason=reason,
        source=source,
        recommended_action="Exclude the affected input and re-collect the source data.",
    )


def inactive_account_with_privileges(
    identity: Mapping[str, Any],
    source: str,
) -> dict[str, str] | None:
    """Return a high-risk finding for an inactive account with privileges."""
    username = _identity_name(identity)
    is_inactive = _is_truthy(identity.get("is_inactive"))
    is_privileged = _is_truthy(identity.get("is_local_admin")) or "sudo" in {
        str(item).lower() for item in identity.get("privileges", [])
    }
    if is_inactive and is_privileged:
        return create_finding(
            risk_level=RiskLevel.HIGH,
            identity=username,
            finding="Inactive account with privileges",
            reason="The account is inactive but still has privileged access.",
            source=source,
            recommended_action="Review whether the account should be disabled or have privileges removed.",
        )
    return None


def multiple_failed_logins_from_same_ip(
    events: Sequence[Mapping[str, Any]],
    source: str,
    threshold: int = 2,
) -> dict[str, str] | None:
    """Return a high-risk finding when the same IP generates repeated failures."""
    counts: dict[str, int] = {}
    for event in events:
        if str(event.get("event_type") or event.get("EventType") or "").lower() != "failed_login":
            continue
        ip_address = str(event.get("IpAddress") or event.get("ip_address") or "unknown")
        raw_count = event.get("count", 1)
        try:
            counts[ip_address] = counts.get(ip_address, 0) + int(raw_count)
        except (TypeError, ValueError):
            counts[ip_address] = counts.get(ip_address, 0) + 1

    for ip_address, count in counts.items():
        if count >= threshold:
            return create_finding(
                risk_level=RiskLevel.HIGH,
                identity=ip_address,
                finding="Multiple failed logins from the same IP address",
                reason="Repeated failed logins were observed from a single network source.",
                source=source,
                recommended_action="Review the source address and associated authentication attempts.",
            )
    return None


def missing_audit_policy(
    policy: Mapping[str, Any],
    source: str,
) -> dict[str, str] | None:
    """Return a high-risk finding when audit policy data is unavailable."""
    audit_policy = policy.get("audit_policy")
    if audit_policy is None:
        return create_finding(
            risk_level=RiskLevel.HIGH,
            identity="system",
            finding="Audit policy missing",
            reason="The audit policy could not be read from the collected data.",
            source=source,
            recommended_action="Re-collect the policy data and verify access to the source.",
        )
    return None


def windows_firewall_disabled(
    policy_rows: Sequence[Mapping[str, Any]],
    source: str,
) -> dict[str, str] | None:
    """Return a high-risk finding when the readable firewall control is disabled."""
    for row in policy_rows:
        check_name = str(row.get("CheckName") or row.get("check_name") or "")
        if check_name.lower() == "firewall_enabled" and str(row.get("Status") or row.get("status") or "").lower() in {"false", "disabled", "off"}:
            return create_finding(
                risk_level=RiskLevel.HIGH,
                identity=str(row.get("ComputerName") or row.get("host") or "system"),
                finding="Windows Firewall disabled",
                reason="A readable policy check shows Windows Firewall is disabled.",
                source=source,
                recommended_action="Review firewall configuration against the approved baseline.",
            )
    return None


def weak_ssh_policy(
    policy: Mapping[str, Any],
    source: str,
) -> dict[str, str] | None:
    """Return a medium-risk finding when the SSH policy is weaker than the baseline."""
    ssh_policy = policy.get("ssh_policy")
    if not isinstance(ssh_policy, Mapping):
        return None

    weak_conditions = (
        str(ssh_policy.get("permit_root_login", "")).strip().lower() == "yes",
        str(ssh_policy.get("password_authentication", "")).strip().lower() == "yes",
        str(ssh_policy.get("pubkey_authentication", "")).strip().lower() == "no",
    )
    if any(weak_conditions):
        return create_finding(
            risk_level=RiskLevel.MEDIUM,
            identity="system",
            finding="Weak SSH policy",
            reason="The SSH policy differs from the expected secure baseline.",
            source=source,
            recommended_action="Review SSH settings against the approved baseline.",
        )
    return None


def normal_user_single_failed_logins(
    identity: Mapping[str, Any],
    auth_events: Sequence[Mapping[str, Any]],
    source: str,
) -> dict[str, str] | None:
    """Return a low-risk finding for a normal user with a single failed login."""
    username = _identity_name(identity)
    is_privileged = _is_truthy(identity.get("is_local_admin")) or "sudo" in {
        str(item).lower() for item in identity.get("privileges", [])
    }
    failed_logins = _count_failed_logins(auth_events, username)
    if not is_privileged and failed_logins == 1:
        return create_finding(
            risk_level=RiskLevel.LOW,
            identity=username,
            finding="Normal user with a single failed login",
            reason="A non-privileged account has one failed login event.",
            source=source,
            recommended_action="Monitor for recurrence if the activity is unexpected.",
        )
    return None


def missing_log_source_but_other_data_exists(
    source: str,
    reason: str,
    identity: str = "system",
) -> dict[str, str]:
    """Return a medium-risk finding when one log source is missing but other data exists."""
    return create_finding(
        risk_level=RiskLevel.MEDIUM,
        identity=identity,
        finding="Missing log source but other data exists",
        reason=reason,
        source=source,
        recommended_action="Proceed with partial analysis and note the source gap in reporting.",
    )
