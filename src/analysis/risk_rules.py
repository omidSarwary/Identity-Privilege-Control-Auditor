"""Risk rule definitions for the identity and privilege audit model."""

from __future__ import annotations

from enum import Enum
from typing import Any, Mapping, Sequence


class RiskLevel(str, Enum):
    """Centralized risk levels used across the analysis layer.

    The values must stay stable because correlation, scoring, reporting, and
    tests all rely on the same vocabulary when describing severity.
    """

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
    """Build a normalized finding record for downstream reporting.

    Expects the severity, identity name, finding text, reason, source, and
    recommended action. The function exists so every rule returns the same
    dictionary shape, which keeps the report and alert pipeline simple.
    """
    return {
        "risk_level": risk_level.value,
        "identity": identity,
        "finding": finding,
        "reason": reason,
        "source": source,
        "recommended_action": recommended_action,
    }


def _identity_name(record: Mapping[str, Any], default: str = "unknown") -> str:
    """Extract the most useful identity name from a mixed input record."""
    return str(record.get("username") or record.get("identity") or default)


def _is_truthy(value: Any) -> bool:
    """Interpret common text and boolean values as a simple enabled/disabled flag."""
    if isinstance(value, str):
        return value.strip().lower() in {"true", "1", "yes", "enabled", "yes"}
    return bool(value)


def _count_failed_logins(events: Sequence[Mapping[str, Any]], username: str) -> int:
    """Count failed login events for one identity.

    This is used by several rules, so the counting logic lives in one place to
    avoid inconsistency between the different risk checks.
    """
    count = 0
    for event in events:
        event_user = str(
            event.get("TargetUserName")
            or event.get("username")
            or event.get("target_user")
            or ""
        )
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
    """Return a critical finding when a disabled account still has activity.

    Expects an identity record, the related authentication events, and a source
    label. Disabled accounts should not be active, so any failed-login evidence
    becomes a CRITICAL finding.
    """
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
    """Return a critical finding for an unapproved Windows administrators member.

    Expects a Windows identity record and the approved admin baseline. Local
    administrator access is high impact, so an unapproved member must be
    escalated immediately.
    """
    username = _identity_name(identity)
    if _is_truthy(identity.get("is_local_admin")) and username not in approved_admins:
        enabled = _is_truthy(identity.get("enabled", True))
        reason = (
            "The disabled account still appears in local administrator membership but is not listed in the approved baseline."
            if not enabled
            else "The account is a local administrator but is not listed in the approved baseline."
        )
        return create_finding(
            risk_level=RiskLevel.CRITICAL,
            identity=username,
            finding="Unapproved Windows administrators member",
            reason=reason,
            source=source,
            recommended_action="Review local administrator membership against the approved baseline.",
        )
    return None


def unauthorized_linux_sudo_user(
    identity: Mapping[str, Any],
    approved_sudoers: Sequence[str],
    source: str,
) -> dict[str, str] | None:
    """Return a critical finding for an unapproved Linux sudo user.

    Expects a Linux identity record and the approved sudo baseline. Sudo access
    changes the host's security posture, so an unapproved sudo user is CRITICAL.
    """
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
    """Return a critical finding for privileged accounts with repeated failed logins.

    Expects an identity record and that identity's failed-login events. Repeated
    failures are more serious on privileged accounts because compromise could
    expose broader host access.
    """
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
    """Return a critical finding when root SSH login is permitted and privileged activity is observed.

    Expects the Linux SSH policy and a flag showing whether privileged activity
    was seen. Allowing root SSH login weakens the host, so observed privileged
    activity under that policy becomes CRITICAL.
    """
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
    """Return a critical finding for corrupt critical input data.

    Expects the source label and a human-readable reason. Corrupt inputs are
    treated as critical because the downstream analysis cannot trust them.
    """
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
    """Return a high-risk finding for an inactive account with privileges.

    Expects an identity record that includes inactivity and privilege details.
    Standing privileged access without normal use deserves HIGH severity because
    it expands the attack surface even when the account appears dormant.
    """
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
    """Return a high-risk finding when the same IP generates repeated failures.

    Expects authentication events and a source label. Repeated failures from
    one network source often indicate brute-force or password-spraying activity.
    """
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
    """Return a high-risk finding when audit policy data is unavailable.

    Expects a policy dictionary and source label. Missing audit policy matters
    because the report needs to know whether logging controls are visible at all.
    """
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
    """Return a high-risk finding when the readable firewall control is disabled.

    Expects Windows policy rows and a source label. The rule only fires when
    the control can be read, which avoids guessing about hidden state.
    """
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
    """Return a medium-risk finding when the SSH policy is weaker than the baseline.

    Expects the SSH policy mapping and a source label. SSH weaknesses are
    important, but the severity stays below CRITICAL unless privileged activity
    or root exposure is also present.
    """
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


def policy_deviation(
    identity: str,
    finding: str,
    reason: str,
    source: str,
) -> dict[str, str]:
    """Return a medium-risk finding for a policy deviation.

    The function is intentionally generic so correlation can describe a control
    mismatch without duplicating the rule in multiple places. It keeps policy
    deviation wording consistent across Linux and Windows findings.
    """
    return create_finding(
        risk_level=RiskLevel.MEDIUM,
        identity=identity,
        finding=finding,
        reason=reason,
        source=source,
        recommended_action="Review the policy against the approved baseline.",
    )


def normal_user_single_failed_logins(
    identity: Mapping[str, Any],
    auth_events: Sequence[Mapping[str, Any]],
    source: str,
) -> dict[str, str] | None:
    """Return a low-risk finding for a normal user with a single failed login.

    Expects a non-privileged identity and related authentication events. A
    single failed login is still worth reporting, but it stays LOW because the
    account does not control privileged functions.
    """
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
    """Return a medium-risk finding when one log source is missing but other data exists.

    Expects a source label and reason string. The finding stays MEDIUM because
    the analysis can continue, but the missing source should be explained in
    the report as a data-quality limitation.
    """
    return create_finding(
        risk_level=RiskLevel.MEDIUM,
        identity=identity,
        finding="Missing log source but other data exists",
        reason=reason,
        source=source,
        recommended_action="Proceed with partial analysis and note the source gap in reporting.",
    )


def partial_platform_evidence(
    *,
    platform: str,
    available_sources: Sequence[str],
    missing_sources: Sequence[str],
    source: str = "data_quality",
) -> dict[str, str] | None:
    """Return a medium source-gap finding for incomplete platform evidence.

    Expects the platform name plus exact available and missing source names.
    The wording avoids calling every gap a log-source issue, which keeps the
    report accurate when identity or policy files are missing.
    """
    if not available_sources or not missing_sources:
        return None
    platform_label = platform.strip().title()
    available_text = ", ".join(available_sources)
    missing_text = ", ".join(missing_sources)
    return create_finding(
        risk_level=RiskLevel.MEDIUM,
        identity="system_policy",
        finding=f"Partial {platform_label} evidence",
        reason=f"{platform_label} evidence was partial: {available_text} was available, but {missing_text} was missing.",
        source=source,
        recommended_action="Re-collect or supply the missing evidence sources before making final access decisions.",
    )
