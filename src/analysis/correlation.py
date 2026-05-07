"""Correlation helpers for identities, privileges, baselines, policy, and events."""

from __future__ import annotations

import logging
from collections import defaultdict
from typing import Any, Mapping, Sequence

from src.analysis.risk_rules import RiskLevel


LOGGER = logging.getLogger("nordsec.ipca.analysis.correlation")

RISK_SCORE_BY_LEVEL = {
    RiskLevel.CRITICAL.value: 90,
    RiskLevel.HIGH.value: 70,
    RiskLevel.MEDIUM.value: 40,
    RiskLevel.LOW.value: 10,
}


def _truthy(value: Any) -> bool:
    """Return ``True`` when a loosely formatted value represents an enabled state."""
    if isinstance(value, str):
        return value.strip().lower() in {"true", "1", "yes", "enabled"}
    return bool(value)


def _string_set(values: Sequence[Any] | None) -> set[str]:
    """Convert a baseline-style input into a username set.

    The baseline files are CSV-based, so this helper accepts either plain
    strings or dictionaries and extracts the account name consistently.
    """
    usernames: set[str] = set()
    for value in values or []:
        if isinstance(value, Mapping):
            username = value.get("username") or value.get("Username")
        else:
            username = value
        if username is not None:
            usernames.add(str(username))
    return usernames


def _build_identity_record(identity: str, platform: str) -> dict[str, Any]:
    """Create the normalized dictionary model used throughout later analysis.

    The model stays dictionary-based so it can be serialized directly to JSON
    without any conversion layer when reports or alerts are produced.
    """
    return {
        "identity": identity,
        "platforms": [platform],
        "privileges": [],
        "status": "enabled",
        "baseline_match": False,
        "events": [],
        "policy_findings": [],
        "risk_score": RISK_SCORE_BY_LEVEL[RiskLevel.LOW.value],
        "risk_level": RiskLevel.LOW.value,
        "reasons": [],
    }


def _merge_platform(record: dict[str, Any], platform: str) -> None:
    """Add a platform to an existing normalized identity record if needed."""
    if platform not in record["platforms"]:
        record["platforms"].append(platform)


def _update_status(record: dict[str, Any], status: str) -> None:
    """Preserve the most restrictive account status seen across sources."""
    current_status = record.get("status", "enabled")
    if current_status == "disabled":
        return
    record["status"] = status


def normalize_identities(
    linux_identity: Mapping[str, Any] | None = None,
    windows_identity_rows: Sequence[Mapping[str, Any]] | None = None,
) -> list[dict[str, Any]]:
    """Normalize Linux and Windows identity inputs into a shared record format.

    The function expects the parsed Linux JSON payload and Windows CSV rows.
    It returns a list of dictionaries that later stages can enrich with
    baselines, events, policy findings, and risk data. This step matters
    because the rest of the pipeline needs one common shape before it can
    compare identities across platforms.
    """
    LOGGER.info("Starting identity normalization")

    records: dict[str, dict[str, Any]] = {}

    linux_payload = linux_identity or {}
    for user in linux_payload.get("users", []) or []:
        username = str(user.get("username") or "unknown")
        record = records.setdefault(username, _build_identity_record(username, "linux"))
        _merge_platform(record, "linux")

        # Linux privilege state is derived from the sudo inventory and the user
        # record so later correlation can compare it to the approved baseline
        # instead of treating Linux and Windows as separate analysis worlds.
        if _truthy(user.get("is_sudo")) and "sudo" not in record["privileges"]:
            record["privileges"].append("sudo")

        if _truthy(user.get("enabled", True)):
            _update_status(record, "enabled")
        else:
            record["status"] = "disabled"

    for username in linux_payload.get("sudo_users", []) or []:
        record = records.setdefault(str(username), _build_identity_record(str(username), "linux"))
        _merge_platform(record, "linux")
        if "sudo" not in record["privileges"]:
            record["privileges"].append("sudo")

    for row in windows_identity_rows or []:
        username = str(row.get("Username") or row.get("username") or "unknown")
        record = records.setdefault(username, _build_identity_record(username, "windows"))
        _merge_platform(record, "windows")

        # Windows local admin membership is tracked separately from account
        # enablement so the later baseline comparison can distinguish standing
        # privilege from the basic enabled/disabled account state.
        if _truthy(row.get("IsLocalAdmin") or row.get("is_local_admin")) and "local_admin" not in record["privileges"]:
            record["privileges"].append("local_admin")

        if _truthy(row.get("Enabled", True)):
            _update_status(record, "enabled")
        else:
            record["status"] = "disabled"

    normalized = sorted(records.values(), key=lambda item: item["identity"])
    LOGGER.info("Completed identity normalization")
    return normalized


def correlate_identity_privileges(
    normalized_identities: Sequence[Mapping[str, Any]] | None,
    approved_linux_sudoers: Sequence[Any] | None = None,
    approved_windows_admins: Sequence[Any] | None = None,
    approved_service_accounts: Sequence[Any] | None = None,
) -> list[dict[str, Any]]:
    """Correlate identity records with approved privilege baselines.

    The function expects normalized identity dictionaries and approved baseline
    rows. It marks whether the identity matches the approved control state and
    stores a short reason when a privileged account is not approved. This is
    the point where baseline membership becomes part of the identity story.
    """
    LOGGER.info("Starting identity privilege correlation")

    approved_linux = _string_set(approved_linux_sudoers)
    approved_windows = _string_set(approved_windows_admins)
    approved_service = _string_set(approved_service_accounts)

    correlated: list[dict[str, Any]] = []
    for identity in normalized_identities or []:
        record = dict(identity)
        username = str(record.get("identity") or "unknown")
        privileges = {str(item).lower() for item in record.get("privileges", [])}

        # Baseline matching is intentionally conservative: non-privileged users
        # are treated as compliant by default, while privileged users must be in
        # an approved list before the account is considered a baseline match.
        # That keeps the report focused on accounts that can actually change the
        # security posture of the host.
        privileged = bool(privileges)
        approved = (
            username in approved_linux
            or username in approved_windows
            or username in approved_service
        )

        if privileged:
            record["baseline_match"] = approved
            if not approved:
                record["reasons"] = list(record.get("reasons", [])) + [
                    "Privileged account is not present in the approved baseline."
                ]
        else:
            record["baseline_match"] = True

        correlated.append(record)

    LOGGER.info("Completed identity privilege correlation")
    return correlated


def correlate_events_to_identities(
    normalized_identities: Sequence[Mapping[str, Any]] | None,
    linux_auth_events: Sequence[Mapping[str, Any]] | None = None,
    windows_events: Sequence[Mapping[str, Any]] | None = None,
) -> list[dict[str, Any]]:
    """Attach authentication events to their matching normalized identities.

    Events are matched by account name so Windows CSV events and Linux auth log
    entries can be compared against the same identity record. This is the key
    step that lets the report explain *who* saw activity, not just *that* an
    event happened somewhere on the host.
    """
    LOGGER.info("Starting event-to-identity correlation")

    event_index: dict[str, list[dict[str, Any]]] = defaultdict(list)

    for event in linux_auth_events or []:
        username = str(event.get("username") or event.get("TargetUserName") or event.get("user") or "unknown")
        event_index[username].append(
            {
                "source": "linux",
                "event_type": str(event.get("event_type") or event.get("EventType") or "unknown"),
                "target_user": username,
                "ip_address": str(event.get("ip_address") or event.get("IpAddress") or ""),
                "count": int(event.get("count", 1) or 1),
            }
        )

    for event in windows_events or []:
        username = str(event.get("TargetUserName") or event.get("username") or "unknown")
        event_index[username].append(
            {
                "source": "windows",
                "event_type": str(event.get("EventType") or event.get("event_type") or "unknown"),
                "target_user": username,
                "ip_address": str(event.get("IpAddress") or event.get("ip_address") or ""),
                "count": int(event.get("count", 1) or 1),
            }
        )

    correlated: list[dict[str, Any]] = []
    for identity in normalized_identities or []:
        record = dict(identity)
        username = str(record.get("identity") or "unknown")
        # Events are attached per identity so later anomaly rules can count
        # failed logins and tie them back to a specific account.
        record["events"] = list(record.get("events", [])) + event_index.get(username, [])
        correlated.append(record)

    LOGGER.info("Completed event-to-identity correlation")
    return correlated


def correlate_policy_findings(
    normalized_identities: Sequence[Mapping[str, Any]] | None,
    linux_policy: Mapping[str, Any] | None = None,
    windows_policy_rows: Sequence[Mapping[str, Any]] | None = None,
    expected_policy_baseline: Mapping[str, Any] | None = None,
) -> list[dict[str, Any]]:
    """Attach policy deviations to the identities that they affect.

    The policy comparison is kept separate from event correlation so that the
    report can explain which control area produced the deviation: SSH on Linux
    and firewall/audit/execution policy on Windows. This separation makes the
    final findings easier to describe in an examination report.
    """
    LOGGER.info("Starting policy correlation")

    correlated: list[dict[str, Any]] = []
    linux_baseline = (expected_policy_baseline or {}).get("ssh_policy", {})
    windows_baseline = expected_policy_baseline or {}

    linux_findings: list[dict[str, Any]] = []
    linux_policy_map = (linux_policy or {}).get("policy", linux_policy or {})
    ssh_policy = linux_policy_map.get("ssh_policy", {})
    if isinstance(ssh_policy, Mapping):
        for key, expected_value in linux_baseline.items():
            observed_value = ssh_policy.get(key)
            if observed_value is not None and str(observed_value).strip().lower() != str(expected_value).strip().lower():
                linux_findings.append(
                    {
                        "check_name": f"ssh_policy.{key}",
                        "source": "linux_policy.json",
                        "expected": expected_value,
                        "observed": observed_value,
                        "deviation": "policy_mismatch",
                    }
                )

    windows_findings: list[dict[str, Any]] = []
    for row in windows_policy_rows or []:
        check_name = str(row.get("CheckName") or row.get("check_name") or "")
        status = str(row.get("Status") or row.get("status") or "")
        value = row.get("Value") or row.get("value")

        # Windows policy rows are already normalized enough for comparison, so
        # the correlation step only records the deviation and leaves scoring to
        # the anomaly phase. This keeps policy comparison separate from risk
        # severity selection.
        if check_name == "firewall_enabled" and status.lower() in {"false", "disabled", "off"}:
            windows_findings.append(
                {
                    "check_name": check_name,
                    "source": "windows_policy.csv",
                    "expected": True,
                    "observed": value,
                    "deviation": "firewall_disabled",
                }
            )
        elif check_name == "audit_policy_enabled" and status.lower() not in {"true", "enabled", "on"}:
            windows_findings.append(
                {
                    "check_name": check_name,
                    "source": "windows_policy.csv",
                    "expected": True,
                    "observed": value,
                    "deviation": "audit_policy_missing",
                }
            )
        elif check_name == "execution_policy":
            expected_execution = windows_baseline.get("execution_policy", {}).get("powershell")
            if expected_execution and str(value).strip().lower() != str(expected_execution).strip().lower():
                windows_findings.append(
                    {
                        "check_name": check_name,
                        "source": "windows_policy.csv",
                        "expected": expected_execution,
                        "observed": value,
                        "deviation": "execution_policy_mismatch",
                    }
                )

    for identity in normalized_identities or []:
        record = dict(identity)
        platforms = {str(item).lower() for item in record.get("platforms", [])}
        record["policy_findings"] = list(record.get("policy_findings", []))

        if "linux" in platforms:
            record["policy_findings"].extend(linux_findings)
        if "windows" in platforms:
            record["policy_findings"].extend(windows_findings)

        correlated.append(record)

    LOGGER.info("Completed policy correlation")
    return correlated
