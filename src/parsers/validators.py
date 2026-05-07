"""Validation helpers for collected and normalized audit records."""

from __future__ import annotations

from dataclasses import dataclass, field
import logging
from typing import Any


LOGGER = logging.getLogger("nordsec.ipca.parsers.validators")


@dataclass
class ValidationStatus:
    """Structured data-quality status for parser outputs.

    The object stores warnings and errors separately so the pipeline can decide
    whether a dataset is acceptable, incomplete, or unusable for analysis.
    """

    valid: bool
    warnings: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)

    def add_warning(self, message: str) -> None:
        """Record a non-fatal quality warning."""
        self.warnings.append(message)
        LOGGER.warning(message)

    def add_error(self, message: str) -> None:
        """Record a fatal quality error."""
        self.errors.append(message)
        self.valid = False
        LOGGER.error(message)


def _validate_mapping(payload: dict[str, Any], required_keys: list[str], context: str) -> ValidationStatus:
    """Validate that a dictionary contains the expected keys for a context."""
    status = ValidationStatus(valid=True)
    for key in required_keys:
        if key not in payload:
            status.add_error(f"{context}: missing required key '{key}'")
    return status


def _validate_column_rows(
    rows: list[dict[str, Any]],
    required_columns: list[str],
    context: str,
) -> ValidationStatus:
    """Validate that a CSV-style record list contains the expected columns."""
    status = ValidationStatus(valid=True)
    if not rows:
        status.add_error(f"{context}: no rows available")
        return status

    for column in required_columns:
        if any(column not in row for row in rows):
            status.add_error(f"{context}: missing required column '{column}'")
    return status


def validate_linux_identity(data: dict[str, Any]) -> ValidationStatus:
    """Validate the normalized Linux identity payload.

    Expects the Linux JSON structure produced by the collector and checks that
    the keys needed for correlation are present. This prevents later stages
    from misreading incomplete account or sudo data.
    """
    status = _validate_mapping(
        data,
        ["source", "host", "collection_time", "mode", "users", "sudo_users", "auth_events", "policy", "collector_status"],
        "linux_identity",
    )
    if status.valid and not data.get("users"):
        status.add_warning("linux_identity: users list is empty")
    if status.valid and not data.get("sudo_users"):
        status.add_warning("linux_identity: sudo_users list is empty")
    return status


def validate_linux_policy(data: dict[str, Any]) -> ValidationStatus:
    """Validate the Linux policy payload.

    Expects the Linux policy JSON structure and verifies that the SSH policy
    block is present. SSH policy is a core control in this project, so missing
    keys must be reported early.
    """
    status = _validate_mapping(data, ["source", "host", "collection_time", "mode", "policy"], "linux_policy")
    policy = data.get("policy", {})
    if status.valid and isinstance(policy, dict):
        ssh_policy = policy.get("ssh_policy")
        if not isinstance(ssh_policy, dict):
            status.add_error("linux_policy: missing ssh_policy mapping")
        else:
            for key in ["permit_root_login", "password_authentication", "pubkey_authentication"]:
                if key not in ssh_policy:
                    status.add_error(f"linux_policy: missing ssh policy key '{key}'")
    return status


def validate_windows_identity(rows: list[dict[str, Any]]) -> ValidationStatus:
    """Validate the Windows identity CSV rows.

    Expects parsed CSV rows and checks that the identity columns required for
    baseline and privilege correlation are present.
    """
    required_columns = ["ComputerName", "CollectionTime", "Username", "Enabled", "IsLocalAdmin", "LastLogon", "Source"]
    status = _validate_column_rows(rows, required_columns, "windows_identity")
    if status.valid and all(str(row.get("Username", "")).strip().lower() == "normal_user" for row in rows):
        status.add_warning("windows_identity: only normal user rows were detected")
    return status


def validate_windows_events(rows: list[dict[str, Any]]) -> ValidationStatus:
    """Validate the Windows event CSV rows.

    Expects parsed event rows and verifies the event fields needed to link
    failures back to identities and network sources.
    """
    required_columns = ["ComputerName", "TimeCreated", "EventId", "TargetUserName", "IpAddress", "EventType"]
    return _validate_column_rows(rows, required_columns, "windows_events")


def validate_windows_policy(rows: list[dict[str, Any]]) -> ValidationStatus:
    """Validate the Windows policy CSV rows.

    Expects parsed Windows policy rows and checks the columns needed to detect
    firewall, audit, and execution policy deviations.
    """
    required_columns = ["ComputerName", "CheckName", "Status", "Value", "RiskHint"]
    return _validate_column_rows(rows, required_columns, "windows_policy")


def validate_baseline_csv(rows: list[dict[str, Any]], required_columns: list[str]) -> ValidationStatus:
    """Validate baseline CSV content against the expected baseline columns.

    Expects baseline rows and a required column list, then reports whether the
    approved baseline can be used safely by the correlation layer.
    """
    return _validate_column_rows(rows, required_columns, "baseline_csv")
