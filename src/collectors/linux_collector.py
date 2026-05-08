"""Linux collector adapter for the Bash identity audit sensor."""

from __future__ import annotations

from pathlib import Path
import logging
from typing import Any

from src.core.command_runner import run_command
from src.core.paths import PROJECT_ROOT, DATA_COLLECTED_DIR


LOGGER = logging.getLogger("nordsec.ipca.collectors.linux")
LINUX_SENSOR_SCRIPT = PROJECT_ROOT / "bash" / "linux_identity_audit.sh"
EXPECTED_OUTPUTS = {
    "linux_identity": DATA_COLLECTED_DIR / "linux_identity.json",
    "linux_policy": DATA_COLLECTED_DIR / "linux_policy.json",
}
CONTROLLED_WARNING_RETURN_CODES = {2}


def _normalized_mode(mode: str) -> str:
    """Map an application mode to the Bash sensor mode."""
    return "test" if str(mode).strip().lower() == "test" else "production"


def _verify_outputs(expected_outputs: dict[str, Path]) -> list[str]:
    """Return a list of expected files that were not created."""
    missing_outputs = []
    for _, path in expected_outputs.items():
        if not path.exists():
            missing_outputs.append(str(path))
    return missing_outputs


def _collector_reason(command_result: dict[str, Any], missing_outputs: list[str]) -> str:
    """Translate a raw collector result into a short human-readable reason."""
    if command_result.get("timed_out"):
        return "collector timed out"

    returncode = command_result.get("returncode")
    stderr = str(command_result.get("stderr_summary") or command_result.get("stderr") or "").lower()

    if returncode == 127:
        return "command unavailable"
    if "permission denied" in stderr or "operation not permitted" in stderr:
        return "permission denied; run with sudo/root if protected files must be inspected"
    if "no such file" in stderr or "file not found" in stderr:
        return "file not found"
    if returncode in CONTROLLED_WARNING_RETURN_CODES:
        return "collector completed with warnings"
    if missing_outputs:
        return "output file missing"
    if returncode not in (0, None):
        return f"collector exited with code {returncode}"
    return "completed successfully"


def _build_output_statuses(missing_outputs: list[str], reason: str) -> dict[str, dict[str, str]]:
    """Build per-file status records for the user-facing summary."""
    statuses: dict[str, dict[str, str]] = {}
    for name, path in EXPECTED_OUTPUTS.items():
        path_str = str(path)
        if path_str in missing_outputs:
            statuses[name] = {
                "status": "failed",
                "reason": reason,
                "path": path_str,
            }
        else:
            statuses[name] = {
                "status": "collected",
                "reason": "output file created",
                "path": path_str,
            }
    return statuses


def collect_linux_data(
    mode: str = "production",
    *,
    log_hours: int = 24,
    max_events: int = 1000,
    timeout: float | None = 300.0,
) -> dict[str, Any]:
    """Run the Linux Bash sensor and validate its expected outputs.

    Expects a mode string plus bounded log-window settings and returns a
    structured status dictionary. The function only launches the approved
    sensor script and checks whether the expected JSON files were created
    successfully. The extra limits keep the read-only collection bounded so
    large logs do not block the orchestrator.
    """
    selected_mode = _normalized_mode(mode)
    command = [
        "bash",
        str(LINUX_SENSOR_SCRIPT),
        "--mode",
        selected_mode,
        "--log-hours",
        str(log_hours),
        "--max-events",
        str(max_events),
    ]
    LOGGER.info(
        "Starting Linux collector in %s mode (log_hours=%s max_events=%s)",
        selected_mode,
        log_hours,
        max_events,
    )
    command_result = run_command(command, cwd=PROJECT_ROOT, timeout=timeout)

    missing_outputs = _verify_outputs(EXPECTED_OUTPUTS)
    success = (
        not command_result.timed_out
        and not missing_outputs
        and (command_result.returncode == 0 or command_result.returncode in CONTROLLED_WARNING_RETURN_CODES)
    )
    reason = _collector_reason(command_result.to_dict(), missing_outputs)
    output_statuses = _build_output_statuses(missing_outputs, reason)
    if success and command_result.succeeded:
        LOGGER.info("Linux collector completed successfully")
    elif success:
        LOGGER.warning("Linux collector completed with warnings: %s", reason)
    else:
        LOGGER.warning("Linux collector did not produce all expected outputs: %s", reason)

    return {
        "platform": "linux",
        "mode": selected_mode,
        "command": command_result.to_dict(),
        "expected_outputs": {name: str(path) for name, path in EXPECTED_OUTPUTS.items()},
        "missing_outputs": missing_outputs,
        "success": success,
        "reason": reason,
        "output_statuses": output_statuses,
    }
