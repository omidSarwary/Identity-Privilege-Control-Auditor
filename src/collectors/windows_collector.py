"""Windows collector adapter for the PowerShell identity audit sensor."""

from __future__ import annotations

from pathlib import Path
import logging
import shutil
from typing import Any

from src.core.command_runner import run_command
from src.core.paths import PROJECT_ROOT, DATA_COLLECTED_DIR


LOGGER = logging.getLogger("nordsec.ipca.collectors.windows")
WINDOWS_SENSOR_SCRIPT = PROJECT_ROOT / "powershell" / "windows_identity_audit.ps1"
EXPECTED_OUTPUTS = {
    "windows_identity": DATA_COLLECTED_DIR / "windows_identity.csv",
    "windows_events": DATA_COLLECTED_DIR / "windows_events.csv",
    "windows_policy": DATA_COLLECTED_DIR / "windows_policy.csv",
}


def _normalized_mode(mode: str) -> str:
    """Map an application mode to the PowerShell sensor mode."""
    return "Test" if str(mode).strip().lower() == "test" else "Production"


def _resolve_powershell_executable() -> str | None:
    """Pick a PowerShell host without using shell parsing."""
    return shutil.which("pwsh") or shutil.which("powershell")


def _inspect_outputs(expected_outputs: dict[str, Path], started_at: float) -> dict[str, list[str]]:
    """Classify expected output files by current-run freshness."""
    missing_outputs: list[str] = []
    stale_outputs: list[str] = []
    current_outputs: list[str] = []
    for _, path in expected_outputs.items():
        path_str = str(path)
        if not path.exists():
            missing_outputs.append(path_str)
            continue
        if path.stat().st_mtime + 0.001 < started_at:
            stale_outputs.append(path_str)
            continue
        current_outputs.append(path_str)
    return {
        "missing_outputs": missing_outputs,
        "stale_outputs": stale_outputs,
        "current_outputs": current_outputs,
    }


def _collector_reason(command_result: dict[str, Any], missing_outputs: list[str], stale_outputs: list[str]) -> str:
    """Translate a raw collector result into a short human-readable reason."""
    if command_result.get("timed_out"):
        return "collector timed out; see logs/windows_audit.log and logs/python_engine.log"

    returncode = command_result.get("returncode")
    stderr = str(command_result.get("stderr_summary") or command_result.get("stderr") or "").lower()

    if returncode == 127:
        return "PowerShell was not found. Windows collection cannot run on this host."
    if "access is denied" in stderr or "permission denied" in stderr:
        return "access denied; run PowerShell as Administrator. See logs/windows_audit.log and logs/python_engine.log"
    if "not recognized" in stderr:
        return "PowerShell command unavailable. See logs/windows_audit.log and logs/python_engine.log"
    if missing_outputs:
        return "output file missing. See logs/windows_audit.log and logs/python_engine.log"
    if stale_outputs:
        return "stale existing output ignored; file was not updated in this run. See logs/windows_audit.log and logs/python_engine.log"
    if returncode not in (0, None):
        return f"collector exited with code {returncode}. See logs/windows_audit.log and logs/python_engine.log"
    return "completed successfully"


def _build_output_statuses(
    *,
    missing_outputs: list[str],
    stale_outputs: list[str],
    reason: str,
) -> dict[str, dict[str, str]]:
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
        elif path_str in stale_outputs:
            statuses[name] = {
                "status": "not collected in this run",
                "reason": "stale existing file ignored",
                "path": path_str,
            }
        else:
            statuses[name] = {
                "status": "collected",
                "reason": "output file created",
                "path": path_str,
            }
    return statuses


def collect_windows_data(
    mode: str = "production",
    *,
    log_hours: int = 24,
    max_events: int = 1000,
    timeout: float | None = 300.0,
) -> dict[str, Any]:
    """Run the Windows PowerShell sensor and validate its expected outputs.

    Expects a mode string plus bounded log-window settings and returns a
    structured status dictionary. The function chooses ``pwsh`` when available
    and falls back to Windows PowerShell otherwise. The extra limits keep the
    Security-log collection bounded so the orchestrator can fail safely instead
    of waiting for an unbounded scan.
    """
    selected_mode = _normalized_mode(mode)
    executable = _resolve_powershell_executable()
    if executable is None:
        reason = "PowerShell was not found. Windows collection cannot run on this host."
        LOGGER.error("No PowerShell host was found on this system")
        expected_outputs = {name: str(path) for name, path in EXPECTED_OUTPUTS.items()}
        return {
            "platform": "windows",
            "mode": selected_mode,
            "command": None,
            "expected_outputs": expected_outputs,
            "missing_outputs": [str(path) for path in EXPECTED_OUTPUTS.values()],
            "stale_outputs": [],
            "current_outputs": [],
            "success": False,
            "reason": reason,
            "output_statuses": {
                name: {"status": "not collected", "reason": reason, "path": path}
                for name, path in expected_outputs.items()
            },
        }

    command = [
        executable,
        "-NoProfile",
        "-ExecutionPolicy",
        "Bypass",
        "-File",
        str(WINDOWS_SENSOR_SCRIPT),
        "-Mode",
        selected_mode,
        "-LogHours",
        str(log_hours),
        "-MaxEvents",
        str(max_events),
    ]
    LOGGER.info(
        "Starting Windows collector in %s mode using %s (log_hours=%s max_events=%s)",
        selected_mode,
        executable,
        log_hours,
        max_events,
    )
    command_result = run_command(command, cwd=PROJECT_ROOT, timeout=timeout)
    collector_started_at = command_result.started_at

    output_state = _inspect_outputs(EXPECTED_OUTPUTS, collector_started_at)
    missing_outputs = output_state["missing_outputs"]
    stale_outputs = output_state["stale_outputs"]
    current_outputs = output_state["current_outputs"]
    success = command_result.succeeded and not missing_outputs and not stale_outputs
    reason = _collector_reason(command_result.to_dict(), missing_outputs, stale_outputs)
    output_statuses = _build_output_statuses(
        missing_outputs=missing_outputs,
        stale_outputs=stale_outputs,
        reason=reason,
    )
    if success and command_result.succeeded:
        LOGGER.info("Windows collector completed successfully")
    elif success:
        LOGGER.warning("Windows collector completed with warnings: %s", reason)
    else:
        LOGGER.warning("Windows collector did not produce all expected outputs: %s", reason)

    return {
        "platform": "windows",
        "mode": selected_mode,
        "command": command_result.to_dict(),
        "expected_outputs": {name: str(path) for name, path in EXPECTED_OUTPUTS.items()},
        "missing_outputs": missing_outputs,
        "stale_outputs": stale_outputs,
        "current_outputs": current_outputs,
        "collector_started_at": collector_started_at,
        "success": success,
        "executable": executable,
        "reason": reason,
        "output_statuses": output_statuses,
    }
