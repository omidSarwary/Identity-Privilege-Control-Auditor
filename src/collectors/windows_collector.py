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


def _verify_outputs(expected_outputs: dict[str, Path]) -> list[str]:
    """Return a list of expected files that were not created."""
    missing_outputs = []
    for _, path in expected_outputs.items():
        if not path.exists():
            missing_outputs.append(str(path))
    return missing_outputs


def collect_windows_data(mode: str = "production", timeout: float | None = 300.0) -> dict[str, Any]:
    """Run the Windows PowerShell sensor and validate its expected outputs.

    Expects a mode string and returns a structured status dictionary. The
    function chooses ``pwsh`` when available and falls back to Windows
    PowerShell otherwise.
    """
    selected_mode = _normalized_mode(mode)
    executable = _resolve_powershell_executable()
    if executable is None:
        LOGGER.error("No PowerShell host was found on this system")
        return {
            "platform": "windows",
            "mode": selected_mode,
            "command": None,
            "expected_outputs": {name: str(path) for name, path in EXPECTED_OUTPUTS.items()},
            "missing_outputs": [str(path) for path in EXPECTED_OUTPUTS.values()],
            "success": False,
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
    ]
    LOGGER.info("Starting Windows collector in %s mode using %s", selected_mode, executable)
    command_result = run_command(command, cwd=PROJECT_ROOT, timeout=timeout)

    missing_outputs = _verify_outputs(EXPECTED_OUTPUTS)
    success = command_result.succeeded and not missing_outputs
    if success:
        LOGGER.info("Windows collector completed successfully")
    else:
        LOGGER.warning("Windows collector did not produce all expected outputs")

    return {
        "platform": "windows",
        "mode": selected_mode,
        "command": command_result.to_dict(),
        "expected_outputs": {name: str(path) for name, path in EXPECTED_OUTPUTS.items()},
        "missing_outputs": missing_outputs,
        "success": success,
        "executable": executable,
    }
