"""Platform selection and orchestration helpers."""

from __future__ import annotations

from dataclasses import asdict, dataclass
import logging
from typing import Callable


LOGGER = logging.getLogger("nordsec.ipca.core.platform_manager")
SUPPORTED_PLATFORMS = ("linux", "windows", "test")
HYBRID_LOGGING_NOTICE = (
    "Hybrid logging: structured outputs will later be written to data/collected/, "
    "manual exports can be copied into data/incoming/, and raw logs may be placed "
    "under logdata/linux/ or logdata/windows/."
)


@dataclass(frozen=True)
class PlatformSelection:
    """Structured selection for the interactive application entry point.

    The selection keeps the user-visible platform choice separate from the
    internal analysis mode so the app can stay explicit about when mock data is
    used.
    """

    platform: str
    analysis_mode: str
    use_mockdata: bool
    instructions: str

    def to_dict(self) -> dict[str, object]:
        """Return a serializable representation of the platform selection."""
        return asdict(self)


def _normalize_platform(value: str) -> str:
    """Normalize a free-form platform answer into a supported value."""
    return value.strip().lower()


def _build_instructions(platform: str) -> str:
    """Build the user-facing message that explains the current logging flow."""
    if platform == "test":
        return (
            "Test mode selected. Mock data will be used if available, and live "
            "system logs will not be modified."
        )
    return (
        f"{platform.title()} mode selected. Native sensors will later feed the "
        "collector output, while manually exported evidence can still be placed "
        "in the approved fallback directories."
    )


def choose_platform(
    requested_platform: str | None = None,
    *,
    test_flag: bool = False,
    input_func: Callable[[str], str] = input,
) -> PlatformSelection:
    """Choose and validate the runtime platform for the current run.

    Expects an optional platform string, the ``--test`` flag, and an input
    function for interactive runs. Returns a structured selection that tells
    the app whether to use test or production data paths. The function only
    validates and describes the choice; it does not start collectors or modify
    system state.
    """
    if test_flag:
        platform = "test"
    elif requested_platform:
        platform = _normalize_platform(requested_platform)
    else:
        platform = ""
        prompt = "Select platform [linux/windows/test]: "
        for attempt in range(3):
            try:
                response = _normalize_platform(input_func(prompt))
            except (EOFError, KeyboardInterrupt):
                LOGGER.warning("Interactive platform selection was interrupted; defaulting to test mode.")
                platform = "test"
                break

            if response in SUPPORTED_PLATFORMS:
                platform = response
                break

            LOGGER.warning("Unsupported platform selection '%s' (attempt %s/3).", response or "<empty>", attempt + 1)
        else:
            platform = "test"
            LOGGER.warning("No valid platform was selected; defaulting to test mode.")

    if platform not in SUPPORTED_PLATFORMS:
        LOGGER.warning("Unsupported platform '%s' was requested; defaulting to test mode.", platform)
        platform = "test"

    analysis_mode = "test" if platform == "test" else "production"
    selection = PlatformSelection(
        platform=platform,
        analysis_mode=analysis_mode,
        use_mockdata=platform == "test",
        instructions=f"{HYBRID_LOGGING_NOTICE} {_build_instructions(platform)}",
    )
    LOGGER.info("Platform selection resolved: %s", selection.platform)
    return selection
