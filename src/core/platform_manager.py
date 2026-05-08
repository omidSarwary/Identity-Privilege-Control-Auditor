"""Platform selection and orchestration helpers."""

from __future__ import annotations

from dataclasses import asdict, dataclass
import logging
from typing import Callable


LOGGER = logging.getLogger("nordsec.ipca.core.platform_manager")
SUPPORTED_PLATFORMS = ("linux", "windows", "test")
DEFAULT_LOG_HOURS = 24
DEFAULT_MAX_EVENTS = 1000
MAX_LOG_HOURS = 720
MAX_MAX_EVENTS = 10000
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
    log_hours: int = DEFAULT_LOG_HOURS
    max_events: int = DEFAULT_MAX_EVENTS
    messages: tuple[str, ...] = ()

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
    if platform == "linux":
        return (
            "Linux mode selected. Linux logs will be collected automatically, "
            "while Windows logs should be copied manually into data/incoming/ "
            "or logdata/windows/. If logs from further back in time are needed, "
            "export them manually and place them in data/incoming/ or "
            "logdata/linux/."
        )
    if platform == "windows":
        return (
            "Windows mode selected. Windows logs will be collected automatically, "
            "while Linux logs should be copied manually into data/incoming/ "
            "or logdata/linux/. If logs from further back in time are needed, "
            "export them manually and place them in data/incoming/ or "
            "logdata/windows/."
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
    windows_log_hours: str | int | None = None,
    windows_max_events: str | int | None = None,
    linux_log_hours: str | int | None = None,
    linux_max_events: str | int | None = None,
) -> PlatformSelection:
    """Choose and validate the runtime platform for the current run.

    Expects an optional platform string, the ``--test`` flag, and an input
    function for interactive runs. Returns a structured selection that tells
    the app whether to use test or production data paths. The function only
    validates and describes the choice; it does not start collectors or modify
    system state.
    """
    user_messages: list[str] = []

    def _resolve_collection_value(raw_value: str | int | None, *, default: int, upper_bound: int, label: str) -> int:
        """Resolve one collection-window value with safe validation and clamping.

        User-facing messages are stored on the final selection so app.py can
        print the same safety decision that is written to the audit log.
        """
        if raw_value is None or str(raw_value).strip() == "":
            return default

        try:
            resolved = int(str(raw_value).strip())
        except ValueError:
            message = f"{label} value '{raw_value}' is invalid; using default {default}."
            LOGGER.warning(message)
            user_messages.append(message)
            return default

        if resolved <= 0:
            message = f"{label} value '{raw_value}' must be positive; using default {default}."
            LOGGER.warning(message)
            user_messages.append(message)
            return default

        if resolved > upper_bound:
            message = f"{label} value '{raw_value}' exceeds the maximum {upper_bound}; clamping to {upper_bound}."
            LOGGER.warning(message)
            user_messages.append("Input exceeded safety limits.")
            if "hours" in label.lower():
                user_messages.append(f"Using maximum allowed {label.lower()}: {upper_bound}.")
            else:
                user_messages.append(f"Using maximum allowed {label.lower()}: {upper_bound}.")
            return upper_bound

        return resolved

    def _prompt_for_value(prompt: str, *, default: int, upper_bound: int, label: str) -> int:
        """Prompt for a collection-window value and resolve it safely."""
        try:
            response = input_func(prompt)
        except (EOFError, KeyboardInterrupt):
            LOGGER.warning("%s prompt was interrupted; using default %s.", label, default)
            return default
        return _resolve_collection_value(response, default=default, upper_bound=upper_bound, label=label)

    interactive_selection = not test_flag and requested_platform is None

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
    if platform == "windows":
        if interactive_selection and windows_log_hours is None:
            windows_log_hours = _prompt_for_value(
                "Windows Security log lookback hours [24]: ",
                default=DEFAULT_LOG_HOURS,
                upper_bound=MAX_LOG_HOURS,
                label="Windows log hours",
            )
        if interactive_selection and windows_max_events is None:
            windows_max_events = _prompt_for_value(
                "Windows max events [1000]: ",
                default=DEFAULT_MAX_EVENTS,
                upper_bound=MAX_MAX_EVENTS,
                label="Windows max events",
            )
        resolved_log_hours = _resolve_collection_value(
            windows_log_hours,
            default=DEFAULT_LOG_HOURS,
            upper_bound=MAX_LOG_HOURS,
            label="Windows log hours",
        )
        resolved_max_events = _resolve_collection_value(
            windows_max_events,
            default=DEFAULT_MAX_EVENTS,
            upper_bound=MAX_MAX_EVENTS,
            label="Windows max events",
        )
    elif platform == "linux":
        if interactive_selection and linux_log_hours is None:
            linux_log_hours = _prompt_for_value(
                "Linux log lookback hours [24]: ",
                default=DEFAULT_LOG_HOURS,
                upper_bound=MAX_LOG_HOURS,
                label="Linux log hours",
            )
        if interactive_selection and linux_max_events is None:
            linux_max_events = _prompt_for_value(
                "Linux max events/lines [1000]: ",
                default=DEFAULT_MAX_EVENTS,
                upper_bound=MAX_MAX_EVENTS,
                label="Linux max events/lines",
            )
        resolved_log_hours = _resolve_collection_value(
            linux_log_hours,
            default=DEFAULT_LOG_HOURS,
            upper_bound=MAX_LOG_HOURS,
            label="Linux log hours",
        )
        resolved_max_events = _resolve_collection_value(
            linux_max_events,
            default=DEFAULT_MAX_EVENTS,
            upper_bound=MAX_MAX_EVENTS,
            label="Linux max events/lines",
        )
    else:
        resolved_log_hours = DEFAULT_LOG_HOURS
        resolved_max_events = DEFAULT_MAX_EVENTS

    selection = PlatformSelection(
        platform=platform,
        analysis_mode=analysis_mode,
        use_mockdata=platform == "test",
        log_hours=resolved_log_hours,
        max_events=resolved_max_events,
        instructions=f"{HYBRID_LOGGING_NOTICE} {_build_instructions(platform)}",
        messages=tuple(dict.fromkeys(user_messages)),
    )
    LOGGER.info(
        "Collection window resolved: platform=%s log_hours=%s max_events=%s",
        selection.platform,
        selection.log_hours,
        selection.max_events,
    )
    LOGGER.info("Platform selection resolved: %s", selection.platform)
    return selection
