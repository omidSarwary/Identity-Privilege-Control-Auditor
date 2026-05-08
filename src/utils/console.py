"""Console formatting helpers for user-facing output."""

from __future__ import annotations

from typing import Sequence


def format_banner(title: str, version: str, mode: str) -> str:
    """Build the console banner shown at program start.

    Expects the project title, version, and mode, and returns a single string
    that can be printed to the console. The banner reminds the user that the
    tool is read-only and does not modify system state.
    """
    lines = [
        "=" * 60,
        f" {title}",
        f" Version: {version}",
        f" Mode: {mode}",
        "",
        " This tool performs read-only security validation.",
        " It does not modify accounts, privileges, or policy state.",
        "=" * 60,
    ]
    return "\n".join(lines)


def print_message(message: str) -> None:
    """Print a concise user-facing console message.

    Expects a single line of text and writes it to standard output. The helper
    keeps user-facing messaging centralized so the console style stays
    consistent.
    """
    print(message)


def build_privilege_notice(platform: str, *, test_mode: bool = False) -> str:
    """Build the startup note about elevated privileges.

    Expects a runtime platform name and a test-mode flag. The returned message
    explains whether Administrator or sudo access may be needed for production
    evidence collection without implying that the app will change system
    state.
    """
    normalized_platform = platform.strip().lower()
    if test_mode:
        return "Test mode uses mockdata and does not require elevated privileges."
    if normalized_platform == "windows":
        return (
            "Production collection may require Administrator access to read "
            "Security logs and audit policy."
        )
    if normalized_platform == "linux":
        return (
            "Production collection may require sudo/root access to read "
            "protected logs, SSH config, or file permissions."
        )
    return (
        "Production collection may require elevated privileges to read "
        "protected evidence sources."
    )


def format_section_title(step: int, total: int, title: str) -> str:
    """Format a numbered pipeline section title for the console."""
    return f"[{step}/{total}] {title}"


def format_status_line(label: str, status: str, reason: str | None = None) -> str:
    """Format a compact status line for one evidence item.

    Expects a short label, a status word, and an optional plain-English
    reason. The helper keeps the terminal readable while still explaining why
    a collector step succeeded, failed, or was skipped.
    """
    line = f"- {label}: {status}"
    if reason:
        line += f" ({reason})"
    return line


def print_lines(lines: Sequence[str]) -> None:
    """Print multiple user-facing lines in order."""
    for line in lines:
        print_message(line)
