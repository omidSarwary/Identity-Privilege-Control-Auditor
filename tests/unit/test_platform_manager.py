"""Tests for interactive platform selection."""

from __future__ import annotations

from src.core.platform_manager import choose_platform


def test_choose_platform_with_test_flag() -> None:
    """The test flag should force test mode without prompting."""
    selection = choose_platform(test_flag=True)

    assert selection.platform == "test"
    assert selection.analysis_mode == "test"
    assert selection.use_mockdata is True
    assert selection.log_hours == 24
    assert selection.max_events == 1000


def test_choose_platform_with_requested_linux_mode() -> None:
    """An explicit Linux request should map to production analysis mode."""
    selection = choose_platform(requested_platform="linux")

    assert selection.platform == "linux"
    assert selection.analysis_mode == "production"
    assert selection.use_mockdata is False
    assert selection.log_hours == 24
    assert selection.max_events == 1000
    assert "Windows logs should be copied manually" in selection.instructions


def test_choose_platform_prompts_for_input() -> None:
    """Interactive selection should accept a valid answer from the prompt."""
    responses = iter(["windows", "12", "500"])
    selection = choose_platform(input_func=lambda _: next(responses))

    assert selection.platform == "windows"
    assert selection.analysis_mode == "production"
    assert "Linux logs should be copied manually" in selection.instructions
    assert selection.log_hours == 12
    assert selection.max_events == 500


def test_choose_platform_defaults_invalid_collection_window_values() -> None:
    """Invalid collection-window values should safely fall back to defaults."""
    selection = choose_platform(
        requested_platform="windows",
        windows_log_hours="abc",
        windows_max_events="-10",
    )

    assert selection.log_hours == 24
    assert selection.max_events == 1000


def test_choose_platform_clamps_collection_window_values() -> None:
    """Collection-window values above the safety bound should be clamped."""
    selection = choose_platform(
        requested_platform="linux",
        linux_log_hours="800",
        linux_max_events="20000",
    )

    assert selection.log_hours == 720
    assert selection.max_events == 10000
    assert "Input exceeded safety limits." in selection.messages
    assert "Using maximum allowed linux log hours: 720." in selection.messages
    assert "Using maximum allowed linux max events/lines: 10000." in selection.messages
