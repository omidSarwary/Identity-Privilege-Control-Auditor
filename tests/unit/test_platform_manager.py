"""Tests for interactive platform selection."""

from __future__ import annotations

from src.core.platform_manager import choose_platform


def test_choose_platform_with_test_flag() -> None:
    """The test flag should force test mode without prompting."""
    selection = choose_platform(test_flag=True)

    assert selection.platform == "test"
    assert selection.analysis_mode == "test"
    assert selection.use_mockdata is True


def test_choose_platform_with_requested_linux_mode() -> None:
    """An explicit Linux request should map to production analysis mode."""
    selection = choose_platform(requested_platform="linux")

    assert selection.platform == "linux"
    assert selection.analysis_mode == "production"
    assert selection.use_mockdata is False


def test_choose_platform_prompts_for_input() -> None:
    """Interactive selection should accept a valid answer from the prompt."""
    selection = choose_platform(input_func=lambda _: "windows")

    assert selection.platform == "windows"
    assert selection.analysis_mode == "production"
