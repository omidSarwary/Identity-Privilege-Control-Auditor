"""Tests for logging setup robustness before the main logger starts."""

from __future__ import annotations

from pathlib import Path

import pytest

from src.utils import logging_config


def test_runtime_permission_error_includes_recovery_guidance(monkeypatch, tmp_path) -> None:
    """Permission failures should produce an actionable message, not a traceback."""
    def _raise_permission(*args, **kwargs):
        raise PermissionError("denied")

    monkeypatch.setattr(Path, "open", _raise_permission)

    with pytest.raises(logging_config.RuntimeLoggingError) as exc_info:
        logging_config.verify_runtime_paths_writable(tmp_path / "python_engine.log")

    message = str(exc_info.value)
    assert "Cannot write" in message
    assert "sudo chown -R $USER:$USER logs reports data/alerts data/collected" in message
