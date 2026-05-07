"""Tests for controlled application shutdown."""

from __future__ import annotations

import logging

from src.utils.safe_exit import safe_exit


def test_safe_exit_logs_and_returns_code(caplog) -> None:
    """Safe exit should log the message and return the requested code."""
    logger = logging.getLogger("nordsec.ipca.tests.safe_exit")

    with caplog.at_level(logging.INFO):
        code = safe_exit(logger, 0, "Safe exit")

    assert code == 0
    assert "Safe exit" in caplog.text
