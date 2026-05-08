"""Shared pytest fixtures for deterministic host-independent app tests."""

from __future__ import annotations

import pytest

import app


@pytest.fixture(autouse=True)
def _allow_platform_collectors_in_orchestrator_unit_tests(monkeypatch):
    """Keep existing orchestrator tests independent from the developer host OS."""
    monkeypatch.setattr(app, "_host_supports_platform", lambda platform: (True, ""))
