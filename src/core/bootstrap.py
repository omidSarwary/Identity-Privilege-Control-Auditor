"""Bootstrap helpers for application start-up checks."""

from __future__ import annotations

import json
from typing import Any

from src.core.paths import APP_CONFIG_FILE


def load_app_config() -> dict[str, Any]:
    """Load the central application configuration file."""
    with APP_CONFIG_FILE.open(encoding="utf-8") as config_file:
        return json.load(config_file)
