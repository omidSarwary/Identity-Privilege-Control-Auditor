"""Bootstrap helpers for application start-up checks."""

from __future__ import annotations

import json
from typing import Any

from src.core.paths import APP_CONFIG_FILE


def load_app_config() -> dict[str, Any]:
    """Load the central application configuration.

    Expects the project configuration file at ``config/app_config.json`` and
    returns the parsed JSON object as a dictionary. The function exists so the
    application can read runtime metadata from one central place instead of
    hardcoding values in multiple modules.
    """
    with APP_CONFIG_FILE.open(encoding="utf-8") as config_file:
        return json.load(config_file)
