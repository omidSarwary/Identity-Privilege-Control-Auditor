"""Integration tests for the fallback data collection pipeline."""

from __future__ import annotations

import shutil
from pathlib import Path

from src.collectors import fallback_collector
from src.collectors.fallback_collector import collect_fallback_data


MOCKDATA_DIR = Path(__file__).resolve().parents[1] / "mockdata"


def _configure_search_roots(monkeypatch, tmp_path: Path, *, test_mockdata_dir: Path | None = None) -> None:
    """Point the fallback collector at isolated directories for one test run."""
    collected_dir = tmp_path / "data" / "collected"
    incoming_dir = tmp_path / "data" / "incoming"
    logdata_dir = tmp_path / "logdata"
    mockdata_dir = test_mockdata_dir or (tmp_path / "tests" / "mockdata")

    for directory in [
        collected_dir,
        incoming_dir,
        logdata_dir / "linux",
        logdata_dir / "windows",
        mockdata_dir,
    ]:
        directory.mkdir(parents=True, exist_ok=True)

    monkeypatch.setattr(fallback_collector, "DATA_COLLECTED_DIR", collected_dir)
    monkeypatch.setattr(fallback_collector, "DATA_INCOMING_DIR", incoming_dir)
    monkeypatch.setattr(fallback_collector, "LOGDATA_DIR", logdata_dir)
    monkeypatch.setattr(fallback_collector, "TEST_MOCKDATA_DIR", mockdata_dir)


def _copy_mock_file(filename: str, destination: Path) -> None:
    """Copy one anonymous mock file into a temporary fallback location."""
    shutil.copyfile(MOCKDATA_DIR / filename, destination / filename)


def _write_invalid_placeholder(path: Path, filename: str) -> None:
    """Write a deliberately invalid placeholder file for fallback testing."""
    target = path / filename
    if filename.endswith(".json"):
        target.write_text("{invalid-json}", encoding="utf-8")
    elif filename.endswith(".csv"):
        target.write_text("", encoding="utf-8")
    else:
        target.write_text("", encoding="utf-8")


def test_test_mode_uses_mockdata_only(monkeypatch, tmp_path) -> None:
    """Test mode must stay isolated and use only the mock data directory.

    This protects the safety contract for ``--test``: the fallback collector
    should not inspect collected output, incoming exports, or raw log folders
    when the application is explicitly running in mock mode.
    """
    _configure_search_roots(monkeypatch, tmp_path, test_mockdata_dir=MOCKDATA_DIR)

    collected_dir = tmp_path / "data" / "collected"
    incoming_dir = tmp_path / "data" / "incoming"
    logdata_linux_dir = tmp_path / "logdata" / "linux"
    logdata_windows_dir = tmp_path / "logdata" / "windows"

    for directory in [collected_dir, incoming_dir, logdata_linux_dir, logdata_windows_dir]:
        _write_invalid_placeholder(directory, "linux_identity.json")
        _write_invalid_placeholder(directory, "linux_policy.json")
        _write_invalid_placeholder(directory, "windows_identity.csv")
        _write_invalid_placeholder(directory, "windows_events.csv")
        _write_invalid_placeholder(directory, "windows_policy.csv")
        _write_invalid_placeholder(directory, "auth.log")

    result = collect_fallback_data(mode="test")

    assert result["searched_directories"] == [str(MOCKDATA_DIR)]
    assert result["no_data_found"] is False
    assert result["used_files"]["linux_identity"]["source_directory"].endswith("mockdata")
    assert result["used_files"]["linux_policy"]["source_directory"].endswith("mockdata")
    assert result["used_files"]["windows_identity"]["source_directory"].endswith("mockdata")
    assert result["used_files"]["windows_policy"]["source_directory"].endswith("mockdata")
    assert all(attempt["source_directory"].endswith("mockdata") for attempt in result["sources"]["linux_identity"]["attempts"])


def test_production_mode_skips_invalid_data_and_returns_no_data(monkeypatch, tmp_path) -> None:
    """Production mode should skip invalid placeholders and avoid mock data."""
    _configure_search_roots(monkeypatch, tmp_path)

    collected_dir = tmp_path / "data" / "collected"
    incoming_dir = tmp_path / "data" / "incoming"
    logdata_linux_dir = tmp_path / "logdata" / "linux"
    logdata_windows_dir = tmp_path / "logdata" / "windows"

    for directory in [collected_dir, incoming_dir, logdata_linux_dir, logdata_windows_dir]:
        _write_invalid_placeholder(directory, "linux_identity.json")
        _write_invalid_placeholder(directory, "linux_policy.json")
        _write_invalid_placeholder(directory, "windows_identity.csv")
        _write_invalid_placeholder(directory, "windows_events.csv")
        _write_invalid_placeholder(directory, "windows_policy.csv")
        _write_invalid_placeholder(directory, "auth.log")

    result = collect_fallback_data(mode="production")

    assert result["no_data_found"] is True
    assert result["used_files"] == {}
    assert result["fallback_activated"] is True
    assert "tests/mockdata" not in "".join(result["searched_directories"])


def test_production_mode_honors_search_order(monkeypatch, tmp_path) -> None:
    """The fallback collector should respect the documented production order.

    A valid file in ``data/incoming`` must be chosen before the same file in
    ``logdata/linux``. This keeps the collector predictable when multiple
    approved locations contain the same evidence type.
    """
    _configure_search_roots(monkeypatch, tmp_path, test_mockdata_dir=MOCKDATA_DIR)

    collected_dir = tmp_path / "data" / "collected"
    incoming_dir = tmp_path / "data" / "incoming"
    logdata_linux_dir = tmp_path / "logdata" / "linux"

    _write_invalid_placeholder(collected_dir, "linux_identity.json")
    _copy_mock_file("linux_identity.json", incoming_dir)
    _copy_mock_file("linux_policy.json", logdata_linux_dir)

    result = collect_fallback_data(mode="production")

    assert result["searched_directories"] == [
        str(collected_dir),
        str(incoming_dir),
        str(logdata_linux_dir),
        str(tmp_path / "logdata" / "windows"),
    ]
    assert result["used_files"]["linux_identity"]["source_directory"].endswith("incoming")
    assert result["used_files"]["linux_policy"]["source_directory"].endswith("linux")
