"""Integration tests for the fallback data collection pipeline."""

from __future__ import annotations

import shutil
from pathlib import Path

from src.collectors import fallback_collector
from src.collectors.fallback_collector import collect_fallback_data


MOCKDATA_DIR = Path(__file__).resolve().parents[1] / "mockdata"


def _configure_search_roots(monkeypatch, tmp_path: Path, *, test_mockdata_dir: Path | None = None) -> None:
    """Point the fallback collector at isolated directories for one test run.

    The integration tests use temporary directories so they can verify the
    search order without touching the repository's real working data folders.
    """
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


def test_fallback_from_data_incoming(monkeypatch, tmp_path) -> None:
    """Fallback should use incoming data when collected output is absent.

    This protects the search order contract by proving that the collector can
    recover useful evidence from `data/incoming/` without changing the data.
    """
    _configure_search_roots(monkeypatch, tmp_path)
    _copy_mock_file("linux_identity.json", tmp_path / "data" / "incoming")
    _copy_mock_file("windows_identity.csv", tmp_path / "data" / "incoming")

    result = collect_fallback_data(mode="production")

    assert result["fallback_activated"] is True
    assert result["no_data_found"] is False
    assert result["used_files"]["linux_identity"]["source_directory"].endswith("incoming")
    assert result["used_files"]["windows_identity"]["source_directory"].endswith("incoming")
    assert "linux_policy.json" in result["missing_files"]


def test_fallback_from_mockdata_in_test_mode(monkeypatch, tmp_path) -> None:
    """Test mode should fall back to the mock data directory last.

    This verifies that the fallback collector can still find a complete sample
    dataset in test mode when the collected and incoming folders are empty.
    """
    _configure_search_roots(monkeypatch, tmp_path, test_mockdata_dir=MOCKDATA_DIR)

    result = collect_fallback_data(mode="test")

    assert result["fallback_activated"] is True
    assert result["no_data_found"] is False
    assert result["used_files"]["linux_identity"]["source_directory"].endswith("mockdata")
    assert result["used_files"]["windows_policy"]["source_directory"].endswith("mockdata")
    assert result["payloads"]["linux_identity"]["users"]


def test_safe_no_data_result_when_no_files_exist(monkeypatch, tmp_path) -> None:
    """An empty environment should return a safe no-data result.

    The collector must fail safely when nothing is available so later phases
    can handle the absence of evidence explicitly.
    """
    _configure_search_roots(monkeypatch, tmp_path)

    result = collect_fallback_data(mode="production")

    assert result["no_data_found"] is True
    assert result["used_files"] == {}
    assert set(result["missing_files"]) == {
        "linux_identity.json",
        "linux_policy.json",
        "windows_identity.csv",
        "windows_events.csv",
        "windows_policy.csv",
        "auth.log",
    }
