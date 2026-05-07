"""Integration test for the Linux-oriented full analysis pipeline."""

from __future__ import annotations

from pathlib import Path

from src.analysis.identity_risk_engine import run_identity_risk_engine


MOCKDATA_DIR = Path(__file__).resolve().parents[1] / "mockdata"
PROJECT_ROOT = Path(__file__).resolve().parents[2]
CONFIG_BASELINES_DIR = PROJECT_ROOT / "config" / "baselines"


def test_full_pipeline_linux_mode_returns_summary_and_findings() -> None:
    """Run the full read-only pipeline against mock Linux and Windows data.

    This verifies the orchestration contract: the engine must load the sample
    sources, correlate them, detect anomalies, and return a structured result
    that reporting code can consume later.
    """
    analysis_result = run_identity_risk_engine(
        mode="test",
        data_paths={
            "mockdata": MOCKDATA_DIR,
            "baselines": CONFIG_BASELINES_DIR,
        },
    )

    assert analysis_result["mode"] == "test"
    assert analysis_result["summary"]["counts"]["CRITICAL"] >= 1
    assert isinstance(analysis_result["findings"], list)
    assert analysis_result["findings"]
