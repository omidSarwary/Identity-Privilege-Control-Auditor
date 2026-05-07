"""Central path definitions for the NordSec Identity & Privilege Control Auditor."""

from __future__ import annotations

from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[2]
SRC_DIR = PROJECT_ROOT / "src"
BASH_DIR = PROJECT_ROOT / "bash"
POWERSHELL_DIR = PROJECT_ROOT / "powershell"
DOCS_DIR = PROJECT_ROOT / "docs"
DATA_DIR = PROJECT_ROOT / "data"
DATA_INCOMING_DIR = DATA_DIR / "incoming"
DATA_COLLECTED_DIR = DATA_DIR / "collected"
DATA_NORMALIZED_DIR = DATA_DIR / "normalized"
DATA_ALERTS_DIR = DATA_DIR / "alerts"
LOGDATA_DIR = PROJECT_ROOT / "logdata"
LOGS_DIR = PROJECT_ROOT / "logs"
LOGS_ARCHIVE_DIR = LOGS_DIR / "archive"
REPORTS_DIR = PROJECT_ROOT / "reports"
REPORTS_EVIDENCE_DIR = REPORTS_DIR / "evidence"
REPORTS_EVIDENCE_SCREENSHOTS_DIR = REPORTS_EVIDENCE_DIR / "screenshots"
REPORTS_EVIDENCE_RUN_OUTPUTS_DIR = REPORTS_EVIDENCE_DIR / "run_outputs"
REPORTS_EVIDENCE_SAMPLE_LOGS_DIR = REPORTS_EVIDENCE_DIR / "sample_logs"
CONFIG_DIR = PROJECT_ROOT / "config"
BASELINES_DIR = CONFIG_DIR / "baselines"
TESTS_DIR = PROJECT_ROOT / "tests"
TEST_MOCKDATA_DIR = TESTS_DIR / "mockdata"

APP_CONFIG_FILE = CONFIG_DIR / "app_config.json"
RISK_RULES_FILE = CONFIG_DIR / "risk_rules.json"
PRODUCTION_CONFIG_FILE = CONFIG_DIR / "production_config.json"
TEST_CONFIG_FILE = CONFIG_DIR / "test_config.json"

REQUIRED_DIRECTORIES = (
    DATA_DIR,
    DATA_INCOMING_DIR,
    DATA_COLLECTED_DIR,
    DATA_NORMALIZED_DIR,
    DATA_ALERTS_DIR,
    LOGDATA_DIR,
    LOGS_DIR,
    LOGS_ARCHIVE_DIR,
    REPORTS_DIR,
    REPORTS_EVIDENCE_DIR,
    REPORTS_EVIDENCE_SCREENSHOTS_DIR,
    REPORTS_EVIDENCE_RUN_OUTPUTS_DIR,
    REPORTS_EVIDENCE_SAMPLE_LOGS_DIR,
    BASH_DIR,
    POWERSHELL_DIR,
    DOCS_DIR,
    CONFIG_DIR,
    BASELINES_DIR,
    TESTS_DIR,
    TEST_MOCKDATA_DIR,
)


def ensure_required_directories() -> None:
    """Create the directories required for the initial project foundation."""
    for directory in REQUIRED_DIRECTORIES:
        directory.mkdir(parents=True, exist_ok=True)
