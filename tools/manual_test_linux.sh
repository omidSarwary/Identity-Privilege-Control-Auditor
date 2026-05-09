#!/usr/bin/env bash

#chmod +x tools/manual_test_linux.sh befor e running. This script is designed to be run on Linux and will execute the app.py with various inputs to test different scenarios. It will also collect evidence from each run into timestamped folders under qa-runs/linux/.
set -euo pipefail

PROJECT_ROOT="$(pwd)"
PYTHON="sudo .venv/bin/python"
RUN_ROOT="$PROJECT_ROOT/qa-runs/linux"
TIMESTAMP="$(date +%Y%m%d-%H%M%S)"
SESSION_ROOT="$RUN_ROOT/$TIMESTAMP"

mkdir -p "$SESSION_ROOT"

section() {
  echo
  echo "============================================================"
  echo "$1"
  echo "============================================================"
}

wait_user() {
  local msg="${1:-Review the output, then press Enter to continue.}"
  echo
  read -r -p "$msg" _
}

clean_generated_runtime_files() {
  echo "Cleaning generated runtime files..."

  sudo rm -f \
    data/alerts/alerts.json \
    data/collected/linux_identity.json \
    data/collected/linux_policy.json \
    data/collected/windows_identity.csv \
    data/collected/windows_events.csv \
    data/collected/windows_policy.csv \
    logs/anomalies.log \
    logs/critical_alerts.log \
    logs/linux_audit.log \
    logs/python_engine.log \
    logs/windows_audit.log \
    reports/executive_summary.txt \
    reports/final_identity_risk_report.json \
    reports/final_identity_risk_report.txt

  sudo rm -f logs/archive/python_engine-*.log 2>/dev/null || true
}

ensure_runtime_folders() {
  mkdir -p \
    data/alerts \
    data/collected \
    data/incoming \
    logs \
    logs/archive \
    reports \
    logdata/linux \
    logdata/windows
}

save_file_status() {
  local output_file="$1"

  {
    printf "%-45s %-8s %-10s %-25s\n" "Path" "Exists" "Length" "LastWriteTime"
    printf "%-45s %-8s %-10s %-25s\n" "----" "------" "------" "-------------"

    for path in \
      "data/collected/windows_identity.csv" \
      "data/collected/windows_events.csv" \
      "data/collected/windows_policy.csv" \
      "data/collected/linux_identity.json" \
      "data/collected/linux_policy.json" \
      "data/alerts/alerts.json" \
      "reports/final_identity_risk_report.txt" \
      "reports/final_identity_risk_report.json" \
      "reports/executive_summary.txt" \
      "logs/critical_alerts.log" \
      "logs/python_engine.log" \
      "logs/windows_audit.log" \
      "logs/linux_audit.log"
    do
      if [ -e "$path" ]; then
        length="$(sudo stat -c%s "$path")"
        mtime="$(sudo stat -c '%y' "$path" | cut -d'.' -f1)"
        printf "%-45s %-8s %-10s %-25s\n" "$path" "true" "$length" "$mtime"
      else
        printf "%-45s %-8s %-10s %-25s\n" "$path" "false" "" ""
      fi
    done
  } > "$output_file"
}

save_report_head() {
  local output_file="$1"

  if [ -f reports/final_identity_risk_report.txt ]; then
    sudo head -120 reports/final_identity_risk_report.txt > "$output_file"
  else
    echo "Text report not found." > "$output_file"
  fi
}

save_json_summary() {
  local output_file="$1"

  if [ ! -f reports/final_identity_risk_report.json ]; then
    echo "JSON report not found." > "$output_file"
    return
  fi

  sudo python3 - <<'PY' > "$output_file"
import json
from pathlib import Path

path = Path("reports/final_identity_risk_report.json")
data = json.load(open(path, encoding="utf-8"))

print("mode:", data.get("mode"))
print("selected_platform:", data.get("selected_platform"))
print("analysis_scope:", data.get("analysis_scope"))
print("manual_cross_evidence_included:", data.get("manual_cross_evidence_included"))
print("manual_cross_evidence_platform:", data.get("manual_cross_evidence_platform"))
print("fallback_used:", data.get("fallback_used"))

findings = data.get("findings", [])
print("finding_count:", len(findings))
summary = data.get("summary", {})
print("summary_counts:", summary.get("counts"))
print("")
print("findings:")
for f in findings:
    print("-", f.get("identity"), "|", f.get("risk_level"), "|", f.get("finding"), "| source=", f.get("source"))
PY
}

save_alerts_summary() {
  local output_file="$1"

  if [ ! -f data/alerts/alerts.json ]; then
    echo "alerts.json not found." > "$output_file"
    return
  fi

  sudo python3 - <<'PY' > "$output_file"
import json
from pathlib import Path

path = Path("data/alerts/alerts.json")
data = json.load(open(path, encoding="utf-8"))

alerts = data.get("alerts", []) if isinstance(data, dict) else data

print("alert_count:", len(alerts))
for a in alerts:
    print("-", a.get("identity"), "|", a.get("risk_level"), "|", a.get("finding"))
PY
}

save_log_tail() {
  local relative_path="$1"
  local output_file="$2"
  local lines="${3:-120}"

  if [ -f "$relative_path" ]; then
    sudo tail -n "$lines" "$relative_path" > "$output_file"
  else
    echo "$relative_path not found." > "$output_file"
  fi
}

save_git_status() {
  local output_file="$1"
  git status --ignored data/collected data/alerts logs reports > "$output_file" 2>&1 || true
}

save_scenario_evidence() {
  local scenario_dir="$1"
  local scenario_name="$2"

  echo "Collecting evidence for $scenario_name..."

  save_file_status "$scenario_dir/file_status.txt"
  save_report_head "$scenario_dir/report_head.txt"
  save_json_summary "$scenario_dir/json_summary.txt"
  save_alerts_summary "$scenario_dir/alerts_summary.txt"
  save_log_tail "logs/python_engine.log" "$scenario_dir/python_engine_tail.txt"
  save_log_tail "logs/windows_audit.log" "$scenario_dir/windows_audit_tail.txt"
  save_log_tail "logs/linux_audit.log" "$scenario_dir/linux_audit_tail.txt"
  save_git_status "$scenario_dir/git_ignored_status.txt"

  cat > "$scenario_dir/notes.txt" <<EOF
Scenario: $scenario_name
Generated at: $(date '+%Y-%m-%d %H:%M:%S')
Project root: $PROJECT_ROOT

Review checklist:
- Did terminal output match expected scenario behavior?
- Did selected_platform and analysis_scope match the scenario?
- Was fallback used correctly?
- Were stale/ignored/manual evidence warnings clear?
- Were generated reports consistent with console output?
- Were wrong-OS or permission problems handled clearly?
- Did git status remain clean except ignored runtime files?
EOF
}

run_app_scenario() {
  local scenario_id="$1"
  local scenario_name="$2"
  local input_text="$3"
  local clean_before="${4:-true}"
  local pause_for_manual_files="${5:-false}"
  local manual_file_message="${6:-}"

  section "$scenario_id - $scenario_name"

  if [ "$clean_before" = "true" ]; then
    clean_generated_runtime_files
    ensure_runtime_folders
  fi

  if [ "$pause_for_manual_files" = "true" ]; then
    echo "$manual_file_message"
    wait_user "Copy the manual evidence files now, then press Enter to run this scenario."
  fi

  local scenario_dir="$SESSION_ROOT/$scenario_id"
  mkdir -p "$scenario_dir"

  local input_file="$scenario_dir/input.txt"
  local console_file="$scenario_dir/console.txt"

  printf "%b" "$input_text" > "$input_file"

  echo "Running scenario..."
  echo "Input saved to: $input_file"
  echo "Console output will be saved to: $console_file"
  echo

  # shellcheck disable=SC2086
  cat "$input_file" | $PYTHON app.py 2>&1 | tee "$console_file"

  save_scenario_evidence "$scenario_dir" "$scenario_name"

  echo
  echo "Scenario output folder:"
  echo "$scenario_dir"
  wait_user
}

show_session_summary() {
  section "Session summary"
  echo "QA session folder:"
  echo "$SESSION_ROOT"
  echo
  echo "Scenario folders:"
  find "$SESSION_ROOT" -maxdepth 1 -mindepth 1 -type d -print
}

section "NordSec Linux Manual QA Harness"
echo "Project root: $PROJECT_ROOT"
echo "Session root: $SESSION_ROOT"
echo
echo "This harness runs one scenario at a time and pauses after each run."
echo "It uses sudo .venv/bin/python app.py so the Linux collector can read protected logs."
wait_user "Press Enter to start L1."

# L1: wrong OS choice on Linux.
run_app_scenario \
  "L1-wrong-os-windows-on-linux" \
  "Wrong OS choice: choose windows on Linux" \
  $'windows\n1\n100\nn\n'

# L2: huge values, should clamp/fallback safely.
run_app_scenario \
  "L2-linux-huge-values" \
  "Linux with very large hours/events" \
  $'linux\n999999\n999999\nn\n'

# L3: normal Linux-only, no manual Windows.
run_app_scenario \
  "L3-linux-normal-no-manual-windows" \
  "Linux normal values, no manual Windows" \
  $'linux\n1\n100\nn\n'

# L4: manual Windows yes, then skip.
run_app_scenario \
  "L4-linux-manual-windows-skip" \
  "Linux normal values, manual Windows yes, then skip" \
  $'linux\n1\n100\ny\nskip\n'

# L5: manual Windows yes, press Enter without adding files.
run_app_scenario \
  "L5-linux-manual-windows-enter-no-new-files" \
  "Linux normal values, manual Windows yes, Enter without adding files" \
  $'linux\n1\n100\ny\n\n'

# L6: manual Windows yes, pause for you to copy files, then continue.
run_app_scenario \
  "L6-linux-manual-windows-with-files" \
  "Linux normal values, manual Windows yes, user adds manual Windows files" \
  $'linux\n1\n100\ny\n\n' \
  "true" \
  "true" \
"Before continuing:
Copy your generated Windows manual evidence into one of these folders:

  $PROJECT_ROOT/data/incoming/
  $PROJECT_ROOT/logdata/windows/

Recommended for this scenario:
- Copy windows_identity.csv, windows_events.csv, windows_policy.csv into data/incoming/
- Copy security_events.csv and eventviewer_export.csv into logdata/windows/

The harness will run sudo .venv/bin/python app.py after you press Enter."

show_session_summary