#!/usr/bin/env bash
# NordSec Identity & Privilege Control Auditor
# Linux Identity Audit Sensor
# Version: 1.0.0
# Read-only collection helper for approved Linux identity, privilege, policy,
# and auth evidence. The sensor only exports data; it does not modify the
# system or perform remediation.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
DATA_DIR="${PROJECT_ROOT}/data"
COLLECTED_DIR="${DATA_DIR}/collected"
LOGS_DIR="${PROJECT_ROOT}/logs"
TEST_MOCKDATA_DIR="${PROJECT_ROOT}/tests/mockdata"

OUTPUT_IDENTITY_JSON="${COLLECTED_DIR}/linux_identity.json"
OUTPUT_POLICY_JSON="${COLLECTED_DIR}/linux_policy.json"
AUDIT_LOG_FILE="${LOGS_DIR}/linux_audit.log"
ANOMALY_LOG_FILE="${LOGS_DIR}/anomalies.log"

MODE="production"
EXIT_CODE=0
HOST_NAME="$(hostname 2>/dev/null || printf 'unknown')"
COLLECTION_TIME="$(date -u +"%Y-%m-%dT%H:%M:%SZ")"

LOCAL_USERS_JSON="[]"
SUDO_USERS_JSON="[]"
AUTH_EVENTS_JSON="[]"
SSH_POLICY_JSON='{"permit_root_login":"unknown","password_authentication":"unknown","pubkey_authentication":"unknown"}'
FILE_PERMISSIONS_JSON='{"files":[]}'

command_exists() {
  command -v "$1" >/dev/null 2>&1
}

log() {
  local level="$1"
  shift
  local message="$*"
  local timestamp
  timestamp="$(date -u +"%Y-%m-%d %H:%M:%S")"
  printf '%s [%s] %s\n' "$timestamp" "$level" "$message" | tee -a "$AUDIT_LOG_FILE" >/dev/null
}

log_anomaly() {
  local level="$1"
  shift
  local message="$*"
  local timestamp
  timestamp="$(date -u +"%Y-%m-%d %H:%M:%S")"
  printf '%s [%s] %s\n' "$timestamp" "$level" "$message" | tee -a "$AUDIT_LOG_FILE" "$ANOMALY_LOG_FILE" >/dev/null
}

mark_missing_source() {
  local message="$1"
  log_anomaly "WARNING" "$message"
  EXIT_CODE=2
}

safe_exit() {
  local code="$1"
  local message="$2"
  log "INFO" "$message"
  exit "$code"
}

parse_args() {
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --mode)
        shift
        if [[ $# -eq 0 ]]; then
          log "ERROR" "Missing value for --mode"
          safe_exit 4 "Invalid mode"
        fi
        MODE="$1"
        ;;
      --mode=*)
        MODE="${1#*=}"
        ;;
      -h|--help)
        printf '%s\n' "Usage: bash/linux_identity_audit.sh [--mode production|test]"
        exit 0
        ;;
      *)
        log "ERROR" "Unsupported argument: $1"
        safe_exit 4 "Invalid mode"
        ;;
    esac
    shift
  done

  case "$MODE" in
    production|test)
      ;;
    *)
      log "ERROR" "Unsupported mode: $MODE"
      safe_exit 4 "Invalid mode"
      ;;
  esac
}

check_dependencies() {
  local required_commands=(python3 tee hostname getent)
  local optional_commands=(passwd lastlog)
  local command_name

  for command_name in "${required_commands[@]}"; do
    if ! command_exists "$command_name"; then
      log "ERROR" "Required command not available: $command_name"
      return 1
    fi
  done

  for command_name in "${optional_commands[@]}"; do
    if ! command_exists "$command_name"; then
      log "WARNING" "Optional command not available: $command_name"
    fi
  done

  return 0
}

init_paths() {
  mkdir -p "$COLLECTED_DIR" "$LOGS_DIR"
  : >> "$AUDIT_LOG_FILE"
  : >> "$ANOMALY_LOG_FILE"
  log "INFO" "Initialized output paths"
}

collect_local_users() {
  log "INFO" "Collecting local users"

  if [[ "$MODE" == "test" ]]; then
    if LOCAL_USERS_JSON="$(
      python3 - "$TEST_MOCKDATA_DIR/linux_identity.json" <<'PY'
import json
import pathlib
import sys

path = pathlib.Path(sys.argv[1])
payload = json.loads(path.read_text(encoding="utf-8"))
print(json.dumps(payload.get("users", []), ensure_ascii=False))
PY
    )"; then
      return 0
    fi

    log "ERROR" "Failed to read mock Linux identity users"
    return 1
  fi

  if LOCAL_USERS_JSON="$(
    python3 <<'PY'
import json
import shutil
import subprocess

def run(command):
    try:
        return subprocess.check_output(command, text=True, stderr=subprocess.DEVNULL)
    except Exception:
        return ""

sudo_members = set()
for group in ("sudo", "wheel"):
    group_output = run(["getent", "group", group]).strip()
    if not group_output:
        continue
    parts = group_output.split(":")
    if len(parts) >= 4 and parts[3].strip():
        for member in parts[3].split(","):
            member = member.strip()
            if member:
                sudo_members.add(member)

users = []
passwd_output = run(["getent", "passwd"])
for line in passwd_output.splitlines():
    parts = line.split(":")
    if len(parts) < 7:
        continue

    username, _, uid, _, _, _, _ = parts[:7]
    try:
        uid_value = int(uid)
    except ValueError:
        continue

    if uid_value < 1000 and username != "root":
        continue

    enabled = True
    if shutil.which("passwd"):
        status_output = run(["passwd", "-S", username]).strip()
        if status_output:
            status_fields = status_output.split()
            if len(status_fields) >= 2 and status_fields[1] in {"L", "LK", "Lk"}:
                enabled = False

    last_login = ""
    is_inactive = False
    if shutil.which("lastlog"):
        lastlog_output = run(["lastlog", "-u", username]).strip()
        lastlog_lines = [line.strip() for line in lastlog_output.splitlines() if line.strip()]
        if lastlog_lines:
            latest_line = lastlog_lines[-1]
            if "Never logged in" in latest_line:
                is_inactive = True
            else:
                last_login = latest_line

    privileges = ["sudo"] if username in sudo_members else []
    users.append(
        {
            "username": username,
            "enabled": enabled,
            "privileges": privileges,
            "is_inactive": is_inactive,
            "last_login": last_login,
        }
    )

print(json.dumps(users, ensure_ascii=False))
PY
  )"; then
    return 0
  fi

  log "ERROR" "Failed to collect local users"
  return 1
}

collect_sudo_users() {
  log "INFO" "Collecting sudo users"

  if [[ "$MODE" == "test" ]]; then
    if SUDO_USERS_JSON="$(
      python3 - "$TEST_MOCKDATA_DIR/linux_identity.json" <<'PY'
import json
import pathlib
import sys

path = pathlib.Path(sys.argv[1])
payload = json.loads(path.read_text(encoding="utf-8"))
print(json.dumps(payload.get("sudo_users", []), ensure_ascii=False))
PY
    )"; then
      return 0
    fi

    log "ERROR" "Failed to read mock sudo users"
    return 1
  fi

  if SUDO_USERS_JSON="$(
    python3 <<'PY'
import json
import subprocess

members = set()
for group in ("sudo", "wheel"):
    try:
        output = subprocess.check_output(["getent", "group", group], text=True, stderr=subprocess.DEVNULL).strip()
    except Exception:
        output = ""
    if not output:
        continue
    parts = output.split(":")
    if len(parts) >= 4 and parts[3].strip():
        for member in parts[3].split(","):
            member = member.strip()
            if member:
                members.add(member)

print(json.dumps(sorted(members), ensure_ascii=False))
PY
  )"; then
    return 0
  fi

  log "ERROR" "Failed to collect sudo users"
  return 1
}

collect_auth_events() {
  log "INFO" "Collecting auth-related events"

  if [[ "$MODE" == "test" ]]; then
    if AUTH_EVENTS_JSON="$(
      python3 - "$TEST_MOCKDATA_DIR/auth.log" <<'PY'
import json
import pathlib
import re
import sys

path = pathlib.Path(sys.argv[1])
pattern = re.compile(
    r"^(?P<timestamp>[A-Z][a-z]{2}\s+\d+\s+\d{2}:\d{2}:\d{2})\s+"
    r"(?P<host>\S+)\s+sshd\[\d+\]:\s+Failed password for "
    r"(?:(?:invalid user )?)(?P<user>\S+)\s+from\s+(?P<ip>\S+)"
)

events = []
for line in path.read_text(encoding="utf-8").splitlines():
    match = pattern.match(line.strip())
    if not match:
        continue
    events.append(
        {
            "username": match.group("user"),
            "event_type": "failed_login",
            "count": 1,
            "timestamp": match.group("timestamp"),
            "source": str(path),
            "ip_address": match.group("ip"),
        }
    )

print(json.dumps(events, ensure_ascii=False))
PY
    )"; then
      return 0
    fi

    log "ERROR" "Failed to parse mock auth log"
    return 1
  fi

  local log_source=""
  if [[ -r "/var/log/auth.log" ]]; then
    log_source="/var/log/auth.log"
  elif [[ -r "/var/log/secure" ]]; then
    log_source="/var/log/secure"
  fi

  if [[ -z "$log_source" ]]; then
    AUTH_EVENTS_JSON='[]'
    mark_missing_source "No readable auth log source was found."
    return 2
  fi

  if AUTH_EVENTS_JSON="$(
    python3 - "$log_source" <<'PY'
import json
import pathlib
import re
import sys

path = pathlib.Path(sys.argv[1])
pattern = re.compile(
    r"^(?P<timestamp>[A-Z][a-z]{2}\s+\d+\s+\d{2}:\d{2}:\d{2})\s+"
    r"(?P<host>\S+)\s+sshd\[\d+\]:\s+Failed password for "
    r"(?:(?:invalid user )?)(?P<user>\S+)\s+from\s+(?P<ip>\S+)"
)

events = []
for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
    match = pattern.match(line.strip())
    if not match:
        continue
    events.append(
        {
            "username": match.group("user"),
            "event_type": "failed_login",
            "count": 1,
            "timestamp": match.group("timestamp"),
            "source": str(path),
            "ip_address": match.group("ip"),
        }
    )

print(json.dumps(events, ensure_ascii=False))
PY
  )"; then
    return 0
  fi

  log "ERROR" "Failed to parse auth log source: $log_source"
  return 1
}

check_ssh_policy() {
  log "INFO" "Checking SSH policy"

  if [[ "$MODE" == "test" ]]; then
    if SSH_POLICY_JSON="$(
      python3 - "$TEST_MOCKDATA_DIR/linux_policy.json" <<'PY'
import json
import pathlib
import sys

path = pathlib.Path(sys.argv[1])
payload = json.loads(path.read_text(encoding="utf-8"))
policy = payload.get("policy", {})
ssh_policy = policy.get("ssh_policy", {})
print(json.dumps(ssh_policy, ensure_ascii=False))
PY
    )"; then
      return 0
    fi

    log "ERROR" "Failed to read mock SSH policy"
    return 1
  fi

  local sshd_config="/etc/ssh/sshd_config"
  if [[ ! -r "$sshd_config" ]]; then
    SSH_POLICY_JSON='{"permit_root_login":"unknown","password_authentication":"unknown","pubkey_authentication":"unknown"}'
    mark_missing_source "SSH policy source is not readable: $sshd_config"
    return 2
  fi

  if SSH_POLICY_JSON="$(
    python3 - "$sshd_config" <<'PY'
import json
import pathlib
import sys

path = pathlib.Path(sys.argv[1])
defaults = {
    "permit_root_login": "unknown",
    "password_authentication": "unknown",
    "pubkey_authentication": "unknown",
}

try:
    lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
except OSError:
    print(json.dumps(defaults, ensure_ascii=False))
    sys.exit(2)

for raw_line in lines:
    line = raw_line.strip()
    if not line or line.startswith("#"):
        continue
    if line.lower().startswith("match "):
        break
    parts = line.split(None, 1)
    if len(parts) != 2:
        continue
    key, value = parts[0].strip().lower(), parts[1].strip()
    if key == "permitrootlogin":
        defaults["permit_root_login"] = value
    elif key == "passwordauthentication":
        defaults["password_authentication"] = value
    elif key == "pubkeyauthentication":
        defaults["pubkey_authentication"] = value

print(json.dumps(defaults, ensure_ascii=False))
PY
  )"; then
    return 0
  fi

  log "ERROR" "Failed to parse SSH policy: $sshd_config"
  return 1
}

check_sensitive_file_permissions() {
  log "INFO" "Checking sensitive file permissions"

  if [[ "$MODE" == "test" ]]; then
    if FILE_PERMISSIONS_JSON="$(
      python3 <<'PY'
import json

print(
    json.dumps(
        {
            "files": [
                {"path": "/etc/passwd", "mode": "644", "readable": True, "status": "test_mode"},
                {"path": "/etc/shadow", "mode": "640", "readable": False, "status": "test_mode"},
                {"path": "/etc/sudoers", "mode": "440", "readable": False, "status": "test_mode"},
            ]
        },
        ensure_ascii=False,
    )
)
PY
    )"; then
      return 0
    fi

    log "ERROR" "Failed to build test-mode file permission snapshot"
    return 1
  fi

  if FILE_PERMISSIONS_JSON="$(
    python3 <<'PY'
import json
import os
from pathlib import Path
import sys

files = ["/etc/passwd", "/etc/shadow", "/etc/sudoers"]
results = []
missing = False

for file_path in files:
    path = Path(file_path)
    if not path.exists():
        results.append({"path": file_path, "mode": None, "readable": False, "status": "missing"})
        missing = True
        continue

    try:
        mode = oct(path.stat().st_mode & 0o777)[2:]
    except OSError:
        mode = None
        missing = True

    readable = os.access(file_path, os.R_OK)
    if not readable:
        missing = True
    results.append(
        {
            "path": file_path,
            "mode": mode,
            "readable": readable,
            "status": "ok" if readable else "unreadable",
        }
    )

print(json.dumps({"files": results}, ensure_ascii=False))
sys.exit(2 if missing else 0)
PY
  )"; then
    return 0
  fi

  rc=$?
  if [[ "$rc" -eq 2 ]]; then
    mark_missing_source "One or more sensitive files were missing or unreadable."
    return 2
  fi

  log "ERROR" "Failed to read sensitive file permissions"
  return 1
}

export_identity_json() {
  log "INFO" "Exporting linux_identity.json"

  if ! mkdir -p "$COLLECTED_DIR"; then
    log "ERROR" "Unable to create collected output directory"
    return 3
  fi

  if HOST_NAME="$HOST_NAME" COLLECTION_TIME="$COLLECTION_TIME" MODE="$MODE" EXIT_CODE="$EXIT_CODE" \
    LOCAL_USERS_JSON="$LOCAL_USERS_JSON" SUDO_USERS_JSON="$SUDO_USERS_JSON" AUTH_EVENTS_JSON="$AUTH_EVENTS_JSON" \
    SSH_POLICY_JSON="$SSH_POLICY_JSON" FILE_PERMISSIONS_JSON="$FILE_PERMISSIONS_JSON" \
    python3 - "$OUTPUT_IDENTITY_JSON" <<'PY'
import json
import os
import pathlib
import sys

output = pathlib.Path(sys.argv[1])
policy = {
    "ssh_policy": json.loads(os.environ.get("SSH_POLICY_JSON", "{}")),
    "file_permissions": json.loads(os.environ.get("FILE_PERMISSIONS_JSON", '{"files": []}')),
}
data = {
    "source": "linux",
    "host": os.environ.get("HOST_NAME", "unknown"),
    "collection_time": os.environ.get("COLLECTION_TIME", ""),
    "mode": os.environ.get("MODE", "production"),
    "users": json.loads(os.environ.get("LOCAL_USERS_JSON", "[]")),
    "sudo_users": json.loads(os.environ.get("SUDO_USERS_JSON", "[]")),
    "auth_events": json.loads(os.environ.get("AUTH_EVENTS_JSON", "[]")),
    "policy": policy,
    "collector_status": {
        "source": "mockdata" if os.environ.get("MODE") == "test" else "sensor",
        "status": "ready" if os.environ.get("EXIT_CODE", "0") == "0" else "ready_with_warnings",
    },
}
output.write_text(json.dumps(data, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
PY
  then
    return 0
  fi

  log "ERROR" "Unable to write linux_identity.json"
  return 3
}

export_policy_json() {
  log "INFO" "Exporting linux_policy.json"

  if ! mkdir -p "$COLLECTED_DIR"; then
    log "ERROR" "Unable to create collected output directory"
    return 3
  fi

  if HOST_NAME="$HOST_NAME" COLLECTION_TIME="$COLLECTION_TIME" MODE="$MODE" EXIT_CODE="$EXIT_CODE" \
    SSH_POLICY_JSON="$SSH_POLICY_JSON" FILE_PERMISSIONS_JSON="$FILE_PERMISSIONS_JSON" \
    python3 - "$OUTPUT_POLICY_JSON" <<'PY'
import json
import os
import pathlib
import sys

output = pathlib.Path(sys.argv[1])
policy = {
    "ssh_policy": json.loads(os.environ.get("SSH_POLICY_JSON", "{}")),
    "file_permissions": json.loads(os.environ.get("FILE_PERMISSIONS_JSON", '{"files": []}')),
}
data = {
    "source": "linux",
    "host": os.environ.get("HOST_NAME", "unknown"),
    "collection_time": os.environ.get("COLLECTION_TIME", ""),
    "mode": os.environ.get("MODE", "production"),
    "policy": policy,
}
output.write_text(json.dumps(data, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
PY
  then
    return 0
  fi

  log "ERROR" "Unable to write linux_policy.json"
  return 3
}

main() {
  parse_args "$@"
  init_paths

  if ! check_dependencies; then
    safe_exit 1 "Dependency check failed"
  fi

  log "INFO" "Starting Linux identity audit sensor"
  log "INFO" "Mode selected: $MODE"

  if collect_local_users; then
    :
  else
    rc=$?
    if [[ "$rc" -eq 2 ]]; then
      EXIT_CODE=2
    else
      safe_exit "$rc" "Local user collection failed"
    fi
  fi

  if collect_sudo_users; then
    :
  else
    rc=$?
    if [[ "$rc" -eq 2 ]]; then
      EXIT_CODE=2
    else
      safe_exit "$rc" "Sudo user collection failed"
    fi
  fi

  if collect_auth_events; then
    :
  else
    rc=$?
    if [[ "$rc" -eq 2 ]]; then
      EXIT_CODE=2
    else
      safe_exit "$rc" "Auth event collection failed"
    fi
  fi

  if check_ssh_policy; then
    :
  else
    rc=$?
    if [[ "$rc" -eq 2 ]]; then
      EXIT_CODE=2
    else
      safe_exit "$rc" "SSH policy collection failed"
    fi
  fi

  if check_sensitive_file_permissions; then
    :
  else
    rc=$?
    if [[ "$rc" -eq 2 ]]; then
      EXIT_CODE=2
    else
      safe_exit "$rc" "Sensitive file permission check failed"
    fi
  fi

  if export_identity_json; then
    :
  else
    safe_exit 3 "Identity export failed"
  fi

  if export_policy_json; then
    :
  else
    safe_exit 3 "Policy export failed"
  fi

  if [[ "$EXIT_CODE" -eq 2 ]]; then
    safe_exit 2 "Linux audit completed with warnings"
  fi

  safe_exit 0 "Linux audit completed successfully"
}

main "$@"
