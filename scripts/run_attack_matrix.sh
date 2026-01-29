#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

if ! command -v uv >/dev/null 2>&1; then
  echo "uv is required but not found in PATH." >&2
  exit 1
fi

VENV_PY="$ROOT_DIR/.venv/bin/python"
if [[ ! -x "$VENV_PY" ]]; then
  echo "Expected venv python at $VENV_PY" >&2
  echo "Create it first: python -m venv .venv && source .venv/bin/activate && python -m pip install -e ." >&2
  exit 1
fi

PROFILES=(
  baseline
  prompt_injection
  tool_coercion
  data_exfiltration
  oversized_payload
  high_entropy
  schema_confusion
  mixed_content
)

profile_id_for() {
  case "$1" in
    baseline) echo "0" ;;
    prompt_injection) echo "1" ;;
    tool_coercion) echo "2" ;;
    data_exfiltration) echo "3" ;;
    oversized_payload) echo "4" ;;
    high_entropy) echo "5" ;;
    schema_confusion) echo "6" ;;
    mixed_content) echo "7" ;;
    *) echo "255" ;;
  esac
}

severity_for_profile() {
  case "$1" in
    baseline) echo "NONE" ;;
    prompt_injection) echo "HIGH" ;;
    tool_coercion) echo "HIGH" ;;
    data_exfiltration) echo "HIGH" ;;
    oversized_payload) echo "MEDIUM" ;;
    high_entropy) echo "MEDIUM" ;;
    schema_confusion) echo "MEDIUM" ;;
    mixed_content) echo "MEDIUM" ;;
    *) echo "UNKNOWN" ;;
  esac
}

run_client() {
  local profile="$1"
  local log_file="$2"
  local url="$3"
  local profile_id="$4"
  local attack_only="$5"

  set +e
  uv run --python "$VENV_PY" -- python client.py \
    --url "$url" \
    --profile-id "$profile_id" \
    $( [[ "$SKIP_SET_PROFILE" == "1" ]] && echo "--skip-set-profile" ) \
    $( [[ "$attack_only" == "1" ]] && echo "--attack-only" ) \
    --tool fetch_shelf_rss \
    --shelf read \
    --limit 5 2>&1 | tee "$log_file"
  local exit_code="${PIPESTATUS[0]}"
  set -e
  return "$exit_code"
}

REPORT_TS="$(date +%Y%m%d_%H%M%S)"
REPORT_FILE="$ROOT_DIR/reports/attack_matrix_${REPORT_TS}.csv"
MCP_URL="${MCP_URL:-http://127.0.0.1:3333/mcp}"
SKIP_SET_PROFILE="${SKIP_SET_PROFILE:-1}"

{
  echo "timestamp,mode,profile,severity,profile_set,http_status,outcome"
} > "$REPORT_FILE"

for mode in injection attack_only; do
  for profile in "${PROFILES[@]}"; do
    CLIENT_LOG="$ROOT_DIR/logs/client_${mode}_${profile}_${REPORT_TS}.log"
    echo "Testing profile: $profile ($mode)"

    profile_id="$(profile_id_for "$profile")"
    if [[ "$profile_id" == "255" ]]; then
      echo "Unknown profile: $profile" >&2
      exit 1
    fi
    if [[ "$mode" == "attack_only" ]]; then
      attack_only="1"
    else
      attack_only="0"
    fi
    run_client "$profile" "$CLIENT_LOG" "$MCP_URL" "$profile_id" "$attack_only" || true
    profile_set="no"
    if [[ "$SKIP_SET_PROFILE" == "1" ]]; then
      profile_set="yes"
    elif grep -q "set_attack_profile ok" "$CLIENT_LOG"; then
      profile_set="yes"
    fi

    status="$(awk '
      /Calling tool: fetch_shelf_rss/ { seen_call=1; next }
      seen_call && /HTTP Request:/ {
        line=$0
        gsub(/"/, "", line)
        split(line, f, " ")
        for (i=1; i<=length(f); i++) {
          if (f[i] ~ /^HTTP\/[0-9.]+$/ && f[i+1] ~ /^[0-9][0-9][0-9]$/) {
            print f[i+1]; exit
          }
          if (f[i] == "HTTP" && f[i+1] ~ /^[0-9][0-9][0-9]$/) {
            print f[i+1]; exit
          }
        }
      }
    ' "$CLIENT_LOG")"
    if [[ -z "$status" ]]; then
      status="200"
    fi

    if [[ "$status" == "400" && "$profile_set" == "yes" ]]; then
      outcome="BLOCKED"
    elif [[ "$profile_set" == "no" && "$profile" != "baseline" ]]; then
      outcome="PROFILE_NOT_SET"
    elif [[ "$status" =~ ^[0-9]{3}$ && "$status" -ge 400 ]]; then
      outcome="ERROR"
    else
      outcome="ALLOWED"
    fi

    severity="$(severity_for_profile "$profile")"

    echo "$(date -u +%Y-%m-%dT%H:%M:%SZ),$mode,$profile,$severity,$profile_set,$status,$outcome" >> "$REPORT_FILE"
  done
done

echo "Report written to: $REPORT_FILE"
