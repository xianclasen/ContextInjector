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

  set +e
  uv run --python "$VENV_PY" -- python client.py \
    --url "$url" \
    --profile "$profile" \
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

{
  echo "timestamp,mode,profile,severity,http_status,outcome"
} > "$REPORT_FILE"

for mode in injection attack_only; do
  for profile in "${PROFILES[@]}"; do
    CLIENT_LOG="$ROOT_DIR/logs/client_${mode}_${profile}_${REPORT_TS}.log"
    echo "Testing profile: $profile ($mode)"

    run_client "$profile" "$CLIENT_LOG" "$MCP_URL" || true
    status="$(grep -Eo 'HTTP/[0-9.]+ [0-9]{3}|HTTP [0-9]{3}' "$CLIENT_LOG" | head -n1 | awk '{print $2}' || true)"
    if [[ -z "$status" ]]; then
      status="200"
    fi

    if [[ "$status" == "400" ]]; then
      outcome="BLOCKED"
    elif [[ "$status" =~ ^[0-9]{3}$ && "$status" -ge 400 ]]; then
      outcome="ERROR"
    else
      outcome="ALLOWED"
    fi

    severity="$(severity_for_profile "$profile")"

    echo "$(date -u +%Y-%m-%dT%H:%M:%SZ),$mode,$profile,$severity,$status,$outcome" >> "$REPORT_FILE"
  done
done

echo "Report written to: $REPORT_FILE"
