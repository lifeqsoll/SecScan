#!/usr/bin/env bash
set -euo pipefail

# One-click full scan for macOS/Linux (Debian/Arch compatible)
# Optional settings via environment variables:
#   OUT_DIR, IOC_PATH, BASELINE_IN, BASELINE_OUT
#   TI_FEED_URL, TI_FEED_TOKEN, MISP_URL, MISP_KEY
#   VT_API_KEY, VT_UPLOAD_MALICIOUS (1/0)
#   SPLUNK_HEC_URL, SPLUNK_HEC_TOKEN
#   ELK_URL, ELK_API_KEY
#   SENTINEL_WORKSPACE_ID, SENTINEL_SHARED_KEY

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$ROOT_DIR"

PYTHON_BIN="${PYTHON_BIN:-./.venv/bin/python}"
OUT_DIR="${OUT_DIR:-./reports}"
RUN_LABEL="${RUN_LABEL:-}"
IOC_PATH="${IOC_PATH:-./ioc-example.json}"
BASELINE_IN="${BASELINE_IN:-./baseline/exec-baseline.json}"
BASELINE_OUT="${BASELINE_OUT:-}"
TI_FEED_URL="${TI_FEED_URL:-}"
TI_FEED_TOKEN="${TI_FEED_TOKEN:-}"
MISP_URL="${MISP_URL:-}"
MISP_KEY="${MISP_KEY:-}"
VT_API_KEY="${VT_API_KEY:-}"
VT_UPLOAD_MALICIOUS="${VT_UPLOAD_MALICIOUS:-0}"
SPLUNK_HEC_URL="${SPLUNK_HEC_URL:-}"
SPLUNK_HEC_TOKEN="${SPLUNK_HEC_TOKEN:-}"
ELK_URL="${ELK_URL:-}"
ELK_API_KEY="${ELK_API_KEY:-}"
SENTINEL_WORKSPACE_ID="${SENTINEL_WORKSPACE_ID:-}"
SENTINEL_SHARED_KEY="${SENTINEL_SHARED_KEY:-}"

if [[ ! -x "$PYTHON_BIN" ]]; then
  echo "[-] Virtualenv python not found: $PYTHON_BIN"
  echo "    Setup:"
  echo "    python3 -m venv .venv"
  echo "    source .venv/bin/activate"
  echo "    pip install -r requirements.txt"
  exit 1
fi

mkdir -p "$OUT_DIR"
if [[ -z "$RUN_LABEL" ]]; then
  RUN_LABEL="$(date +%Y%m%d-%H%M%S)"
fi
RUN_DIR="$OUT_DIR/$RUN_LABEL"
mkdir -p "$RUN_DIR"
REPORT_PATH="$RUN_DIR/secscan-report.json"
JSONL_PATH="$RUN_DIR/secscan-findings.jsonl"
SUMMARY_PATH="$RUN_DIR/secscan-summary.json"

ARGS=(-m secscan report --out "$REPORT_PATH" --jsonl-out "$JSONL_PATH")

if [[ -f "$IOC_PATH" ]]; then
  ARGS+=(--ioc "$IOC_PATH")
fi
if [[ -f "$BASELINE_IN" ]]; then
  ARGS+=(--baseline-in "$BASELINE_IN")
fi
if [[ -n "$BASELINE_OUT" ]]; then
  ARGS+=(--baseline-out "$BASELINE_OUT")
fi
if [[ -n "$TI_FEED_URL" ]]; then
  ARGS+=(--ti-feed-url "$TI_FEED_URL")
fi
if [[ -n "$TI_FEED_TOKEN" ]]; then
  ARGS+=(--ti-feed-token "$TI_FEED_TOKEN")
fi
if [[ -n "$MISP_URL" ]]; then
  ARGS+=(--misp-url "$MISP_URL")
fi
if [[ -n "$MISP_KEY" ]]; then
  ARGS+=(--misp-key "$MISP_KEY")
fi
if [[ -n "$VT_API_KEY" ]]; then
  ARGS+=(--vt-api-key "$VT_API_KEY")
fi
if [[ "$VT_UPLOAD_MALICIOUS" == "1" ]]; then
  ARGS+=(--vt-upload-malicious)
fi
if [[ -n "$SPLUNK_HEC_URL" ]]; then
  ARGS+=(--splunk-hec-url "$SPLUNK_HEC_URL")
fi
if [[ -n "$SPLUNK_HEC_TOKEN" ]]; then
  ARGS+=(--splunk-hec-token "$SPLUNK_HEC_TOKEN")
fi
if [[ -n "$ELK_URL" ]]; then
  ARGS+=(--elk-url "$ELK_URL")
fi
if [[ -n "$ELK_API_KEY" ]]; then
  ARGS+=(--elk-api-key "$ELK_API_KEY")
fi
if [[ -n "$SENTINEL_WORKSPACE_ID" ]]; then
  ARGS+=(--sentinel-workspace-id "$SENTINEL_WORKSPACE_ID")
fi
if [[ -n "$SENTINEL_SHARED_KEY" ]]; then
  ARGS+=(--sentinel-shared-key "$SENTINEL_SHARED_KEY")
fi

echo "[*] Starting full scan..."
"$PYTHON_BIN" "${ARGS[@]}"

echo "[*] Running aggregate analyzer..."
"$PYTHON_BIN" "./analyze_scan_results.py" --reports-dir "$RUN_DIR" --out "$SUMMARY_PATH"

echo "[+] Done."
echo "    RunDir : $RUN_DIR"
echo "    Report : $REPORT_PATH"
echo "    JSONL  : $JSONL_PATH"
echo "    Summary: $SUMMARY_PATH"
