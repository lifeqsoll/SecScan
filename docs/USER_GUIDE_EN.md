# User Guide (English)

## 1. Quick Start

1. Create and activate virtual environment
2. Install dependencies
3. Run a scan command
4. Review JSON / JSONL outputs

## 2. Recommended Local Workflow

```bash
python -m secscan processes
python -m secscan ports
python -m secscan report --out reports/report.json --jsonl-out reports/findings.jsonl
```

## 3. Full Script Workflow

Windows:

```bat
run_full_scan.bat
```

Linux/macOS:

```bash
./run_full_scan.sh
```

The full run executes:

1. Full `report` command
2. Aggregation (`analyze_scan_results.py`)
3. Summary generation for the current run directory only

## 4. Interpreting Findings

- `critical`: immediate incident response required
- `high`: investigate quickly, high probability of risk
- `medium`: possible risk or drift, triage in context
- `low/info`: context and hardening signals

## 5. Hidden Process/Port Checks

- Hidden process mismatch (Windows): `psutil` vs `tasklist`
- Hidden port mismatch:
  - high-level API (`psutil`)
  - low-level kernel-facing structures (`/proc/net/*` or Windows IP Helper API)

## 6. Threat Intel and VirusTotal

### Hash reputation

When `--vt-api-key` is provided, the tool queries VirusTotal by SHA256.

### File upload

When `--vt-upload-malicious` is used together with VT API key:

1. process file hashes are checked in VT
2. files flagged malicious/suspicious are selected
3. selected files are uploaded to VT
4. upload status is printed in CLI

## 7. Safe Process Termination by Suspicious Port

```bash
python -m secscan ports --kill-suspicious
```

By default, each kill action requires interactive confirmation.

## 8. Permissions

Run as Administrator/root for best visibility:

- process ownership data
- kernel-facing port tables
- fewer access-denied blind spots

## 9. Output Files

Per run directory (`reports/<timestamp>/`):

- `secscan-report.json` - main report
- `secscan-findings.jsonl` - SIEM pipeline format
- `secscan-summary.json` - aggregated summary
- `run.log` - full script execution log (Windows full script)

## 10. Operational Tips

- Keep baseline file updated only after approved change windows
- Use SIEM correlation with endpoint, DNS, and proxy logs
- Treat unknown unsigned binaries with stricter policy if in user-writable paths
