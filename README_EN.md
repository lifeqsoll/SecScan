# secscan (Defensive Security Scanner)

`secscan` is a cross-platform defensive CLI utility for endpoint security visibility.
It is designed for Windows, Linux, and macOS, and focuses on safe detection logic
without exploit behavior.

## What It Does

- Process inventory and suspicious process heuristics
- Hidden-process anomaly checks (Windows `psutil` vs `tasklist`)
- Hidden-port mismatch checks (high-level vs low-level data sources)
- Host security checks (firewall, SMBv1, SSH root login, Gatekeeper, etc.)
- Passive network device discovery (ARP / neighbor cache)
- Threat intelligence enrichment (VirusTotal / MISP / external TI feed)
- SIEM export support (Splunk HEC / ELK / Microsoft Sentinel)
- JSON and JSONL reporting

## Safety Model

- No vulnerability exploitation
- No lateral movement logic
- No persistence or offensive actions
- Optional process termination is user-confirmed by default

## Installation

```bash
python -m venv .venv
```

Windows:

```powershell
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
```

Linux/macOS:

```bash
source .venv/bin/activate
pip install -r requirements.txt
```

## Core Commands

```bash
python -m secscan --help
python -m secscan processes
python -m secscan ports
python -m secscan host
python -m secscan network
python -m secscan report --out report.json
```

## Hidden Port Mismatch Detection

`secscan ports` compares:

- High-level source: `psutil.net_connections(kind="inet")`
- Low-level sources:
  - Linux: `/proc/net/tcp`, `/proc/net/tcp6`, `/proc/net/udp`, `/proc/net/udp6`
  - Windows: `GetExtendedTcpTable` / `GetExtendedUdpTable` (IPv4 + IPv6 via `ctypes`)

If a port appears in low-level kernel-visible structures but not in high-level API output,
it is flagged as suspicious (`port.hidden_mismatch`).

## Kill Suspicious Port Owner (Interactive)

```bash
python -m secscan ports --kill-suspicious
```

The tool asks for confirmation per suspicious process.
For automation, you can use `-y`, but this is dangerous and should be restricted.

## One-Click Full Run

Windows:

```bat
run_full_scan.bat
```

Linux/macOS:

```bash
chmod +x ./run_full_scan.sh
./run_full_scan.sh
```

Each run is stored in a timestamped directory:

`reports/<YYYYMMDD-HHMMSS>/`

Artifacts:

- `secscan-report.json`
- `secscan-findings.jsonl`
- `secscan-summary.json`
- `run.log` (Windows full script)

## Enterprise Integrations

- VirusTotal: `--vt-api-key`, `--vt-upload-malicious`
- MISP: `--misp-url`, `--misp-key`
- External TI feed: `--ti-feed-url`, `--ti-feed-token`
- Splunk HEC: `--splunk-hec-url`, `--splunk-hec-token`
- ELK: `--elk-url`, `--elk-api-key`
- Sentinel: `--sentinel-workspace-id`, `--sentinel-shared-key`

## Limitations

- Not a kernel-mode anti-rootkit product
- Low-level visibility still depends on OS permissions
- Best results require administrator/root privileges
- Should be used with EDR/SIEM in corporate environments
