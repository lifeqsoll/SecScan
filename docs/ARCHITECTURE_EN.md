# Architecture and Execution Flow

## High-Level Flow

```mermaid
flowchart TD
  A[run_full_scan script] --> B[secscan report]
  B --> C[Process Analysis]
  B --> D[Port Mismatch Analysis]
  B --> E[Host Checks]
  B --> F[Threat Intel Enrichment]
  F --> G[VirusTotal/MISP/TI Feed]
  B --> H[SIEM Export]
  H --> I[Splunk/ELK/Sentinel]
  B --> J[JSON + JSONL Outputs]
  A --> K[analyze_scan_results.py]
  K --> L[secscan-summary.json]
```

## Hidden Port Detection Model

```mermaid
flowchart LR
  H1[High-level: psutil.net_connections] --> CMP[Compare Ports]
  L1[Low-level Linux: /proc/net/tcp,udp,tcp6,udp6] --> CMP
  L2[Low-level Windows: GetExtendedTcpTable/GetExtendedUdpTable] --> CMP
  CMP --> M{Visible in low-level<br/>but absent in high-level?}
  M -- Yes --> S[Create port.hidden_mismatch finding]
  M -- No --> N[No mismatch finding]
```

## Process/TI Pipeline

```mermaid
flowchart TD
  P[Process enumeration] --> R[Heuristics + signature checks]
  R --> T[SHA256 collection]
  T --> VT[VirusTotal hash lookup]
  T --> MI[MISP hash search]
  T --> FEED[External TI feed correlation]
  VT --> U[Optional VT file upload]
  R --> O[Findings]
  MI --> O
  FEED --> O
  U --> O
```

## Run Artifacts

Each full run creates a dedicated folder:

`reports/<timestamp>/`

Files:

- `secscan-report.json`
- `secscan-findings.jsonl`
- `secscan-summary.json`
- `run.log` (Windows full script)
