from __future__ import annotations

import argparse
import json
import sys
from collections import Counter
from pathlib import Path
from typing import Any


def _force_utf8_stdio_best_effort() -> None:
    for stream in (sys.stdout, sys.stderr):
        try:
            if hasattr(stream, "reconfigure"):
                stream.reconfigure(encoding="utf-8", errors="replace")
        except Exception:
            pass


def _read_json(path: Path) -> dict[str, Any] | None:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return None


def _read_jsonl(path: Path) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    try:
        for line in path.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                out.append(json.loads(line))
            except Exception:
                continue
    except Exception:
        pass
    return out


def _extract_artifacts(details: dict[str, Any]) -> dict[str, list[str]]:
    artifacts = {
        "file_paths": [],
        "hashes_sha256": [],
        "ips": [],
        "masks_or_patterns": [],
    }
    path_keys = {"exe", "file", "path"}
    hash_keys = {"sha256", "expected_sha256", "actual_sha256"}
    ip_keys = {"ip", "remote_ip"}
    mask_keys = {"paths", "pattern", "mask"}

    for key, value in details.items():
        k = str(key).lower()
        if k in path_keys and isinstance(value, str):
            artifacts["file_paths"].append(value)
        elif k in hash_keys and isinstance(value, str):
            artifacts["hashes_sha256"].append(value)
        elif k in ip_keys and isinstance(value, str):
            artifacts["ips"].append(value)
        elif k in mask_keys:
            if isinstance(value, str):
                artifacts["masks_or_patterns"].append(value)
            elif isinstance(value, list):
                artifacts["masks_or_patterns"].extend([str(x) for x in value])

    return artifacts


def _dedupe_signature_risk(details: dict[str, Any]) -> str | None:
    exe = details.get("exe")
    if isinstance(exe, str) and exe:
        return exe.lower()
    return None


def aggregate(reports_dir: Path) -> dict[str, Any]:
    json_files = sorted(reports_dir.glob("*.json"))
    jsonl_files = sorted(reports_dir.glob("*.jsonl"))
    findings: list[dict[str, Any]] = []

    for path in json_files:
        data = _read_json(path)
        if not data:
            continue
        for f in data.get("findings", []):
            if isinstance(f, dict):
                f = dict(f)
                f["_source_file"] = str(path)
                findings.append(f)

    for path in jsonl_files:
        for row in _read_jsonl(path):
            if isinstance(row, dict):
                row = dict(row)
                row["_source_file"] = str(path)
                findings.append(row)

    dedup: dict[tuple[str, str, str], dict[str, Any]] = {}
    all_paths: set[str] = set()
    all_hashes: set[str] = set()
    all_ips: set[str] = set()
    all_masks: set[str] = set()
    src_files: set[str] = set()
    sev_counter: Counter[str] = Counter()

    for f in findings:
        fid = str(f.get("id", "unknown"))
        sev = str(f.get("severity", "unknown"))
        title = str(f.get("title", ""))
        details = f.get("details", {})
        if not isinstance(details, dict):
            details = {}
        dedupe_suffix = None
        if fid == "proc.signature_risk":
            dedupe_suffix = _dedupe_signature_risk(details)
        key = (fid, sev, title, dedupe_suffix or "")
        if key not in dedup:
            dedup[key] = {
                "id": fid,
                "severity": sev,
                "title": title,
                "recommendation": f.get("recommendation"),
                "instances": 0,
                "details_examples": [],
                "source_files": set(),
            }
        item = dedup[key]
        item["instances"] += 1
        if len(item["details_examples"]) < 3:
            item["details_examples"].append(details)
        item["source_files"].add(str(f.get("_source_file", "")))
        src_files.add(str(f.get("_source_file", "")))
        sev_counter[sev] += 1

        artifacts = _extract_artifacts(details)
        all_paths.update(artifacts["file_paths"])
        all_hashes.update(artifacts["hashes_sha256"])
        all_ips.update(artifacts["ips"])
        all_masks.update(artifacts["masks_or_patterns"])

    vulnerabilities = []
    sev_rank = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    for v in dedup.values():
        v["source_files"] = sorted(x for x in v["source_files"] if x)
        vulnerabilities.append(v)
    vulnerabilities.sort(key=lambda x: (sev_rank.get(x["severity"], 99), x["id"]))

    return {
        "summary": {
            "total_raw_findings": len(findings),
            "total_unique_vulnerabilities": len(vulnerabilities),
            "by_severity": dict(sev_counter),
            "source_files_count": len([x for x in src_files if x]),
        },
        "artifacts": {
            "file_paths": sorted(all_paths),
            "hashes_sha256": sorted(all_hashes),
            "ips": sorted(all_ips),
            "masks_or_patterns": sorted(all_masks),
        },
        "vulnerabilities": vulnerabilities,
    }


def print_cli(result: dict[str, Any]) -> None:
    s = result["summary"]
    print("=== AGGREGATED SECURITY SUMMARY ===")
    print(f"Raw findings: {s['total_raw_findings']}")
    print(f"Unique vulnerabilities: {s['total_unique_vulnerabilities']}")
    print("By severity:", s["by_severity"])
    print("")
    print("=== WHAT IS SUSPICIOUS RIGHT NOW ===")
    priorities = [v for v in result["vulnerabilities"] if v["severity"] in {"critical", "high"}][:10]
    if not priorities:
        priorities = [v for v in result["vulnerabilities"] if v["severity"] == "medium"][:10]
    if priorities:
        for v in priorities:
            print(f"- [{v['severity'].upper()}] {v['title']}")
    else:
        print("- No suspicious findings in current run.")
    print("")
    print("=== VULNERABILITIES ===")
    for v in result["vulnerabilities"]:
        print(f"- [{v['severity'].upper()}] {v['id']} :: {v['title']} (instances={v['instances']})")
        if v.get("recommendation"):
            print(f"  Recommendation: {v['recommendation']}")
        if v["source_files"]:
            print(f"  Sources: {', '.join(v['source_files'])}")
    print("")
    print("=== ARTIFACTS ===")
    for key in ("file_paths", "hashes_sha256", "ips", "masks_or_patterns"):
        vals = result["artifacts"].get(key, [])
        print(f"{key}: {len(vals)}")
        for val in vals[:20]:
            print(f"  - {val}")
        if len(vals) > 20:
            print("  ...")


def main() -> int:
    _force_utf8_stdio_best_effort()
    ap = argparse.ArgumentParser(description="Aggregate secscan outputs into one summary")
    ap.add_argument("--reports-dir", default="reports", help="Directory with secscan JSON/JSONL outputs")
    ap.add_argument("--out", default="reports/secscan-summary.json", help="Output summary JSON path")
    args = ap.parse_args()

    reports_dir = Path(args.reports_dir).expanduser().resolve()
    reports_dir.mkdir(parents=True, exist_ok=True)
    result = aggregate(reports_dir)
    out = Path(args.out).expanduser().resolve()
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding="utf-8")
    print_cli(result)
    print("")
    print(f"Summary written: {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
