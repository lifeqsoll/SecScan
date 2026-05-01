from __future__ import annotations

import json
import uuid
from pathlib import Path
from urllib import error, parse, request

from secscan.model import Finding, Severity


def _json_request(url: str, method: str = "GET", headers: dict[str, str] | None = None, body: bytes | None = None, timeout: int = 20) -> tuple[int, dict]:
    req = request.Request(url=url, method=method, headers=headers or {}, data=body)
    try:
        with request.urlopen(req, timeout=timeout) as resp:
            raw = resp.read().decode("utf-8", errors="replace")
            return resp.status, json.loads(raw) if raw.strip() else {}
    except error.HTTPError as e:
        payload = e.read().decode("utf-8", errors="replace") if e.fp else ""
        try:
            return e.code, json.loads(payload) if payload.strip() else {}
        except Exception:
            return e.code, {"error": payload}
    except Exception as e:
        return 0, {"error": f"{type(e).__name__}: {e}"}


def fetch_ti_feed_ioc(feed_url: str | None, bearer_token: str | None = None) -> dict[str, list[str]]:
    if not feed_url:
        return {"sha256": [], "names": [], "paths": []}
    headers = {"Accept": "application/json"}
    if bearer_token:
        headers["Authorization"] = f"Bearer {bearer_token}"
    status, data = _json_request(feed_url, headers=headers)
    if status != 200:
        return {"sha256": [], "names": [], "paths": []}
    return {
        "sha256": [str(x).lower() for x in data.get("sha256", [])],
        "names": [str(x).lower() for x in data.get("names", [])],
        "paths": [str(x).lower() for x in data.get("paths", [])],
    }


def query_misp_hashes(misp_url: str | None, misp_key: str | None, hashes: list[str]) -> set[str]:
    if not misp_url or not misp_key or not hashes:
        return set()
    base = misp_url.rstrip("/")
    url = f"{base}/attributes/restSearch"
    body = json.dumps(
        {
            "returnFormat": "json",
            "type": ["sha256"],
            "value": hashes,
            "to_ids": True,
        }
    ).encode("utf-8")
    headers = {
        "Authorization": misp_key,
        "Accept": "application/json",
        "Content-Type": "application/json",
    }
    status, data = _json_request(url, method="POST", headers=headers, body=body)
    if status != 200:
        return set()
    out: set[str] = set()
    attrs = data.get("response", {}).get("Attribute", [])
    for a in attrs:
        value = str(a.get("value", "")).lower().strip()
        if value:
            out.add(value)
    return out


def query_virustotal_hash(vt_api_key: str, sha256_hash: str) -> dict:
    url = f"https://www.virustotal.com/api/v3/files/{parse.quote(sha256_hash)}"
    headers = {"x-apikey": vt_api_key, "Accept": "application/json"}
    status, data = _json_request(url, headers=headers)
    if status != 200:
        return {"ok": False, "status": status, "error": data.get("error")}
    attrs = data.get("data", {}).get("attributes", {})
    stats = attrs.get("last_analysis_stats", {}) or {}
    mal = int(stats.get("malicious", 0) or 0)
    susp = int(stats.get("suspicious", 0) or 0)
    harmless = int(stats.get("harmless", 0) or 0)
    return {
        "ok": True,
        "status": 200,
        "malicious": mal,
        "suspicious": susp,
        "harmless": harmless,
        "permalink": f"https://www.virustotal.com/gui/file/{sha256_hash}",
    }


def build_threat_intel_findings(
    proc_hashes: list[dict],
    vt_api_key: str | None,
    misp_url: str | None,
    misp_key: str | None,
    vt_max_hash_checks: int = 40,
) -> tuple[list[Finding], list[str], set[str]]:
    findings: list[Finding] = []
    logs: list[str] = []
    hash_values = [x["sha256"] for x in proc_hashes if x.get("sha256")]
    misp_hits = query_misp_hashes(misp_url, misp_key, hash_values)
    if misp_url and misp_key:
        logs.append(f"MISP: найдено совпадений по SHA256: {len(misp_hits)}")

    vt_malicious_hashes: set[str] = set()
    if vt_api_key:
        checked = 0
        limited = proc_hashes[: max(1, int(vt_max_hash_checks))]
        if len(proc_hashes) > len(limited):
            logs.append(f"VirusTotal: hash checks limited to {len(limited)} of {len(proc_hashes)} processes")
        for item in limited:
            sha = item.get("sha256")
            if not sha:
                continue
            checked += 1
            vt = query_virustotal_hash(vt_api_key, sha)
            if not vt.get("ok"):
                continue
            mal = int(vt.get("malicious", 0))
            susp = int(vt.get("suspicious", 0))
            if mal > 0 or susp >= 3:
                vt_malicious_hashes.add(sha)
                findings.append(
                    Finding(
                        id="intel.virustotal_detection",
                        title="VirusTotal обнаружил вредоносность/подозрительность файла процесса",
                        severity=Severity.critical if mal > 0 else Severity.high,
                        details={
                            "pid": item.get("pid"),
                            "name": item.get("name"),
                            "exe": item.get("exe"),
                            "sha256": sha,
                            "vt_malicious": mal,
                            "vt_suspicious": susp,
                            "vt_permalink": vt.get("permalink"),
                        },
                        recommendation="Изолируйте хост и запустите процедуру IR. Проверьте источник файла, цепочку запуска и lateral movement.",
                    )
                )
        logs.append(f"VirusTotal: проверено хешей: {checked}, срабатываний: {len(vt_malicious_hashes)}")

    for item in proc_hashes:
        sha = item.get("sha256")
        if not sha:
            continue
        if sha in misp_hits:
            findings.append(
                Finding(
                    id="intel.misp_match",
                    title="Совпадение SHA256 с MISP (to_ids)",
                    severity=Severity.critical,
                    details={"pid": item.get("pid"), "name": item.get("name"), "exe": item.get("exe"), "sha256": sha},
                    recommendation="Немедленно изолируйте хост, зафиксируйте IOC в SIEM/EDR и проведите расследование.",
                )
            )
    return findings, logs, vt_malicious_hashes


def upload_files_to_virustotal(vt_api_key: str | None, paths: list[str], max_files: int = 10) -> list[str]:
    if not vt_api_key or not paths:
        return []
    logs: list[str] = []
    for p in paths[:max_files]:
        fpath = Path(p)
        if not fpath.exists() or not fpath.is_file():
            continue
        boundary = f"----secscan-{uuid.uuid4().hex}"
        file_bytes = fpath.read_bytes()
        lines: list[bytes] = []
        lines.append(f"--{boundary}\r\n".encode("utf-8"))
        lines.append(f'Content-Disposition: form-data; name="file"; filename="{fpath.name}"\r\n'.encode("utf-8"))
        lines.append(b"Content-Type: application/octet-stream\r\n\r\n")
        lines.append(file_bytes)
        lines.append(f"\r\n--{boundary}--\r\n".encode("utf-8"))
        body = b"".join(lines)
        headers = {
            "x-apikey": vt_api_key,
            "Accept": "application/json",
            "Content-Type": f"multipart/form-data; boundary={boundary}",
        }
        status, data = _json_request("https://www.virustotal.com/api/v3/files", method="POST", headers=headers, body=body, timeout=60)
        if status in (200, 202):
            analysis_id = data.get("data", {}).get("id")
            logs.append(f"VT upload ok: {fpath} (analysis_id={analysis_id})")
            result = _fetch_vt_analysis_result(vt_api_key, analysis_id)
            if result:
                logs.append(f"VT analysis: {fpath} => {result}")
        else:
            logs.append(f"VT upload failed: {fpath} (status={status})")
    return logs


def _fetch_vt_analysis_result(vt_api_key: str, analysis_id: str | None) -> str | None:
    if not analysis_id:
        return None
    url = f"https://www.virustotal.com/api/v3/analyses/{parse.quote(analysis_id)}"
    headers = {"x-apikey": vt_api_key, "Accept": "application/json"}
    status, data = _json_request(url, headers=headers)
    if status != 200:
        return None
    attrs = data.get("data", {}).get("attributes", {}) or {}
    st = attrs.get("status")
    stats = attrs.get("stats", {}) or {}
    mal = int(stats.get("malicious", 0) or 0)
    susp = int(stats.get("suspicious", 0) or 0)
    harmless = int(stats.get("harmless", 0) or 0)
    return f"status={st}, malicious={mal}, suspicious={susp}, harmless={harmless}"
