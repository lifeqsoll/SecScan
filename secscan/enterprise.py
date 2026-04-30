from __future__ import annotations

import hashlib
import ipaddress
import json
from dataclasses import asdict
from pathlib import Path

import psutil

from secscan.model import Finding, Severity
from secscan.platform import is_windows
from secscan.processes import ProcessInfo
from secscan.util import run_cmd


def _sha256_file(path: str) -> str | None:
    try:
        h = hashlib.sha256()
        with open(path, "rb") as f:
            while True:
                chunk = f.read(1024 * 1024)
                if not chunk:
                    break
                h.update(chunk)
        return h.hexdigest()
    except Exception:
        return None


def _load_ioc(path: str | None) -> dict:
    if not path:
        return {"sha256": [], "names": [], "paths": []}
    p = Path(path).expanduser().resolve()
    if not p.exists():
        return {"sha256": [], "names": [], "paths": []}
    try:
        data = json.loads(p.read_text(encoding="utf-8"))
        return {
            "sha256": [str(x).lower() for x in data.get("sha256", [])],
            "names": [str(x).lower() for x in data.get("names", [])],
            "paths": [str(x).lower() for x in data.get("paths", [])],
        }
    except Exception:
        return {"sha256": [], "names": [], "paths": []}


def _win_signature(path: str) -> dict[str, str | None]:
    ps_cmd = (
        "$sig=Get-AuthenticodeSignature -FilePath '{}' ; "
        "$cert=$sig.SignerCertificate ; "
        "[PSCustomObject]@{{Status=$sig.Status.ToString();Signer=($cert.Subject);Thumbprint=($cert.Thumbprint)}} "
        "| ConvertTo-Json -Compress"
    ).format(path.replace("'", "''"))
    code, out = run_cmd(["powershell", "-NoProfile", "-Command", ps_cmd], timeout_s=8)
    if code != 0 or not out:
        return {"status": "unknown", "signer": None, "thumbprint": None}
    try:
        data = json.loads(out)
        return {
            "status": str(data.get("Status") or "unknown"),
            "signer": data.get("Signer"),
            "thumbprint": data.get("Thumbprint"),
        }
    except Exception:
        return {"status": "unknown", "signer": None, "thumbprint": None}


def _is_external_ip(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
        return not (addr.is_private or addr.is_loopback or addr.is_link_local or addr.is_multicast)
    except Exception:
        return False


def enrich_process_findings(
    procs: list[ProcessInfo],
    findings: list[Finding],
    ioc_path: str | None = None,
    extra_ioc: dict[str, list[str]] | None = None,
) -> list[Finding]:
    enriched = list(findings)
    ioc = merge_ioc_sources(_load_ioc(ioc_path), extra_ioc or {"sha256": [], "names": [], "paths": []})
    flagged_pids = {f.details.get("pid") for f in findings if f.id.startswith("proc.") and isinstance(f.details.get("pid"), int)}
    sig_cache: dict[str, dict[str, str | None]] = {}
    signature_reported_exes: set[str] = set()

    # Correlate suspicious processes with live outbound network sessions.
    try:
        for c in psutil.net_connections(kind="inet"):
            if c.pid not in flagged_pids:
                continue
            if not c.raddr:
                continue
            r_ip = str(c.raddr.ip)
            if c.status != psutil.CONN_ESTABLISHED:
                continue
            if not _is_external_ip(r_ip):
                continue
            enriched.append(
                Finding(
                    id="proc.network_correlation",
                    title="Подозрительный процесс имеет активное внешнее сетевое соединение",
                    severity=Severity.high,
                    details={"pid": c.pid, "remote_ip": r_ip, "remote_port": c.raddr.port, "status": c.status},
                    recommendation="Изолируйте хост, проверьте сетевые артефакты и при необходимости блокируйте C2/IOC на периметре.",
                )
            )
    except Exception:
        pass

    # Signature, hash, IOC reputation checks.
    for p in procs:
        if not p.exe:
            continue
        exe = p.exe
        exe_lower = exe.lower()
        name_lower = (p.name or "").lower()

        file_sha = _sha256_file(exe)
        if file_sha and file_sha.lower() in ioc["sha256"]:
            enriched.append(
                Finding(
                    id="proc.ioc_sha256_match",
                    title="Совпадение SHA256 процесса с IOC",
                    severity=Severity.critical,
                    details={"pid": p.pid, "name": p.name, "exe": exe, "sha256": file_sha},
                    recommendation="Немедленно изолируйте хост, остановите процесс и запустите процедуру инцидент-реагирования.",
                )
            )

        if name_lower and name_lower in ioc["names"]:
            enriched.append(
                Finding(
                    id="proc.ioc_name_match",
                    title="Имя процесса совпадает с IOC",
                    severity=Severity.high,
                    details={"pid": p.pid, "name": p.name, "exe": exe},
                    recommendation="Подтвердите легитимность файла по подписи/хешу и проверьте источник запуска.",
                )
            )

        if any(exe_lower.startswith(x) for x in ioc["paths"]):
            enriched.append(
                Finding(
                    id="proc.ioc_path_match",
                    title="Путь процесса совпадает с IOC-шаблоном",
                    severity=Severity.high,
                    details={"pid": p.pid, "name": p.name, "exe": exe},
                    recommendation="Проверьте persistence-механизмы (Run keys, Scheduled Tasks, Services) и источник появления файла.",
                )
            )

        if is_windows() and _should_check_signature(p, flagged_pids):
            sig = sig_cache.get(exe)
            if sig is None:
                sig = _win_signature(exe)
                sig_cache[exe] = sig
            status = (sig.get("status") or "unknown").lower()
            severity = _signature_risk_severity(exe, status)
            if severity is not None and exe not in signature_reported_exes:
                signature_reported_exes.add(exe)
                enriched.append(
                    Finding(
                        id="proc.signature_risk",
                        title="Риск по цифровой подписи исполняемого файла",
                        severity=severity,
                        details={
                            "pid": p.pid,
                            "name": p.name,
                            "exe": exe,
                            "signature_status": sig.get("status"),
                            "signer": sig.get("signer"),
                            "thumbprint": sig.get("thumbprint"),
                        },
                        recommendation="Проверьте происхождение файла, издателя, хеш и цепочку доверия. Для неподписанных бинарников применяйте allowlist-политику.",
                    )
                )

    return enriched


def _should_check_signature(p: ProcessInfo, flagged_pids: set[int]) -> bool:
    if not is_windows() or not p.exe:
        return False
    exe = p.exe.lower()
    # Always check signatures for already suspicious processes.
    if p.pid in flagged_pids:
        return True
    # Check non-system locations first to keep runtime practical.
    trusted_prefixes = [
        r"c:\windows\system32\\",
        r"c:\windows\winsxs\\",
        r"c:\program files\\",
        r"c:\program files (x86)\\",
    ]
    return not any(exe.startswith(pref) for pref in trusted_prefixes)


def _signature_risk_severity(exe: str, status: str) -> Severity | None:
    if status not in {"notsigned", "hashmismatch", "unknownerror", "nottrusted"}:
        return None

    lower = exe.lower()
    high_risk_prefixes = [
        r"c:\users\\",
        r"c:\windows\temp\\",
        r"c:\temp\\",
        r"c:\programdata\\",
    ]
    medium_risk_prefixes = [
        r"c:\program files\\",
        r"c:\program files (x86)\\",
        r"c:\program files\windowsapps\\",
    ]

    if status in {"hashmismatch", "nottrusted"}:
        return Severity.high
    if any(lower.startswith(pref) for pref in high_risk_prefixes):
        return Severity.high
    if any(lower.startswith(pref) for pref in medium_risk_prefixes):
        return Severity.medium
    return Severity.low


def build_integrity_baseline(procs: list[ProcessInfo]) -> dict:
    entries: dict[str, dict] = {}
    for p in procs:
        if not p.exe:
            continue
        exe = p.exe
        if exe in entries:
            continue
        entry = {"sha256": _sha256_file(exe)}
        if is_windows() and _should_check_signature(p, flagged_pids=set()):
            entry["signature"] = _win_signature(exe)
        entries[exe] = entry
    return {"executables": entries}


def check_integrity_baseline(procs: list[ProcessInfo], baseline_data: dict) -> list[Finding]:
    findings: list[Finding] = []
    entries = baseline_data.get("executables", {})
    if not isinstance(entries, dict):
        return findings

    current = build_integrity_baseline(procs).get("executables", {})
    for exe, expected in entries.items():
        now = current.get(exe)
        if not now:
            findings.append(
                Finding(
                    id="integrity.missing_executable",
                    title="Объект из baseline отсутствует",
                    severity=Severity.medium,
                    details={"exe": exe},
                    recommendation="Проверьте, было ли это плановое изменение ПО. Если нет — выполните расследование.",
                )
            )
            continue

        if expected.get("sha256") and now.get("sha256") and expected["sha256"] != now["sha256"]:
            findings.append(
                Finding(
                    id="integrity.hash_mismatch",
                    title="Нарушение целостности: хеш исполняемого файла изменился",
                    severity=Severity.critical,
                    details={"exe": exe, "expected_sha256": expected["sha256"], "actual_sha256": now["sha256"]},
                    recommendation="Считайте файл скомпрометированным до подтверждения. Изолируйте хост и переустановите бинарник из доверенного источника.",
                )
            )

    return findings


def findings_as_jsonl(findings: list[Finding], host: dict) -> list[str]:
    lines: list[str] = []
    for f in findings:
        lines.append(
            json.dumps(
                {
                    "id": f.id,
                    "title": f.title,
                    "severity": f.severity.value,
                    "details": f.details,
                    "recommendation": f.recommendation,
                    "host": host,
                },
                ensure_ascii=False,
            )
        )
    return lines


def merge_ioc_sources(*sources: dict[str, list[str]]) -> dict[str, list[str]]:
    merged = {"sha256": set(), "names": set(), "paths": set()}
    for src in sources:
        for k in ("sha256", "names", "paths"):
            for v in src.get(k, []) or []:
                merged[k].add(str(v).lower())
    return {k: sorted(v) for k, v in merged.items()}


def collect_process_hashes(procs: list[ProcessInfo]) -> list[dict]:
    out: list[dict] = []
    seen_exe: set[str] = set()
    for p in procs:
        if not p.exe:
            continue
        exe = p.exe
        if exe in seen_exe:
            continue
        seen_exe.add(exe)
        out.append(
            {
                "pid": p.pid,
                "name": p.name,
                "exe": exe,
                "sha256": _sha256_file(exe),
            }
        )
    return out
