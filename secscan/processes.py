from __future__ import annotations

import os
from dataclasses import asdict, dataclass
from pathlib import Path

import psutil

from secscan.model import Finding, Severity
from secscan.platform import is_windows
from secscan.util import run_cmd


@dataclass(frozen=True)
class ProcessInfo:
    pid: int
    ppid: int | None
    name: str | None
    exe: str | None
    username: str | None
    create_time: float | None
    cmdline: list[str]


def _safe_str(p: psutil.Process, attr: str) -> str | None:
    try:
        v = getattr(p, attr)()
        return v if isinstance(v, str) else None
    except Exception:
        return None


def _safe_int(p: psutil.Process, attr: str) -> int | None:
    try:
        v = getattr(p, attr)()
        return int(v) if v is not None else None
    except Exception:
        return None


def list_processes() -> list[ProcessInfo]:
    out: list[ProcessInfo] = []
    for p in psutil.process_iter(attrs=[], ad_value=None):
        try:
            pid = p.pid
            ppid = p.ppid()
        except Exception:
            continue

        try:
            cmdline = p.cmdline() or []
        except Exception:
            cmdline = []

        out.append(
            ProcessInfo(
                pid=pid,
                ppid=ppid,
                name=_safe_str(p, "name"),
                exe=_safe_str(p, "exe"),
                username=_safe_str(p, "username"),
                create_time=_safe_int(p, "create_time"),
                cmdline=cmdline,
            )
        )
    return out


def analyze_processes(procs: list[ProcessInfo]) -> list[Finding]:
    findings: list[Finding] = []
    proc_pids = {p.pid for p in procs}

    # Best-effort anti-evasion check for Windows:
    # compare psutil process list with tasklist output.
    # This does not detect kernel rootkits reliably, but helps spot enumeration anomalies.
    if is_windows():
        findings.extend(_check_windows_pid_visibility(proc_pids))

    for p in procs:
        # Heuristics only; "hidden" rootkits require kernel-level checks which we do not do.
        if not p.exe:
            if _is_known_windows_system_process_without_exe(p):
                continue
            findings.append(
                Finding(
                    id="proc.no_exe_path",
                    title="Процесс без пути к исполняемому файлу",
                    severity=Severity.medium,
                    details={"pid": p.pid, "name": p.name, "username": p.username, "cmdline": p.cmdline},
                    recommendation="Проверьте процесс в диспетчере задач/Activity Monitor/ps, сравните с ожидаемым ПО. Если это не системный процесс — завершите вручную и проверьте автозапуск.",
                )
            )
            continue

        exe = p.exe
        lower = exe.lower()

        # Suspicious locations
        if is_windows():
            suspicious_dirs = [
                r"c:\users\public\\",
                r"c:\programdata\\",
                r"c:\users\\",
                r"c:\windows\temp\\",
                r"c:\temp\\",
            ]
            if any(lower.startswith(d) for d in suspicious_dirs) and not lower.startswith(r"c:\windows\system32\\"):
                findings.append(
                    Finding(
                        id="proc.suspicious_location",
                        title="Процесс запущен из подозрительной директории",
                        severity=Severity.high,
                        details={"pid": p.pid, "name": p.name, "exe": exe, "username": p.username},
                        recommendation="Проверьте цифровую подпись и происхождение файла. Если это не ваш софт — изолируйте хост и выполните полное AV/EDR-сканирование.",
                    )
                )
        else:
            # Linux/macOS common suspicious dirs
            suspicious_prefixes = ["/tmp/", "/var/tmp/", "/dev/shm/", "/private/tmp/"]
            if any(exe.startswith(pref) for pref in suspicious_prefixes):
                findings.append(
                    Finding(
                        id="proc.suspicious_location",
                        title="Процесс запущен из временной директории",
                        severity=Severity.high,
                        details={"pid": p.pid, "name": p.name, "exe": exe, "username": p.username},
                        recommendation="Проверьте владельца/права файла и причины запуска из tmp. Часто это признак вредоносной активности.",
                    )
                )

        # Odd names / masquerading patterns (heuristic)
        if p.name and any(ch in p.name for ch in ["\u200b", "\u200e", "\u200f"]):
            findings.append(
                Finding(
                    id="proc.unicode_obfuscation",
                    title="Подозрительные unicode-символы в имени процесса",
                    severity=Severity.high,
                    details={"pid": p.pid, "name": p.name, "exe": exe},
                    recommendation="Проверьте файл и родительский процесс. Обфускация имени часто используется для маскировки.",
                )
            )

        # World-writable executable (best-effort)
        try:
            st = os.stat(exe)
            if not is_windows():
                if bool(st.st_mode & 0o002):
                    findings.append(
                        Finding(
                            id="proc.world_writable_exe",
                            title="Исполняемый файл процесса доступен на запись всем пользователям",
                            severity=Severity.critical,
                            details={"pid": p.pid, "exe": exe},
                            recommendation="Срочно исправьте права на файл и проверьте целостность. Это позволяет подменить бинарник и закрепиться в системе.",
                        )
                    )
        except Exception:
            pass

        # Very long command line
        if len(" ".join(p.cmdline)) > 4000:
            findings.append(
                Finding(
                    id="proc.very_long_cmdline",
                    title="Аномально длинная командная строка процесса",
                    severity=Severity.medium,
                    details={"pid": p.pid, "name": p.name, "exe": exe},
                    recommendation="Проверьте аргументы запуска. Иногда это упаковка/обфускация или вредоносная нагрузка.",
                )
            )

        # Executable deleted while running (Unix)
        if not is_windows():
            try:
                if not Path(exe).exists():
                    findings.append(
                        Finding(
                            id="proc.exe_missing",
                            title="Исполняемый файл процесса не найден на диске",
                            severity=Severity.high,
                            details={"pid": p.pid, "name": p.name, "exe": exe},
                            recommendation="Возможна техника 'delete-on-exec'. Изолируйте хост и соберите форензику (память/FD) перед перезагрузкой.",
                        )
                    )
            except Exception:
                pass

    return findings


def processes_as_dict(procs: list[ProcessInfo]) -> list[dict]:
    return [asdict(p) for p in procs]


def _parse_tasklist_pids(output: str) -> set[int]:
    pids: set[int] = set()
    for line in output.splitlines():
        line = line.strip()
        if not line:
            continue
        # CSV mode: "Image Name","PID","Session Name","Session#","Mem Usage"
        if not line.startswith('"'):
            continue
        parts = [p.strip().strip('"') for p in line.split('","')]
        if len(parts) < 2:
            continue
        pid_raw = parts[1].strip('"')
        if pid_raw.isdigit():
            pids.add(int(pid_raw))
    return pids


def _check_windows_pid_visibility(psutil_pids: set[int]) -> list[Finding]:
    findings: list[Finding] = []
    code, out = run_cmd(["tasklist", "/FO", "CSV"], timeout_s=8)
    if code != 0 or not out:
        findings.append(
            Finding(
                id="proc.visibility_check_unavailable",
                title="Проверка видимости процессов через tasklist недоступна",
                severity=Severity.low,
                details={"return_code": code, "output": out[:400]},
                recommendation="Запустите скан с достаточными правами и проверьте доступность tasklist в окружении.",
            )
        )
        return findings

    tasklist_pids = _parse_tasklist_pids(out)
    if not tasklist_pids:
        return findings

    only_psutil = sorted(psutil_pids - tasklist_pids)
    only_tasklist = sorted(tasklist_pids - psutil_pids)

    # Small mismatch may happen because of race conditions during snapshot collection.
    mismatch = len(only_psutil) + len(only_tasklist)
    if mismatch >= 5:
        findings.append(
            Finding(
                id="proc.pid_visibility_mismatch",
                title="Несоответствие списков процессов (psutil vs tasklist)",
                severity=Severity.high,
                details={
                    "psutil_count": len(psutil_pids),
                    "tasklist_count": len(tasklist_pids),
                    "only_psutil_pids": only_psutil[:30],
                    "only_tasklist_pids": only_tasklist[:30],
                },
                recommendation="Проверьте хост EDR/антивирусом и Sysinternals (Process Explorer/Autoruns). Возможны tampering, race condition или ограничение прав.",
            )
        )

    return findings


def _is_known_windows_system_process_without_exe(p: ProcessInfo) -> bool:
    if not is_windows():
        return False

    # Common built-in Windows processes that may not expose an executable path via APIs.
    known = {
        (0, "system idle process"),
        (4, "system"),
    }
    if p.name is None:
        return False
    return (p.pid, p.name.strip().lower()) in known

