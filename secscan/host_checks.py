from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

from secscan.model import Finding, Severity
from secscan.platform import is_admin, is_linux, is_macos, is_windows
from secscan.util import run_cmd


def run_host_checks() -> list[Finding]:
    findings: list[Finding] = []
    admin = is_admin()

    if admin:
        rec = "Скан запущен с повышенными правами. Доступ к системным источникам расширен."
    else:
        rec = "Для части проверок нужны админ/рутовые права (например, чтение некоторых системных источников)."

    findings.append(
        Finding(
            id="host.privilege",
            title="Уровень прав запуска",
            severity=Severity.info,
            details={"is_admin": admin},
            recommendation=rec,
        )
    )

    if is_windows():
        findings.extend(_windows_checks())
    elif is_linux():
        findings.extend(_linux_checks())
    elif is_macos():
        findings.extend(_macos_checks())

    return findings


def _windows_checks() -> list[Finding]:
    findings: list[Finding] = []

    # Firewall profiles
    code, out = run_cmd(["powershell", "-NoProfile", "-Command", "Get-NetFirewallProfile | Select Name, Enabled | ConvertTo-Json"], timeout_s=8)
    if code == 0 and out:
        findings.append(
            Finding(
                id="win.firewall_profiles",
                title="Профили Windows Firewall",
                severity=Severity.info,
                details={"raw": out},
                recommendation="Убедитесь, что Firewall включен для всех профилей, где это требуется политикой.",
            )
        )

        if '"Enabled": false' in out or '"Enabled":  false' in out:
            findings.append(
                Finding(
                    id="win.firewall_disabled",
                    title="Firewall отключен для одного или нескольких профилей",
                    severity=Severity.critical,
                    details={"raw": out},
                    recommendation="Включите Firewall и проверьте GPO/локальные политики. Это существенно повышает риск компрометации.",
                )
            )

    # SMBv1 (best-effort)
    code, out = run_cmd(
        ["powershell", "-NoProfile", "-Command", "(Get-WindowsOptionalFeature -Online -FeatureName SMB1Protocol).State"],
        timeout_s=10,
    )
    if code == 0 and out:
        state = out.strip()
        if "Enabled" in state:
            findings.append(
                Finding(
                    id="win.smb1_enabled",
                    title="SMBv1 включен",
                    severity=Severity.critical,
                    details={"state": state},
                    recommendation="Отключите SMBv1 (устаревший протокол). Проверьте совместимость и используйте SMBv2/SMBv3.",
                )
            )

    return findings


def _linux_checks() -> list[Finding]:
    findings: list[Finding] = []

    # SSH root login
    sshd = Path("/etc/ssh/sshd_config")
    if sshd.exists():
        try:
            txt = sshd.read_text(errors="ignore")
            if "PermitRootLogin yes" in txt:
                findings.append(
                    Finding(
                        id="linux.ssh_root_login",
                        title="SSH разрешает логин root (PermitRootLogin yes)",
                        severity=Severity.critical,
                        details={"file": str(sshd)},
                        recommendation="Отключите прямой root-login по SSH. Используйте sudo, ключи, MFA/2FA, ограничение по AllowUsers/Match и fail2ban/Rate limit.",
                    )
                )
        except Exception:
            pass

    # World-writable PATH dirs
    path = os.environ.get("PATH", "")
    ww: list[str] = []
    for d in path.split(":"):
        d = d.strip()
        if not d:
            continue
        try:
            st = os.stat(d)
            if bool(st.st_mode & 0o002):
                ww.append(d)
        except Exception:
            continue
    if ww:
        findings.append(
            Finding(
                id="linux.world_writable_path",
                title="В PATH присутствуют директории, доступные на запись всем",
                severity=Severity.high,
                details={"dirs": ww},
                recommendation="Уберите world-writable директории из PATH или исправьте права. Иначе возможна подмена утилит и повышение привилегий.",
            )
        )

    return findings


def _macos_checks() -> list[Finding]:
    findings: list[Finding] = []

    # Gatekeeper status (best-effort)
    code, out = run_cmd(["spctl", "--status"], timeout_s=5)
    if code == 0 and out:
        if "assessments disabled" in out.lower():
            findings.append(
                Finding(
                    id="mac.gatekeeper_disabled",
                    title="Gatekeeper отключен",
                    severity=Severity.high,
                    details={"status": out},
                    recommendation="Включите Gatekeeper, если это соответствует вашей политике безопасности.",
                )
            )

    return findings

