from __future__ import annotations

import argparse
import json
import sys
from dataclasses import asdict
from pathlib import Path

from rich.console import Console
from rich.table import Table

from secscan.enterprise import (
    build_integrity_baseline,
    check_integrity_baseline,
    collect_process_hashes,
    enrich_process_findings,
    findings_as_jsonl,
    merge_ioc_sources,
)
from secscan.model import Report, Severity, utc_now_iso
from secscan.network import local_subnets, neighbors_passive
from secscan.platform import platform_summary
from secscan.ports import PortRecord, kill_suspicious_ports, scan_hidden_ports
from secscan.processes import analyze_processes, list_processes, processes_as_dict
from secscan.siem import export_elk, export_sentinel, export_splunk_hec
from secscan.threat_intel import (
    build_threat_intel_findings,
    fetch_ti_feed_ioc,
    upload_files_to_virustotal,
)
from secscan.host_checks import run_host_checks
from secscan.util import dumps_pretty


console = Console()


def _force_utf8_stdio_best_effort() -> None:
    """
    Windows консоли/CI иногда используют кодировки, которые не умеют печатать UTF-8.
    Для корректного вывода русских сообщений включаем UTF-8, если это возможно.
    """
    for stream in (sys.stdout, sys.stderr):
        try:
            if hasattr(stream, "reconfigure"):
                stream.reconfigure(encoding="utf-8", errors="replace")
        except Exception:
            pass


def _severity_rank(s: str) -> int:
    order = {
        Severity.critical.value: 0,
        Severity.high.value: 1,
        Severity.medium.value: 2,
        Severity.low.value: 3,
        Severity.info.value: 4,
    }
    return order.get(s, 99)


def _print_findings(findings):
    if not findings:
        console.print("[green]Ничего подозрительного не найдено (по текущим правилам).[/green]")
        return

    findings_sorted = sorted(findings, key=lambda f: (_severity_rank(f.severity.value), f.id))
    table = Table(title="Findings")
    table.add_column("Severity", style="bold")
    table.add_column("ID")
    table.add_column("Title")
    for f in findings_sorted:
        sev = f.severity.value.upper()
        style = {
            "CRITICAL": "bold red",
            "HIGH": "red",
            "MEDIUM": "yellow",
            "LOW": "cyan",
            "INFO": "dim",
        }.get(sev, "white")
        table.add_row(f.severity.value, f.id, f.title, style=style)
    console.print(table)

    critical = [f for f in findings if f.severity == Severity.critical]
    if critical:
        console.print("[bold red]КРИТИЧНО:[/bold red] обнаружены критические проблемы. Рекомендуется немедленно устранить или изолировать хост.")


def _print_process_findings_details(findings, procs) -> None:
    proc_findings = [f for f in findings if f.id.startswith("proc.")]
    if not proc_findings:
        return

    pid_to_proc = {p.pid: p for p in procs}

    table = Table(title="Подозрительные процессы: причины и рекомендации")
    table.add_column("Severity", style="bold")
    table.add_column("PID")
    table.add_column("Процесс")
    table.add_column("Путь (exe)")
    table.add_column("Что не так")
    table.add_column("Рекомендация")

    for f in sorted(proc_findings, key=lambda x: (_severity_rank(x.severity.value), x.id)):
        pid = f.details.get("pid")
        proc = pid_to_proc.get(pid) if isinstance(pid, int) else None
        name = f.details.get("name") or (proc.name if proc else None) or "-"
        exe = f.details.get("exe") or (proc.exe if proc else None) or "-"
        recommendation = f.recommendation or "-"

        sev = f.severity.value.upper()
        style = {
            "CRITICAL": "bold red",
            "HIGH": "red",
            "MEDIUM": "yellow",
            "LOW": "cyan",
            "INFO": "dim",
        }.get(sev, "white")
        table.add_row(
            f.severity.value,
            str(pid) if pid is not None else "-",
            str(name),
            str(exe),
            f.title,
            recommendation,
            style=style,
        )

    console.print(table)


def _run_threat_intel_and_siem(args, procs, findings, host_info) -> list:
    proc_hashes = collect_process_hashes(procs)
    intel_findings, intel_logs, vt_malicious_hashes = build_threat_intel_findings(
        proc_hashes=proc_hashes,
        vt_api_key=args.vt_api_key,
        misp_url=args.misp_url,
        misp_key=args.misp_key,
    )
    for line in intel_logs:
        console.print(f"[cyan]{line}[/cyan]")
    findings = findings + intel_findings

    if args.vt_upload_malicious and args.vt_api_key:
        malicious_paths = sorted({x.get("exe") for x in proc_hashes if x.get("sha256") in vt_malicious_hashes and x.get("exe")})
        upload_logs = upload_files_to_virustotal(args.vt_api_key, malicious_paths, max_files=args.vt_upload_max_files)
        for line in upload_logs:
            console.print(f"[magenta]{line}[/magenta]")

    if args.splunk_hec_url:
        console.print(f"[green]{export_splunk_hec(findings, host_info, args.splunk_hec_url, args.splunk_hec_token, args.splunk_sourcetype)}[/green]")
    if args.elk_url:
        console.print(f"[green]{export_elk(findings, host_info, args.elk_url, args.elk_api_key, args.elk_index)}[/green]")
    if args.sentinel_workspace_id:
        console.print(
            f"[green]{export_sentinel(findings, host_info, args.sentinel_workspace_id, args.sentinel_shared_key, args.sentinel_log_type)}[/green]"
        )

    return findings


def _print_port_suspicious(suspicious: list[PortRecord]) -> None:
    if not suspicious:
        console.print("[green]Подозрительных портовых расхождений не найдено.[/green]")
        return
    table = Table(title="Подозрительные порты (low-level есть, high-level нет)")
    table.add_column("Proto")
    table.add_column("Port")
    table.add_column("Local IP")
    table.add_column("PID")
    table.add_column("State")
    table.add_column("Source", style="dim")
    for rec in suspicious:
        table.add_row(rec.proto, str(rec.local_port), rec.local_ip, str(rec.pid) if rec.pid else "-", rec.state or "-", rec.source)
    console.print(table)


def cmd_processes(args) -> int:
    procs = list_processes()
    findings = analyze_processes(procs)
    ti_ioc = fetch_ti_feed_ioc(args.ti_feed_url, bearer_token=args.ti_feed_token)
    merged_ioc = merge_ioc_sources(ti_ioc)
    findings = enrich_process_findings(procs, findings, ioc_path=args.ioc, extra_ioc=merged_ioc)

    if args.baseline_in:
        bpath = Path(args.baseline_in).expanduser().resolve()
        if bpath.exists():
            try:
                baseline_data = json.loads(bpath.read_text(encoding="utf-8"))
                findings.extend(check_integrity_baseline(procs, baseline_data))
            except Exception as e:
                console.print(f"[yellow]Не удалось прочитать baseline:[/yellow] {e}")

    if args.baseline_out:
        bdata = build_integrity_baseline(procs)
        bout = Path(args.baseline_out).expanduser().resolve()
        bout.parent.mkdir(parents=True, exist_ok=True)
        bout.write_text(dumps_pretty(bdata), encoding="utf-8")
        console.print(f"[green]Baseline сохранен:[/green] {bout}")

    host_info = {"platform": platform_summary()}
    findings = _run_threat_intel_and_siem(args, procs, findings, host_info)

    _print_findings(findings)
    _print_process_findings_details(findings, procs)
    if args.json:
        console.print(dumps_pretty({"processes": processes_as_dict(procs), "findings": [asdict(f) for f in findings]}))
    if args.jsonl_out:
        jout = Path(args.jsonl_out).expanduser().resolve()
        jout.parent.mkdir(parents=True, exist_ok=True)
        jout.write_text("\n".join(findings_as_jsonl(findings, host_info)) + "\n", encoding="utf-8")
        console.print(f"[green]JSONL сохранен:[/green] {jout}")
    return 0


def cmd_ports(args) -> int:
    findings, suspicious = scan_hidden_ports()
    _print_findings(findings)
    _print_port_suspicious(suspicious)

    if args.kill_suspicious:
        logs = kill_suspicious_ports(suspicious, ask_confirmation=(not args.yes))
        for line in logs:
            console.print(f"[yellow]{line}[/yellow]")

    if args.json:
        console.print(dumps_pretty({"suspicious_ports": [r.__dict__ for r in suspicious], "findings": [asdict(f) for f in findings]}))
    return 0


def cmd_host(args) -> int:
    findings = run_host_checks()
    _print_findings(findings)
    if args.json:
        console.print(dumps_pretty({"findings": [asdict(f) for f in findings]}))
    return 0


def cmd_network(args) -> int:
    subs = local_subnets()
    neigh = neighbors_passive()

    console.print("[bold]Локальные подсети:[/bold]")
    for s in subs:
        console.print(f"- {s}")

    table = Table(title="Устройства (пассивно из ARP/neighbor cache)")
    table.add_column("IP")
    table.add_column("MAC")
    table.add_column("Interface")
    table.add_column("State")
    table.add_column("Source", style="dim")
    for n in neigh:
        table.add_row(n.ip, n.mac or "", n.interface or "", n.state or "", n.source)
    console.print(table)

    if args.json:
        console.print(dumps_pretty({"subnets": subs, "neighbors": [asdict(n) for n in neigh]}))
    return 0


def cmd_report(args) -> int:
    procs = list_processes()
    proc_findings = analyze_processes(procs)
    port_findings, _ = scan_hidden_ports()
    ti_ioc = fetch_ti_feed_ioc(args.ti_feed_url, bearer_token=args.ti_feed_token)
    merged_ioc = merge_ioc_sources(ti_ioc)
    proc_findings = enrich_process_findings(procs, proc_findings, ioc_path=args.ioc, extra_ioc=merged_ioc)
    host_findings = run_host_checks()
    if args.baseline_in:
        bpath = Path(args.baseline_in).expanduser().resolve()
        if bpath.exists():
            try:
                baseline_data = json.loads(bpath.read_text(encoding="utf-8"))
                proc_findings.extend(check_integrity_baseline(procs, baseline_data))
            except Exception as e:
                console.print(f"[yellow]Не удалось прочитать baseline:[/yellow] {e}")

    if args.baseline_out:
        bdata = build_integrity_baseline(procs)
        bout = Path(args.baseline_out).expanduser().resolve()
        bout.parent.mkdir(parents=True, exist_ok=True)
        bout.write_text(dumps_pretty(bdata), encoding="utf-8")
        console.print(f"[green]Baseline сохранен:[/green] {bout}")

    host_obj = {"platform": platform_summary(), "subnets": local_subnets(), "neighbors": [asdict(n) for n in neighbors_passive()]}
    all_findings = _run_threat_intel_and_siem(args, procs, proc_findings + host_findings + port_findings, host_obj)
    report = Report(
        created_at=utc_now_iso(),
        host=host_obj,
        findings=all_findings,
    )

    data = report.to_jsonable()
    out_path = Path(args.out).expanduser().resolve()
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(dumps_pretty(data), encoding="utf-8")
    console.print(f"[green]Отчёт сохранён:[/green] {out_path}")
    if args.jsonl_out:
        jout = Path(args.jsonl_out).expanduser().resolve()
        jout.parent.mkdir(parents=True, exist_ok=True)
        jout.write_text("\n".join(findings_as_jsonl(all_findings, report.host)) + "\n", encoding="utf-8")
        console.print(f"[green]JSONL для SIEM сохранен:[/green] {jout}")

    critical = [f for f in all_findings if f.severity == Severity.critical]
    if critical:
        console.print("[bold red]КРИТИЧНО:[/bold red] в отчёте есть критические находки. Откройте файл и выполните рекомендации.")

    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="secscan", description="Defensive host/network scanner (safe, non-exploit).")
    sub = p.add_subparsers(dest="cmd", required=True)

    p_proc = sub.add_parser("processes", help="Сбор и анализ процессов (эвристики).")
    p_proc.add_argument("--json", action="store_true", help="Печатать JSON в stdout.")
    p_proc.add_argument("--ioc", default=None, help="Путь к IOC-файлу (JSON: sha256/names/paths).")
    p_proc.add_argument("--ti-feed-url", default=None, help="URL внешнего TI feed (JSON: sha256/names/paths).")
    p_proc.add_argument("--ti-feed-token", default=None, help="Bearer token для TI feed.")
    p_proc.add_argument("--misp-url", default=None, help="Base URL MISP (например https://misp.company.local).")
    p_proc.add_argument("--misp-key", default=None, help="MISP API key.")
    p_proc.add_argument("--vt-api-key", default=None, help="VirusTotal API key.")
    p_proc.add_argument("--vt-upload-malicious", action="store_true", help="Загружать в VirusTotal файлы, распознанные как вредоносные по VT.")
    p_proc.add_argument("--vt-upload-max-files", type=int, default=10, help="Лимит файлов для загрузки в VT.")
    p_proc.add_argument("--jsonl-out", default=None, help="Путь для JSONL выгрузки находок в SIEM.")
    p_proc.add_argument("--splunk-hec-url", default=None, help="Splunk HEC endpoint URL.")
    p_proc.add_argument("--splunk-hec-token", default=None, help="Splunk HEC token.")
    p_proc.add_argument("--splunk-sourcetype", default="secscan:json", help="Splunk sourcetype.")
    p_proc.add_argument("--elk-url", default=None, help="Elasticsearch endpoint URL.")
    p_proc.add_argument("--elk-api-key", default=None, help="Elasticsearch API key.")
    p_proc.add_argument("--elk-index", default="secscan-findings", help="ELK index prefix.")
    p_proc.add_argument("--sentinel-workspace-id", default=None, help="Microsoft Sentinel Workspace ID.")
    p_proc.add_argument("--sentinel-shared-key", default=None, help="Microsoft Sentinel shared key (base64).")
    p_proc.add_argument("--sentinel-log-type", default="SecScanFindings", help="Microsoft Sentinel log type.")
    p_proc.add_argument("--baseline-out", default=None, help="Путь для сохранения baseline целостности.")
    p_proc.add_argument("--baseline-in", default=None, help="Путь к baseline для проверки tamper-изменений.")
    p_proc.set_defaults(func=cmd_processes)

    p_host = sub.add_parser("host", help="Локальные security-checks (настройки, best-effort).")
    p_host.add_argument("--json", action="store_true", help="Печатать JSON в stdout.")
    p_host.set_defaults(func=cmd_host)

    p_net = sub.add_parser("network", help="Пассивное обнаружение устройств в сети (ARP/neighbor cache).")
    p_net.add_argument("--json", action="store_true", help="Печатать JSON в stdout.")
    p_net.set_defaults(func=cmd_network)

    p_ports = sub.add_parser("ports", help="Сравнение high-level и low-level источников портов (rootkit mismatch check).")
    p_ports.add_argument("--json", action="store_true", help="Печатать JSON в stdout.")
    p_ports.add_argument("--kill-suspicious", action="store_true", help="Предложить завершить процесс, занимающий подозрительный порт.")
    p_ports.add_argument("-y", "--yes", action="store_true", help="Не спрашивать подтверждение (опасно).")
    p_ports.set_defaults(func=cmd_ports)

    p_rep = sub.add_parser("report", help="Сформировать итоговый отчёт.")
    p_rep.add_argument("--out", default="secscan-report.json", help="Путь для сохранения JSON отчёта.")
    p_rep.add_argument("--ioc", default=None, help="Путь к IOC-файлу (JSON: sha256/names/paths).")
    p_rep.add_argument("--ti-feed-url", default=None, help="URL внешнего TI feed (JSON: sha256/names/paths).")
    p_rep.add_argument("--ti-feed-token", default=None, help="Bearer token для TI feed.")
    p_rep.add_argument("--misp-url", default=None, help="Base URL MISP.")
    p_rep.add_argument("--misp-key", default=None, help="MISP API key.")
    p_rep.add_argument("--vt-api-key", default=None, help="VirusTotal API key.")
    p_rep.add_argument("--vt-upload-malicious", action="store_true", help="Загружать в VirusTotal файлы, распознанные как вредоносные по VT.")
    p_rep.add_argument("--vt-upload-max-files", type=int, default=10, help="Лимит файлов для загрузки в VT.")
    p_rep.add_argument("--jsonl-out", default=None, help="Путь для JSONL выгрузки в SIEM.")
    p_rep.add_argument("--splunk-hec-url", default=None, help="Splunk HEC endpoint URL.")
    p_rep.add_argument("--splunk-hec-token", default=None, help="Splunk HEC token.")
    p_rep.add_argument("--splunk-sourcetype", default="secscan:json", help="Splunk sourcetype.")
    p_rep.add_argument("--elk-url", default=None, help="Elasticsearch endpoint URL.")
    p_rep.add_argument("--elk-api-key", default=None, help="Elasticsearch API key.")
    p_rep.add_argument("--elk-index", default="secscan-findings", help="ELK index prefix.")
    p_rep.add_argument("--sentinel-workspace-id", default=None, help="Microsoft Sentinel Workspace ID.")
    p_rep.add_argument("--sentinel-shared-key", default=None, help="Microsoft Sentinel shared key (base64).")
    p_rep.add_argument("--sentinel-log-type", default="SecScanFindings", help="Microsoft Sentinel log type.")
    p_rep.add_argument("--baseline-out", default=None, help="Путь для сохранения baseline целостности.")
    p_rep.add_argument("--baseline-in", default=None, help="Путь к baseline для проверки tamper-изменений.")
    p_rep.set_defaults(func=cmd_report)

    return p


def main(argv: list[str] | None = None) -> int:
    _force_utf8_stdio_best_effort()
    p = build_parser()
    args = p.parse_args(argv)
    return int(args.func(args))

