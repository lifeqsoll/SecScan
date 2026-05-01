from __future__ import annotations

import json
import os
import re
import subprocess
import sys
import threading
import time
from dataclasses import asdict
from datetime import datetime
from pathlib import Path
from tkinter import BOTH, END, LEFT, RIGHT, VERTICAL, W, Y, Button, Frame, Label, StringVar, Tk, ttk
from tkinter.scrolledtext import ScrolledText


def launch_desktop_app() -> int:
    app = SecScanDesktopApp()
    app.run()
    return 0


class SecScanDesktopApp:
    def __init__(self) -> None:
        self.root = Tk()
        self.root.title("SecScan Desktop")
        self.root.geometry("1200x760")
        self.status = StringVar(value="Ready")
        self.current_step = StringVar(value="Idle")
        self.current_report_path: Path | None = None
        self._current_process: subprocess.Popen | None = None
        self._findings_cache: list[dict] = []
        self._build_ui()

    def _build_ui(self) -> None:
        top = Frame(self.root)
        top.pack(fill="x", padx=8, pady=8)

        self.btn_report = Button(top, text="Run Full Report", command=self._run_report)
        self.btn_report.pack(side=LEFT, padx=4)
        self.btn_ports = Button(top, text="Run Ports Check", command=self._run_ports)
        self.btn_ports.pack(side=LEFT, padx=4)
        self.btn_refresh = Button(top, text="Refresh Last Report", command=self._load_last_report)
        self.btn_refresh.pack(side=LEFT, padx=4)
        self.btn_stop = Button(top, text="Stop Current Task", command=self._stop_current_task, state="disabled")
        self.btn_stop.pack(side=LEFT, padx=4)
        Label(top, text="Current step:").pack(side=RIGHT, padx=(10, 2))
        Label(top, textvariable=self.current_step, anchor=W).pack(side=RIGHT)
        Label(top, textvariable=self.status, anchor=W).pack(side=RIGHT, padx=(10, 2))

        mid = Frame(self.root)
        mid.pack(fill=BOTH, expand=True, padx=8, pady=8)

        left = Frame(mid)
        left.pack(side=LEFT, fill=BOTH, expand=True)
        right = Frame(mid)
        right.pack(side=RIGHT, fill=BOTH, expand=True)

        self.tree = ttk.Treeview(left, columns=("severity", "id", "title", "process", "port"), show="headings")
        self.tree.heading("severity", text="Severity")
        self.tree.heading("id", text="ID")
        self.tree.heading("title", text="Title")
        self.tree.heading("process", text="Process/Path")
        self.tree.heading("port", text="Port")
        self.tree.column("severity", width=90, anchor=W)
        self.tree.column("id", width=220, anchor=W)
        self.tree.column("title", width=380, anchor=W)
        self.tree.column("process", width=350, anchor=W)
        self.tree.column("port", width=90, anchor=W)
        self.tree.pack(side=LEFT, fill=BOTH, expand=True)
        self.tree.bind("<<TreeviewSelect>>", self._on_select)

        tree_scroll = ttk.Scrollbar(left, orient=VERTICAL, command=self.tree.yview)
        tree_scroll.pack(side=RIGHT, fill=Y)
        self.tree.configure(yscrollcommand=tree_scroll.set)

        self.details = ScrolledText(right, wrap="word")
        self.details.pack(fill=BOTH, expand=True)
        self.details.insert(END, "Select a finding to view details.\n")
        self.details.configure(state="disabled")

        bottom = Frame(self.root)
        bottom.pack(fill=BOTH, padx=8, pady=8)
        Label(bottom, text="Human-readable summary").pack(anchor=W)
        self.summary = ScrolledText(bottom, height=10, wrap="word")
        self.summary.pack(fill=BOTH, expand=False)
        self.summary.configure(state="disabled")

        logs = Frame(self.root)
        logs.pack(fill=BOTH, expand=False, padx=8, pady=(0, 8))
        Label(logs, text="Live Log").pack(anchor=W)
        self.live_log = ScrolledText(logs, height=12, wrap="word")
        self.live_log.pack(fill=BOTH, expand=False)
        self.live_log.configure(bg="#0f111a", fg="#e6edf3", insertbackground="#e6edf3")
        self.live_log.tag_config("START", foreground="#7ee787")
        self.live_log.tag_config("STEP", foreground="#79c0ff")
        self.live_log.tag_config("HEARTBEAT", foreground="#a5d6ff")
        self.live_log.tag_config("STDOUT", foreground="#f0f6fc")
        self.live_log.tag_config("STDERR", foreground="#ffdf5d")
        self.live_log.tag_config("DONE", foreground="#56d364")
        self.live_log.tag_config("ERROR", foreground="#ff7b72")
        self.live_log.tag_config("WARN", foreground="#f2cc60")
        self.live_log.tag_config("INFO", foreground="#c9d1d9")
        self.live_log.configure(state="disabled")

    def run(self) -> None:
        self.root.mainloop()

    def _run_report(self) -> None:
        ts = datetime.now().strftime("%Y%m%d-%H%M%S")
        run_dir = Path("reports") / ts
        run_dir.mkdir(parents=True, exist_ok=True)
        report = run_dir / "secscan-report.json"
        jsonl = run_dir / "secscan-findings.jsonl"
        cmd = [sys.executable, "-m", "secscan", "report", "--out", str(report), "--jsonl-out", str(jsonl)]
        self._run_background(cmd, report, "Running full report...")

    def _run_ports(self) -> None:
        cmd = [sys.executable, "-m", "secscan", "ports", "--json", "--json-only"]
        self._run_background(cmd, None, "Running ports check...")

    def _run_background(self, cmd: list[str], report_path: Path | None, status_text: str) -> None:
        self.status.set(status_text)
        self.current_step.set(status_text)
        self._set_busy(True)
        self._append_log(f"$ {' '.join(cmd)}")

        def worker() -> None:
            try:
                child_env = os.environ.copy()
                # Force UTF-8 in child process to avoid cp1252 decode crashes on Windows terminals.
                child_env["PYTHONUTF8"] = "1"
                proc = subprocess.Popen(
                    cmd,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                    encoding="utf-8",
                    errors="replace",
                    env=child_env,
                    bufsize=1,
                )
                self._current_process = proc
                stdout_lines: list[str] = []
                stderr_lines: list[str] = []

                def stream_reader(stream, target_list: list[str], prefix: str) -> None:
                    if stream is None:
                        return
                    for line in stream:
                        text_line = line.rstrip("\n")
                        target_list.append(text_line)
                        self.root.after(0, lambda t=f"[{prefix}] {text_line}": self._append_log(t))

                t_out = threading.Thread(target=stream_reader, args=(proc.stdout, stdout_lines, "OUT"), daemon=True)
                t_err = threading.Thread(target=stream_reader, args=(proc.stderr, stderr_lines, "ERR"), daemon=True)
                t_out.start()
                t_err.start()
                started = time.time()
                last_hb = 0.0
                while proc.poll() is None:
                    elapsed = int(time.time() - started)
                    if elapsed - last_hb >= 2:
                        last_hb = float(elapsed)
                        self.root.after(0, lambda e=elapsed: self._append_log(f"[HEARTBEAT] Task still running: {e}s"))
                    time.sleep(0.2)
                ret = int(proc.returncode or 0)
                t_out.join(timeout=2)
                t_err.join(timeout=2)
                output = "\n".join(stdout_lines + stderr_lines)

                if report_path and report_path.exists():
                    self.current_report_path = report_path
                    self.root.after(0, lambda: self._load_report(report_path))
                elif "ports" in cmd:
                    self.root.after(0, lambda: self._load_ports_json_output(output))
                if ret != 0:
                    self.root.after(0, lambda: self._append_log(f"[ERROR] Task exit code: {ret}"))
                    if output:
                        self.root.after(0, lambda: self._show_raw_ports_output(output))
                msg = f"Done (exit={ret})"
            except Exception as e:
                msg = f"Failed: {type(e).__name__}: {e}"
                self.root.after(0, lambda: self._append_log(msg))
            finally:
                self._current_process = None
                self.root.after(0, lambda: self._set_busy(False))
                self.root.after(0, lambda: self.current_step.set("Idle"))
            self.root.after(0, lambda: self.status.set(msg))

        threading.Thread(target=worker, daemon=True).start()

    def _load_last_report(self) -> None:
        reports = list(Path("reports").glob("*/secscan-report.json"))
        reports.sort(key=lambda p: p.stat().st_mtime if p.exists() else 0, reverse=True)
        if not reports:
            self.status.set("No reports found")
            return
        self.current_report_path = reports[0]
        self._load_report(reports[0])
        self.status.set(f"Loaded {reports[0]}")

    def _load_report(self, path: Path) -> None:
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except Exception as e:
            self.status.set(f"Unable to read report: {e}")
            return

        for item in self.tree.get_children():
            self.tree.delete(item)

        findings = data.get("findings", [])
        self._findings_cache = findings
        for idx, f in enumerate(findings):
            details = f.get("details", {}) if isinstance(f.get("details"), dict) else {}
            proc = details.get("exe") or details.get("process_exe") or details.get("name") or "-"
            port = details.get("local_port") or "-"
            self.tree.insert(
                "",
                END,
                iid=str(idx),
                values=(f.get("severity", "-"), f.get("id", "-"), f.get("title", "-"), str(proc), str(port)),
            )

        self._render_summary(findings)
        self.status.set(f"Loaded report: {path}")

    def _render_summary(self, findings: list[dict]) -> None:
        sev_counts: dict[str, int] = {}
        for f in findings:
            sev = str(f.get("severity", "unknown"))
            sev_counts[sev] = sev_counts.get(sev, 0) + 1

        lines = []
        lines.append(f"Total findings: {len(findings)}")
        lines.append("By severity:")
        for sev in ("critical", "high", "medium", "low", "info", "unknown"):
            if sev in sev_counts:
                lines.append(f"  - {sev}: {sev_counts[sev]}")

        suspicious_now = [f for f in findings if str(f.get("severity")) in {"critical", "high"}]
        if not suspicious_now:
            suspicious_now = [f for f in findings if str(f.get("severity")) == "medium"]

        lines.append("")
        lines.append("What is suspicious right now:")
        if suspicious_now:
            for f in suspicious_now[:10]:
                lines.append(f"  - [{f.get('severity')}] {f.get('title')} ({f.get('id')})")
        else:
            lines.append("  - No suspicious findings.")

        self.summary.configure(state="normal")
        self.summary.delete("1.0", END)
        self.summary.insert(END, "\n".join(lines))
        self.summary.configure(state="disabled")

    def _on_select(self, _event=None) -> None:
        if not self._findings_cache:
            return
        selected = self.tree.selection()
        if not selected:
            return
        idx = int(selected[0])
        try:
            finding = self._findings_cache[idx]
        except Exception:
            return
        self.details.configure(state="normal")
        self.details.delete("1.0", END)
        self.details.insert(END, json.dumps(finding, ensure_ascii=False, indent=2))
        self.details.configure(state="disabled")

    def _show_raw_ports_output(self, text: str) -> None:
        self.details.configure(state="normal")
        self.details.delete("1.0", END)
        self.details.insert(END, text or "No output.")
        self.details.configure(state="disabled")

    def _load_ports_json_output(self, text: str) -> None:
        payload = None
        try:
            payload = json.loads(text)
        except Exception:
            # If mixed output appears, fallback to raw log panel.
            self._show_raw_ports_output(text)
            return

        findings = payload.get("findings", [])
        self._findings_cache = findings
        for item in self.tree.get_children():
            self.tree.delete(item)

        for idx, f in enumerate(findings):
            details = f.get("details", {}) if isinstance(f.get("details"), dict) else {}
            proc = details.get("process_exe") or details.get("process_name") or "-"
            port = details.get("local_port") or "-"
            self.tree.insert(
                "",
                END,
                iid=str(idx),
                values=(f.get("severity", "-"), f.get("id", "-"), f.get("title", "-"), str(proc), str(port)),
            )

        if not findings:
            self._render_summary([])
            self.details.configure(state="normal")
            self.details.delete("1.0", END)
            self.details.insert(END, "Ports check completed.\nNo suspicious mismatches found.\n")
            self.details.configure(state="disabled")
        else:
            self._render_summary(findings)

    def _append_log(self, line: str) -> None:
        level = self._extract_level(line)
        self._update_step_from_line(line)
        self.live_log.configure(state="normal")
        if level:
            self.live_log.insert(END, line + "\n", level)
        else:
            self.live_log.insert(END, line + "\n", "INFO")
        self.live_log.see(END)
        self.live_log.configure(state="disabled")

    def _set_busy(self, busy: bool) -> None:
        state_busy = "disabled" if busy else "normal"
        self.btn_report.configure(state=state_busy)
        self.btn_ports.configure(state=state_busy)
        self.btn_refresh.configure(state=state_busy)
        self.btn_stop.configure(state="normal" if busy else "disabled")

    def _stop_current_task(self) -> None:
        if self._current_process and self._current_process.poll() is None:
            try:
                self._current_process.terminate()
                self._append_log("[SYS] Terminate signal sent to current task.")
            except Exception as e:
                self._append_log(f"[SYS] Failed to stop task: {e}")

    def _extract_level(self, line: str) -> str | None:
        m = re.search(r"\[([A-Z]+)\]", line)
        if not m:
            return None
        lvl = m.group(1)
        if lvl in {"START", "STEP", "HEARTBEAT", "STDOUT", "STDERR", "DONE", "ERROR", "WARN", "INFO"}:
            return lvl
        return None

    def _update_step_from_line(self, line: str) -> None:
        low = line.lower()
        if "running secscan report" in low:
            self.current_step.set("Scanning processes / host / ports")
        elif "running aggregate analyzer" in low:
            self.current_step.set("Aggregating findings")
        elif "virustotal" in low or "misp" in low or "ti feed" in low:
            self.current_step.set("Threat intel enrichment")
        elif "jsonl" in low or "отчёт сохран" in low or "report" in low and "saved" in low:
            self.current_step.set("Writing report artifacts")
