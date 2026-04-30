from __future__ import annotations

import ctypes
import ipaddress
import os
import re
import socket
import struct
from dataclasses import dataclass
from pathlib import Path

import psutil

from secscan.model import Finding, Severity
from secscan.platform import is_linux, is_windows


@dataclass(frozen=True)
class PortRecord:
    proto: str
    local_ip: str
    local_port: int
    pid: int | None
    state: str | None
    source: str
    inode: str | None = None


def scan_hidden_ports() -> tuple[list[Finding], list[PortRecord]]:
    high_ports, high_errors = _high_level_ports_psutil()
    low_ports = _low_level_ports()
    suspicious = _find_low_level_mismatches(low_ports, high_ports)

    findings: list[Finding] = []
    for rec in suspicious:
        proc_meta = _process_meta(rec.pid)
        findings.append(
            Finding(
                id="port.hidden_mismatch",
                title="Порт виден в низкоуровневом источнике, но отсутствует в high-level выдаче",
                severity=Severity.high,
                details={
                    "proto": rec.proto,
                    "local_ip": rec.local_ip,
                    "local_port": rec.local_port,
                    "pid": rec.pid,
                    "state": rec.state,
                    "source": rec.source,
                    "inode": rec.inode,
                    "process_name": proc_meta.get("name"),
                    "process_exe": proc_meta.get("exe"),
                    "process_cmdline": proc_meta.get("cmdline"),
                },
                recommendation="Проверьте процесс и сетевую активность через EDR/Sysmon/pcap. Такое расхождение может указывать на tampering или rootkit-техники скрытия.",
            )
        )

    if high_errors:
        findings.append(
            Finding(
                id="port.high_level_access_limited",
                title="High-level источник портов может быть неполным из-за ограничений доступа",
                severity=Severity.info,
                details={"errors": high_errors},
                recommendation="Запустите скан от администратора/root: ограничения видимости могут создавать ложные расхождения.",
            )
        )

    return findings, suspicious


def kill_suspicious_ports(suspicious: list[PortRecord], ask_confirmation: bool = True) -> list[str]:
    logs: list[str] = []
    seen_pids: set[int] = set()
    for rec in suspicious:
        if rec.pid is None or rec.pid <= 0:
            logs.append(f"skip {rec.proto}:{rec.local_port}: pid unavailable")
            continue
        if rec.pid in seen_pids:
            continue
        seen_pids.add(rec.pid)
        proc_label = f"pid={rec.pid} port={rec.proto}:{rec.local_port}"

        if ask_confirmation:
            answer = input(f"Kill suspicious process {proc_label}? [y/N]: ").strip().lower()
            if answer not in {"y", "yes"}:
                logs.append(f"skip {proc_label}: user declined")
                continue

        try:
            p = psutil.Process(rec.pid)
            p.terminate()
            try:
                p.wait(timeout=5)
                logs.append(f"killed {proc_label}")
            except psutil.TimeoutExpired:
                p.kill()
                logs.append(f"killed-force {proc_label}")
        except Exception as e:
            logs.append(f"failed {proc_label}: {type(e).__name__}: {e}")
    return logs


def _find_low_level_mismatches(low_ports: list[PortRecord], high_ports: list[PortRecord]) -> list[PortRecord]:
    # We compare by proto+local_port first (broad visibility check), then by pid when available.
    high_by_proto_port = {(p.proto, p.local_port) for p in high_ports}
    high_by_full = {(p.proto, p.local_port, p.pid) for p in high_ports}
    out: list[PortRecord] = []

    for rec in low_ports:
        if rec.local_port <= 0:
            continue
        if (rec.proto, rec.local_port) not in high_by_proto_port:
            out.append(rec)
            continue
        if rec.pid is not None and (rec.proto, rec.local_port, rec.pid) not in high_by_full:
            out.append(rec)

    # Dedupe by proto/port/pid/source.
    seen: set[tuple[str, int, int | None, str]] = set()
    deduped: list[PortRecord] = []
    for rec in out:
        key = (rec.proto, rec.local_port, rec.pid, rec.source)
        if key in seen:
            continue
        seen.add(key)
        deduped.append(rec)
    return deduped


def _high_level_ports_psutil() -> tuple[list[PortRecord], list[str]]:
    out: list[PortRecord] = []
    errors: list[str] = []
    try:
        conns = psutil.net_connections(kind="inet")
    except Exception as e:
        return [], [f"{type(e).__name__}: {e}"]

    for c in conns:
        if not c.laddr:
            continue
        try:
            port = int(c.laddr.port)
        except Exception:
            continue
        proto = "tcp" if c.type == socket.SOCK_STREAM else "udp"
        out.append(
            PortRecord(
                proto=proto,
                local_ip=str(c.laddr.ip),
                local_port=port,
                pid=c.pid,
                state=str(c.status) if c.status else None,
                source="high:psutil",
            )
        )
    return out, errors


def _low_level_ports() -> list[PortRecord]:
    if is_linux():
        return _low_level_ports_linux()
    if is_windows():
        return _low_level_ports_windows()
    return []


def _low_level_ports_linux() -> list[PortRecord]:
    records: list[PortRecord] = []
    records.extend(_parse_proc_net_file("/proc/net/tcp", "tcp"))
    records.extend(_parse_proc_net_file("/proc/net/tcp6", "tcp"))
    records.extend(_parse_proc_net_file("/proc/net/udp", "udp"))
    records.extend(_parse_proc_net_file("/proc/net/udp6", "udp"))
    inode_to_pid = _build_inode_pid_map()

    out: list[PortRecord] = []
    for r in records:
        pid = inode_to_pid.get(r.inode) if r.inode else None
        out.append(
            PortRecord(
                proto=r.proto,
                local_ip=r.local_ip,
                local_port=r.local_port,
                pid=pid,
                state=r.state,
                source=r.source,
                inode=r.inode,
            )
        )
    return out


def _parse_proc_net_file(path: str, proto: str) -> list[PortRecord]:
    rows: list[PortRecord] = []
    p = Path(path)
    if not p.exists():
        return rows
    try:
        lines = p.read_text(encoding="utf-8", errors="ignore").splitlines()
    except Exception:
        return rows

    for line in lines[1:]:
        parts = line.split()
        if len(parts) < 10:
            continue
        local = parts[1]
        st = parts[3]
        inode = parts[9]
        ip_hex, port_hex = local.split(":")
        ip = _decode_linux_ip(ip_hex)
        try:
            port = int(port_hex, 16)
        except Exception:
            continue
        state = _linux_tcp_state(st) if proto == "tcp" else None
        rows.append(
            PortRecord(
                proto=proto,
                local_ip=ip,
                local_port=port,
                pid=None,
                state=state,
                source=f"low:{path}",
                inode=inode,
            )
        )
    return rows


def _decode_linux_ip(raw: str) -> str:
    try:
        if len(raw) == 8:
            packed = struct.pack("<I", int(raw, 16))
            return socket.inet_ntoa(packed)
        if len(raw) == 32:
            b = bytes.fromhex(raw)
            return str(ipaddress.IPv6Address(b))
    except Exception:
        return "unknown"
    return "unknown"


def _linux_tcp_state(raw: str) -> str:
    states = {
        "01": "ESTABLISHED",
        "02": "SYN_SENT",
        "03": "SYN_RECV",
        "04": "FIN_WAIT1",
        "05": "FIN_WAIT2",
        "06": "TIME_WAIT",
        "07": "CLOSE",
        "08": "CLOSE_WAIT",
        "09": "LAST_ACK",
        "0A": "LISTEN",
        "0B": "CLOSING",
    }
    return states.get(raw.upper(), raw)


def _build_inode_pid_map() -> dict[str, int]:
    mapping: dict[str, int] = {}
    sock_re = re.compile(r"socket:\[(\d+)\]")
    for proc_dir in Path("/proc").iterdir():
        if not proc_dir.is_dir() or not proc_dir.name.isdigit():
            continue
        pid = int(proc_dir.name)
        fd_dir = proc_dir / "fd"
        if not fd_dir.exists():
            continue
        try:
            for fd in fd_dir.iterdir():
                try:
                    target = os.readlink(fd)
                except OSError:
                    continue
                m = sock_re.search(target)
                if m:
                    inode = m.group(1)
                    mapping.setdefault(inode, pid)
        except PermissionError:
            # Access denied is expected for some PIDs without root.
            continue
        except Exception:
            continue
    return mapping


def _low_level_ports_windows() -> list[PortRecord]:
    records: list[PortRecord] = []
    try:
        records.extend(_win_tcp_table_ipv4())
    except Exception:
        pass
    try:
        records.extend(_win_udp_table_ipv4())
    except Exception:
        pass
    try:
        records.extend(_win_tcp_table_ipv6())
    except Exception:
        pass
    try:
        records.extend(_win_udp_table_ipv6())
    except Exception:
        pass
    return records


def _win_tcp_table_ipv4() -> list[PortRecord]:
    AF_INET = 2
    TCP_TABLE_OWNER_PID_ALL = 5
    ERROR_INSUFFICIENT_BUFFER = 122

    class MIB_TCPROW_OWNER_PID(ctypes.Structure):
        _fields_ = [
            ("dwState", ctypes.c_ulong),
            ("dwLocalAddr", ctypes.c_ulong),
            ("dwLocalPort", ctypes.c_ulong),
            ("dwRemoteAddr", ctypes.c_ulong),
            ("dwRemotePort", ctypes.c_ulong),
            ("dwOwningPid", ctypes.c_ulong),
        ]

    size = ctypes.c_ulong(0)
    iphlp = ctypes.WinDLL("iphlpapi.dll")
    get_table = iphlp.GetExtendedTcpTable
    ret = get_table(None, ctypes.byref(size), False, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0)
    if ret != ERROR_INSUFFICIENT_BUFFER:
        return []

    buf = ctypes.create_string_buffer(size.value)
    ret = get_table(buf, ctypes.byref(size), False, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0)
    if ret != 0:
        return []

    count = ctypes.cast(buf, ctypes.POINTER(ctypes.c_ulong)).contents.value
    row_array_type = MIB_TCPROW_OWNER_PID * count
    row_ptr = ctypes.cast(ctypes.byref(buf, ctypes.sizeof(ctypes.c_ulong)), ctypes.POINTER(row_array_type))

    out: list[PortRecord] = []
    for row in row_ptr.contents:
        ip = socket.inet_ntoa(struct.pack("<L", row.dwLocalAddr))
        port = socket.ntohs(row.dwLocalPort & 0xFFFF)
        out.append(
            PortRecord(
                proto="tcp",
                local_ip=ip,
                local_port=port,
                pid=int(row.dwOwningPid),
                state=_win_tcp_state(int(row.dwState)),
                source="low:GetExtendedTcpTable",
            )
        )
    return out


def _win_udp_table_ipv4() -> list[PortRecord]:
    AF_INET = 2
    UDP_TABLE_OWNER_PID = 1
    ERROR_INSUFFICIENT_BUFFER = 122

    class MIB_UDPROW_OWNER_PID(ctypes.Structure):
        _fields_ = [
            ("dwLocalAddr", ctypes.c_ulong),
            ("dwLocalPort", ctypes.c_ulong),
            ("dwOwningPid", ctypes.c_ulong),
        ]

    size = ctypes.c_ulong(0)
    iphlp = ctypes.WinDLL("iphlpapi.dll")
    get_table = iphlp.GetExtendedUdpTable
    ret = get_table(None, ctypes.byref(size), False, AF_INET, UDP_TABLE_OWNER_PID, 0)
    if ret != ERROR_INSUFFICIENT_BUFFER:
        return []
    buf = ctypes.create_string_buffer(size.value)
    ret = get_table(buf, ctypes.byref(size), False, AF_INET, UDP_TABLE_OWNER_PID, 0)
    if ret != 0:
        return []

    count = ctypes.cast(buf, ctypes.POINTER(ctypes.c_ulong)).contents.value
    row_array_type = MIB_UDPROW_OWNER_PID * count
    row_ptr = ctypes.cast(ctypes.byref(buf, ctypes.sizeof(ctypes.c_ulong)), ctypes.POINTER(row_array_type))

    out: list[PortRecord] = []
    for row in row_ptr.contents:
        ip = socket.inet_ntoa(struct.pack("<L", row.dwLocalAddr))
        port = socket.ntohs(row.dwLocalPort & 0xFFFF)
        out.append(
            PortRecord(
                proto="udp",
                local_ip=ip,
                local_port=port,
                pid=int(row.dwOwningPid),
                state=None,
                source="low:GetExtendedUdpTable",
            )
        )
    return out


def _win_tcp_table_ipv6() -> list[PortRecord]:
    AF_INET6 = 23
    TCP_TABLE_OWNER_PID_ALL = 5
    ERROR_INSUFFICIENT_BUFFER = 122

    class MIB_TCP6ROW_OWNER_PID(ctypes.Structure):
        _fields_ = [
            ("ucLocalAddr", ctypes.c_ubyte * 16),
            ("dwLocalScopeId", ctypes.c_ulong),
            ("dwLocalPort", ctypes.c_ulong),
            ("ucRemoteAddr", ctypes.c_ubyte * 16),
            ("dwRemoteScopeId", ctypes.c_ulong),
            ("dwRemotePort", ctypes.c_ulong),
            ("dwState", ctypes.c_ulong),
            ("dwOwningPid", ctypes.c_ulong),
        ]

    size = ctypes.c_ulong(0)
    iphlp = ctypes.WinDLL("iphlpapi.dll")
    get_table = iphlp.GetExtendedTcpTable
    ret = get_table(None, ctypes.byref(size), False, AF_INET6, TCP_TABLE_OWNER_PID_ALL, 0)
    if ret != ERROR_INSUFFICIENT_BUFFER:
        return []

    buf = ctypes.create_string_buffer(size.value)
    ret = get_table(buf, ctypes.byref(size), False, AF_INET6, TCP_TABLE_OWNER_PID_ALL, 0)
    if ret != 0:
        return []

    count = ctypes.cast(buf, ctypes.POINTER(ctypes.c_ulong)).contents.value
    row_array_type = MIB_TCP6ROW_OWNER_PID * count
    row_ptr = ctypes.cast(ctypes.byref(buf, ctypes.sizeof(ctypes.c_ulong)), ctypes.POINTER(row_array_type))

    out: list[PortRecord] = []
    for row in row_ptr.contents:
        try:
            ip = str(ipaddress.IPv6Address(bytes(row.ucLocalAddr)))
        except Exception:
            ip = "::"
        port = socket.ntohs(row.dwLocalPort & 0xFFFF)
        out.append(
            PortRecord(
                proto="tcp",
                local_ip=ip,
                local_port=port,
                pid=int(row.dwOwningPid),
                state=_win_tcp_state(int(row.dwState)),
                source="low:GetExtendedTcpTable6",
            )
        )
    return out


def _win_udp_table_ipv6() -> list[PortRecord]:
    AF_INET6 = 23
    UDP_TABLE_OWNER_PID = 1
    ERROR_INSUFFICIENT_BUFFER = 122

    class MIB_UDP6ROW_OWNER_PID(ctypes.Structure):
        _fields_ = [
            ("ucLocalAddr", ctypes.c_ubyte * 16),
            ("dwLocalScopeId", ctypes.c_ulong),
            ("dwLocalPort", ctypes.c_ulong),
            ("dwOwningPid", ctypes.c_ulong),
        ]

    size = ctypes.c_ulong(0)
    iphlp = ctypes.WinDLL("iphlpapi.dll")
    get_table = iphlp.GetExtendedUdpTable
    ret = get_table(None, ctypes.byref(size), False, AF_INET6, UDP_TABLE_OWNER_PID, 0)
    if ret != ERROR_INSUFFICIENT_BUFFER:
        return []

    buf = ctypes.create_string_buffer(size.value)
    ret = get_table(buf, ctypes.byref(size), False, AF_INET6, UDP_TABLE_OWNER_PID, 0)
    if ret != 0:
        return []

    count = ctypes.cast(buf, ctypes.POINTER(ctypes.c_ulong)).contents.value
    row_array_type = MIB_UDP6ROW_OWNER_PID * count
    row_ptr = ctypes.cast(ctypes.byref(buf, ctypes.sizeof(ctypes.c_ulong)), ctypes.POINTER(row_array_type))

    out: list[PortRecord] = []
    for row in row_ptr.contents:
        try:
            ip = str(ipaddress.IPv6Address(bytes(row.ucLocalAddr)))
        except Exception:
            ip = "::"
        port = socket.ntohs(row.dwLocalPort & 0xFFFF)
        out.append(
            PortRecord(
                proto="udp",
                local_ip=ip,
                local_port=port,
                pid=int(row.dwOwningPid),
                state=None,
                source="low:GetExtendedUdpTable6",
            )
        )
    return out


def _win_tcp_state(raw: int) -> str:
    states = {
        1: "CLOSED",
        2: "LISTEN",
        3: "SYN_SENT",
        4: "SYN_RCVD",
        5: "ESTABLISHED",
        6: "FIN_WAIT1",
        7: "FIN_WAIT2",
        8: "CLOSE_WAIT",
        9: "CLOSING",
        10: "LAST_ACK",
        11: "TIME_WAIT",
        12: "DELETE_TCB",
    }
    return states.get(raw, str(raw))


def _process_meta(pid: int | None) -> dict:
    if pid is None or pid <= 0:
        return {"name": None, "exe": None, "cmdline": []}
    try:
        p = psutil.Process(pid)
        try:
            cmd = p.cmdline()
        except Exception:
            cmd = []
        return {"name": p.name(), "exe": p.exe(), "cmdline": cmd}
    except Exception:
        return {"name": None, "exe": None, "cmdline": []}
