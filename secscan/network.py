from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass

import psutil

from secscan.platform import is_linux, is_macos, is_windows
from secscan.util import run_cmd


@dataclass(frozen=True)
class Neighbor:
    ip: str
    mac: str | None
    interface: str | None
    state: str | None
    source: str


_RE_IPV4 = re.compile(r"(?P<ip>\d{1,3}(?:\.\d{1,3}){3})")
_RE_MAC = re.compile(r"(?P<mac>(?:[0-9a-fA-F]{2}[:-]){5}[0-9a-fA-F]{2})")


def local_subnets() -> list[str]:
    subnets: set[str] = set()
    for ifname, addrs in psutil.net_if_addrs().items():
        for a in addrs:
            if a.family.name not in ("AF_INET", "AddressFamily.AF_INET"):
                continue
            if not a.address or not a.netmask:
                continue
            try:
                net = ipaddress.IPv4Network(f"{a.address}/{a.netmask}", strict=False)
            except Exception:
                continue
            if net.is_loopback:
                continue
            subnets.add(str(net))
    return sorted(subnets)


def neighbors_passive() -> list[Neighbor]:
    """
    Пассивное обнаружение устройств: читает neighbor/ARP cache ОС.
    Не делает активного сканирования/эксплуатации.
    """
    if is_windows():
        code, out = run_cmd(["arp", "-a"], timeout_s=5)
        if code != 0:
            return []
        res: list[Neighbor] = []
        for line in out.splitlines():
            ipm = _RE_IPV4.search(line)
            macm = _RE_MAC.search(line)
            if not ipm:
                continue
            ip = ipm.group("ip")
            mac = macm.group("mac") if macm else None
            res.append(Neighbor(ip=ip, mac=mac, interface=None, state=None, source="arp-a"))
        return _dedupe(res)

    if is_linux():
        code, out = run_cmd(["ip", "neigh"], timeout_s=5)
        if code != 0:
            # fallback
            code2, out2 = run_cmd(["arp", "-n"], timeout_s=5)
            out = out2 if code2 == 0 else ""
        res = _parse_ip_neigh(out, source="ip-neigh")
        return _dedupe(res)

    if is_macos():
        code, out = run_cmd(["arp", "-a"], timeout_s=5)
        if code != 0:
            return []
        res: list[Neighbor] = []
        for line in out.splitlines():
            ipm = _RE_IPV4.search(line)
            macm = _RE_MAC.search(line)
            if not ipm:
                continue
            res.append(Neighbor(ip=ipm.group("ip"), mac=(macm.group("mac") if macm else None), interface=None, state=None, source="arp-a"))
        return _dedupe(res)

    return []


def _parse_ip_neigh(out: str, source: str) -> list[Neighbor]:
    res: list[Neighbor] = []
    for line in out.splitlines():
        # Example: "192.168.1.1 dev eth0 lladdr aa:bb:cc:dd:ee:ff REACHABLE"
        ipm = _RE_IPV4.search(line)
        if not ipm:
            continue
        ip = ipm.group("ip")
        macm = _RE_MAC.search(line)
        mac = macm.group("mac") if macm else None

        iface = None
        mdev = re.search(r"\bdev\s+(?P<dev>\S+)", line)
        if mdev:
            iface = mdev.group("dev")

        state = None
        mtail = re.search(r"\b(FAILED|INCOMPLETE|STALE|DELAY|PROBE|REACHABLE|PERMANENT|NOARP)\b", line)
        if mtail:
            state = mtail.group(1)

        res.append(Neighbor(ip=ip, mac=mac, interface=iface, state=state, source=source))
    return res


def _dedupe(items: list[Neighbor]) -> list[Neighbor]:
    seen: set[tuple[str, str | None]] = set()
    out: list[Neighbor] = []
    for n in items:
        key = (n.ip, n.mac)
        if key in seen:
            continue
        seen.add(key)
        out.append(n)
    return out

