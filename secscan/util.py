from __future__ import annotations

import json
import subprocess
from typing import Iterable


def _decode_best_effort(data: bytes | None) -> str:
    if not data:
        return ""
    # Order matters: prefer UTF-8, then common Windows console encodings.
    for enc in ("utf-8", "cp866", "cp1251", "cp1252"):
        try:
            return data.decode(enc)
        except Exception:
            continue
    return data.decode("utf-8", errors="replace")


def run_cmd(argv: list[str], timeout_s: int = 5) -> tuple[int, str]:
    try:
        p = subprocess.run(
            argv,
            capture_output=True,
            text=False,
            timeout=timeout_s,
            check=False,
        )
        out_s = _decode_best_effort(p.stdout)
        err_s = _decode_best_effort(p.stderr)
        out = out_s + (("\n" + err_s) if err_s else "")
        return p.returncode, out.strip()
    except Exception as e:
        return 1, f"{type(e).__name__}: {e}"


def first_nonempty(lines: Iterable[str]) -> str | None:
    for s in lines:
        s = (s or "").strip()
        if s:
            return s
    return None


def dumps_pretty(obj: object) -> str:
    return json.dumps(obj, ensure_ascii=False, indent=2, sort_keys=True)

