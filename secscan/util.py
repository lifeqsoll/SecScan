from __future__ import annotations

import json
import subprocess
from typing import Iterable


def run_cmd(argv: list[str], timeout_s: int = 5) -> tuple[int, str]:
    try:
        p = subprocess.run(
            argv,
            capture_output=True,
            text=True,
            timeout=timeout_s,
            check=False,
        )
        out = (p.stdout or "") + (("\n" + p.stderr) if p.stderr else "")
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

