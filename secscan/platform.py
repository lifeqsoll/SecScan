from __future__ import annotations

import os
import platform as _platform


def os_family() -> str:
    # "Windows", "Linux", "Darwin"
    return _platform.system()


def is_windows() -> bool:
    return os_family() == "Windows"


def is_linux() -> bool:
    return os_family() == "Linux"


def is_macos() -> bool:
    return os_family() == "Darwin"


def platform_summary() -> dict[str, str]:
    return {
        "system": _platform.system(),
        "release": _platform.release(),
        "version": _platform.version(),
        "machine": _platform.machine(),
        "python": _platform.python_version(),
    }


def is_admin() -> bool:
    if is_windows():
        try:
            import ctypes

            return bool(ctypes.windll.shell32.IsUserAnAdmin())
        except Exception:
            return False
    else:
        return os.geteuid() == 0

