from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any


class Severity(str, Enum):
    info = "info"
    low = "low"
    medium = "medium"
    high = "high"
    critical = "critical"


@dataclass(frozen=True)
class Finding:
    id: str
    title: str
    severity: Severity
    details: dict[str, Any] = field(default_factory=dict)
    recommendation: str | None = None


@dataclass(frozen=True)
class Report:
    created_at: str
    host: dict[str, Any]
    findings: list[Finding]

    def to_jsonable(self) -> dict[str, Any]:
        return {
            "created_at": self.created_at,
            "host": self.host,
            "findings": [
                {
                    "id": f.id,
                    "title": f.title,
                    "severity": f.severity.value,
                    "details": f.details,
                    "recommendation": f.recommendation,
                }
                for f in self.findings
            ],
        }


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()

