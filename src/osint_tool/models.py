"""Modelos de datos compartidos por módulos y reportes."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import IntEnum
from typing import Any


class Severity(IntEnum):
    INFO = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3

    @property
    def label(self) -> str:
        return self.name.lower()


@dataclass(frozen=True)
class Finding:
    """Un hallazgo: qué se vio, qué tan grave es y cómo corregirlo."""

    title: str
    severity: Severity
    description: str
    remediation: str
    evidence: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "title": self.title,
            "severity": self.severity.label,
            "description": self.description,
            "evidence": self.evidence,
            "remediation": self.remediation,
        }


@dataclass
class ModuleResult:
    module: str
    target: str
    data: dict[str, Any] = field(default_factory=dict)
    findings: list[Finding] = field(default_factory=list)
    error: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "module": self.module,
            "target": self.target,
            "error": self.error,
            "data": self.data,
            "findings": [f.to_dict() for f in self.findings],
        }


@dataclass
class Report:
    target: str
    results: list[ModuleResult]
    generated_at: datetime = field(
        default_factory=lambda: datetime.now(timezone.utc)
    )

    def all_findings(self) -> list[tuple[str, Finding]]:
        """Hallazgos de todos los módulos, del más grave al menos grave."""
        pairs = [(r.module, f) for r in self.results for f in r.findings]
        return sorted(pairs, key=lambda p: p[1].severity, reverse=True)

    def to_dict(self) -> dict[str, Any]:
        counts = {s.label: 0 for s in Severity}
        for _, finding in self.all_findings():
            counts[finding.severity.label] += 1
        return {
            "target": self.target,
            "generated_at": self.generated_at.isoformat(),
            "summary": counts,
            "results": [r.to_dict() for r in self.results],
        }
