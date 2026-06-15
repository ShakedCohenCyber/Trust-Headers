"""Shared data models for parsing and analysis."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any


@dataclass(frozen=True)
class AttachmentArtifact:
    filename: str
    sha256: str
    size: int


@dataclass
class ParsedEmail:
    metadata: dict[str, str] = field(default_factory=dict)
    sender_headers: dict[str, list[str]] = field(default_factory=dict)
    routing_headers: dict[str, list[str]] = field(default_factory=dict)
    authentication_headers: dict[str, list[str]] = field(default_factory=dict)
    originating_ips: list[str] = field(default_factory=list)
    domains: list[str] = field(default_factory=list)
    attachments: list[AttachmentArtifact] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class Finding:
    rule: str
    status: str
    summary: str
    evidence: str = ""


@dataclass
class AnalysisResult:
    parsed: ParsedEmail
    findings: list[Finding]

    @property
    def anomaly_count(self) -> int:
        return sum(finding.status == "ANOMALY" for finding in self.findings)

    @property
    def verdict(self) -> str:
        return "SUSPICIOUS" if self.anomaly_count else "NO LOCAL ANOMALIES"

    def to_dict(self) -> dict[str, Any]:
        return {
            "parsed": self.parsed.to_dict(),
            "findings": [asdict(finding) for finding in self.findings],
            "anomaly_count": self.anomaly_count,
            "verdict": self.verdict,
        }
