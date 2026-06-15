"""Ticket-ready plain-text report generation."""

from __future__ import annotations

from datetime import datetime, timezone

from .models import AnalysisResult


def build_report(result: AnalysisResult, intel: list[dict[str, str]]) -> str:
    parsed = result.parsed
    lines = [
        "TRUST-HEADERS ANALYSIS",
        f"Generated: {datetime.now(timezone.utc).isoformat(timespec='seconds')}",
        f"Verdict: {result.verdict}",
        f"Anomalies: {result.anomaly_count}",
        "",
        "[METADATA]",
    ]
    if parsed.metadata:
        lines.extend(f"{key}: {value}" for key, value in parsed.metadata.items())
    else:
        lines.append("No metadata retained.")

    lines.extend(("", "[ANOMALIES / LOCAL CHECKS]"))
    lines.extend(
        f"{finding.status} | {finding.rule} | {finding.summary}"
        + (f" | {finding.evidence}" if finding.evidence else "")
        for finding in result.findings
    )

    lines.extend(("", "[INDICATORS]"))
    lines.append(f"IPs: {', '.join(parsed.originating_ips) or 'None'}")
    lines.append(f"Domains: {', '.join(parsed.domains) or 'None'}")
    lines.append(f"Attachments: {len(parsed.attachments)}")
    lines.extend(
        f"Attachment: {item.filename} | sha256={item.sha256} | bytes={item.size}"
        for item in parsed.attachments
    )

    lines.extend(("", "[THREAT INTEL]"))
    lines.extend(
        f"{item['source']} | {item['indicator']} | {item['status']} | {item['summary']}"
        for item in intel
    )
    if not intel:
        lines.append("No enrichment results.")
    return "\n".join(lines)
