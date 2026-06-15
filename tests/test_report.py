from __future__ import annotations

from trust_headers.analysis import analyze_email
from trust_headers.parser import parse_email
from trust_headers.report import build_report


def test_report_contains_standard_sections() -> None:
    result = analyze_email(parse_email("From: user@example.com\n\n"))
    report = build_report(result, [])

    assert "[METADATA]" in report
    assert "[ANOMALIES / LOCAL CHECKS]" in report
    assert "[INDICATORS]" in report
    assert "[THREAT INTEL]" in report
