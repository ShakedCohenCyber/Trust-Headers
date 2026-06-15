from __future__ import annotations

from trust_headers.analysis import analyze_email
from trust_headers.parser import parse_email


def findings_by_rule(raw: str):
    result = analyze_email(parse_email(raw))
    return {finding.rule: finding for finding in result.findings}


def test_passing_authentication_and_alignment() -> None:
    raw = """From: Acme Alerts <acme.alerts@acme.example>
Return-Path: <bounce@mailer.acme.example>
Authentication-Results: mx.example; spf=pass smtp.mailfrom=bounce@mailer.acme.example; dkim=pass header.d=acme.example; dmarc=pass header.from=acme.example

"""
    findings = findings_by_rule(raw)

    assert findings["Name mismatch"].status == "PASS"
    assert findings["Domain mismatch"].status == "PASS"
    assert findings["SPF"].status == "PASS"
    assert findings["DMARC alignment"].status == "PASS"


def test_flags_identity_domain_and_auth_failures() -> None:
    raw = """From: Microsoft Security <invoice@attacker.example>
Return-Path: <bounce@other.example>
Authentication-Results: mx.example; spf=fail smtp.mailfrom=bounce@other.example; dmarc=fail header.from=attacker.example

"""
    findings = findings_by_rule(raw)

    assert findings["Name mismatch"].status == "ANOMALY"
    assert findings["Domain mismatch"].status == "ANOMALY"
    assert findings["SPF"].status == "ANOMALY"
    assert findings["DMARC alignment"].status == "ANOMALY"


def test_infers_dkim_alignment_without_explicit_dmarc_result() -> None:
    raw = """From: Alerts <alerts@acme.example>
Authentication-Results: mx.example; dkim=pass header.d=mail.acme.example

"""
    findings = findings_by_rule(raw)

    assert findings["DMARC alignment"].status == "PASS"
