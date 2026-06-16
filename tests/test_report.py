from __future__ import annotations

from trust_headers.analysis import analyze_email
from trust_headers.parser import parse_email
from trust_headers.report import build_report, build_soc_notes


def test_report_contains_standard_sections() -> None:
    result = analyze_email(parse_email("From: user@example.com\n\n"))
    report = build_report(result, [])

    assert "[METADATA]" in report
    assert "[SOC INVESTIGATION NOTES]" in report
    assert "[ANOMALIES / LOCAL CHECKS]" in report
    assert "[INDICATORS]" in report
    assert "[THREAT INTEL]" in report


def test_soc_notes_contains_paste_ready_investigation_sentences() -> None:
    raw = """From: Kupat Ha'ir <michael@jewishaffiliatenetwork.net>
To: Analyst Target <target@example.org>
Reply-To: <info@merkavamarketing.com>
Return-Path: <bounce@merkavamarketing.com>
Authentication-Results: mx.example; spf=fail smtp.mailfrom=bounce@merkavamarketing.com; dmarc=fail header.from=jewishaffiliatenetwork.net
Subject: Payment review

https://merkavamarketing.com/pay
https://merkavamarketing.com/confirm
"""
    result = analyze_email(parse_email(raw))
    notes = build_soc_notes(result, [])

    assert notes.startswith("Details:\n")
    assert "Impacted User Email: target@example.org" in notes
    assert "Impacted User Display Name: Analyst Target" in notes
    assert "Email Subject: Payment review" in notes
    assert "Sender Name: Kupat Ha'ir" in notes
    assert "Sender Email: michael@jewishaffiliatenetwork.net" in notes
    assert "Return Path: bounce@merkavamarketing.com" in notes
    assert "Sender IP:" not in notes
    assert "Not available" not in notes
    assert "URLs:\n1. https://merkavamarketing.com/pay\n\n2. https://merkavamarketing.com/confirm" in notes
    assert "\nInvestigation:\n" in notes
    assert (
        "An email was sent from Kupat Ha'ir <michael@jewishaffiliatenetwork.net> "
        "to target@example.org, containing 2 links and 0 attachments. "
        "The email failed SPF and DMARC authentication."
    ) in notes
    assert (
        "The email failed SPF and DMARC authentication.\n\n"
        "The analyzed email with subject 'Payment review' is assessed as SUSPICIOUS"
    ) in notes
    assert (
        "The 'Reply-To' email address info@merkavamarketing.com is inconsistent with "
        "the 'From' email address michael@jewishaffiliatenetwork.net."
    ) in notes
    assert (
        "The local-part of an email address is the part of an email address before the '@' symbol.\n\n"
        "The 'Reply-To' email address info@merkavamarketing.com is inconsistent"
    ) in notes
    assert (
        "The 'From' email address local-part michael is inconsistent with "
        "the display-name Kupat Ha'ir provided in the email."
    ) in notes
    assert (
        "The local-part of an email address is the part of an email address before the '@' symbol."
    ) in notes


def test_soc_notes_uses_singular_anomaly_grammar() -> None:
    raw = """From: Michael <michael@example.com>
Reply-To: <info@other.example>

"""
    result = analyze_email(parse_email(raw))
    notes = build_soc_notes(result, [])

    assert "1 local header anomaly was identified" in notes
