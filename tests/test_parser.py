from __future__ import annotations

import hashlib

from trust_headers.parser import parse_email


def test_parses_relevant_headers_and_discards_body() -> None:
    raw = """From: Acme Alerts <alerts@acme.example>
Return-Path: <bounce@mailer.acme.example>
Reply-To: support@acme.example
Received: from relay.acme.example (relay.acme.example [8.8.8.8]) by mx.example.net
Authentication-Results: mx.example.net; spf=pass smtp.mailfrom=bounce@mailer.acme.example
Subject: Test message
X-Unrelated: should-not-be-retained

SECRET BODY CONTENT
"""
    parsed = parse_email(raw)

    assert parsed.sender_headers["From"] == ["Acme Alerts <alerts@acme.example>"]
    assert parsed.originating_ips == ["8.8.8.8"]
    assert "acme.example" in parsed.domains
    assert "SECRET BODY CONTENT" not in str(parsed.to_dict())
    assert "X-Unrelated" not in str(parsed.to_dict())


def test_hashes_eml_attachments() -> None:
    raw = b"""From: sender@example.com
To: recipient@example.net
MIME-Version: 1.0
Content-Type: multipart/mixed; boundary="BOUNDARY"

--BOUNDARY
Content-Type: text/plain

body
--BOUNDARY
Content-Type: application/octet-stream
Content-Disposition: attachment; filename="sample.bin"
Content-Transfer-Encoding: base64

aGVsbG8=
--BOUNDARY--
"""
    parsed = parse_email(raw, "message.eml")

    assert len(parsed.attachments) == 1
    assert parsed.attachments[0].filename == "sample.bin"
    assert parsed.attachments[0].size == 5
    assert parsed.attachments[0].sha256 == hashlib.sha256(b"hello").hexdigest()
