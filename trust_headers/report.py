"""Ticket-ready plain-text report generation."""

from __future__ import annotations

import re
from datetime import datetime, timezone
from email.utils import getaddresses, parseaddr

from .models import AnalysisResult


def build_soc_notes(result: AnalysisResult, intel: list[dict[str, str]]) -> str:
    """Build paste-ready SOC investigation notes from the analysis result."""
    sentences = [_investigation_intro(result), _opening_sentence(result)]

    finding_sentences = [
        sentence
        for finding in result.findings
        if finding.status == "ANOMALY"
        for sentence in [_finding_sentence(result, finding.rule, finding.summary, finding.evidence)]
        if sentence
    ]
    sentences.extend(finding_sentences)

    intel_sentence = _intel_sentence(intel)
    if intel_sentence:
        sentences.append(intel_sentence)

    return "\n".join(
        [
            "Details:",
            *_detail_lines(result),
            "",
            "Investigation:",
            "\n\n".join(sentences),
        ]
    )


def build_report(result: AnalysisResult, intel: list[dict[str, str]]) -> str:
    parsed = result.parsed
    lines = [
        "TRUST-HEADERS ANALYSIS",
        f"Generated: {datetime.now(timezone.utc).isoformat(timespec='seconds')}",
        f"Verdict: {result.verdict}",
        f"Anomalies: {result.anomaly_count}",
        "",
        "[SOC INVESTIGATION NOTES]",
        build_soc_notes(result, intel),
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
    lines.extend(_url_detail_lines(result))
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


def _finding_sentence(result: AnalysisResult, rule: str, summary: str, evidence: str) -> str:
    parsed = result.parsed
    if rule == "Reply-To mismatch":
        from_address = _email_address(_first(parsed.sender_headers, "From"))
        reply_to_address = _email_address(_first(parsed.sender_headers, "Reply-To"))
        if from_address and reply_to_address:
            return (
                f"The 'Reply-To' email address {reply_to_address} is inconsistent with "
                f"the 'From' email address {from_address}."
            )

    if rule == "Name mismatch":
        display_name, from_address = parseaddr(_first(parsed.sender_headers, "From"))
        local_part = from_address.split("@", 1)[0] if "@" in from_address else ""
        display_name = _inline(display_name)
        if local_part and display_name:
            return (
                f"The 'From' email address local-part {local_part} is inconsistent with "
                f"the display-name {display_name} provided in the email. "
                "The local-part of an email address is the part of an email address before the '@' symbol."
            )

    if rule == "Domain mismatch":
        from_address = _email_address(_first(parsed.sender_headers, "From"))
        return_path_address = _email_address(_first(parsed.sender_headers, "Return-Path"))
        if from_address and return_path_address:
            return (
                f"The 'Return-Path' email address {return_path_address} is not aligned with "
                f"the 'From' email address {from_address}, indicating the envelope sender differs "
                "from the visible sender."
            )

    if rule == "SPF":
        spf_result = _auth_result(parsed.authentication_headers, "spf")
        if spf_result:
            return (
                f"The email did not pass SPF authentication ({spf_result}), based on the "
                "Authentication-Results header."
            )

    if rule == "DMARC alignment":
        dmarc_result = _auth_result(parsed.authentication_headers, "dmarc")
        if dmarc_result:
            return (
                f"The email did not pass DMARC authentication ({dmarc_result}), indicating DMARC "
                "did not validate alignment with the visible 'From' domain."
            )
        return (
            "Passing authentication mechanisms are not aligned with the visible 'From' domain, "
            "so DMARC alignment is suspicious."
        )

    return _fallback_sentence(rule, summary, evidence)


def _detail_lines(result: AnalysisResult) -> list[str]:
    details = _soc_details(result)
    fields = [
        ("Impacted User Email", details["impacted_user_email"]),
        ("Impacted User Display Name", details["impacted_user_display_name"]),
        ("Email Subject", details["email_subject"]),
        ("Sender Name", details["sender_name"]),
        ("Sender Email", details["sender_email"]),
        ("Return Path", details["return_path"]),
        ("Sender IP", details["sender_ip"]),
    ]
    return [
        *(f"{label}: {value}" for label, value in fields if value),
        *_url_detail_lines(result),
    ]


def _soc_details(result: AnalysisResult) -> dict[str, str]:
    parsed = result.parsed
    recipient_name, recipient_email = _first_mailbox(parsed.metadata.get("To", ""))
    sender_name, sender_email = _mailbox(_first(parsed.sender_headers, "From"))
    return_path = _email_address(_first(parsed.sender_headers, "Return-Path"))
    return {
        "impacted_user_email": recipient_email,
        "impacted_user_display_name": recipient_name,
        "email_subject": _inline(parsed.metadata.get("Subject", "")),
        "sender_name": sender_name,
        "sender_email": sender_email,
        "return_path": return_path,
        "sender_ip": ", ".join(parsed.originating_ips),
    }


def _url_detail_lines(result: AnalysisResult) -> list[str]:
    urls = _urls(result.parsed)
    if not urls:
        return ["URLs: None"]
        
    if len(urls) == 1:
        return ["URLs:", urls[0]]
        
    lines = ["URLs:"]
    for i, url in enumerate(urls, 1):
        lines.append(f"{i}. {url}")
        if i < len(urls):
            lines.append("")
            
    return lines


def _investigation_intro(result: AnalysisResult) -> str:
    parsed = result.parsed
    details = _soc_details(result)
    sender = _sender_reference(details["sender_name"], details["sender_email"])
    recipient = details["impacted_user_email"]
    route = _route_phrase(sender, recipient)
    link_count = len(_urls(parsed))
    attachment_count = len(parsed.attachments)
    return (
        f"An email was sent{route}, containing "
        f"{_plural(link_count, 'link', 'links')} and {_plural(attachment_count, 'attachment', 'attachments')}. "
        f"{_authentication_sentence(result)}"
    )


def _authentication_sentence(result: AnalysisResult) -> str:
    failed_protocols = []
    for finding in result.findings:
        if finding.status != "ANOMALY":
            continue
        if finding.rule == "SPF":
            failed_protocols.append("SPF")
        elif finding.rule == "DMARC alignment":
            failed_protocols.append("DMARC")
    if failed_protocols:
        return f"The email failed {_join_words(failed_protocols)} authentication."
    return "The retained headers do not show a failed authentication protocol."


def _opening_sentence(result: AnalysisResult) -> str:
    subject = _inline(result.parsed.metadata.get("Subject", ""))
    anomaly_count = result.anomaly_count
    anomalies = _plural(anomaly_count, "local header anomaly", "local header anomalies")
    verb = "was" if anomaly_count == 1 else "were"
    if subject and anomaly_count:
        return (
            f"The analyzed email with subject '{subject}' is assessed as {result.verdict} "
            f"because {anomalies} {verb} identified."
        )
    if anomaly_count:
        return f"The analyzed email is assessed as {result.verdict} because {anomalies} {verb} identified."
    return f"The analyzed email is assessed as {result.verdict}; no local header anomalies were identified."


def _intel_sentence(intel: list[dict[str, str]]) -> str:
    hits = [item for item in intel if item.get("status", "").lower() == "hit"]
    if hits:
        hit_text = "; ".join(
            f"{_inline(item.get('source', 'Unknown source'))} reported {item.get('indicator', 'unknown indicator')} "
            f"as a hit ({_inline(item.get('summary', 'no summary'))})"
            for item in hits[:5]
        )
        more = f" Additional hits were also returned ({len(hits) - 5} more)." if len(hits) > 5 else ""
        return f"Threat-intelligence enrichment returned indicator hits: {hit_text}.{more}"

    clean_or_configured = [
        item
        for item in intel
        if item.get("status", "").lower() in {"clean", "not found"}
    ]
    if clean_or_configured:
        return "Configured threat-intelligence enrichment did not return indicator hits for the retained public indicators."
    return ""


def _fallback_sentence(rule: str, summary: str, evidence: str) -> str:
    sentence = f"The {rule} check was flagged as anomalous: {_inline(summary)}"
    if evidence:
        sentence += f" Evidence: {_inline(evidence)}"
    return sentence.rstrip(".") + "."


def _auth_result(authentication_headers: dict[str, list[str]], name: str) -> str:
    auth_text = "\n".join(
        value
        for values in authentication_headers.values()
        for value in values
    ).lower()
    match = re.search(rf"\b{re.escape(name)}\s*=\s*([a-z]+)", auth_text)
    return match.group(1) if match else ""


def _email_address(value: str) -> str:
    address = parseaddr(value)[1] or value.strip("<> ")
    return _inline(address.lower())


def _mailbox(value: str) -> tuple[str, str]:
    display_name, address = parseaddr(value)
    return _inline(display_name), _email_address(address)


def _first_mailbox(value: str) -> tuple[str, str]:
    for display_name, address in getaddresses([value]):
        if address:
            return _inline(display_name), _email_address(address)
    return "", ""


def _first(headers: dict[str, list[str]], name: str) -> str:
    values = headers.get(name, [])
    return values[0] if values else ""


def _inline(value: str) -> str:
    return re.sub(r"\s+", " ", str(value)).strip()


def _urls(parsed: object) -> list[str]:
    return list(getattr(parsed, "urls", []))


def _plural(count: int, singular: str, plural: str) -> str:
    return f"{count} {singular if count == 1 else plural}"


def _sender_reference(sender_name: str, sender_email: str) -> str:
    if sender_name and sender_email:
        return f"{sender_name} <{sender_email}>"
    if sender_email:
        return sender_email
    if sender_name:
        return sender_name
    return ""


def _route_phrase(sender: str, recipient: str) -> str:
    if sender and recipient:
        return f" from {sender} to {recipient}"
    if sender:
        return f" from {sender}"
    if recipient:
        return f" to {recipient}"
    return ""


def _join_words(values: list[str]) -> str:
    if len(values) <= 2:
        return " and ".join(values)
    return ", ".join(values[:-1]) + f", and {values[-1]}"
