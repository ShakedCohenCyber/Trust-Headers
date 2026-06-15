"""Deterministic phishing checks over retained email headers."""

from __future__ import annotations

import re
from email.utils import parseaddr

from .models import AnalysisResult, Finding, ParsedEmail


def analyze_email(parsed: ParsedEmail) -> AnalysisResult:
    findings = [
        _name_mismatch(parsed),
        _domain_mismatch(parsed),
        _spf_check(parsed),
        _dmarc_alignment(parsed),
    ]
    return AnalysisResult(parsed=parsed, findings=findings)


def _first(parsed: ParsedEmail, header: str) -> str:
    values = parsed.sender_headers.get(header, [])
    return values[0] if values else ""


def _auth_text(parsed: ParsedEmail) -> str:
    return "\n".join(
        value
        for values in parsed.authentication_headers.values()
        for value in values
    ).lower()


def _name_mismatch(parsed: ParsedEmail) -> Finding:
    from_header = _first(parsed, "From")
    display_name, address = parseaddr(from_header)
    if not display_name or "@" not in address:
        return Finding("Name mismatch", "UNKNOWN", "Display name or sender address unavailable.", from_header)

    local_part = address.split("@", 1)[0]
    display_norm = _normalize_identity(display_name)
    local_norm = _normalize_identity(local_part)
    matches = (
        display_norm == local_norm
        or display_norm in local_norm
        or local_norm in display_norm
        or bool(set(_tokens(display_name)) & set(_tokens(local_part)))
    )
    if matches:
        return Finding("Name mismatch", "PASS", "Display name is consistent with the sender local-part.", from_header)
    return Finding(
        "Name mismatch",
        "ANOMALY",
        "Display name does not resemble the sender local-part.",
        f"display={display_name!r}; local-part={local_part!r}",
    )


def _domain_mismatch(parsed: ParsedEmail) -> Finding:
    from_domain = _address_domain(_first(parsed, "From"))
    return_domain = _address_domain(_first(parsed, "Return-Path"))
    if not from_domain or not return_domain:
        return Finding("Domain mismatch", "UNKNOWN", "From or Return-Path domain unavailable.")
    if _aligned(from_domain, return_domain):
        return Finding(
            "Domain mismatch",
            "PASS",
            "From and Return-Path domains are aligned.",
            f"from={from_domain}; return-path={return_domain}",
        )
    return Finding(
        "Domain mismatch",
        "ANOMALY",
        "From and Return-Path domains are not aligned.",
        f"from={from_domain}; return-path={return_domain}",
    )


def _spf_check(parsed: ParsedEmail) -> Finding:
    auth = _auth_text(parsed)
    if re.search(r"\bspf\s*=\s*pass\b", auth) or re.search(r"(?m)^\s*pass\b", auth):
        return Finding("SPF", "PASS", "Authentication headers contain an explicit SPF pass.")
    if re.search(r"\bspf\s*=\s*(?:fail|softfail|neutral|temperror|permerror)\b", auth):
        result = re.search(r"\bspf\s*=\s*([a-z]+)", auth)
        return Finding("SPF", "ANOMALY", f"SPF did not pass ({result.group(1) if result else 'failure'}).")
    return Finding("SPF", "UNKNOWN", "No explicit SPF result was found.")


def _dmarc_alignment(parsed: ParsedEmail) -> Finding:
    auth = _auth_text(parsed)
    explicit = re.search(r"\bdmarc\s*=\s*([a-z]+)", auth)
    if explicit:
        result = explicit.group(1)
        status = "PASS" if result == "pass" else "ANOMALY"
        return Finding("DMARC alignment", status, f"Authentication headers report DMARC {result}.")

    from_domain = _address_domain(_first(parsed, "From"))
    mailfrom = _auth_property(auth, "smtp.mailfrom")
    dkim_domain = _auth_property(auth, "header.d")
    spf_pass = bool(re.search(r"\bspf\s*=\s*pass\b", auth))
    dkim_pass = bool(re.search(r"\bdkim\s*=\s*pass\b", auth))
    spf_aligned = spf_pass and _aligned(from_domain, _address_domain(mailfrom))
    dkim_aligned = dkim_pass and _aligned(from_domain, dkim_domain)
    if from_domain and (spf_aligned or dkim_aligned):
        mechanisms = ", ".join(name for name, value in (("SPF", spf_aligned), ("DKIM", dkim_aligned)) if value)
        return Finding("DMARC alignment", "PASS", f"DMARC alignment inferred through {mechanisms}.")
    if from_domain and (spf_pass or dkim_pass):
        return Finding("DMARC alignment", "ANOMALY", "Passing authentication mechanisms are not aligned with From.")
    return Finding("DMARC alignment", "UNKNOWN", "DMARC result or sufficient alignment evidence was not found.")


def _address_domain(value: str) -> str:
    address = parseaddr(value)[1] or value.strip("<> ")
    return address.rsplit("@", 1)[1].lower().rstrip(".") if "@" in address else ""


def _auth_property(auth: str, name: str) -> str:
    match = re.search(rf"\b{re.escape(name)}\s*=\s*([^\s;]+)", auth)
    return match.group(1).strip("<>") if match else ""


def _aligned(first: str, second: str) -> bool:
    if not first or not second:
        return False
    first, second = first.lower().rstrip("."), second.lower().rstrip(".")
    return first == second or first.endswith("." + second) or second.endswith("." + first)


def _normalize_identity(value: str) -> str:
    return re.sub(r"[^a-z0-9]", "", value.lower())


def _tokens(value: str) -> list[str]:
    return [token for token in re.split(r"[^a-z0-9]+", value.lower()) if len(token) >= 3]
