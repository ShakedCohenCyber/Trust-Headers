"""Parse email files while retaining only security-relevant header artifacts."""

from __future__ import annotations

import hashlib
import io
import ipaddress
import re
from email import policy
from email.message import Message
from email.parser import BytesParser, Parser
from email.utils import parseaddr
from pathlib import Path
from typing import Iterable

from .models import AttachmentArtifact, ParsedEmail

SENDER_HEADERS = ("from", "reply-to", "return-path", "sender")
ROUTING_HEADERS = (
    "received",
    "delivered-to",
    "x-originating-ip",
    "x-forwarded-for",
    "x-envelope-from",
    "x-original-to",
)
AUTH_HEADERS = (
    "authentication-results",
    "arc-authentication-results",
    "received-spf",
    "dmarc-filter",
    "dkim-signature",
)
METADATA_HEADERS = ("subject", "date", "message-id", "to")

IP_CANDIDATE_RE = re.compile(
    r"(?<![\w:])(?:\d{1,3}\.){3}\d{1,3}(?![\w:])|"
    r"(?<![\w:])(?:[0-9a-fA-F]{0,4}:){2,7}[0-9a-fA-F]{0,4}(?![\w:])"
)
DOMAIN_RE = re.compile(r"(?i)(?<![@\w.-])(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}")
URL_RE = re.compile(r"(?i)\bhttps?://[^\s<>'\"]+")


class ParseError(ValueError):
    """Raised when an uploaded email cannot be parsed."""


def parse_email(content: bytes | str, filename: str = "pasted.txt") -> ParsedEmail:
    """Parse supported email input and discard body content after artifact extraction."""
    suffix = Path(filename).suffix.lower()
    if suffix == ".msg":
        return _parse_msg(_as_bytes(content))
    if suffix not in {".eml", ".txt", ""}:
        raise ParseError(f"Unsupported file type: {suffix or 'unknown'}")

    if isinstance(content, bytes) and suffix == ".eml":
        message = BytesParser(policy=policy.default).parsebytes(content)
        attachments = _hash_mime_attachments(message)
        urls = _extract_message_urls(message)
    else:
        text = content.decode("utf-8", errors="replace") if isinstance(content, bytes) else content
        message = Parser(policy=policy.default).parsestr(_header_block(text))
        attachments = []
        urls = _extract_urls(text)
    return _build_parsed_email(message, attachments, urls)


def _parse_msg(content: bytes) -> ParsedEmail:
    try:
        import extract_msg
    except ImportError as exc:
        raise ParseError("MSG support requires the extract-msg package.") from exc

    try:
        msg = extract_msg.openMsg(io.BytesIO(content))
        header_text = msg.header.as_string() if hasattr(msg.header, "as_string") else str(msg.header or "")
        message = Parser(policy=policy.default).parsestr(_header_block(header_text))
        attachments = []
        url_text_parts = [header_text]
        for index, attachment in enumerate(msg.attachments, start=1):
            data = attachment.data
            if not isinstance(data, bytes):
                data = bytes(data)
            filename = attachment.longFilename or attachment.shortFilename or f"attachment-{index}"
            attachments.append(_attachment_artifact(filename, data))
        for attr in ("body", "htmlBody"):
            value = getattr(msg, attr, "")
            if value:
                url_text_parts.append(_text(value))
        urls = _extract_urls("\n".join(url_text_parts))
        msg.close()
        return _build_parsed_email(message, attachments, urls)
    except Exception as exc:
        raise ParseError(f"Could not parse MSG input: {exc}") from exc


def _header_block(text: str) -> str:
    normalized = text.replace("\r\n", "\n").replace("\r", "\n")
    return normalized.split("\n\n", 1)[0]


def _as_bytes(content: bytes | str) -> bytes:
    return content if isinstance(content, bytes) else content.encode("utf-8", errors="replace")


def _hash_mime_attachments(message: Message) -> list[AttachmentArtifact]:
    artifacts: list[AttachmentArtifact] = []
    if not message.is_multipart():
        return artifacts
    for index, part in enumerate(message.walk(), start=1):
        filename = part.get_filename()
        if part.get_content_disposition() != "attachment" and not filename:
            continue
        payload = part.get_payload(decode=True) or b""
        artifacts.append(_attachment_artifact(filename or f"attachment-{index}", payload))
    return artifacts


def _extract_message_urls(message: Message) -> list[str]:
    text_parts: list[str] = []
    for part in message.walk():
        if part.get_content_disposition() == "attachment":
            continue
        if part.get_content_type() not in {"text/plain", "text/html"}:
            continue
        try:
            text_parts.append(_text(part.get_content()))
        except Exception:
            payload = part.get_payload(decode=True)
            if payload:
                charset = part.get_content_charset() or "utf-8"
                text_parts.append(payload.decode(charset, errors="replace"))
    return _extract_urls("\n".join(text_parts))


def _extract_urls(text: str) -> list[str]:
    found: list[str] = []
    seen: set[str] = set()
    for match in URL_RE.findall(text):
        url = match.rstrip(".,;:!?)]}")
        if url not in seen:
            found.append(url)
            seen.add(url)
    return found[:50]


def _attachment_artifact(filename: str, payload: bytes) -> AttachmentArtifact:
    return AttachmentArtifact(
        filename=_clean(filename, limit=260),
        sha256=hashlib.sha256(payload).hexdigest(),
        size=len(payload),
    )


def _build_parsed_email(
    message: Message, attachments: list[AttachmentArtifact], urls: list[str]
) -> ParsedEmail:
    sender = _collect_headers(message, SENDER_HEADERS)
    routing = _collect_headers(message, ROUTING_HEADERS)
    authentication = _collect_headers(message, AUTH_HEADERS)
    metadata = {
        name.title(): _clean(str(message.get(name, "")), limit=1000)
        for name in METADATA_HEADERS
        if message.get(name)
    }
    return ParsedEmail(
        metadata=metadata,
        sender_headers=sender,
        routing_headers=routing,
        authentication_headers=authentication,
        originating_ips=_extract_public_ips(routing),
        domains=_extract_domains(sender, routing),
        urls=urls,
        attachments=attachments,
    )


def _collect_headers(message: Message, names: Iterable[str]) -> dict[str, list[str]]:
    result: dict[str, list[str]] = {}
    for name in names:
        values = [_clean(str(value), limit=4000) for value in message.get_all(name, [])]
        if values:
            result[name.title()] = values
    return result


def _extract_public_ips(routing: dict[str, list[str]]) -> list[str]:
    found: set[str] = set()
    for values in routing.values():
        for value in values:
            for candidate in IP_CANDIDATE_RE.findall(value):
                try:
                    address = ipaddress.ip_address(candidate)
                except ValueError:
                    continue
                if address.is_global:
                    found.add(address.compressed)
    return sorted(found)[:20]


def _extract_domains(
    sender: dict[str, list[str]], routing: dict[str, list[str]]
) -> list[str]:
    found: set[str] = set()
    for values in sender.values():
        for value in values:
            address = parseaddr(value)[1]
            if "@" in address:
                found.add(address.rsplit("@", 1)[1].lower().rstrip("."))

    for value in routing.get("Received", []):
        for candidate in DOMAIN_RE.findall(value):
            found.add(candidate.lower().rstrip("."))
    return sorted(domain for domain in found if "." in domain)[:30]


def _clean(value: str, limit: int) -> str:
    value = "".join(char for char in value if char in "\t\n" or ord(char) >= 32)
    return value.strip()[:limit]


def _text(value: object) -> str:
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="replace")
    return str(value)
