"""Bounded asynchronous threat-intelligence enrichment."""

from __future__ import annotations

import asyncio
import json
from dataclasses import asdict, dataclass
from typing import Any

import aiohttp


@dataclass(frozen=True)
class IntelResult:
    source: str
    indicator: str
    kind: str
    status: str
    summary: str


async def enrich(
    ips: tuple[str, ...],
    domains: tuple[str, ...],
    api_keys: dict[str, str],
    timeout_seconds: float = 7.0,
) -> list[dict[str, str]]:
    """Query all configured sources concurrently within a single timeout budget."""
    timeout = aiohttp.ClientTimeout(total=timeout_seconds, connect=3)
    connector = aiohttp.TCPConnector(limit=24, ttl_dns_cache=300)
    async with aiohttp.ClientSession(timeout=timeout, connector=connector) as session:
        tasks = []
        for ip in ips[:10]:
            tasks.extend(
                (
                    _abuseipdb(session, ip, api_keys.get("ABUSEIPDB_API_KEY", "")),
                    _otx(session, ip, "IPv4", api_keys.get("OTX_API_KEY", "")),
                    _virustotal(session, ip, "ip_addresses", api_keys.get("VIRUSTOTAL_API_KEY", "")),
                    _threatfox(session, ip, "ip", api_keys.get("THREATFOX_API_KEY", "")),
                )
            )
        for domain in domains[:10]:
            tasks.extend(
                (
                    _otx(session, domain, "domain", api_keys.get("OTX_API_KEY", "")),
                    _virustotal(session, domain, "domains", api_keys.get("VIRUSTOTAL_API_KEY", "")),
                    _threatfox(session, domain, "domain", api_keys.get("THREATFOX_API_KEY", "")),
                )
            )
        results = await asyncio.gather(*tasks, return_exceptions=True)

    normalized = []
    for result in results:
        if isinstance(result, IntelResult):
            normalized.append(asdict(result))
        elif isinstance(result, Exception):
            normalized.append(asdict(IntelResult("Unknown", "", "", "Error", _clean(str(result)))))
    return normalized


def enrich_sync(
    ips: tuple[str, ...], domains: tuple[str, ...], api_keys: dict[str, str]
) -> list[dict[str, str]]:
    if not ips and not domains:
        return []
    return asyncio.run(enrich(ips, domains, api_keys))


async def _abuseipdb(session: aiohttp.ClientSession, ip: str, key: str) -> IntelResult:
    source = "AbuseIPDB"
    if not key:
        return IntelResult(source, ip, "ip", "Not Configured", "API key not configured.")
    payload = await _request_json(
        session,
        "GET",
        "https://api.abuseipdb.com/api/v2/check",
        source,
        ip,
        headers={"Key": key, "Accept": "application/json"},
        params={"ipAddress": ip, "maxAgeInDays": "90"},
    )
    if isinstance(payload, IntelResult):
        return payload
    data = payload.get("data", {})
    score = _integer(data.get("abuseConfidenceScore"))
    reports = _integer(data.get("totalReports"))
    status = "Hit" if score > 0 else "Clean"
    return IntelResult(source, ip, "ip", status, f"Confidence {score}/100; {reports} reports.")


async def _otx(
    session: aiohttp.ClientSession, indicator: str, kind: str, key: str
) -> IntelResult:
    source = "AlienVault OTX"
    if not key:
        return IntelResult(source, indicator, kind.lower(), "Not Configured", "API key not configured.")
    payload = await _request_json(
        session,
        "GET",
        f"https://otx.alienvault.com/api/v1/indicators/{kind}/{indicator}/general",
        source,
        indicator,
        headers={"X-OTX-API-KEY": key},
    )
    if isinstance(payload, IntelResult):
        return payload
    pulses = _integer(payload.get("pulse_info", {}).get("count"))
    status = "Hit" if pulses > 0 else "Clean"
    return IntelResult(source, indicator, kind.lower(), status, f"{pulses} malicious/community pulses.")


async def _virustotal(
    session: aiohttp.ClientSession, indicator: str, endpoint: str, key: str
) -> IntelResult:
    source = "VirusTotal"
    kind = "ip" if endpoint == "ip_addresses" else "domain"
    if not key:
        return IntelResult(source, indicator, kind, "Not Configured", "API key not configured.")
    payload = await _request_json(
        session,
        "GET",
        f"https://www.virustotal.com/api/v3/{endpoint}/{indicator}",
        source,
        indicator,
        headers={"x-apikey": key},
    )
    if isinstance(payload, IntelResult):
        return payload
    attrs = payload.get("data", {}).get("attributes", {})
    stats = attrs.get("last_analysis_stats", {})
    malicious = _integer(stats.get("malicious"))
    suspicious = _integer(stats.get("suspicious"))
    total = sum(_integer(value) for value in stats.values())
    reputation = _integer(attrs.get("reputation"))
    status = "Hit" if malicious or suspicious else "Clean"
    return IntelResult(
        source,
        indicator,
        kind,
        status,
        f"{malicious} malicious + {suspicious} suspicious / {total} vendors; reputation {reputation}.",
    )


async def _threatfox(
    session: aiohttp.ClientSession, indicator: str, kind: str, key: str
) -> IntelResult:
    source = "Abuse.ch ThreatFox"
    if not key:
        return IntelResult(source, indicator, kind, "Not Configured", "API key not configured.")
    payload = await _request_json(
        session,
        "POST",
        "https://threatfox-api.abuse.ch/api/v1/",
        source,
        indicator,
        headers={"Auth-Key": key},
        json_body={"query": "search_ioc", "search_term": indicator, "exact_match": True},
    )
    if isinstance(payload, IntelResult):
        return payload
    query_status = str(payload.get("query_status", "unknown"))
    hits = payload.get("data", [])
    hit_count = len(hits) if isinstance(hits, list) else 0
    status = "Hit" if query_status == "ok" and hit_count else "Clean"
    return IntelResult(source, indicator, kind, status, f"{hit_count} ThreatFox IOC matches ({query_status}).")


async def _request_json(
    session: aiohttp.ClientSession,
    method: str,
    url: str,
    source: str,
    indicator: str,
    *,
    headers: dict[str, str] | None = None,
    params: dict[str, str] | None = None,
    json_body: dict[str, Any] | None = None,
) -> dict[str, Any] | IntelResult:
    try:
        async with session.request(method, url, headers=headers, params=params, json=json_body) as response:
            if response.status == 429:
                return IntelResult(source, indicator, "", "Rate Limited", "Provider rate limit reached.")
            if response.status in {401, 403}:
                return IntelResult(source, indicator, "", "Auth Error", "API key rejected or unauthorized.")
            if response.status >= 400:
                return IntelResult(source, indicator, "", "Error", f"Provider returned HTTP {response.status}.")
            raw = await response.text()
            return _sanitize(json.loads(raw))
    except asyncio.TimeoutError:
        return IntelResult(source, indicator, "", "Timed Out", "Provider did not respond within the time budget.")
    except (aiohttp.ClientError, json.JSONDecodeError) as exc:
        return IntelResult(source, indicator, "", "Error", _clean(str(exc)))


def _sanitize(value: Any, depth: int = 0) -> Any:
    if depth > 8:
        return None
    if isinstance(value, dict):
        return {_clean(str(key), 120): _sanitize(item, depth + 1) for key, item in list(value.items())[:200]}
    if isinstance(value, list):
        return [_sanitize(item, depth + 1) for item in value[:200]]
    if isinstance(value, str):
        return _clean(value)
    if isinstance(value, (int, float, bool)) or value is None:
        return value
    return _clean(str(value))


def _clean(value: str, limit: int = 1000) -> str:
    return "".join(char for char in value if char in "\t\n" or ord(char) >= 32).strip()[:limit]


def _integer(value: Any) -> int:
    try:
        return int(value or 0)
    except (TypeError, ValueError):
        return 0
