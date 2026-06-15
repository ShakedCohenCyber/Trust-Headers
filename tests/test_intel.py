from __future__ import annotations

import asyncio

from trust_headers.intel import _threatfox


def test_threatfox_skips_request_without_required_key() -> None:
    result = asyncio.run(_threatfox(None, "example.com", "domain", ""))  # type: ignore[arg-type]

    assert result.status == "Not Configured"
