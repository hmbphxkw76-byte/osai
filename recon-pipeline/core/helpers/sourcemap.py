"""JS sourcemap discovery and restoration (P1-1-A/B).

Discovers `//# sourceMappingURL=` comments and `SourceMap` / `X-SourceMap`
response headers, then derives the `.map` URL and attempts to fetch the
original source map to recover deobfuscated source.
"""
from __future__ import annotations

import logging
import re
from dataclasses import dataclass
from typing import Any
from urllib.parse import urljoin, urlparse

logger = logging.getLogger(__name__)

_SOURCE_MAP_COMMENT = re.compile(
    r"//#\s*sourceMappingURL=(?P<url>\S+)", re.IGNORECASE
)


@dataclass
class SourceMapRef:
    js_url: str
    map_url: str
    discovered_via: str  # "comment" | "header"


def discover_sourcemap(js_url: str, js_content: str, headers: dict[str, str] | None = None) -> SourceMapRef | None:
    """P1-1-A: Discover a sourceMappingURL from comment or response header."""
    # 1. Comment in JS body
    m = _SOURCE_MAP_COMMENT.search(js_content or "")
    if m:
        raw = m.group("url").strip().strip('"').strip("'")
        if raw.startswith("data:"):
            return None  # inline map, not fetched here
        map_url = urljoin(js_url, raw)
        return SourceMapRef(js_url=js_url, map_url=map_url, discovered_via="comment")

    # 2. Response headers
    headers = headers or {}
    for h_key in ("sourcemap", "x-sourcemap"):
        if h_key in {k.lower(): v for k, v in headers.items()}:
            raw = headers.get(h_key) or headers.get(h_key.title())
            if raw:
                map_url = urljoin(js_url, raw)
                return SourceMapRef(js_url=js_url, map_url=map_url, discovered_via="header")
    return None


def derive_map_url(js_url: str) -> str:
    """P1-1-B: Brute-force the conventional `<name>.js.map` path."""
    parsed = urlparse(js_url)
    path = parsed.path
    if path.endswith(".js"):
        base = path[:-3] + ".js.map"
    else:
        base = path + ".map"
    return f"{parsed.scheme}://{parsed.netloc}{base}"


async def fetch_source(js_url: str, js_content: str, headers: dict[str, str] | None = None) -> dict[str, Any]:
    """P1-1-A/B/C: Discover + fetch source map; return recovered source (if any)."""
    import httpx

    ref = discover_sourcemap(js_url, js_content, headers)
    candidates: list[str] = []
    if ref:
        candidates.append(ref.map_url)
    candidates.append(derive_map_url(js_url))

    async with httpx.AsyncClient(timeout=10, verify=False, follow_redirects=True) as client:
        for map_url in candidates:
            try:
                resp = await client.get(map_url)
            except httpx.HTTPError:
                continue
            if resp.status_code != 200:
                continue
            try:
                smap = resp.json()
            except ValueError:
                continue
            sources = smap.get("sources", [])
            contents = smap.get("sourcesContent", [])
            recovered = "\n".join(c for c in contents if isinstance(c, str))
            if recovered:
                return {
                    "recovered": True,
                    "map_url": map_url,
                    "sources": sources,
                    "source_content": recovered,
                }
    return {"recovered": False, "map_url": None, "sources": [], "source_content": ""}
