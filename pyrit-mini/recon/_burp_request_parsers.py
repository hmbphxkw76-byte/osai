"""recon/_burp_request_parsers — Burp input detection + multi-format request parsing.

Extracted from `recon/burp_parser.py` (SRP). Reads raw / HAR / Site Map / Postman
inputs and splits them into `ParsedBurpRequest` objects; the deep interpretation
of a single HTTP block is delegated to `recon._burp_fingerprint._parse_raw_http`.
"""

from __future__ import annotations

import json
import logging
import re
from pathlib import Path
from typing import Any

from recon._burp_fingerprint import _parse_raw_http
from recon._burp_models import ParsedBurpRequest

logger = logging.getLogger(__name__)


# HTTP request-line detector for multi-request splitting (REQ-160 ②)
_REQUEST_LINE_RE = re.compile(
    r"^(GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS|TRACE|CONNECT)\s+\S+\s+HTTP/\d",
    re.IGNORECASE,
)


def parse_burp_request(file_path: str | Path) -> ParsedBurpRequest:
    """Burp HTTP (single) — first request of the input.

    Backward-compatible facade over `parse_burp_requests`. Existing callers that
    expect exactly one request keep working; multi-request/HAR inputs yield the
    first entry.

    Raises:
        FileNotFoundError: file missing.
        ValueError: no valid HTTP request found.
    """
    return parse_burp_requests(file_path)[0]


def parse_burp_requests(file_path: str | Path) -> list[ParsedBurpRequest]:
    """Parse any supported Burp input into a list of `ParsedBurpRequest` (REQ-160).

    Supported inputs:
        - Raw HTTP request (+ optional response) — single or multiple requests
          concatenated in one file (① multi-request, ② HAR-less raw).
        - HAR export (`.har` or JSON with `log.entries`) — request/response
          timing preserved per entry (③).
        - Burp Site Map export (XML or JSON) — endpoint stubs for enumeration.
        - Postman v2.x collection — recursively flattened requests.

    All entries converge into the existing `ParsedBurpRequest` contract; no
    parallel data structure is introduced (I12).

    Raises:
        FileNotFoundError: file missing.
        ValueError: input contains no parseable HTTP request.
    """
    path = Path(file_path)
    raw = path.read_text(encoding="utf-8", errors="replace")

    fmt = _detect_input_format(path, raw)
    if fmt == "har":
        entries = _parse_har(raw)
        if entries:
            return entries
        raise ValueError(f"HAR file contained no usable request entries: {path}")
    if fmt == "sitemap":
        entries = _parse_sitemap(raw)
        if entries:
            return entries
        raise ValueError(f"Site Map contained no usable endpoints: {path}")
    if fmt == "postman":
        entries = _parse_postman(raw)
        if entries:
            return entries
        raise ValueError(f"Postman collection contained no usable requests: {path}")

    chunks = _split_multi_requests(raw)
    entries = []
    for chunk in chunks:
        try:
            entries.append(_parse_raw_http(chunk))
        except ValueError as e:
            logger.warning("Skipping unparseable HTTP block in %s: %s", path.name, e)
    if not entries:
        raise ValueError(f"No valid HTTP request found in: {path}")
    return entries


def _detect_input_format(path: Path, raw: str) -> str:
    """Classify the input file: 'har' | 'sitemap' | 'postman' | 'raw' (REQ-160).

    Ordering matters: HAR and Postman are both JSON, so we inspect content rather
    than trusting the extension alone (`capture.json` may be either).
    """
    suffix = path.suffix.lower()
    if suffix == ".har":
        return "har"
    if suffix == ".xml":
        return "sitemap"

    stripped = raw.lstrip()
    if not stripped.startswith("{") and not stripped.startswith("["):
        return "raw"
    try:
        data = json.loads(stripped)
    except json.JSONDecodeError:
        return "raw"
    if isinstance(data, dict):
        if isinstance((data.get("log") or {}).get("entries"), list):
            return "har"
        if "item" in data and "info" in data:
            return "postman"
        if isinstance(data.get("items"), list):
            return "sitemap"
    if isinstance(data, list) and data and isinstance(data[0], (str, dict)):
        return "sitemap"
    return "raw"


def _split_multi_requests(raw: str) -> list[str]:
    """Split a raw Burp dump containing several request/response pairs.

    Burp "Save items" can emit multiple requests concatenated. We split on
    lines that start a new HTTP request; each block is parsed independently.
    A single-request input is returned as-is (zero behavior change).
    """
    normalized = raw.replace("\r\n", "\n").replace("\r", "\n")
    lines = normalized.split("\n")
    starts = [i for i, line in enumerate(lines) if _REQUEST_LINE_RE.match(line.strip())]
    if len(starts) <= 1:
        return [normalized]
    chunks: list[str] = []
    for idx, start in enumerate(starts):
        end = starts[idx + 1] if idx + 1 < len(starts) else len(lines)
        chunk = "\n".join(lines[start:end]).strip("\n")
        if chunk:
            chunks.append(chunk)
    return chunks


def _request_from_url(
    method: str,
    url: str,
    header_pairs: list[tuple[str, str]],
    body: str,
) -> ParsedBurpRequest | None:
    """Build a `ParsedBurpRequest` from an absolute URL + method + headers + body.

    Shared by HAR / Site Map / Postman importers (REQ-160 ③). Returns None when
    the URL is unusable. The absolute URL is authoritative for scheme.
    """
    from urllib.parse import urlparse

    if not url:
        return None
    parsed_url = urlparse(url)
    if not parsed_url.netloc:
        return None

    path = parsed_url.path or "/"
    if parsed_url.query:
        path = f"{path}?{parsed_url.query}"
    host = parsed_url.netloc

    lines = [f"{method} {path} HTTP/1.1"]
    if not any(k.lower() == "host" for k, _ in header_pairs) and host:
        lines.append(f"Host: {host}")
    for name, value in header_pairs:
        if not name or name.lower() == "content-length":
            continue
        lines.append(f"{name}: {value}")
    raw_request = "\n".join(lines) + "\n\n" + body

    try:
        parsed = _parse_raw_http(raw_request)
    except ValueError as e:
        logger.warning("Skipping unparseable entry (%s %s): %s", method, path, e)
        return None

    if parsed_url.scheme:
        parsed.use_tls = parsed_url.scheme.lower() == "https"
    parsed.url = url
    parsed.http_version = "HTTP/1.1"
    return parsed


def _parse_har(raw: str) -> list[ParsedBurpRequest]:
    """Convert HAR `log.entries[*]` into `ParsedBurpRequest` list (REQ-160 ③)."""
    data = json.loads(raw)
    entries = (data.get("log") or {}).get("entries") or []

    out: list[ParsedBurpRequest] = []
    for entry in entries:
        req = entry.get("request") or {}
        method = str(req.get("method") or "POST").upper()
        url = str(req.get("url") or "")
        headers = [
            (str(h.get("name") or ""), str(h.get("value") or ""))
            for h in (req.get("headers") or [])
            if h.get("name")
        ]
        body = str((req.get("postData") or {}).get("text") or "")
        parsed = _request_from_url(method, url, headers, body)
        if parsed is not None:
            out.append(parsed)
    return out


def _parse_sitemap(raw: str) -> list[ParsedBurpRequest]:
    """Import a Burp Site Map export (XML or JSON) as endpoint stubs (REQ-160 ③).

    A Site Map has no bodies, so each entry becomes a request with an empty body;
    it is used for endpoint enumeration, not for replay.
    """
    stripped = raw.lstrip()
    out: list[ParsedBurpRequest] = []

    if stripped.startswith("<"):
        import xml.etree.ElementTree as ET

        try:
            root = ET.fromstring(stripped)
        except ET.ParseError as e:
            logger.warning("Site Map XML parse failed: %s", e)
            return []

        def _local(tag: str) -> str:
            return tag.rsplit("}", 1)[-1].lower()

        for item in root.iter():
            if _local(item.tag) != "item":
                continue
            url: str | None = None
            method = "GET"
            for child in item:
                ctag = _local(child.tag)
                if ctag == "url":
                    url = (child.text or "").strip() or child.get("url")
                elif ctag == "method":
                    method = (child.text or "").strip().upper() or "GET"
            if not url:
                url = item.get("url")
            if url:
                parsed = _request_from_url(method or "GET", url, [], "")
                if parsed is not None:
                    out.append(parsed)
        return out

    data = json.loads(stripped)
    items = data.get("items") if isinstance(data, dict) else data
    for it in items or []:
        url: str | None
        method = "GET"
        if isinstance(it, str):
            url = it
        elif isinstance(it, dict):
            url = it.get("url") or it.get("URL")
            method = str(it.get("method") or "GET").upper()
        else:
            continue
        if url:
            parsed = _request_from_url(method, str(url), [], "")
            if parsed is not None:
                out.append(parsed)
    return out


def _parse_postman(raw: str) -> list[ParsedBurpRequest]:
    """Import a Postman v2.x collection (recursively flattened) — REQ-160 ③."""
    data = json.loads(raw)
    out: list[ParsedBurpRequest] = []

    def _walk(items: Any) -> None:
        for it in items or []:
            if not isinstance(it, dict):
                continue
            if isinstance(it.get("item"), list):
                _walk(it["item"])
                continue
            req = it.get("request")
            if not isinstance(req, dict):
                continue
            method = str(req.get("method") or "GET").upper()
            raw_url = req.get("url")
            url = str((raw_url or {}).get("raw") or "") if isinstance(raw_url, dict) else str(raw_url or "")
            headers = [
                (str(h.get("key") or ""), str(h.get("value") or ""))
                for h in (req.get("header") or [])
                if h.get("key")
            ]
            body_obj = req.get("body") or {}
            body = str(body_obj.get("raw") or "") if isinstance(body_obj, dict) else ""
            if url:
                parsed = _request_from_url(method, url, headers, body)
                if parsed is not None:
                    out.append(parsed)

    _walk(data.get("item"))
    return out


def build_raw_http_request(parsed: ParsedBurpRequest) -> str:
    """HTTP (CRLF )"""
    lines = [f"{parsed.method} {parsed.path} {parsed.http_version}"]

    for key, value in parsed.raw_headers:
        if key.lower() == "content-length":
            continue
        lines.append(f"{key}: {value}")

    if parsed.body:
        lines.append(f"Content-Length: {len(parsed.body.encode('utf-8'))}")

    request = "\r\n".join(lines)
    if parsed.body:
        request += "\r\n\r\n" + parsed.body
    else:
        request += "\r\n\r\n"
    return request
