"""Tests for REQ-160: multi-request and HAR input parsing in recon.burp_parser.

Covers:
    - ② single file containing multiple raw HTTP requests (Burp "Save items")
    - ③ HAR export (`.har` / JSON with `log.entries`)
    - backward compatibility of `parse_burp_request` (single-request facade)
"""

from __future__ import annotations

import json

import pytest

from recon.burp_parser import parse_burp_request, parse_burp_requests

_SINGLE = (
    "POST /api/chat HTTP/1.1\n"
    "Host: target.example.com\n"
    "Content-Type: application/json\n"
    "Authorization: Bearer sk-test\n"
    "\n"
    '{"prompt":"{PROMPT}"}'
)

_MULTI = (
    "POST /api/chat HTTP/1.1\n"
    "Host: target.example.com\n"
    "Content-Type: application/json\n"
    "\n"
    '{"prompt":"{PROMPT}"}\n'
    "GET /api/tools HTTP/1.1\n"
    "Host: target.example.com\n"
    "\n"
)


def _write(tmp_path, name: str, text: str):
    p = tmp_path / name
    p.write_text(text, encoding="utf-8")
    return p


class TestSingleRequestBackwardCompat:
    def test_parse_burp_request_returns_first(self, tmp_path) -> None:
        path = _write(tmp_path, "one.txt", _SINGLE)
        parsed = parse_burp_request(path)
        assert parsed.method == "POST"
        assert parsed.path == "/api/chat"
        assert parsed.host == "target.example.com"
        assert "{PROMPT}" in parsed.body

    def test_parse_burp_requests_single(self, tmp_path) -> None:
        path = _write(tmp_path, "one.txt", _SINGLE)
        entries = parse_burp_requests(path)
        assert len(entries) == 1
        assert entries[0].method == "POST"


class TestMultiRequestFile:
    def test_two_requests_split(self, tmp_path) -> None:
        path = _write(tmp_path, "multi.txt", _MULTI)
        entries = parse_burp_requests(path)
        assert len(entries) == 2
        assert [e.method for e in entries] == ["POST", "GET"]
        assert [e.path for e in entries] == ["/api/chat", "/api/tools"]

    def test_single_request_not_split(self, tmp_path) -> None:
        path = _write(tmp_path, "one.txt", _SINGLE)
        assert len(parse_burp_requests(path)) == 1


class TestHarImport:
    def _har(self) -> str:
        return json.dumps(
            {
                "log": {
                    "version": "1.2",
                    "entries": [
                        {
                            "request": {
                                "method": "POST",
                                "url": "https://target.example.com/api/chat?x=1",
                                "headers": [
                                    {"name": "Content-Type", "value": "application/json"},
                                    {"name": "Authorization", "value": "Bearer sk-test"},
                                ],
                                "postData": {"text": '{"prompt":"{PROMPT}"}'},
                            },
                            "response": {"status": 200},
                        },
                        {
                            "request": {
                                "method": "GET",
                                "url": "http://second.example.com/api/tools",
                                "headers": [],
                            },
                            "response": {"status": 200},
                        },
                    ],
                }
            }
        )

    def test_har_extension(self, tmp_path) -> None:
        path = _write(tmp_path, "capture.har", self._har())
        entries = parse_burp_requests(path)
        assert len(entries) == 2
        assert entries[0].method == "POST"
        assert entries[0].host == "target.example.com"
        assert entries[0].path == "/api/chat?x=1"

    def test_har_scheme_authoritative(self, tmp_path) -> None:
        path = _write(tmp_path, "capture.har", self._har())
        entries = parse_burp_requests(path)
        assert entries[0].use_tls is True
        assert entries[1].use_tls is False
        assert entries[1].url.startswith("http://second.example.com"), (
            "HAR URL must be authoritative over header-based inference"
        )

    def test_json_har_without_extension(self, tmp_path) -> None:
        path = _write(tmp_path, "capture.json", self._har())
        assert len(parse_burp_requests(path)) == 2

    def test_har_preserves_body_placeholder(self, tmp_path) -> None:
        path = _write(tmp_path, "capture.har", self._har())
        entries = parse_burp_requests(path)
        assert "{PROMPT}" in entries[0].body


class TestErrors:
    def test_empty_file_raises(self, tmp_path) -> None:
        path = _write(tmp_path, "empty.txt", "")
        with pytest.raises(ValueError):
            parse_burp_requests(path)

    def test_empty_har_raises(self, tmp_path) -> None:
        path = _write(tmp_path, "empty.har", json.dumps({"log": {"entries": []}}))
        with pytest.raises(ValueError):
            parse_burp_requests(path)


_SITEMAP_XML = (
    "<items>"
    "<item><url>https://a.example.com/api/chat</url><method>POST</method></item>"
    "<item><url>https://a.example.com/api/tools</url><method>GET</method></item>"
    "</items>"
)


class TestSiteMapImport:
    def test_xml_sitemap(self, tmp_path) -> None:
        path = _write(tmp_path, "map.xml", _SITEMAP_XML)
        entries = parse_burp_requests(path)
        assert len(entries) == 2
        assert [e.method for e in entries] == ["POST", "GET"]
        assert entries[0].path == "/api/chat"
        assert entries[0].use_tls is True

    def test_json_sitemap_dict(self, tmp_path) -> None:
        path = _write(
            tmp_path,
            "map.json",
            json.dumps({"items": [{"url": "http://h/api/x", "method": "POST"}]}),
        )
        entries = parse_burp_requests(path)
        assert len(entries) == 1
        assert entries[0].use_tls is False

    def test_json_sitemap_string_list(self, tmp_path) -> None:
        path = _write(tmp_path, "map.json", json.dumps(["https://h/a", "https://h/b"]))
        assert len(parse_burp_requests(path)) == 2


_POSTMAN = json.dumps(
    {
        "info": {"name": "c", "schema": "https://schema.getpostman.com/json/collection/v2.1.0/"},
        "item": [
            {
                "name": "chat",
                "request": {
                    "method": "POST",
                    "url": {"raw": "https://t.example.com/api/chat"},
                    "header": [{"key": "Content-Type", "value": "application/json"}],
                    "body": {"mode": "raw", "raw": '{"prompt":"{PROMPT}"}'},
                },
            },
            {
                "name": "folder",
                "item": [
                    {
                        "name": "tools",
                        "request": {"method": "GET", "url": {"raw": "https://t.example.com/api/tools"}},
                    }
                ],
            },
        ],
    }
)


class TestPostmanImport:
    def test_nested_collection_flattened(self, tmp_path) -> None:
        path = _write(tmp_path, "collection.json", _POSTMAN)
        entries = parse_burp_requests(path)
        assert len(entries) == 2
        assert [e.method for e in entries] == ["POST", "GET"]

    def test_postman_body_preserved(self, tmp_path) -> None:
        path = _write(tmp_path, "collection.json", _POSTMAN)
        entries = parse_burp_requests(path)
        assert "{PROMPT}" in entries[0].body
        assert entries[0].headers.get("content-type") == "application/json"
