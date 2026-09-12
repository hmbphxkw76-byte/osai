"""Tests for REQ-161: GraphQL introspection probe + WAF/rate-limit detection."""

from __future__ import annotations

import json

from recon.graphql_probe import (
    GraphQLSchemaSummary,
    build_introspection_request,
    is_graphql_signal,
    summarize_introspection,
)
from recon.waf_detector import fingerprint_waf, parse_rate_limit_headers, waf_to_fingerprint_fields


class TestGraphQLSignal:
    def test_known_path(self) -> None:
        assert is_graphql_signal(path="/graphql") is True
        assert is_graphql_signal(path="/api/graphql") is True

    def test_generic_path_with_marker(self) -> None:
        assert is_graphql_signal(path="/api/query", body='{"query":"{ __schema }"}') is True

    def test_content_type(self) -> None:
        assert is_graphql_signal(path="/x", content_type="application/graphql") is True

    def test_negative(self) -> None:
        assert is_graphql_signal(path="/api/chat", body='{"prompt":"hi"}') is False


class TestIntrospection:
    def test_build_request_shape(self) -> None:
        req = build_introspection_request()
        assert "query" in req and "__schema" in req["query"]

    def test_summarize_full_schema(self) -> None:
        payload = {
            "data": {
                "__schema": {
                    "queryType": {"name": "Query"},
                    "mutationType": {"name": "Mutation"},
                    "types": [
                        {"kind": "OBJECT", "name": "Query", "fields": [{"name": "users"}, {"name": "me"}]},
                        {"kind": "OBJECT", "name": "Mutation", "fields": [{"name": "createUser"}]},
                        {"kind": "OBJECT", "name": "__Schema", "fields": []},
                    ],
                }
            }
        }
        s = summarize_introspection(payload, endpoint="https://h/graphql")
        assert s.detected and s.introspection_enabled
        assert s.endpoint == "https://h/graphql"
        assert s.queries == ["me", "users"]
        assert s.mutations == ["createUser"]
        assert "__Schema" not in s.types

    def test_summarize_from_string(self) -> None:
        s = summarize_introspection(json.dumps({"data": {"__schema": {"types": []}}}))
        assert s.detected and s.introspection_enabled

    def test_introspection_disabled(self) -> None:
        s = summarize_introspection({"errors": [{"message": "Introspection is disabled"}]})
        assert s.detected is True
        assert s.introspection_enabled is False
        assert "introspection_disabled_or_blocked" in s.evidence

    def test_invalid_payload_never_raises(self) -> None:
        assert isinstance(summarize_introspection("not-json"), GraphQLSchemaSummary)
        assert isinstance(summarize_introspection(None), GraphQLSchemaSummary)


class TestWAFDetection:
    def test_cloudflare(self) -> None:
        r = fingerprint_waf(headers={"CF-RAY": "abc123", "Server": "cloudflare"})
        assert r.detected and "cloudflare" in r.vendors
        assert r.confidence > 0.6

    def test_aws(self) -> None:
        r = fingerprint_waf(headers={"x-amz-cf-id": "xyz"})
        assert "aws_waf" in r.vendors

    def test_imperva_cookie(self) -> None:
        r = fingerprint_waf(headers={}, cookies={"incap_ses_123": "v"})
        assert "imperva_incapsula" in r.vendors

    def test_modsecurity_body(self) -> None:
        r = fingerprint_waf(headers={"Server": "Apache"}, body="Blocked by ModSecurity rule 942100")
        assert "modsecurity" in r.vendors

    def test_block_page_without_vendor(self) -> None:
        r = fingerprint_waf(headers={}, body="Access Denied", status_code=403)
        assert r.blocked is True and r.detected is True

    def test_clean_response(self) -> None:
        r = fingerprint_waf(headers={"Server": "nginx"}, body='{"ok":true}', status_code=200)
        assert r.detected is False
        assert r.vendors == []

    def test_multiple_vendors(self) -> None:
        r = fingerprint_waf(headers={"cf-ray": "1", "x-sucuri-id": "2"})
        assert {"cloudflare", "sucuri"}.issubset(set(r.vendors))


class TestRateLimit:
    def test_parse_standard_headers(self) -> None:
        info = parse_rate_limit_headers(
            {"X-RateLimit-Limit": "60", "X-RateLimit-Remaining": "12", "X-RateLimit-Reset": "30"}
        )
        assert info.limited is True
        assert info.limit == 60 and info.remaining == 12 and info.reset_seconds == 30.0

    def test_retry_after(self) -> None:
        info = parse_rate_limit_headers({"Retry-After": "120"})
        assert info.limited is True and info.retry_after_seconds == 120.0

    def test_absent(self) -> None:
        info = parse_rate_limit_headers({"Server": "nginx"})
        assert info.limited is False and info.limit is None

    def test_waf_report_carries_rate_limit(self) -> None:
        r = fingerprint_waf(headers={"X-RateLimit-Limit": "10", "X-RateLimit-Remaining": "0"})
        assert r.rate_limit.limited is True
        assert r.rate_limit.remaining == 0


class TestFingerprintMapping:
    def test_mapping_keys(self) -> None:
        report = fingerprint_waf(headers={"cf-ray": "1"})
        fields = waf_to_fingerprint_fields(report)
        assert fields["waf_detected"] is True
        assert "cloudflare" in fields["waf_vendors"]
        assert "rate_limit" in fields


_BURP_WITH_CF = (
    "POST /api/chat HTTP/1.1\n"
    "Host: t.example.com\n"
    "Content-Type: application/json\n"
    "\n"
    '{"prompt":"{PROMPT}"}\n'
    "HTTP/1.1 403 Forbidden\n"
    "Server: cloudflare\n"
    "CF-RAY: 8abc123\n"
    "Set-Cookie: __cf_bm=xyz; Path=/\n"
    "Content-Type: text/html\n"
    "\n"
    "Access Denied"
)


class TestWAFWiring:
    def test_waf_detected_from_burp_response(self, tmp_path) -> None:
        from recon.burp_parser import parse_burp_request

        p = tmp_path / "cf.txt"
        p.write_text(_BURP_WITH_CF, encoding="utf-8")
        fp = parse_burp_request(p).target_fingerprint
        assert fp.extra.get("waf_detected") is True
        assert "cloudflare" in fp.extra.get("waf_vendors", [])
        assert fp.extra.get("waf_blocked") is True

    def test_clean_response_no_waf_key(self, tmp_path) -> None:
        from recon.burp_parser import parse_burp_request

        p = tmp_path / "clean.txt"
        p.write_text(
            "POST /api/chat HTTP/1.1\nHost: t\n\n{}\nHTTP/1.1 200 OK\nServer: nginx\n\n{}",
            encoding="utf-8",
        )
        fp = parse_burp_request(p).target_fingerprint
        assert fp.extra.get("waf_detected") is False
