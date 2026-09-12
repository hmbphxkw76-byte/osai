"""session_token_extractor.py - Session Token Extractor from HTTP Responses.

Extracts and catalogs session tokens from HTTP responses including
headers, cookies, response bodies, and redirect URLs.

Academic basis:
    - OWASP Testing Guide: Session Token Extraction
    - Grossman et al. - Session token leakage vectors in web applications

Constitution compliance:
    - R-SIZE: < 800 lines
    - R-H3: Single responsibility — token extraction only
    - R-S1: No hardcoded target identifiers
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from typing import Any


@dataclass
class ExtractedToken:
    """An extracted session token."""

    token_type: str  # cookie, header, body_field, url_param
    name: str
    value: str
    source: str  # response header, body, redirect, etc.
    attributes: dict[str, str] = field(default_factory=dict)
    risk_notes: list[str] = field(default_factory=list)


class SessionTokenExtractor:
    """Extract session tokens from HTTP responses."""

    # Cookie patterns that typically carry session tokens
    SESSION_COOKIE_NAMES: list[str] = [
        "session",
        "sessionid",
        "sid",
        "jsessionid",
        "phpsessid",
        "asp_session",
        "connect.sid",
        "auth_token",
        "access_token",
        "refresh_token",
        "id_token",
        "bearer",
        "jwt",
    ]

    # Response body JSON field names that may contain tokens
    TOKEN_BODY_FIELDS: list[str] = [
        "token",
        "access_token",
        "refresh_token",
        "session_id",
        "auth_token",
        "jwt",
        "bearer_token",
        "session_key",
    ]

    # Header patterns
    TOKEN_HEADER_PATTERNS: list[re.Pattern] = [
        re.compile(r"(?i)set-cookie:\s*([^=]+)=([^;]+)"),
        re.compile(r"(?i)authorization:\s*bearer\s+(\S+)"),
        re.compile(r"(?i)x-auth-token:\s*(\S+)"),
        re.compile(r"(?i)x-session-id:\s*(\S+)"),
    ]

    def __init__(self) -> None:
        self.extracted_tokens: list[ExtractedToken] = []

    def extract_from_response(
        self,
        headers: dict[str, str],
        body: str = "",
        url: str = "",
    ) -> list[ExtractedToken]:
        """Extract all session tokens from an HTTP response."""
        tokens: list[ExtractedToken] = []

        # From Set-Cookie headers
        tokens.extend(self._extract_from_cookies(headers.get("Set-Cookie", "")))

        # From Authorization headers
        tokens.extend(self._extract_from_auth_header(headers.get("Authorization", "")))

        # From custom headers
        for header_name, header_value in headers.items():
            if self._is_token_header(header_name):
                tokens.append(
                    ExtractedToken(
                        token_type="header",
                        name=header_name,
                        value=header_value[:50],
                        source="response_header",
                    )
                )

        # From body
        if body:
            tokens.extend(self._extract_from_body(body))

        # From URL
        if url:
            tokens.extend(self._extract_from_url(url))

        self.extracted_tokens.extend(tokens)
        return tokens

    def get_all_tokens(self) -> list[ExtractedToken]:
        """Get all extracted tokens."""
        return self.extracted_tokens

    def get_token_summary(self) -> dict[str, Any]:
        """Get summary of extracted tokens."""
        if not self.extracted_tokens:
            return {"total": 0, "types": {}}

        type_counts: dict[str, int] = {}
        for token in self.extracted_tokens:
            type_counts[token.token_type] = type_counts.get(token.token_type, 0) + 1

        return {
            "total": len(self.extracted_tokens),
            "types": type_counts,
            "unique_names": list(set(t.name for t in self.extracted_tokens)),
        }

    def _extract_from_cookies(self, cookie_header: str) -> list[ExtractedToken]:
        """Extract tokens from Set-Cookie header."""
        tokens: list[ExtractedToken] = []
        if not cookie_header:
            return tokens

        # Parse individual cookies
        cookie_parts = cookie_header.split(";")
        for part in cookie_parts:
            if "=" in part:
                name_value = part.strip().split("=", 1)
                if len(name_value) == 2:
                    name, value = name_value
                    if any(sess_name in name.lower() for sess_name in self.SESSION_COOKIE_NAMES):
                        attributes = self._parse_cookie_attributes(cookie_header)
                        risk_notes = self._assess_cookie_risk(attributes)
                        tokens.append(
                            ExtractedToken(
                                token_type="cookie",
                                name=name,
                                value=value[:30],
                                source="set_cookie_header",
                                attributes=attributes,
                                risk_notes=risk_notes,
                            )
                        )

        return tokens

    def _extract_from_auth_header(self, auth_header: str) -> list[ExtractedToken]:
        """Extract tokens from Authorization header."""
        tokens: list[ExtractedToken] = []
        if not auth_header:
            return tokens

        if auth_header.lower().startswith("bearer "):
            token_value = auth_header[7:].strip()
            tokens.append(
                ExtractedToken(
                    token_type="bearer_token",
                    name="Authorization",
                    value=token_value[:30],
                    source="authorization_header",
                )
            )

        return tokens

    def _extract_from_body(self, body: str) -> list[ExtractedToken]:
        """Extract tokens from response body."""
        tokens: list[ExtractedToken] = []

        try:
            data = json.loads(body)
            if isinstance(data, dict):
                for field_name in self.TOKEN_BODY_FIELDS:
                    if field_name in data:
                        tokens.append(
                            ExtractedToken(
                                token_type="body_field",
                                name=field_name,
                                value=str(data[field_name])[:30],
                                source="response_body",
                            )
                        )
        except (json.JSONDecodeError, TypeError):
            # Try regex extraction for non-JSON
            for pattern in [r'(?i)"token"\s*:\s*"([^"]+)"', r'(?i)"session_id"\s*:\s*"([^"]+)"']:
                matches = re.findall(pattern, body)
                for match in matches:
                    tokens.append(
                        ExtractedToken(
                            token_type="body_field",
                            name="extracted",
                            value=match[:30],
                            source="response_body_regex",
                        )
                    )

        return tokens

    def _extract_from_url(self, url: str) -> list[ExtractedToken]:
        """Extract tokens from URL parameters."""
        tokens: list[ExtractedToken] = []
        token_params = ["session_id", "token", "sid", "jwt", "access_token"]

        for param in token_params:
            pattern = rf"(?i){param}=([^&]+)"
            match = re.search(pattern, url)
            if match:
                tokens.append(
                    ExtractedToken(
                        token_type="url_param",
                        name=param,
                        value=match.group(1)[:30],
                        source="url_parameter",
                        risk_notes=["Session token in URL (leakage risk)"],
                    )
                )

        return tokens

    def _is_token_header(self, header_name: str) -> bool:
        """Check if header is a token-carrying header."""
        token_headers = ["x-auth-token", "x-session-id", "x-csrf-token", "x-api-key"]
        return header_name.lower() in token_headers

    def _parse_cookie_attributes(self, cookie_header: str) -> dict[str, str]:
        """Parse cookie attributes (Secure, HttpOnly, SameSite, etc.)."""
        attributes: dict[str, str] = {}
        parts = cookie_header.lower().split(";")[1:]  # Skip name=value
        for part in parts:
            attr = part.strip()
            if "=" in attr:
                k, v = attr.split("=", 1)
                attributes[k.strip()] = v.strip()
            else:
                attributes[attr] = "true"
        return attributes

    def _assess_cookie_risk(self, attributes: dict[str, str]) -> list[str]:
        """Assess security risks based on cookie attributes."""
        risks: list[str] = []
        if "httponly" not in attributes:
            risks.append("Missing HttpOnly flag — accessible via JavaScript")
        if "secure" not in attributes:
            risks.append("Missing Secure flag — transmitted over HTTP")
        if "samesite" not in attributes:
            risks.append("Missing SameSite — vulnerable to CSRF")
        return risks
