"""web_input_mapper.py - Input Point Identification & Classification.

Identifies and classifies input points in web APIs including URL parameters,
body fields, headers, and file upload endpoints.

Academic basis:
    - OWASP Input Validation
    - Kafasis et al. (2023) - Automated input surface analysis
    - OWASP WSTG: Input Validation Testing

Constitution compliance:
    - R-SIZE: < 800 lines
    - R-H3: Single responsibility — input mapping only
    - R-S1: No hardcoded target identifiers
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class InputType(Enum):
    """Types of input points."""
    URL_PARAM = "url_param"
    BODY_FIELD = "body_field"
    HEADER = "header"
    COOKIE = "cookie"
    PATH_PARAM = "path_param"
    FILE_UPLOAD = "file_upload"
    QUERY_STRING = "query_string"


class RiskLevel(Enum):
    """Risk levels for inputs."""
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass
class InputPoint:
    """A discovered input point."""

    name: str
    input_type: InputType
    endpoint: str
    method: str
    data_type: str = "string"  # string, int, json, file
    required: bool = False
    sanitized: bool = False
    risk_level: RiskLevel = RiskLevel.LOW
    attack_surfaces: list[str] = field(default_factory=list)


class WebInputMapper:
    """Map and classify web API input points."""

    # High-risk field names (likely injection points)
    HIGH_RISK_FIELDS: list[re.Pattern] = [
        re.compile(r"(?i)(?:query|search|filter|where)"),
        re.compile(r"(?i)(?:callback|redirect|return|url|next)"),
        re.compile(r"(?i)(?:path|file|dir|folder)"),
        re.compile(r"(?i)(?:command|exec|run|script)"),
        re.compile(r"(?i)(?:template|tpl|render|format)"),
    ]

    # SQL injection indicators
    SQLI_INDICATORS: list[str] = ["id", "order", "sort", "category", "type"]

    # XSS indicators
    XSS_INDICATORS: list[str] = ["name", "title", "content", "body", "message", "comment"]

    def __init__(self) -> None:
        self.input_points: list[InputPoint] = []

    def map_from_openapi(
        self, spec: dict[str, Any], path: str, method: str
    ) -> list[InputPoint]:
        """Map input points from OpenAPI specification."""
        inputs: list[InputPoint] = []

        path_spec = spec.get("paths", {}).get(path, {})
        method_spec = path_spec.get(method, {})
        if isinstance(method_spec, dict):
            for param in method_spec.get("parameters", []):
                param_type = self._param_type_to_input_type(param.get("in", "query"))

                input_point = InputPoint(
                    name=param.get("name", "unknown"),
                    input_type=param_type,
                    endpoint=path,
                    method=method,
                    data_type=param.get("type", "string"),
                    required=param.get("required", False),
                    risk_level=self._assess_input_risk(param),
                    attack_surfaces=self._identify_attack_surfaces(param),
                )
                inputs.append(input_point)

        self.input_points.extend(inputs)
        return inputs

    def map_from_traffic(
        self,
        request_method: str,
        request_path: str,
        request_params: dict[str, Any],
        request_headers: dict[str, str],
        request_body: dict[str, Any] | None = None,
    ) -> list[InputPoint]:
        """Map input points from HTTP traffic analysis."""
        inputs: list[InputPoint] = []

        # URL/Query params
        for name, value in request_params.items():
            input_point = InputPoint(
                name=name,
                input_type=InputType.URL_PARAM,
                endpoint=request_path,
                method=request_method,
                data_type=type(value).__name__,
                risk_level=self._assess_input_name_risk(name),
                attack_surfaces=self._identify_attack_surfaces({"name": name, "type": type(value).__name__}),
            )
            inputs.append(input_point)

        # Body fields
        if request_body and isinstance(request_body, dict):
            for name, value in request_body.items():
                input_point = InputPoint(
                    name=name,
                    input_type=InputType.BODY_FIELD,
                    endpoint=request_path,
                    method=request_method,
                    data_type=type(value).__name__,
                    risk_level=self._assess_input_name_risk(name),
                    attack_surfaces=self._identify_attack_surfaces({"name": name, "type": type(value).__name__}),
                )
                inputs.append(input_point)

        # Auth headers
        for header in ["Authorization", "X-API-Key", "X-Auth-Token"]:
            if header in request_headers:
                inputs.append(InputPoint(
                    name=header,
                    input_type=InputType.HEADER,
                    endpoint=request_path,
                    method=request_method,
                    data_type="string",
                    required=True,
                    risk_level=RiskLevel.MEDIUM,
                    attack_surfaces=["auth_bypass", "token_theft"],
                ))

        self.input_points.extend(inputs)
        return inputs

    def get_high_risk_inputs(self) -> list[InputPoint]:
        """Get high-risk input points."""
        return [
            ip for ip in self.input_points
            if ip.risk_level in (RiskLevel.HIGH, RiskLevel.CRITICAL)
        ]

    def get_attack_surface_summary(self) -> dict[str, list[str]]:
        """Get attack surface summary."""
        surfaces: dict[str, list[str]] = {}
        for ip in self.input_points:
            for surface in ip.attack_surfaces:
                if surface not in surfaces:
                    surfaces[surface] = []
                surfaces[surface].append(f"{ip.endpoint}.{ip.name}")
        return surfaces

    def get_input_summary(self) -> dict[str, Any]:
        """Get input mapping summary."""
        if not self.input_points:
            return {"total": 0, "types": {}, "high_risk": 0}

        types: dict[str, int] = {}
        for ip in self.input_points:
            types[ip.input_type.value] = types.get(ip.input_type.value, 0) + 1

        return {
            "total": len(self.input_points),
            "unique_names": len(set(ip.name for ip in self.input_points)),
            "types": types,
            "high_risk": len(self.get_high_risk_inputs()),
            "endpoints_covered": len(set(ip.endpoint for ip in self.input_points)),
        }

    def _param_type_to_input_type(self, param_in: str) -> InputType:
        """Convert OpenAPI param location to InputType."""
        mapping: dict[str, InputType] = {
            "query": InputType.URL_PARAM,
            "path": InputType.PATH_PARAM,
            "header": InputType.HEADER,
            "cookie": InputType.COOKIE,
            "body": InputType.BODY_FIELD,
        }
        return mapping.get(param_in, InputType.URL_PARAM)

    def _assess_input_risk(self, param: dict[str, Any]) -> RiskLevel:
        """Assess risk level of an input parameter."""
        name = param.get("name", "")
        param_type = param.get("type", "string")

        for pattern in self.HIGH_RISK_FIELDS:
            if pattern.search(name):
                return RiskLevel.HIGH

        if param_type == "file":
            return RiskLevel.HIGH

        return RiskLevel.LOW

    def _assess_input_name_risk(self, name: str) -> RiskLevel:
        """Assess risk based on input name."""
        for pattern in self.HIGH_RISK_FIELDS:
            if pattern.search(name):
                return RiskLevel.HIGH
        return RiskLevel.LOW

    def _identify_attack_surfaces(self, param: dict[str, Any]) -> list[str]:
        """Identify potential attack surfaces for a parameter."""
        surfaces: list[str] = []
        name = param.get(" name", param.get("name", ""))

        if name.lower() in self.SQLI_INDICATORS:
            surfaces.append("sql_injection")
        if name.lower() in self.XSS_INDICATORS:
            surfaces.append("xss")
        if "file" in name.lower() or param.get("type") == "file":
            surfaces.append("file_upload")
        if "redirect" in name.lower() or "url" in name.lower():
            surfaces.append("open_redirect")
        if "callback" in name.lower():
            surfaces.append("callback_injection")

        return surfaces if surfaces else ["generic_input"]
