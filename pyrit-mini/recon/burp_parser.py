"""Burp Suite HTTP -> PyRIT HTTPTarget  (facade)

This module is now a thin re-export facade. The implementation was split by
responsibility (SRP) into focused modules:

    - recon._burp_models            : TargetFingerprint, ParsedBurpRequest dataclasses
    - recon._burp_enumeration       : session enumeration plan + chat-id field names
    - recon._burp_fingerprint       : raw HTTP parsing + fingerprint extraction
    - recon._burp_request_parsers   : multi-format input detection + request parsing

The public surface below is unchanged so all existing importers
(`recon.target_router`, `recon.target_builder`, `recon.capability_probe`,
`recon.capability_detector`, `core.context`, tests, ...) keep working.
"""

from __future__ import annotations

from recon._burp_enumeration import (
    _CHAT_ID_FIELD_NAMES,
    _ENUMERATION_ARGS,
    _build_enumeration_plan,
    set_enumeration_args,
)
from recon._burp_fingerprint import (
    _extract_fingerprint,
    _parse_raw_http,
    _split_request_response,
)
from recon._burp_models import ParsedBurpRequest, TargetFingerprint
from recon._burp_request_parsers import (
    _REQUEST_LINE_RE,
    _detect_input_format,
    _parse_har,
    _parse_postman,
    _parse_sitemap,
    _request_from_url,
    _split_multi_requests,
    build_raw_http_request,
    parse_burp_request,
    parse_burp_requests,
)

# Sub-helper names that historically lived in this module's namespace (imported
# from the lower-level recon.fingerprint / recon.model.* helpers) are re-exported
# so callers like `from recon.burp_parser import extract_chat_id_from_response` keep
# working unchanged.
from recon.fingerprint import (
    extract_ai_framework_fingerprint,
    extract_ai_sdk_from_request_headers,
    split_response_headers_body,
)
from recon.model.api_classifier import detect_api_category
from recon.model.prompt_injector import (
    build_full_url,
    detect_and_inject_chat_id_placeholder,
    extract_chat_id_from_response,
    extract_model_info_from_response,
    extract_original_prompt_value,
    infer_tls,
    inject_prompt_placeholder,
)

# Re-exports from capability_detector and target_builder for backwards compatibility
from recon.capability_detector import (  # noqa: F401, E402
    _detect_language,
    _detect_model_family,
    _infer_json_path,
    _probe_capabilities,
    probe_active_capabilities,
    probe_response_path,
)
from recon.target_builder import (  # noqa: F401, E402
    ChatIdStateManager,
    RequestPreprocessor,
    build_http_target,
)
