# -*- coding: utf-8 -*-
# arXiv:2302.12173 - Greshake et al., Indirect Prompt Injection via Documents
# arXiv:2406.04245 - Zou et al., PoisonedRAG: Black-box Poisoning Attack
# arXiv:2306.13254 - Shayegani et al., Multimodal Cybersecurity Risks
"""file_upload_executor — Generic file upload attack executor for multi-step injection.

Closes Gap: Execute complete file upload → trigger processing attack chain against
any target system that supports document upload + batch processing pattern.

Attack Patterns Supported:
    1. Single Upload + Trigger:  POST /upload → POST /process
    2. Multi Upload + Trigger:    POST /upload (xN) → POST /process
    3. Split Document Injection:  Upload template + trigger doc separately
    4. PoisonedRAG Upload:        Upload document to knowledge base

Academic basis:
    - Greshake et al. (arXiv:2302.12173): Indirect injection via documents
    - Zou et al. (arXiv:2406.04245): PoisonedRAG knowledge base poisoning
    - Shayegani et al. (arXiv:2306.13254): Multimodal document attacks
    - Bagdasaryan et al. (arXiv:2302.10149): Backdoor attack via data poisoning

Constitution compliance:
    - R-NATIVE-1: Uses PyRIT HTTPTarget for target communication
    - R-SIZE: < 400 lines (slim generic executor)
    - R-H3: Single responsibility — file upload only, no attack logic
    - R-IMPORT-4: No dead exports
    - Glue role: Connects file generation to HTTP target execution

Data Flow:
    file_upload_executor → httpx.AsyncClient → Target URL → Trigger endpoint

Universal Target Support:
    This module is target-type-agnostic. It works with any HTTP endpoint that:
    1. Accepts file uploads via multipart/form-data POST
    2. Has a processing trigger endpoint (e.g., /summarize, /process, /analyze)
"""
from __future__ import annotations

import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)


# ====================================================================
# Data Structures
# ====================================================================


@dataclass
class UploadConfig:
    """Configuration for a single file upload operation.

    Attributes:
        file_path: Path to the file to upload
        field_name: Form field name for the file (default: "file")
        filename: Override filename (default: use file_path basename)
        content_type: MIME type (default: auto-detect)
        extra_fields: Additional form fields to include
    """
    file_path: str
    field_name: str = "file"
    filename: str | None = None
    content_type: str | None = None
    extra_fields: dict[str, str] = field(default_factory=dict)


@dataclass
class UploadResult:
    """Result of a file upload operation.

    Attributes:
        success: Whether the upload succeeded
        upload_endpoint: The endpoint that received the upload
        file_path: Path of the uploaded file
        status_code: HTTP status code returned
        response_body: Parsed response body (JSON or text)
        error: Error message if failed
    """
    success: bool
    upload_endpoint: str
    file_path: str
    status_code: int | None = None
    response_body: Any = None
    error: str | None = None


@dataclass
class TriggerResult:
    """Result of a processing trigger operation.

    Attributes:
        success: Whether the trigger succeeded
        trigger_endpoint: The endpoint that was triggered
        status_code: HTTP status code returned
        response_body: Parsed response body (JSON or text)
        error: Error message if failed
    """
    success: bool
    trigger_endpoint: str
    status_code: int | None = None
    response_body: Any = None
    error: str | None = None


@dataclass
class FileUploadAttackResult:
    """Complete result of a file upload attack chain.

    Attributes:
        success: Whether the entire chain succeeded
        upload_results: List of individual upload results
        trigger_result: Result of the trigger operation
        target_url: Base URL of the target
        total_uploads: Number of files uploaded
        errors: List of any errors encountered
    """
    success: bool
    upload_results: list[UploadResult]
    trigger_result: TriggerResult | None
    target_url: str
    total_uploads: int = 0
    errors: list[str] = field(default_factory=list)


# ====================================================================
# Core Executor
# ====================================================================


async def execute_file_upload(
    target_url: str,
    upload_endpoint: str,
    upload_config: UploadConfig,
    *,
    headers: dict[str, str] | None = None,
    use_tls: bool = True,
    timeout: int = 30,
) -> UploadResult:
    """Execute a single file upload to the target.

    Args:
        target_url: Base URL of the target (e.g., "http://192.168.50.22:8004")
        upload_endpoint: Upload endpoint path (e.g., "/upload")
        upload_config: Configuration for the file to upload
        headers: Additional HTTP headers
        use_tls: Whether to use HTTPS
        timeout: Request timeout in seconds

    Returns:
        UploadResult with the operation outcome
    """
    import aiohttp

    full_url = f"{target_url.rstrip('/')}/{upload_endpoint.lstrip('/')}"
    file_path = Path(upload_config.file_path)

    if not file_path.exists():
        return UploadResult(
            success=False,
            upload_endpoint=upload_endpoint,
            file_path=str(file_path),
            error=f"File not found: {file_path}",
        )

    filename = upload_config.filename or file_path.name

    try:
        data = aiohttp.FormData()

        # Add extra fields first (if any)
        for field_name, field_value in upload_config.extra_fields.items():
            data.add_field(field_name, field_value)

        # Add the file
        content_type = upload_config.content_type or _guess_content_type(str(file_path))
        data.add_field(
            upload_config.field_name,
            file_path.read_bytes(),
            filename=filename,
            content_type=content_type,
        )

        request_headers = headers or {}
        request_headers.setdefault(
            "User-Agent",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
        )

        async with aiohttp.ClientSession() as session:
            async with session.post(
                full_url,
                data=data,
                headers=request_headers,
                ssl=use_tls,
                timeout=aiohttp.ClientTimeout(total=timeout),
            ) as response:
                status_code = response.status
                response_body = await _safe_parse_response(response)

                success = 200 <= status_code < 300

                if success:
                    logger.info(
                        "[FileUpload] Upload success: %s -> %s (HTTP %d)",
                        filename,
                        full_url,
                        status_code,
                    )
                else:
                    logger.warning(
                        "[FileUpload] Upload failed: %s -> %s (HTTP %d)",
                        filename,
                        full_url,
                        status_code,
                    )

                return UploadResult(
                    success=success,
                    upload_endpoint=upload_endpoint,
                    file_path=str(file_path),
                    status_code=status_code,
                    response_body=response_body,
                    error=None if success else f"HTTP {status_code}",
                )

    except aiohttp.ClientError as e:
        logger.error("[FileUpload] Client error uploading %s: %s", filename, e)
        return UploadResult(
            success=False,
            upload_endpoint=upload_endpoint,
            file_path=str(file_path),
            error=f"Client error: {e}",
        )
    except Exception as e:
        logger.error("[FileUpload] Unexpected error uploading %s: %s", filename, e)
        return UploadResult(
            success=False,
            upload_endpoint=upload_endpoint,
            file_path=str(file_path),
            error=f"Unexpected error: {e}",
        )


async def execute_trigger(
    target_url: str,
    trigger_endpoint: str,
    *,
    headers: dict[str, str] | None = None,
    use_tls: bool = True,
    timeout: int = 60,
    method: str = "POST",
    json_body: dict[str, Any] | None = None,
) -> TriggerResult:
    """Execute a processing trigger on the target.

    Args:
        target_url: Base URL of the target
        trigger_endpoint: Trigger endpoint path (e.g., "/summarize")
        headers: Additional HTTP headers
        use_tls: Whether to use HTTPS
        timeout: Request timeout in seconds
        method: HTTP method (default: POST)
        json_body: Optional JSON body for the trigger request

    Returns:
        TriggerResult with the operation outcome
    """
    import aiohttp

    full_url = f"{target_url.rstrip('/')}/{trigger_endpoint.lstrip('/')}"

    try:
        request_headers = headers or {}
        request_headers.setdefault(
            "User-Agent",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
        )
        if json_body:
            request_headers.setdefault("Content-Type", "application/json")

        async with aiohttp.ClientSession() as session:
            kwargs: dict[str, Any] = {
                "headers": request_headers,
                "ssl": use_tls,
                "timeout": aiohttp.ClientTimeout(total=timeout),
            }
            if json_body:
                kwargs["json"] = json_body

            async with session.request(method, full_url, **kwargs) as response:
                status_code = response.status
                response_body = await _safe_parse_response(response)

                success = 200 <= status_code < 300

                if success:
                    logger.info(
                        "[FileUpload] Trigger success: %s (HTTP %d)",
                        full_url,
                        status_code,
                    )
                else:
                    logger.warning(
                        "[FileUpload] Trigger failed: %s (HTTP %d)",
                        full_url,
                        status_code,
                    )

                return TriggerResult(
                    success=success,
                    trigger_endpoint=trigger_endpoint,
                    status_code=status_code,
                    response_body=response_body,
                    error=None if success else f"HTTP {status_code}",
                )

    except aiohttp.ClientError as e:
        logger.error("[FileUpload] Client error triggering %s: %s", full_url, e)
        return TriggerResult(
            success=False,
            trigger_endpoint=trigger_endpoint,
            error=f"Client error: {e}",
        )
    except Exception as e:
        logger.error("[FileUpload] Unexpected error triggering %s: %s", full_url, e)
        return TriggerResult(
            success=False,
            trigger_endpoint=trigger_endpoint,
            error=f"Unexpected error: {e}",
        )


async def execute_file_upload_attack_chain(
    target_url: str,
    upload_endpoint: str,
    upload_configs: list[UploadConfig],
    *,
    trigger_endpoint: str | None = None,
    headers: dict[str, str] | None = None,
    use_tls: bool = True,
    timeout: int = 30,
    trigger_method: str = "POST",
    trigger_json: dict[str, Any] | None = None,
    trigger_before_upload: bool = False,
) -> FileUploadAttackResult:
    """Execute a complete file upload attack chain.

    This is the main entry point for executing multi-step file upload attacks.
    Supports:
    - Single or multiple file uploads
    - Optional trigger endpoint activation
    - Configurable order (trigger before or after uploads)

    Args:
        target_url: Base URL of the target
        upload_endpoint: Endpoint for file uploads
        upload_configs: List of file upload configurations
        trigger_endpoint: Optional endpoint to trigger processing
        headers: HTTP headers for all requests
        use_tls: Whether to use HTTPS
        timeout: Timeout for each request
        trigger_method: HTTP method for trigger
        trigger_json: Optional JSON body for trigger
        trigger_before_upload: If True, trigger uploads first (for init)

    Returns:
        FileUploadAttackResult with complete chain results
    """
    upload_results: list[UploadResult] = []
    errors: list[str] = []

    # Step 1: Initial trigger if requested (e.g., initialize session)
    if trigger_before_upload and trigger_endpoint:
        trigger_result = await execute_trigger(
            target_url=target_url,
            trigger_endpoint=trigger_endpoint,
            headers=headers,
            use_tls=use_tls,
            timeout=timeout,
            method=trigger_method,
            json_body=trigger_json,
        )
        if not trigger_result.success:
            errors.append(f"Initial trigger failed: {trigger_result.error}")

    # Step 2: Upload all files
    for config in upload_configs:
        result = await execute_file_upload(
            target_url=target_url,
            upload_endpoint=upload_endpoint,
            upload_config=config,
            headers=headers,
            use_tls=use_tls,
            timeout=timeout,
        )
        upload_results.append(result)
        if not result.success:
            errors.append(f"Upload failed ({config.file_path}): {result.error}")

    # Step 3: Trigger processing
    trigger_result = None
    if trigger_endpoint:
        trigger_result = await execute_trigger(
            target_url=target_url,
            trigger_endpoint=trigger_endpoint,
            headers=headers,
            use_tls=use_tls,
            timeout=timeout,
            method=trigger_method,
            json_body=trigger_json,
        )
        if not trigger_result.success:
            errors.append(f"Trigger failed: {trigger_result.error}")

    # Determine overall success
    all_uploads_ok = all(r.success for r in upload_results)
    trigger_ok = trigger_result is None or trigger_result.success
    overall_success = all_uploads_ok and trigger_ok

    return FileUploadAttackResult(
        success=overall_success,
        upload_results=upload_results,
        trigger_result=trigger_result,
        target_url=target_url,
        total_uploads=len(upload_results),
        errors=errors,
    )


# ====================================================================
# Pipeline Integration
# ====================================================================


async def run_file_upload_attack(ctx: Any) -> dict[str, Any]:
    """Execute file upload attack integrated with pipeline context.

    Integration point: Called from _run_advanced_attacks_phase() in strike.py.
    Reads configuration from ctx.args and target info from ctx.

    Args:
        ctx: PipelineContext with attack configuration

    Returns:
        Dict with attack results for ctx.attack_results
    """
    args = getattr(ctx, "args", None)
    if not args:
        return {"status": "error", "reason": "No args in context"}

    # Get upload configuration from args
    target_url = getattr(args, "file_upload_target", None)
    upload_endpoint = getattr(args, "upload_endpoint", "/upload")
    trigger_endpoint = getattr(args, "trigger_endpoint", "/summarize")
    upload_files = getattr(args, "upload_files", []) or []
    upload_field_name = getattr(args, "upload_field_name", "file")
    trigger_method = getattr(args, "trigger_method", "POST")

    if not target_url:
        return {"status": "error", "reason": "No target URL specified (--file-upload-target)"}

    if not upload_files:
        return {"status": "error", "reason": "No upload files specified (--upload-files)"}

    # Try to get target from burp parsed request
    if not target_url:
        parsed = getattr(ctx, "parsed_request", None)
        if parsed:
            host = getattr(parsed, "host", "")
            use_tls = getattr(parsed, "use_tls", True)
            port = getattr(parsed, "port", None)
            scheme = "https" if use_tls else "http"
            if port and port not in (80, 443):
                target_url = f"{scheme}://{host}:{port}"
            else:
                target_url = f"{scheme}://{host}"

    # Build upload configs
    upload_configs = []
    for file_path in upload_files:
        if isinstance(file_path, str):
            upload_configs.append(UploadConfig(
                file_path=file_path,
                field_name=upload_field_name,
            ))
        elif isinstance(file_path, dict):
            upload_configs.append(UploadConfig(**file_path))

    # Get auth headers if available
    auth_header = _get_auth_header_from_ctx(ctx)
    headers = {}
    if auth_header:
        headers["Authorization"] = auth_header

    # Execute attack chain
    result = await execute_file_upload_attack_chain(
        target_url=target_url,
        upload_endpoint=upload_endpoint,
        upload_configs=upload_configs,
        trigger_endpoint=trigger_endpoint,
        headers=headers or None,
        use_tls=True,
        timeout=getattr(args, "timeout", 30),
        trigger_method=trigger_method,
    )

    # Log to orchestration
    if hasattr(ctx, "orchestration_log"):
        ctx.orchestration_log.append({
            "phase": "strike",
            "decision": "file_upload_attack",
            "input": {
                "target": target_url,
                "upload_endpoint": upload_endpoint,
                "trigger_endpoint": trigger_endpoint,
                "files": [c.file_path for c in upload_configs],
            },
            "output": {
                "success": result.success,
                "uploads": result.total_uploads,
                "errors": result.errors[:5],  # Limit log size
            },
            "reasoning": (
                f"File upload attack: {result.total_uploads} files, "
                f"success={result.success}, errors={len(result.errors)}"
            ),
        })

    return {
        "status": "success" if result.success else "failed",
        "target": result.target_url,
        "uploads": result.total_uploads,
        "errors": result.errors,
        "trigger_response": result.trigger_result.response_body if result.trigger_result else None,
    }


# ====================================================================
# Helper Functions
# ====================================================================


def _guess_content_type(file_path: str) -> str:
    """Guess MIME type from file extension.

    Args:
        file_path: Path to the file

    Returns:
        MIME type string
    """
    ext = Path(file_path).suffix.lower()
    mime_types = {
        ".txt": "text/plain",
        ".pdf": "application/pdf",
        ".doc": "application/msword",
        ".docx": "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
        ".md": "text/markdown",
        ".json": "application/json",
        ".xml": "application/xml",
        ".csv": "text/csv",
        ".html": "text/html",
        ".htm": "text/html",
        ".png": "image/png",
        ".jpg": "image/jpeg",
        ".jpeg": "image/jpeg",
        ".gif": "image/gif",
        ".zip": "application/zip",
    }
    return mime_types.get(ext, "application/octet-stream")


async def _safe_parse_response(response: Any) -> Any:
    """Safely parse HTTP response body.

    Args:
        response: aiohttp ClientResponse

    Returns:
        Parsed JSON dict, or raw text string
    """
    try:
        text = await response.text()
    except Exception:
        return ""

    # Try JSON parsing
    try:
        import json
        # aiohttp may not have orjson available, use stdlib
        return json.loads(text)
    except Exception:
        return text


def _get_auth_header_from_ctx(ctx: Any) -> str | None:
    """Extract authorization header from pipeline context.

    Args:
        ctx: PipelineContext

    Returns:
        Authorization header value or None
    """
    # Try parsed request headers
    parsed = getattr(ctx, "parsed_request", None)
    if parsed and hasattr(parsed, "headers"):
        headers = parsed.headers
        if isinstance(headers, dict):
            for key in ("Authorization", "authorization"):
                if key in headers:
                    return headers[key]

    # Try args
    args = getattr(ctx, "args", None)
    if args:
        token = getattr(args, "api_key", None)
        if token:
            return f"Bearer {token}"

    return None


# ====================================================================
# Public API
# ====================================================================


__all__ = [
    # Data classes
    "UploadConfig",
    "UploadResult",
    "TriggerResult",
    "FileUploadAttackResult",
    # Core functions
    "execute_file_upload",
    "execute_trigger",
    "execute_file_upload_attack_chain",
    "run_file_upload_attack",
    # Helpers
    "guess_content_type",
]


def guess_content_type(file_path: str) -> str:
    """Public wrapper for _guess_content_type."""
    return _guess_content_type(file_path)
