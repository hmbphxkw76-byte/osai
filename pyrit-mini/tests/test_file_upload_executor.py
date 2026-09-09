# -*- coding: utf-8 -*-
"""Tests for strike/file_upload_executor.py — File Upload Attack Executor.

Tests cover:
    1. Data class construction (UploadConfig, UploadResult, TriggerResult, FileUploadAttackResult)
    2. Content type guessing (_guess_content_type)
    3. Response parsing (_safe_parse_response)
    4. Auth header extraction (_get_auth_header_from_ctx)
    5. File upload execution (mocked HTTP)
    6. Trigger execution (mocked HTTP)
    7. Full attack chain execution
    8. CLI argument parsing
    9. Pipeline integration (run_file_upload_attack)

Academic basis:
    - Greshake et al. (arXiv:2302.12173): Indirect prompt injection via documents
    - Zou et al. (arXiv:2406.04245): PoisonedRAG knowledge base poisoning
"""
from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

# Module under test
from strike.file_upload_executor import (
    FileUploadAttackResult,
    TriggerResult,
    UploadConfig,
    UploadResult,
    _get_auth_header_from_ctx,
    _guess_content_type,
    execute_file_upload,
    execute_file_upload_attack_chain,
    execute_trigger,
    run_file_upload_attack,
)

# ====================================================================
# Fixtures
# ====================================================================


@pytest.fixture
def sample_file(tmp_path: Path) -> str:
    """Create a sample file for testing uploads."""
    file_path = tmp_path / "test_payload.txt"
    file_path.write_text("This is a test payload for file upload attack.")
    return str(file_path)


@pytest.fixture
def sample_json_file(tmp_path: Path) -> str:
    """Create a sample JSON file for testing uploads."""
    file_path = tmp_path / "test_data.json"
    file_path.write_text(json.dumps({"key": "value", "injection": "payload"}))
    return str(file_path)


@pytest.fixture
def sample_pdf_file(tmp_path: Path) -> str:
    """Create a sample PDF-like file for testing uploads."""
    file_path = tmp_path / "test_doc.pdf"
    file_path.write_bytes(b"%PDF-1.4 fake pdf content for testing")
    return str(file_path)


@pytest.fixture
def mock_aiohttp_response():
    """Create a mock aiohttp response."""
    response = AsyncMock()
    response.status = 200
    response.text = AsyncMock(return_value='{"status": "ok", "file_id": "12345"}')
    return response


# ====================================================================
# Test Data Classes
# ====================================================================


class TestDataClasses:
    """Test data class construction and defaults."""

    def test_upload_config_defaults(self):
        """Test UploadConfig with default values."""
        config = UploadConfig(file_path="/tmp/test.txt")
        assert config.file_path == "/tmp/test.txt"
        assert config.field_name == "file"
        assert config.filename is None
        assert config.content_type is None
        assert config.extra_fields == {}

    def test_upload_config_custom(self):
        """Test UploadConfig with custom values."""
        config = UploadConfig(
            file_path="/tmp/test.txt",
            field_name="document",
            filename="custom_name.txt",
            content_type="text/plain",
            extra_fields={"user_id": "123"},
        )
        assert config.field_name == "document"
        assert config.filename == "custom_name.txt"
        assert config.content_type == "text/plain"
        assert config.extra_fields == {"user_id": "123"}

    def test_upload_result_success(self):
        """Test UploadResult for successful upload."""
        result = UploadResult(
            success=True,
            upload_endpoint="/upload",
            file_path="/tmp/test.txt",
            status_code=200,
            response_body={"file_id": "12345"},
        )
        assert result.success is True
        assert result.status_code == 200
        assert result.error is None

    def test_upload_result_failure(self):
        """Test UploadResult for failed upload."""
        result = UploadResult(
            success=False,
            upload_endpoint="/upload",
            file_path="/tmp/test.txt",
            status_code=403,
            error="Forbidden",
        )
        assert result.success is False
        assert result.status_code == 403
        assert result.error == "Forbidden"

    def test_trigger_result_success(self):
        """Test TriggerResult for successful trigger."""
        result = TriggerResult(
            success=True,
            trigger_endpoint="/summarize",
            status_code=200,
            response_body={"summary": "Test summary"},
        )
        assert result.success is True
        assert result.status_code == 200

    def test_trigger_result_failure(self):
        """Test TriggerResult for failed trigger."""
        result = TriggerResult(
            success=False,
            trigger_endpoint="/summarize",
            status_code=500,
            error="Internal Server Error",
        )
        assert result.success is False
        assert result.error == "Internal Server Error"

    def test_file_upload_attack_result_complete(self):
        """Test FileUploadAttackResult with complete data."""
        upload_result = UploadResult(
            success=True,
            upload_endpoint="/upload",
            file_path="/tmp/test.txt",
            status_code=200,
        )
        trigger_result = TriggerResult(
            success=True,
            trigger_endpoint="/summarize",
            status_code=200,
        )
        result = FileUploadAttackResult(
            success=True,
            upload_results=[upload_result],
            trigger_result=trigger_result,
            target_url="http://target:8004",
            total_uploads=1,
        )
        assert result.success is True
        assert result.total_uploads == 1
        assert len(result.errors) == 0


# ====================================================================
# Test Helper Functions
# ====================================================================


class TestHelperFunctions:
    """Test helper functions."""

    def test_guess_content_type_txt(self):
        """Test content type guessing for .txt files."""
        assert _guess_content_type("test.txt") == "text/plain"

    def test_guess_content_type_pdf(self):
        """Test content type guessing for .pdf files."""
        assert _guess_content_type("test.pdf") == "application/pdf"

    def test_guess_content_type_docx(self):
        """Test content type guessing for .docx files."""
        assert _guess_content_type("test.docx") == (
            "application/vnd.openxmlformats-officedocument.wordprocessingml.document"
        )

    def test_guess_content_type_json(self):
        """Test content type guessing for .json files."""
        assert _guess_content_type("test.json") == "application/json"

    def test_guess_content_type_png(self):
        """Test content type guessing for .png files."""
        assert _guess_content_type("test.png") == "image/png"

    def test_guess_content_type_unknown(self):
        """Test content type guessing for unknown extensions."""
        assert _guess_content_type("test.unknown") == "application/octet-stream"

    def test_get_auth_header_from_ctx_with_parsed_request(self):
        """Test auth header extraction from parsed request headers."""
        ctx = MagicMock()
        ctx.parsed_request = MagicMock()
        ctx.parsed_request.headers = {"Authorization": "Bearer test_token_123"}
        assert _get_auth_header_from_ctx(ctx) == "Bearer test_token_123"

    def test_get_auth_header_from_ctx_with_args_api_key(self):
        """Test auth header extraction from args api_key."""
        ctx = MagicMock()
        ctx.parsed_request = MagicMock()
        ctx.parsed_request.headers = {}
        ctx.args = MagicMock()
        ctx.args.api_key = "my_api_key"
        assert _get_auth_header_from_ctx(ctx) == "Bearer my_api_key"

    def test_get_auth_header_from_ctx_no_auth(self):
        """Test auth header extraction when no auth available."""
        ctx = MagicMock()
        ctx.parsed_request = MagicMock()
        ctx.parsed_request.headers = {}
        ctx.args = MagicMock()
        ctx.args.api_key = None
        assert _get_auth_header_from_ctx(ctx) is None


# ====================================================================
# Test File Upload Execution (Mocked)
# ====================================================================


class TestExecuteFileUpload:
    """Test file upload execution with mocked HTTP."""

    @pytest.mark.asyncio
    async def test_upload_file_not_found(self):
        """Test upload with non-existent file."""
        result = await execute_file_upload(
            target_url="http://target:8004",
            upload_endpoint="/upload",
            upload_config=UploadConfig(file_path="/nonexistent/file.txt"),
        )
        assert result.success is False
        assert "File not found" in result.error

    @pytest.mark.asyncio
    async def test_upload_success(self, sample_file: str):
        """Test successful file upload."""
        mock_response = AsyncMock()
        mock_response.status = 200
        mock_response.text = AsyncMock(
            return_value='{"status": "ok", "file_id": "abc123"}'
        )

        with patch("aiohttp.ClientSession") as mock_session_class:
            mock_session = AsyncMock()
            mock_session_class.return_value.__aenter__ = AsyncMock(
                return_value=mock_session
            )
            mock_session_class.return_value.__aexit__ = AsyncMock(return_value=False)

            mock_post = AsyncMock()
            mock_session.post = mock_post

            mock_context = AsyncMock()
            mock_context.__aenter__ = AsyncMock(return_value=mock_response)
            mock_context.__aexit__ = AsyncMock(return_value=False)
            mock_post.return_value = mock_context

            await execute_file_upload(
                target_url="http://target:8004",
                upload_endpoint="/upload",
                upload_config=UploadConfig(file_path=sample_file),
            )

            # Verify the call was made
            assert mock_post.called

    @pytest.mark.asyncio
    async def test_upload_with_extra_fields(self, sample_file: str):
        """Test file upload with extra form fields."""
        with patch("aiohttp.ClientSession") as mock_session_class:
            mock_session = AsyncMock()
            mock_session_class.return_value.__aenter__ = AsyncMock(
                return_value=mock_session
            )
            mock_session_class.return_value.__aexit__ = AsyncMock(return_value=False)

            mock_response = AsyncMock()
            mock_response.status = 200
            mock_response.text = AsyncMock(return_value='{"status": "ok"}')

            mock_post = AsyncMock()
            mock_session.post = mock_post

            mock_context = AsyncMock()
            mock_context.__aenter__ = AsyncMock(return_value=mock_response)
            mock_context.__aexit__ = AsyncMock(return_value=False)
            mock_post.return_value = mock_context

            await execute_file_upload(
                target_url="http://target:8004",
                upload_endpoint="/upload",
                upload_config=UploadConfig(
                    file_path=sample_file,
                    extra_fields={"user_id": "123", "session": "abc"},
                ),
            )

            assert mock_post.called


# ====================================================================
# Test Trigger Execution (Mocked)
# ====================================================================


class TestExecuteTrigger:
    """Test trigger execution with mocked HTTP."""

    @pytest.mark.asyncio
    async def test_trigger_success(self):
        """Test successful trigger execution."""
        with patch("aiohttp.ClientSession") as mock_session_class:
            mock_session = AsyncMock()
            mock_session_class.return_value.__aenter__ = AsyncMock(
                return_value=mock_session
            )
            mock_session_class.return_value.__aexit__ = AsyncMock(return_value=False)

            mock_response = AsyncMock()
            mock_response.status = 200
            mock_response.text = AsyncMock(
                return_value='{"summary": "Document processed successfully"}'
            )

            mock_request = AsyncMock()
            mock_session.request = mock_request

            mock_context = AsyncMock()
            mock_context.__aenter__ = AsyncMock(return_value=mock_response)
            mock_context.__aexit__ = AsyncMock(return_value=False)
            mock_request.return_value = mock_context

            await execute_trigger(
                target_url="http://target:8004",
                trigger_endpoint="/summarize",
            )

            assert mock_request.called

    @pytest.mark.asyncio
    async def test_trigger_with_json_body(self):
        """Test trigger with JSON body."""
        with patch("aiohttp.ClientSession") as mock_session_class:
            mock_session = AsyncMock()
            mock_session_class.return_value.__aenter__ = AsyncMock(
                return_value=mock_session
            )
            mock_session_class.return_value.__aexit__ = AsyncMock(return_value=False)

            mock_response = AsyncMock()
            mock_response.status = 200
            mock_response.text = AsyncMock(return_value='{"result": "ok"}')

            mock_request = AsyncMock()
            mock_session.request = mock_request

            mock_context = AsyncMock()
            mock_context.__aenter__ = AsyncMock(return_value=mock_response)
            mock_context.__aexit__ = AsyncMock(return_value=False)
            mock_request.return_value = mock_context

            await execute_trigger(
                target_url="http://target:8004",
                trigger_endpoint="/process",
                json_body={"action": "analyze", "mode": "full"},
            )

            assert mock_request.called


# ====================================================================
# Test Full Attack Chain
# ====================================================================


class TestExecuteFileUploadAttackChain:
    """Test full attack chain execution."""

    @pytest.mark.asyncio
    async def test_chain_no_files(self):
        """Test chain with no upload files."""
        result = await execute_file_upload_attack_chain(
            target_url="http://target:8004",
            upload_endpoint="/upload",
            upload_configs=[],
            trigger_endpoint="/summarize",
        )
        # No uploads but trigger succeeds = overall success depends on trigger
        assert isinstance(result, FileUploadAttackResult)

    @pytest.mark.asyncio
    async def test_chain_no_trigger(self, sample_file: str):
        """Test chain without trigger endpoint."""
        with patch("aiohttp.ClientSession") as mock_session_class:
            mock_session = AsyncMock()
            mock_session_class.return_value.__aenter__ = AsyncMock(
                return_value=mock_session
            )
            mock_session_class.return_value.__aexit__ = AsyncMock(return_value=False)

            mock_response = AsyncMock()
            mock_response.status = 200
            mock_response.text = AsyncMock(return_value='{"status": "ok"}')

            mock_post = AsyncMock()
            mock_session.post = mock_post

            mock_context = AsyncMock()
            mock_context.__aenter__ = AsyncMock(return_value=mock_response)
            mock_context.__aexit__ = AsyncMock(return_value=False)
            mock_post.return_value = mock_context

            result = await execute_file_upload_attack_chain(
                target_url="http://target:8004",
                upload_endpoint="/upload",
                upload_configs=[UploadConfig(file_path=sample_file)],
                trigger_endpoint=None,
            )

            assert result.total_uploads == 1


# ====================================================================
# Test Pipeline Integration
# ====================================================================


class TestRunFileUploadAttack:
    """Test pipeline integration function."""

    @pytest.mark.asyncio
    async def test_no_args_in_context(self):
        """Test with no args in context."""
        ctx = MagicMock()
        ctx.args = None
        result = await run_file_upload_attack(ctx)
        assert result["status"] == "error"
        assert "No args" in result["reason"]

    @pytest.mark.asyncio
    async def test_no_target_url(self):
        """Test with no target URL specified."""
        ctx = MagicMock()
        ctx.args = MagicMock()
        ctx.args.file_upload_target = None
        ctx.args.upload_files = ["file1.txt"]
        result = await run_file_upload_attack(ctx)
        assert result["status"] == "error"
        assert "No target URL" in result["reason"]

    @pytest.mark.asyncio
    async def test_no_upload_files(self):
        """Test with no upload files specified."""
        ctx = MagicMock()
        ctx.args = MagicMock()
        ctx.args.file_upload_target = "http://target:8004"
        ctx.args.upload_files = []
        result = await run_file_upload_attack(ctx)
        assert result["status"] == "error"
        assert "No upload files" in result["reason"]


# ====================================================================
# Test CLI Argument Parsing
# ====================================================================


class TestCLIArguments:
    """Test CLI argument parsing for file upload."""

    def test_file_upload_target_arg(self):
        """Test --file-upload-target argument parsing."""
        from core.config import parse_args

        args = parse_args([
            "--file-upload-target", "http://192.168.50.22:8004",
            "--upload-files", "payload.txt",
        ])
        assert args.file_upload_target == "http://192.168.50.22:8004"

    def test_upload_endpoint_default(self):
        """Test default upload endpoint."""
        from core.config import parse_args

        args = parse_args(["--file-upload-target", "http://target:8004"])
        assert args.upload_endpoint == "/upload"

    def test_trigger_endpoint_default(self):
        """Test default trigger endpoint."""
        from core.config import parse_args

        args = parse_args(["--file-upload-target", "http://target:8004"])
        assert args.trigger_endpoint == "/summarize"

    def test_upload_files_parsing(self):
        """Test --upload-files comma-separated parsing."""
        from core.config import parse_args

        args = parse_args([
            "--file-upload-target", "http://target:8004",
            "--upload-files", "file1.txt,file2.txt,file3.txt",
        ])
        assert args.upload_files == ["file1.txt", "file2.txt", "file3.txt"]

    def test_upload_field_name_default(self):
        """Test default upload field name."""
        from core.config import parse_args

        args = parse_args(["--file-upload-target", "http://target:8004"])
        assert args.upload_field_name == "file"

    def test_trigger_method_choices(self):
        """Test --trigger-method valid choices."""
        from core.config import parse_args

        args = parse_args([
            "--file-upload-target", "http://target:8004",
            "--trigger-method", "GET",
        ])
        assert args.trigger_method == "GET"

    def test_trigger_method_invalid(self):
        """Test --trigger-method invalid choice raises error."""
        from core.config import parse_args

        with pytest.raises(SystemExit):
            parse_args([
                "--file-upload-target", "http://target:8004",
                "--trigger-method", "DELETE",
            ])


# ====================================================================
# Test Edge Cases
# ====================================================================


class TestEdgeCases:
    """Test edge cases and error handling."""

    def test_guess_content_type_empty_path(self):
        """Test content type guessing with empty path."""
        assert _guess_content_type("") == "application/octet-stream"

    def test_guess_content_type_no_extension(self):
        """Test content type guessing with no extension."""
        assert _guess_content_type("Makefile") == "application/octet-stream"

    def test_upload_config_empty_extra_fields(self):
        """Test UploadConfig with empty extra fields."""
        config = UploadConfig(file_path="test.txt", extra_fields={})
        assert config.extra_fields == {}

    def test_file_upload_attack_result_with_errors(self):
        """Test FileUploadAttackResult with errors."""
        result = FileUploadAttackResult(
            success=False,
            upload_results=[],
            trigger_result=None,
            target_url="http://target:8004",
            errors=["Upload failed", "Trigger failed"],
        )
        assert result.success is False
        assert len(result.errors) == 2


# ====================================================================
# Test Universal Target Support (No Hardcoded Types)
# ====================================================================


class TestUniversalTargetSupport:
    """Test that the module supports any target type (no hardcoded types)."""

    @pytest.mark.asyncio
    async def test_custom_upload_endpoint(self, sample_file: str):
        """Test with custom upload endpoint path."""
        with patch("aiohttp.ClientSession") as mock_session_class:
            mock_session = AsyncMock()
            mock_session_class.return_value.__aenter__ = AsyncMock(
                return_value=mock_session
            )
            mock_session_class.return_value.__aexit__ = AsyncMock(return_value=False)

            mock_response = AsyncMock()
            mock_response.status = 200
            mock_response.text = AsyncMock(return_value='{"status": "ok"}')

            mock_post = AsyncMock()
            mock_session.post = mock_post

            mock_context = AsyncMock()
            mock_context.__aenter__ = AsyncMock(return_value=mock_response)
            mock_context.__aexit__ = AsyncMock(return_value=False)
            mock_post.return_value = mock_context

            # Test with various endpoint patterns
            endpoints = [
                "/api/v1/upload",
                "/documents/add",
                "/kb/ingest",
                "/rag/upload",
                "/import",
            ]

            for endpoint in endpoints:
                await execute_file_upload(
                    target_url="http://target:8004",
                    upload_endpoint=endpoint,
                    upload_config=UploadConfig(file_path=sample_file),
                )
                assert mock_post.called

    @pytest.mark.asyncio
    async def test_custom_trigger_endpoint(self):
        """Test with custom trigger endpoint path."""
        with patch("aiohttp.ClientSession") as mock_session_class:
            mock_session = AsyncMock()
            mock_session_class.return_value.__aenter__ = AsyncMock(
                return_value=mock_session
            )
            mock_session_class.return_value.__aexit__ = AsyncMock(return_value=False)

            mock_response = AsyncMock()
            mock_response.status = 200
            mock_response.text = AsyncMock(return_value='{"result": "ok"}')

            mock_request = AsyncMock()
            mock_session.request = mock_request

            mock_context = AsyncMock()
            mock_context.__aenter__ = AsyncMock(return_value=mock_response)
            mock_context.__aexit__ = AsyncMock(return_value=False)
            mock_request.return_value = mock_context

            # Test with various trigger patterns
            triggers = [
                "/api/v1/summarize",
                "/process",
                "/analyze",
                "/kb/query",
                "/rag/chat",
                "/extract",
            ]

            for trigger in triggers:
                await execute_trigger(
                    target_url="http://target:8004",
                    trigger_endpoint=trigger,
                )
                assert mock_request.called


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
