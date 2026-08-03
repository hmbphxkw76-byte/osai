# Copyright (c) 2026 OSAI Project.
# Licensed under the MIT license.

"""Tests for the decoupled pipeline stages (pipeline/)."""

import asyncio

import pytest

from pipeline.models import (
    AuthDecision,
    PipelineContext,
    PlatformVendor,
    TargetCategory,
    TargetClassification,
)
from pipeline.registry import autodiscover, get_stage, list_stages, register
from pipeline.stages.base import PipelineStage
from pipeline.context_loader import load_context
from pipeline.stages.classify_stage import ClassifyStage
from pipeline.stages.auth_stage import AuthStage


# ───────────────────────────────────────────────────────────
# 模型层
# ───────────────────────────────────────────────────────────
def test_target_classification_to_dict():
    tc = TargetClassification(
        category=TargetCategory.MODEL_PLATFORM,
        platform_vendor=PlatformVendor.OLLAMA,
        requires_auth=False,
        confidence=0.85,
    )
    d = tc.to_dict()
    assert d["category"] == "model_platform"
    assert d["platform_vendor"] == "ollama"
    assert d["confidence"] == 0.85


def test_pipeline_context_to_dict():
    ctx = PipelineContext(target_url="https://x.test", org_domains=["x.test"])
    d = ctx.to_dict()
    assert d["target_url"] == "https://x.test"
    assert d["org_domains"] == ["x.test"]


# ───────────────────────────────────────────────────────────
# 注册表
# ───────────────────────────────────────────────────────────
def test_registry_has_core_stages():
    autodiscover()
    names = list_stages()
    for expected in ("classify", "auth", "recon", "export"):
        assert expected in names


def test_registry_get_stage_returns_class():
    autodiscover()
    cls = get_stage("classify")
    assert issubclass(cls, PipelineStage)


def test_registry_register_custom():
    class DummyStage(PipelineStage):
        name = "dummy"

        async def run(self, context):  # noqa: D401
            return "ok"

    register(DummyStage)
    assert "dummy" in list_stages()
    assert get_stage("dummy") is DummyStage


# ───────────────────────────────────────────────────────────
# 分类阶段 (离线, 不启动浏览器)
# ───────────────────────────────────────────────────────────
def test_classify_ollama_vendor():
    stage = ClassifyStage()
    ctx = PipelineContext(
        target_url="http://localhost:11434/api/tags",
        target_type_hint="auto",
    )
    # 直接调用 _detect_vendor 验证厂商识别
    vendor = stage._detect_vendor(ctx.target_url)
    assert vendor.value == "ollama"


def test_classify_openai_vendor():
    stage = ClassifyStage()
    assert stage._detect_vendor("https://api.openai.com/v1/models").value == "openai"


def test_classify_lm_studio_vendor():
    stage = ClassifyStage()
    assert stage._detect_vendor("http://localhost:1234/v1/models").value == "lm_studio"


def test_classify_category_model_platform_by_vendor():
    """命中厂商指纹即判定为模型平台 (即使无浏览器)。"""
    stage = ClassifyStage()

    class _Ctx:
        target_url = "http://localhost:11434/api/generate"
        target_type_hint = "auto"

    classification = asyncio.run(stage.run(_Ctx()))
    assert classification.category == TargetCategory.MODEL_PLATFORM
    assert classification.platform_vendor.value == "ollama"


def test_classify_user_hint_override():
    stage = ClassifyStage()

    class _Ctx:
        target_url = "http://localhost:11434/api/generate"
        target_type_hint = "llm_webapp"

    classification = asyncio.run(stage.run(_Ctx()))
    assert classification.category == TargetCategory.LLM_WEBAPP


# ───────────────────────────────────────────────────────────
# 认证决策阶段
# ───────────────────────────────────────────────────────────
def _ctx_with(classification: TargetClassification, api_key="", auth_type_hint="auto"):
    return PipelineContext(
        target_url="https://x.test",
        api_key=api_key,
        auth_type_hint=auth_type_hint,
        classification=classification,
    )


def test_auth_decision_model_platform_with_key():
    cls = TargetClassification(category=TargetCategory.MODEL_PLATFORM, requires_auth=False)
    ctx = _ctx_with(cls, api_key="sk-test-123")
    decision = asyncio.run(AuthStage().run(ctx))
    assert decision.strategy_name == "APIKeyAuth"
    assert decision.api_key_env == "API_KEY"


def test_auth_decision_model_platform_no_key():
    cls = TargetClassification(category=TargetCategory.MODEL_PLATFORM, requires_auth=False)
    ctx = _ctx_with(cls, api_key="")
    decision = asyncio.run(AuthStage().run(ctx))
    assert decision.strategy_name == "NoneAuth"


def test_auth_decision_webapp_same_domain():
    cls = TargetClassification(
        category=TargetCategory.LLM_WEBAPP,
        requires_auth=True,
        auth_topology="same_domain",
    )
    ctx = _ctx_with(cls)
    decision = asyncio.run(AuthStage().run(ctx))
    assert decision.strategy_name == "PlaywrightAuth"
    assert decision.needs_browser is True
    assert decision.needs_human is False


def test_auth_decision_webapp_cross_domain_with_otp():
    cls = TargetClassification(
        category=TargetCategory.LLM_WEBAPP,
        requires_auth=True,
        auth_topology="cross_domain",
        second_factor="otp",
    )
    ctx = _ctx_with(cls)
    decision = asyncio.run(AuthStage().run(ctx))
    assert decision.strategy_name == "PlaywrightAuth"
    assert decision.needs_browser is True
    assert decision.needs_human is True


def test_auth_decision_webapp_no_auth():
    cls = TargetClassification(
        category=TargetCategory.LLM_WEBAPP, requires_auth=False, auth_topology="none"
    )
    ctx = _ctx_with(cls)
    decision = asyncio.run(AuthStage().run(ctx))
    assert decision.strategy_name == "NoneAuth"


# ───────────────────────────────────────────────────────────
# context_loader (.env)
# ───────────────────────────────────────────────────────────
def test_load_context_defaults():
    ctx = load_context()
    # 从 .env (默认 example.test) 加载
    assert isinstance(ctx.target_url, str)
    assert ctx.export_formats  # 至少包含 json/pyrit/garak (来自 .env 或默认)
    assert ctx.target_type_hint in ("auto", "llm_webapp", "model_platform")


def test_load_context_override():
    ctx = load_context(overrides={"target_url": "https://override.test"})
    assert ctx.target_url == "https://override.test"


# ───────────────────────────────────────────────────────────
# StageResult 隔离 (阶段异常不向上抛)
# ───────────────────────────────────────────────────────────
def test_stage_result_captures_exception():
    class BoomStage(PipelineStage):
        name = "boom"

        async def run(self, context):
            raise RuntimeError("boom")

    result = asyncio.run(BoomStage().execute(PipelineContext()))
    assert result.status == "failed"
    assert result.error == "boom"


def test_stage_result_success():
    class OkStage(PipelineStage):
        name = "ok"

        async def run(self, context):
            return {"ok": True}

    result = asyncio.run(OkStage().execute(PipelineContext()))
    assert result.status == "success"
    assert result.artifact == {"ok": True}
