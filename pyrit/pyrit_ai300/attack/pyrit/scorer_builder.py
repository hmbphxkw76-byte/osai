# -*- coding: utf-8 -*-
"""
AI-300 Framework - Scorer Builder
PyRIT 评分器构建模块

职责：
- 根据配置构建 PyRIT Scorer 实例
- 支持 ASI 类别自动选择评分器类型
- 支持外部 LLM 评分器后端（config/scores/*.yaml + CLI 参数覆盖）
- 多级回退链：openai_compatible → local_provider → objective_target → 规则评分器

回退链设计（确保评分器失效不中断流水线）：
    1. openai_compatible  — 云端高精度 API（需要 SCORES_API_KEY，含连通性探测）
    2. local_provider     — 本地模型服务（Ollama/LM Studio，无需认证，含连通性探测）
    3. objective_target   — 复用攻击目标作为评分器后端（仅 OpenAIChatTarget，排除 PlaywrightTarget）
    4. substring          — 规则评分器兜底（纯文本匹配，无需 LLM）
    5. 空列表             — PyRIT 默认行为（无评分器，攻击照常执行）

    自适应机制：每个 LLM 后端在返回前进行轻量级连通性探测（GET /v1/models，
    3 秒超时）。探测失败的后端被跳过，自动尝试下一个回退选项。
    当所有 LLM 后端不可用时，自动降级为规则评分器（static_prompt_injection）。

从 AttackOrchestrator 拆分，遵循单一职责原则。

PyRIT 0.14.0 兼容
"""

from __future__ import annotations

import logging
import os
from pathlib import Path
from typing import Any, Dict, List, Optional

import yaml

from pyrit.prompt_target import PromptTarget, OpenAIChatTarget
from pyrit.score import Scorer

# 连通性探测超时（秒）
_PROBE_TIMEOUT = 3.0

from .component_registry import SCORER_MAP, LLM_BACKEND_SCORERS, RULE_BASED_SCORERS
from ...utils.env_loader import resolve_env_vars

logger = logging.getLogger(__name__)

# 评分器 LLM 后端回退顺序（高精度 → 高可用 → 兜底）
FALLBACK_BACKEND_ORDER: List[str] = ["openai_compatible", "local_provider"]

# LLM 评分器 → 规则评分器降级映射（当所有 LLM 后端不可用时使用）
# 选择标准：无需必需参数 + 通用检测能力
LLM_TO_RULE_FALLBACK: Dict[str, str] = {
    "refusal": "static_prompt_injection",     # SelfAskRefusalScorer → StaticPromptInjectionScorer
    "true_false": "static_prompt_injection",  # SelfAskTrueFalseScorer → StaticPromptInjectionScorer
    "category": "static_prompt_injection",    # SelfAskCategoryScorer → StaticPromptInjectionScorer
    # P0-3: Float Scale 降级
    "likert": "static_prompt_injection",      # SelfAskLikertScorer → StaticPromptInjectionScorer
    "scale": "static_prompt_injection",       # SelfAskScaleScorer → StaticPromptInjectionScorer
    # P0-4: ConversationScorer 降级
    "conversation": "static_prompt_injection", # ConversationScorer → StaticPromptInjectionScorer
}

# 规则评分器默认参数（需要必需参数的评分器）
RULE_SCORER_DEFAULT_PARAMS: Dict[str, Dict[str, Any]] = {
    "substring": {"substring": ""},  # SubStringScorer 需要 substring 参数
    # P0-3: BatchScorer 默认 batch_size=10
    "batch": {"batch_size": 10},
    # P0-3: MarkdownInjectionScorer 无必需参数
    "markdown_injection": {},
}


class ScorerBuilder:
    """
    PyRIT 评分器构建器

    逻辑：
    1. 如果 scorer_configs 非空，使用用户显式配置
    2. 否则根据 asi_category 自动选择评分器类型
    3. LLM 评分器使用多级回退链选择后端

    回退链（确保评分器失效不中断流水线）：
        openai_compatible → local_provider → objective_target → 规则评分器 → 空列表

    使用方式：
        builder = ScorerBuilder(scorer_config_path="config/scores/")
        builder.load_config()
        scorers = builder.build(scorer_configs, objective_target=target, asi_category="ASI01")
    """

    def __init__(
        self,
        scorer_config_path: str = "config/scores/",
        scorer_url: Optional[str] = None,
        scorer_key: Optional[str] = None,
        scorer_model: Optional[str] = None,
    ):
        """
        Args:
            scorer_config_path: 评分器配置目录路径
            scorer_url: 外部评分 LLM 端点 URL（CLI 传入，优先级最高）
            scorer_key: 外部评分 LLM 的 API Key
            scorer_model: 外部评分 LLM 的模型名称
        """
        self._scorer_config_path = scorer_config_path
        self._scorer_url = scorer_url
        self._scorer_key = scorer_key
        self._scorer_model = scorer_model
        self._scorer_config: Dict[str, Any] = {}
        self._last_used_backend: str = "none"

    @property
    def scorer_config(self) -> Dict[str, Any]:
        """获取已加载的评分器配置"""
        return self._scorer_config

    def load_config(self) -> None:
        """
        加载评分器 LLM 后端配置（目录模式）

        从 config/scores/ 目录加载所有 *.yaml 文件，合并 scorer_llm_backends。

        优先级：
        1. CLI 参数（--scorer-url / --scorer-key / --scorer-model）
        2. 环境变量（SCORES_BASE_URL / SCORES_API_KEY / SCORES_MODEL_NAME）
        3. 配置文件（config/scores/*.yaml 中的 scorer_llm_backends）
        4. 默认 local_provider
        """
        logger.info("\n######## 加载评分器配置 ########")
        backends: Dict[str, Any] = {}

        # 从 config/scores/ 目录加载所有 YAML 文件
        config_dir = Path(self._scorer_config_path)
        if config_dir.exists() and config_dir.is_dir():
            yaml_files = sorted(config_dir.glob("*.yaml"))
            if not yaml_files:
                yaml_files = sorted(config_dir.glob("*.yml"))
            for yaml_file in yaml_files:
                try:
                    with open(yaml_file, "r", encoding="utf-8") as f:
                        data = yaml.safe_load(f) or {}
                    # 统一解析 ${VAR} 和 ${VAR:-default} 环境变量引用
                    data = resolve_env_vars(data)
                    file_backends = data.get("scorer_llm_backends", {})
                    if file_backends:
                        backends.update(file_backends)
                        logger.info("Scorer config loaded: %d backends from %s", len(file_backends), yaml_file.name)
                except Exception as e:
                    logger.warning("Failed to load %s: %s", yaml_file.name, e)
            if not backends:
                logger.info("No scorer backends found in %s, using defaults", config_dir)
        else:
            logger.info("Scorer config dir not found: %s, using defaults", config_dir)

        # CLI 参数优先级最高：如果提供了 scorer_url，覆盖 local_provider
        if self._scorer_url:
            backends["local_provider"] = {
                "provider": "openai",
                "base_url": self._scorer_url,
                "api_key": self._scorer_key or "not-needed",
                "model_name": self._scorer_model or "gpt-4o-mini",
                "temperature": 0.0,
                "max_tokens": 1024,
            }
            logger.info("CLI override: scorer backend → %s (%s)", self._scorer_url, self._scorer_model or "gpt-4o-mini")

        self._scorer_config = {"scorer_llm_backends": backends}

    def build(
        self,
        scorer_configs: List[Dict[str, Any]],
        objective_target: Optional[PromptTarget] = None,
        asi_category: str = "",
        asi_scorer_map: Optional[Dict[str, str]] = None,
        enable_ensemble: bool = True,
        enable_semantic: bool = True,
    ) -> List[Scorer]:
        """
        构建评分器（ASI 自动选择 + 外部 LLM 后端 + 集成投票 + 语义增强）

        REV-4: 关键类别启用多评分器集成投票
        REV-5: 关键类别启用语义评分器

        Args:
            scorer_configs: 评分器配置列表（通常为空，由 ASI 自动选择）
            objective_target: 目标（用于 SelfAsk 评分器）
            asi_category: ASI 类别 (如 "ASI01")，用于自动选择评分器类型
            asi_scorer_map: ASI 类别→评分器类型映射表（可选，默认使用内置）
            enable_ensemble: 是否启用集成评分 (REV-4)
            enable_semantic: 是否启用语义评分 (REV-5)

        Returns:
            评分器实例列表
        """
        scorers: List[Scorer] = []

        scorer_type = None
        if scorer_configs:
            config = scorer_configs[0]
            if isinstance(config, str):
                scorer_type = config
            else:
                scorer_type = config.get("name", "")
        elif asi_category:
            scorer_map = asi_scorer_map or {}
            scorer_type = scorer_map.get(asi_category, "refusal")

        if not scorer_type:
            logger.debug("No scorer type determined, skipping scorer creation")
            return scorers

        # REV-4: 关键类别启用多评分器集成投票
        if enable_ensemble and asi_category:
            ensemble = self._try_build_ensemble(asi_category, objective_target)
            if ensemble:
                scorers.append(ensemble)
                logger.info("REV-4: Ensemble scorer enabled for %s", asi_category)

        # REV-5: 关键类别启用语义评分器
        if enable_semantic and asi_category:
            semantic = self._try_build_semantic(asi_category, objective_target)
            if semantic:
                scorers.append(semantic)
                logger.info("REV-5: Semantic scorer enabled for %s", asi_category)

        # 如果已通过 ensemble/semantic 添加了评分器，且无显式配置，直接返回
        if scorers and not scorer_configs:
            return scorers

        # 构建常规评分器
        scorer_class = SCORER_MAP.get(scorer_type)
        if not scorer_class:
            if not scorers:
                logger.warning("Unknown scorer type: %s", scorer_type)
            return scorers

        try:
            if scorer_type in LLM_BACKEND_SCORERS:
                chat_target = self._resolve_llm_target_with_fallback(objective_target)
                if chat_target:
                    # P0-3: float_scale 系列评分器特殊构建
                    if scorer_type == "likert":
                        from pyrit.score import SelfAskLikertScorer, LikertScalePaths
                        scorers.append(SelfAskLikertScorer(
                            chat_target=chat_target,
                            likert_scale=LikertScalePaths.PRIVACY_SCALE,
                        ))
                        logger.info("Added Likert scorer: privacy_scale (backend=%s)", self._last_used_backend)
                    elif scorer_type == "scale":
                        scorers.append(scorer_class(chat_target=chat_target))
                        logger.info("Added Scale scorer (backend=%s)", self._last_used_backend)
                    elif scorer_type == "conversation":
                        # P0-4: ConversationScorer 需要 ScorerPromptValidator
                        from pyrit.score import ScorerPromptValidator
                        validator = ScorerPromptValidator(scorer_class(chat_target=chat_target))
                        scorers.append(scorer_class(
                            validator=validator,
                            chat_target=chat_target,
                        ))
                        logger.info("Added Conversation scorer (backend=%s)", self._last_used_backend)
                    else:
                        scorers.append(scorer_class(chat_target=chat_target))
                        logger.info("Added LLM scorer: %s (backend=%s)", scorer_type, self._last_used_backend)
                else:
                    # 所有 LLM 后端不可用 → 降级为规则评分器
                    fallback_scorer = self._build_rule_based_fallback(scorer_type)
                    if fallback_scorer:
                        scorers.append(fallback_scorer)
                        logger.warning(
                            "LLM scorer '%s' unavailable, degraded to rule-based fallback",
                            scorer_type,
                        )
                    else:
                        logger.warning("No scorer available for type: %s (pipeline continues without scoring)", scorer_type)
            else:
                # 规则评分器：使用默认参数构建（某些评分器如 SubStringScorer 需要必需参数）
                default_params = RULE_SCORER_DEFAULT_PARAMS.get(scorer_type, {})
                scorers.append(scorer_class(**default_params))
                logger.debug("Added rule-based scorer: %s", scorer_type)
        except TypeError as e:
            # L5: 使用异常分类进行精确错误处理
            from ...utils.exceptions import ScorerBuildError
            logger.warning(
                "Scorer %s construction failed (TypeError): %s (pipeline continues)",
                scorer_type, e,
                extra={"scorer_type": scorer_type, "error": str(e)},
            )
            # 尝试规则评分器兜底
            fallback_scorer = self._build_rule_based_fallback(scorer_type)
            if fallback_scorer and not scorers:
                scorers.append(fallback_scorer)
                logger.warning("Recovered with rule-based fallback for '%s'", scorer_type)
        except Exception as e:
            # L5: 统一异常处理，不中断流水线
            from ...utils.exceptions import ScorerBuildError
            logger.warning(
                "Scorer %s construction failed: %s (pipeline continues)",
                scorer_type, e,
                extra={"scorer_type": scorer_type, "error": str(e)},
            )
            # 尝试规则评分器兜底
            fallback_scorer = self._build_rule_based_fallback(scorer_type)
            if fallback_scorer and not scorers:
                scorers.append(fallback_scorer)
                logger.warning("Recovered with rule-based fallback for '%s'", scorer_type)

        return scorers

    def _try_build_ensemble(
        self,
        asi_category: str,
        objective_target: Optional[PromptTarget],
    ) -> Optional[Any]:
        """REV-4: 尝试为关键类别构建集成评分器（使用回退链）"""
        from ..scoring.ensemble_scorer import ENSEMBLE_SCORER_CONFIG, EnsembleScorer

        owasp_upper = asi_category.upper()
        scorer_types = ENSEMBLE_SCORER_CONFIG.get(owasp_upper)

        if not scorer_types or len(scorer_types) < 2:
            return None

        # 构建多个评分器（使用回退链）
        sub_scorers: List[Scorer] = []
        for st in scorer_types:
            scorer_class = SCORER_MAP.get(st)
            if not scorer_class:
                continue
            try:
                if st in LLM_BACKEND_SCORERS:
                    chat_target = self._resolve_llm_target_with_fallback(objective_target)
                    if chat_target:
                        sub_scorers.append(scorer_class(chat_target=chat_target))
                    else:
                        # LLM 不可用 → 规则评分器兜底
                        fallback = self._build_rule_based_fallback(st)
                        if fallback:
                            sub_scorers.append(fallback)
                else:
                    sub_scorers.append(scorer_class())
            except Exception as e:
                logger.debug("Failed to build sub-scorer %s: %s", st, e)

        if len(sub_scorers) < 2:
            return None

        return EnsembleScorer(
            scorers=sub_scorers,
            vote_strategy="majority",
        )

    def _try_build_semantic(
        self,
        asi_category: str,
        objective_target: Optional[PromptTarget],
    ) -> Optional[Any]:
        """REV-5: 尝试为关键类别构建语义评分器（使用回退链）"""
        from ..scoring.semantic_scorer import create_semantic_scorer

        chat_target = self._resolve_llm_target_with_fallback(objective_target)

        return create_semantic_scorer(asi_category, chat_target)

    def _build_scorer_llm_target(self, backend_name: str) -> Optional[PromptTarget]:
        """根据后端名称创建 LLM 评分器目标

        自动判断是否需要 API Key：
        - provider=ollama（本地部署）：跳过 API Key 校验，空值回退为 not-needed
        - provider=openai 等云端平台：校验 API Key，未配置时提示用户
        """
        backends = self._scorer_config.get("scorer_llm_backends", {})
        backend = backends.get(backend_name)
        if not backend:
            logger.debug("Scorer LLM backend '%s' not found", backend_name)
            return None

        # 环境变量已在 load_config() 中通过 resolve_env_vars 统一解析
        provider = str(backend.get("provider", "ollama")).lower()
        api_key = str(backend.get("api_key", "")).strip()
        base_url = backend.get("base_url", "http://localhost:11434/v1")
        model_name = backend.get("model_name", "qwen3:0.6b")

        # 按提供商类型判断是否需要 API Key
        if provider == "ollama":
            # 本地部署（Ollama / LM Studio / vLLM）：无需认证，跳过校验
            if not api_key:
                api_key = "not-needed"
        else:
            # 云端平台（openai / 智谱 / DeepSeek 等）：必须配置 API Key
            if not api_key:
                logger.debug(
                    "Scorer backend '%s' (provider=%s) requires API Key but not configured",
                    backend_name, provider,
                )
                return None

        try:
            target = OpenAIChatTarget(
                endpoint=base_url,
                api_key=api_key,
                model_name=model_name,
            )
        except Exception as e:
            logger.debug("Failed to create OpenAIChatTarget for '%s': %s", backend_name, e)
            return None

        # 运行时连通性探测：确保端点实际可达，避免评分器在运行时才崩溃
        if not self._probe_backend_connectivity(base_url, api_key):
            logger.warning(
                "Scorer backend '%s' unreachable at %s (connectivity probe failed), "
                "trying next fallback...",
                backend_name, base_url,
            )
            return None

        logger.debug("Scorer backend '%s' connectivity verified at %s", backend_name, base_url)
        return target

    def _probe_backend_connectivity(self, base_url: str, api_key: str) -> bool:
        """
        轻量级连通性探测：发送 GET /v1/models 请求验证端点可达

        设计原则：
        - 快速失败（3 秒超时），不阻塞流水线
        - 不发送实际评分请求，只验证服务存活
        - 兼容 Ollama / OpenAI / 智谱 / DeepSeek 等所有 OpenAI 兼容端点

        Args:
            base_url: LLM 端点 URL（如 http://localhost:11434/v1）
            api_key: API Key（Ollama 可为 not-needed）

        Returns:
            True 如果端点可达，False 如果不可达
        """
        try:
            import httpx

            # 构造 /models 端点（OpenAI 标准健康检查）
            models_url = base_url.rstrip("/") + "/models"
            headers = {"Authorization": f"Bearer {api_key}"} if api_key and api_key != "not-needed" else {}

            with httpx.Client(timeout=_PROBE_TIMEOUT) as client:
                resp = client.get(models_url, headers=headers)
                # 200 = 可达，401/403 = 可达但认证问题（仍可用）
                return resp.status_code in (200, 401, 403)

        except Exception as e:
            logger.debug("Connectivity probe failed for %s: %s", base_url, str(e)[:100])
            return False

    def _resolve_llm_target_with_fallback(
        self,
        objective_target: Optional[PromptTarget] = None,
    ) -> Optional[PromptTarget]:
        """多级回退链解析 LLM 评分器后端

        回退顺序：
        1. openai_compatible  — 云端高精度 API（需 SCORES_API_KEY）
        2. local_provider     — 本地模型服务（Ollama，无需认证）
        3. objective_target   — 复用攻击目标作为评分器后端

        Args:
            objective_target: 攻击目标（最终回退选项）

        Returns:
            可用的 PromptTarget 实例，或 None（全部不可用）
        """
        self._last_used_backend: str = "none"

        # 阶段 1+2: 尝试配置的后端（按回退顺序）
        for backend_name in FALLBACK_BACKEND_ORDER:
            try:
                target = self._build_scorer_llm_target(backend_name)
                if target:
                    self._last_used_backend = backend_name
                    logger.info("Scorer LLM backend resolved: %s", backend_name)
                    return target
            except Exception as e:
                logger.debug("Backend '%s' failed: %s", backend_name, e)
                continue

        # 阶段 3: 复用攻击目标（仅当它是 OpenAIChatTarget 时）
        # PlaywrightTarget（SPA 浏览器自动化）不能作为评分器 LLM 后端
        if objective_target and isinstance(objective_target, OpenAIChatTarget):
            self._last_used_backend = "objective_target"
            logger.info("Scorer LLM backend resolved: objective_target (fallback)")
            return objective_target
        elif objective_target and not isinstance(objective_target, OpenAIChatTarget):
            logger.info(
                "objective_target is %s (not OpenAIChatTarget), "
                "cannot use as scorer LLM backend, skipping",
                type(objective_target).__name__,
            )

        # 全部不可用
        self._last_used_backend = "none"
        logger.warning(
            "═══════════════════════════════════════════════════════════\n"
            "  所有 LLM 评分器后端不可用。\n"
            "  回退链尝试顺序：\n"
            "    1. openai_compatible — 需要 SCORES_API_KEY\n"
            "    2. local_provider    — 需要本地模型服务运行\n"
            "    3. objective_target  — 需要攻击目标可用\n"
            "  将降级为规则评分器（static_prompt_injection），确保流水线不中断。\n"
            "═══════════════════════════════════════════════════════════"
        )
        return None

    def _build_rule_based_fallback(self, scorer_type: str) -> Optional[Scorer]:
        """构建规则评分器兜底（当 LLM 评分器不可用时）

        降级映射：
            refusal / true_false / category → static_prompt_injection（内置注入检测）
            规则评分器本身                  → 原样构建（自动填充必需参数）

        选择 static_prompt_injection 作为通用兜底的原因：
        - 无需必需参数（内置 6 类注入检测模式）
        - 适用于大多数 LLM 攻击场景
        - 检测指令覆盖、系统提示提取、越狱、约束移除等模式

        Args:
            scorer_type: 原始评分器类型

        Returns:
            规则评分器实例，或 None（无可用兜底）
        """
        # 确定回退类型
        if scorer_type in RULE_BASED_SCORERS:
            # 本身就是规则评分器
            fallback_type = scorer_type
        else:
            # LLM 评分器降级
            fallback_type = LLM_TO_RULE_FALLBACK.get(scorer_type)

        if not fallback_type:
            return None

        scorer_class = SCORER_MAP.get(fallback_type)
        if not scorer_class:
            return None

        # 获取默认参数（某些评分器需要必需参数）
        default_params = RULE_SCORER_DEFAULT_PARAMS.get(fallback_type, {})

        try:
            return scorer_class(**default_params)
        except Exception as e:
            logger.debug("Fallback scorer '%s' failed: %s", fallback_type, e)
            return None

    def check_adversarial_available(self) -> bool:
        """检查是否有可用的对抗性 LLM（Crescendo/TAP 需要）"""
        backends = self._scorer_config.get("scorer_llm_backends", {})
        scorer_backends = {k: v for k, v in backends.items() if k != "objective_target"}
        return len(scorer_backends) > 0

    def build_adversarial_config(self, objective_target: PromptTarget) -> Optional[Any]:
        """构建对抗性配置（Crescendo/TAP 需要，使用回退链）"""
        from pyrit.executor.attack import AttackAdversarialConfig

        # 使用回退链解析对抗性 LLM 目标
        target = self._resolve_llm_target_with_fallback(objective_target)
        if target:
            try:
                return AttackAdversarialConfig(target=target)
            except Exception as e:
                logger.debug("Failed to build adversarial config: %s", e)
        return None
