# -*- coding: utf-8 -*-
"""
AI-300 Framework - Scorer Builder
PyRIT 评分器构建模块

职责：
- 根据配置构建 PyRIT Scorer 实例
- 支持 ASI 类别自动选择评分器类型
- 支持外部 LLM 评分器后端（config/scores/*.yaml + CLI 参数覆盖）

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

from .component_registry import SCORER_MAP, LLM_BACKEND_SCORERS

logger = logging.getLogger(__name__)


class ScorerBuilder:
    """
    PyRIT 评分器构建器

    逻辑：
    1. 如果 scorer_configs 非空，使用用户显式配置
    2. 否则根据 asi_category 自动选择评分器类型
    3. LLM 评分器使用 local_ollama 后端（或 CLI 覆盖的外部 LLM）

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
        2. 环境变量（SCORER_BASE_URL / SCORER_API_KEY / SCORER_MODEL_NAME）
        3. 配置文件（config/scores/*.yaml 中的 scorer_llm_backends）
        4. 默认 local_ollama
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

        # CLI 参数优先级最高：如果提供了 scorer_url，覆盖 local_ollama
        if self._scorer_url:
            backends["local_ollama"] = {
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
                chat_target = self._build_scorer_llm_target("local_ollama")
                if chat_target is None and objective_target:
                    chat_target = objective_target
                if chat_target:
                    scorers.append(scorer_class(chat_target=chat_target))
                    logger.debug("Added scorer: %s (backend=local_ollama)", scorer_type)
                else:
                    logger.warning("No LLM backend available for scorer: %s", scorer_type)
            else:
                scorers.append(scorer_class())
                logger.debug("Added rule-based scorer: %s", scorer_type)
        except TypeError as e:
            logger.warning("Scorer %s requires params: %s", scorer_type, e)

        return scorers

    def _try_build_ensemble(
        self,
        asi_category: str,
        objective_target: Optional[PromptTarget],
    ) -> Optional[Any]:
        """REV-4: 尝试为关键类别构建集成评分器"""
        from .ensemble_scorer import ENSEMBLE_SCORER_CONFIG, EnsembleScorer

        owasp_upper = asi_category.upper()
        scorer_types = ENSEMBLE_SCORER_CONFIG.get(owasp_upper)

        if not scorer_types or len(scorer_types) < 2:
            return None

        # 构建多个评分器
        sub_scorers: List[Scorer] = []
        for st in scorer_types:
            scorer_class = SCORER_MAP.get(st)
            if not scorer_class:
                continue
            try:
                if st in LLM_BACKEND_SCORERS:
                    chat_target = self._build_scorer_llm_target("local_ollama")
                    if chat_target is None and objective_target:
                        chat_target = objective_target
                    if chat_target:
                        sub_scorers.append(scorer_class(chat_target=chat_target))
                else:
                    sub_scorers.append(scorer_class())
            except (TypeError, Exception) as e:
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
        """REV-5: 尝试为关键类别构建语义评分器"""
        from .semantic_scorer import create_semantic_scorer

        chat_target = self._build_scorer_llm_target("local_ollama")
        if chat_target is None and objective_target:
            chat_target = objective_target

        return create_semantic_scorer(asi_category, chat_target)

    def _build_scorer_llm_target(self, backend_name: str) -> Optional[PromptTarget]:
        """根据后端名称创建 LLM 评分器目标"""
        backends = self._scorer_config.get("scorer_llm_backends", {})
        backend = backends.get(backend_name)
        if not backend:
            logger.warning("Scorer LLM backend '%s' not found", backend_name)
            return None

        api_key = backend.get("api_key", "not-needed")
        if api_key.startswith("${") and api_key.endswith("}"):
            env_var = api_key[2:-1]
            api_key = os.environ.get(env_var, "")
            if not api_key:
                logger.warning("Environment variable %s not set for backend '%s'", env_var, backend_name)

        base_url = backend.get("base_url", "http://localhost:11434/v1")
        model_name = backend.get("model_name", "qwen3:0.6b")

        return OpenAIChatTarget(
            endpoint=base_url,
            api_key=api_key,
            model_name=model_name,
        )

    def check_adversarial_available(self) -> bool:
        """检查是否有可用的对抗性 LLM（Crescendo/TAP 需要）"""
        backends = self._scorer_config.get("scorer_llm_backends", {})
        scorer_backends = {k: v for k, v in backends.items() if k != "objective_target"}
        return len(scorer_backends) > 0

    def build_adversarial_config(self, objective_target: PromptTarget) -> Optional[Any]:
        """构建对抗性配置（Crescendo/TAP 需要）"""
        from pyrit.executor.attack import AttackAdversarialConfig

        backends = self._scorer_config.get("scorer_llm_backends", {})
        for name, backend in backends.items():
            if name == "objective_target":
                continue
            try:
                target = self._build_scorer_llm_target(name)
                if target:
                    return AttackAdversarialConfig(target=target)
            except Exception:
                continue
        return None
