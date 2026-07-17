# -*- coding: utf-8 -*-
"""
AI-300 Framework - Attack Orchestrator v3.0
攻击编排器：使用 PyRIT 原生攻击策略执行

核心改进（v3.0）：
- 不再手动循环执行，全部使用 PyRIT 原生攻击
- PromptSendingAttack: 单轮 + 内置重试 (max_attempts_on_failure)
- CrescendoAttack: 渐进升级 + 自动回退 (role_play / complex)
- TreeOfAttacksWithPruningAttack: 树搜索 + 剪枝 (context_overflow / adversarial)
- SequentialAttack: 多 preset 早停 (FIRST_SUCCESS)

组件映射和攻击注册表已拆分为独立模块：
- component_registry.py: CONVERTER_MAP, SCORER_MAP 等
- attack_registry.py: ATTACK_REGISTRY, list_attacks() 等

PyRIT 0.14.0 API 说明：
- 内存：SQLiteMemory + CentralMemory.set_memory_instance()
- 攻击：直接使用 PyRIT 攻击类 + execute_async()
- 转换器：AttackConverterConfig 包装
- 评分器：AttackScoringConfig 包装
"""

from __future__ import annotations

import asyncio
import importlib
import logging
import os
from pathlib import Path
from typing import Any, Dict, List, Optional

import yaml

# PyRIT 0.14.0 核心组件导入
from pyrit.memory import CentralMemory, SQLiteMemory
from pyrit.executor.attack import (
    PromptSendingAttack,
    AttackConverterConfig,
    AttackScoringConfig,
    AttackAdversarialConfig,
)
from pyrit.prompt_converter import PromptConverter
from pyrit.prompt_target import PromptTarget, OpenAIChatTarget
from pyrit.score import Scorer

# 组件映射和攻击注册表从独立模块导入
from .component_registry import (
    CONVERTER_MAP,
    SCORER_MAP,
    SPECIAL_PRESETS,
    LLM_BACKEND_SCORERS,
    CONVERTER_NAME_MAP,
    SCORER_NAME_MAP,
)

# 速率控制器
from .rate_controller import RateController, create_rate_controller

logger = logging.getLogger(__name__)


def _import_class(fqn: str) -> type:
    """从全限定名导入类"""
    module_path, class_name = fqn.rsplit(".", 1)
    module = importlib.import_module(module_path)
    return getattr(module, class_name)


class AttackOrchestrator:
    """
    攻击编排器 v3.0

    功能：
    1. 从配置加载攻击策略
    2. 自动组合 PyRIT 转换器链
    3. 使用 PyRIT 原生攻击执行（不再手动循环）
    4. 自动评分和结果存储
    5. 支持外部 LLM 评分器后端（config/scores/ 目录）

    核心改进：
    - SmartMatcher 选择 PyRIT 攻击策略
    - 执行全部交给 PyRIT 原生攻击
    - 继承 PyRIT 的全部能力（重试、升级、回退、剪枝、早停）
    """

    # 评分器配置路径（支持目录或单文件）
    SCORER_CONFIG_PATH = "config/scores/"

    # 数据目录路径（payload_refs 解析用）
    DATA_DIR = "data"

    # 类级别 PayloadManager 实例（共享缓存）
    _payload_manager: Optional[Any] = None

    def __init__(
        self,
        config_path: Optional[str] = None,
        config_dict: Optional[Dict[str, Any]] = None,
        memory_type: str = "in_memory",
        scorer_config_path: Optional[str] = None,
        data_dir: Optional[str] = None,
    ):
        self.config = self._load_config(config_path, config_dict)
        self.memory_type = memory_type
        self._components_initialized = False
        self._results: List[Dict[str, Any]] = []
        self._scorer_config: Dict[str, Any] = {}
        self._scorer_config_path = scorer_config_path or self.SCORER_CONFIG_PATH
        self._data_dir = data_dir or self.DATA_DIR
        self._rate_controller: Optional[RateController] = None

        # 初始化 PayloadManager
        self._init_payload_manager()
        # 初始化 PyRIT 内存
        self._initialize_pyrit()
        # 加载评分器配置
        self._load_scorer_config()

    def _init_payload_manager(self) -> None:
        """初始化 PayloadManager（类级别单例）"""
        if AttackOrchestrator._payload_manager is None:
            from ..payloads.payload_manager import PayloadManager
            AttackOrchestrator._payload_manager = PayloadManager()
            AttackOrchestrator._payload_manager.load_data_dir(self._data_dir)
        self._payload_mgr = AttackOrchestrator._payload_manager

    def resolve_payload_refs(self, refs: List[str]) -> List[str]:
        """解析 payload_refs 为实际载荷列表"""
        return self._payload_mgr.resolve_refs(refs)

    def _load_config(
        self,
        config_path: Optional[str],
        config_dict: Optional[Dict[str, Any]],
    ) -> Dict[str, Any]:
        """加载配置"""
        if config_dict:
            return config_dict
        if config_path:
            path = Path(config_path)
            if path.suffix in (".yaml", ".yml"):
                with open(path, "r", encoding="utf-8") as f:
                    return yaml.safe_load(f)
            raise ValueError(f"Unsupported config format: {path.suffix}")
        return {}

    def _load_scorer_config(self) -> None:
        """
        加载评分器配置

        支持两种模式：
        - 目录模式：加载 path 下所有 *.yaml 文件，合并 scorer_llm_backends / scorer_definitions / best_scorer_by_scenario
        - 单文件模式：向后兼容旧的 config/scorers.yaml
        """
        logger.info("\n######## 加载评分器配置 ########")
        path = Path(self._scorer_config_path)

        if not path.exists():
            logger.warning("Scorer config not found: %s, using defaults", self._scorer_config_path)
            self._scorer_config = {"scorer_llm_backends": {}, "scorer_definitions": {}}
            return

        # 初始化合并容器
        merged_backends: Dict[str, Any] = {}
        merged_definitions: Dict[str, Any] = {}
        merged_scenarios: Dict[str, Any] = {}
        loaded_files: List[str] = []

        if path.is_dir():
            # 目录模式：遍历所有 YAML 文件
            yaml_files = sorted(path.glob("*.yaml")) + sorted(path.glob("*.yml"))
            for yaml_file in yaml_files:
                try:
                    with open(yaml_file, "r", encoding="utf-8") as f:
                        data = yaml.safe_load(f) or {}
                    if not isinstance(data, dict):
                        continue
                    # 合并各段落（后加载的覆盖先加载的）
                    if "scorer_llm_backends" in data:
                        merged_backends.update(data["scorer_llm_backends"])
                    if "scorer_definitions" in data:
                        merged_definitions.update(data["scorer_definitions"])
                    if "best_scorer_by_scenario" in data:
                        merged_scenarios.update(data["best_scorer_by_scenario"])
                    loaded_files.append(yaml_file.name)
                except Exception as e:
                    logger.warning("Failed to load %s: %s", yaml_file.name, e)
        else:
            # 单文件模式（向后兼容）
            try:
                with open(path, "r", encoding="utf-8") as f:
                    data = yaml.safe_load(f) or {}
                merged_backends = data.get("scorer_llm_backends", {})
                merged_definitions = data.get("scorer_definitions", {})
                merged_scenarios = data.get("best_scorer_by_scenario", {})
                loaded_files.append(path.name)
            except Exception as e:
                logger.warning("Failed to load %s: %s", path.name, e)

        self._scorer_config = {
            "scorer_llm_backends": merged_backends,
            "scorer_definitions": merged_definitions,
            "best_scorer_by_scenario": merged_scenarios,
        }

        logger.info(
            "Scorer config loaded: %d backends, %d definitions, %d scenarios",
            len(merged_backends),
            len(merged_definitions),
            len(merged_scenarios),
        )

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

    def _initialize_pyrit(self):
        """初始化 PyRIT 0.14.0 内存"""
        logger.info("\n######## 初始化 PyRIT ########")
        if self.memory_type == "in_memory":
            memory = SQLiteMemory(db_path=":memory:")
        else:
            memory = SQLiteMemory()
        CentralMemory.set_memory_instance(memory)
        self._components_initialized = True
        logger.info("PyRIT 0.14.0 initialized with %s memory", self.memory_type)

    def build_target(self, target_config: Dict[str, Any]) -> PromptTarget:
        """
        根据配置构建 PyRIT PromptTarget

        支持类型：
        - ollama / openai → OpenAIChatTarget
        - http → HTTPTarget（原始 HTTP 请求）
        - playwright → PlaywrightTarget（浏览器自动化，SPA 支持）

        同时创建速率控制器（RateController），基于目标类型自动选择最优并发值。
        """
        target_type = target_config.get("type", "openai")
        connection = target_config.get("connection", {})

        # 创建速率控制器（基于目标类型默认值或配置覆盖）
        self._rate_controller = self._create_rate_controller(target_config)

        if target_type in ("ollama", "openai"):
            return OpenAIChatTarget(
                endpoint=connection.get("endpoint", "http://localhost:11434/v1"),
                api_key=connection.get("api_key", "not-needed"),
                model_name=connection.get("model", "llama3.2:latest"),
            )
        elif target_type == "http":
            from pyrit.prompt_target.http_target.http_target import HTTPTarget
            http_request = connection.get("http_request")
            if not http_request:
                raise ValueError(
                    "HTTPTarget requires 'http_request' in connection config."
                )
            return HTTPTarget(
                http_request=http_request,
                prompt_regex_string=connection.get("prompt_regex_string", "{PROMPT}"),
                use_tls=connection.get("use_tls", True),
            )
        elif target_type == "playwright":
            return self._build_playwright_target(target_config)
        else:
            raise ValueError(f"Unsupported target type: {target_type}")

    def _create_rate_controller(self, target_config: Dict[str, Any]) -> RateController:
        """
        根据目标配置创建速率控制器

        优先级：
        1. 配置中显式指定的 concurrency / rate_limit
        2. 目标类型默认值

        Args:
            target_config: 目标配置字典

        Returns:
            RateController 实例
        """
        target_type = target_config.get("type", "openai")
        rate_config = target_config.get("rate_control", {})

        max_concurrent = rate_config.get("max_concurrent", 0)
        rate_limit = rate_config.get("rate_limit", 0.0)

        controller = create_rate_controller(
            target_type=target_type,
            max_concurrent=max_concurrent,
            rate_limit=rate_limit,
        )

        return controller

    def _build_playwright_target(self, target_config: Dict[str, Any]) -> Any:
        """
        构建 PlaywrightTarget（SPA 浏览器自动化）

        流程：
        1. 解析认证配置（如有）→ AuthProfile
        2. 启动 Playwright 浏览器
        3. 注入认证信息（Cookie + Authorization）
        4. 创建带认证的 Page
        5. 构建交互函数
        6. 返回 PlaywrightTarget

        Args:
            target_config: 目标配置字典

        Returns:
            PlaywrightTarget 实例
        """
        from pyrit.prompt_target.playwright_target import PlaywrightTarget

        connection = target_config.get("connection", {})
        auth_config = target_config.get("auth", {})
        selectors = target_config.get("selectors", {})

        # 1. 解析认证配置
        auth_profile = None
        header_file = auth_config.get("header_file", "")
        if header_file:
            from .auth import parse_header_file
            auth_profile = parse_header_file(header_file)
            logger.info("Auth loaded: %s", auth_profile.summary())

        # 2. 启动 Playwright 浏览器
        page = self._launch_playwright_browser(connection, auth_profile)

        # 3. 构建交互函数
        from .interactions.web_chat import create_web_chat_interaction
        interaction_func = create_web_chat_interaction(selectors)

        # 4. 创建 PlaywrightTarget
        target = PlaywrightTarget(
            interaction_func=interaction_func,
            page=page,
        )

        logger.info(
            "PlaywrightTarget created: url=%s, auth=%s",
            connection.get("url", ""),
            auth_profile.auth_type if auth_profile else "none",
        )
        return target

    def _launch_playwright_browser(
        self,
        connection: Dict[str, Any],
        auth_profile: Any = None,
    ) -> Any:
        """
        启动 Playwright 浏览器并创建带认证的页面

        Args:
            connection: 连接配置
            auth_profile: 认证配置文件（可选）

        Returns:
            Playwright Page 实例
        """
        try:
            from playwright.async_api import async_playwright
        except ImportError:
            raise ImportError(
                "Playwright is required for playwright target. "
                "Install with: pip install playwright && playwright install chromium"
            )

        import asyncio

        async def _launch():
            async with async_playwright() as p:
                browser_type = connection.get("browser", "chromium")
                headless = connection.get("headless", True)

                # 选择浏览器类型
                if browser_type == "firefox":
                    browser = await p.firefox.launch(headless=headless)
                elif browser_type == "webkit":
                    browser = await p.webkit.launch(headless=headless)
                else:
                    browser = await p.chromium.launch(headless=headless)

                # 创建上下文
                context = await browser.new_context()

                # 注入认证
                if auth_profile and auth_profile.has_auth():
                    from .auth import inject_auth
                    # 先创建 page 再注入（set_extra_http_headers 需要 page）
                    page = await context.new_page()
                    await inject_auth(context, page, auth_profile)
                else:
                    page = await context.new_page()

                # 导航到目标 URL
                url = connection.get("url", "")
                if url:
                    wait_until = connection.get("wait_until", "domcontentloaded")
                    await page.goto(url, wait_until=wait_until)

                # 保持浏览器运行（返回 page 供后续使用）
                # 注意：这里需要保持 browser 实例不被垃圾回收
                # 将 browser 引用附加到 page 对象上
                page._browser_ref = browser  # noqa: SLF001
                return page

        # 在同步上下文中运行异步代码
        page = asyncio.run(_launch())
        return page

    def build_converters(
        self,
        converter_configs: List[Dict[str, Any]],
    ) -> List[PromptConverter]:
        """根据配置列表构建转换器链"""
        converters = []
        for config in converter_configs:
            name = config.get("name") if isinstance(config, dict) else config
            params = config.get("params", {}) if isinstance(config, dict) else {}

            if name in SPECIAL_PRESETS:
                logger.debug("Special preset '%s' - skipping converter creation", name)
                continue

            converter_class = CONVERTER_MAP.get(name)
            if converter_class:
                try:
                    converters.append(converter_class(**params))
                    logger.debug("Added converter: %s", name)
                except TypeError as e:
                    logger.warning("Converter %s requires params: %s", name, e)
            else:
                logger.warning("Unknown converter: %s", name)
        return converters

    def build_scorers(
        self,
        scorer_configs: List[Dict[str, Any]],
        objective_target: Optional[PromptTarget] = None,
        asi_category: str = "",
    ) -> List[Scorer]:
        """
        根据配置列表构建评分器

        Args:
            scorer_configs: 评分器配置列表
            objective_target: 目标（用于 SelfAsk 评分器）
            asi_category: ASI 类别 (如 "ASI01")，用于自动选择最佳评分器

        Returns:
            评分器实例列表
        """
        scorers = []
        selection_meta: List[Dict[str, str]] = []

        for config in scorer_configs:
            if isinstance(config, str):
                config = {"name": config}
            name = config.get("name", "")
            backend_name = config.get("backend")
            definition_name = config.get("definition")
            params = config.get("params", {})

            if definition_name:
                definition = self._scorer_config.get("scorer_definitions", {}).get(definition_name)
                if definition:
                    name = definition.get("type", name)
                    backend_name = definition.get("backend", backend_name)
                    def_params = definition.get("params", {})
                    def_params.update(params)
                    params = def_params
                else:
                    logger.warning("Scorer definition '%s' not found", definition_name)
                    continue

            scorer_class = SCORER_MAP.get(name)
            if not scorer_class:
                logger.warning("Unknown scorer: %s", name)
                continue

            try:
                if name in LLM_BACKEND_SCORERS:
                    chat_target = None
                    if backend_name:
                        chat_target = self._build_scorer_llm_target(backend_name)
                    if chat_target is None and objective_target:
                        chat_target = objective_target
                    if chat_target:
                        params.setdefault("chat_target", chat_target)

                scorers.append(scorer_class(**params))
                selection_meta.append({
                    "name": name,
                    "backend": backend_name or "objective_target",
                    "definition": definition_name or "",
                })
                logger.debug("Added scorer: %s (backend=%s)", name, backend_name or "objective_target")
            except TypeError as e:
                logger.warning("Scorer %s requires params: %s", name, e)

        if selection_meta:
            scorer_names = [s["name"] for s in selection_meta]
            backends = [s["backend"] for s in selection_meta]
            logger.debug(
                "\n######## 评分器选择 ########\nSelected scorers: %s (backends: %s)",
                ", ".join(scorer_names), ", ".join(backends),
            )
        else:
            logger.debug("\n######## 评分器选择 ########\nNo scorers configured for this attack")

        return scorers

    def get_scorer_info(self, scorer_configs: List[Dict[str, Any]]) -> List[Dict[str, str]]:
        """获取评分器展示信息"""
        info = []
        for config in scorer_configs:
            if isinstance(config, str):
                config = {"name": config}
            name = config.get("name", "")
            backend_name = config.get("backend")
            definition_name = config.get("definition")

            description = ""
            if definition_name:
                definition = self._scorer_config.get("scorer_definitions", {}).get(definition_name)
                if definition:
                    name = definition.get("type", name)
                    backend_name = definition.get("backend")
                    description = definition.get("description", "")

            backend_info = ""
            if backend_name:
                backends = self._scorer_config.get("scorer_llm_backends", {})
                backend = backends.get(backend_name, {})
                backend_info = f"{backend.get('model_name', '')} @ {backend.get('base_url', '')}"

            info.append({
                "name": name,
                "type": name,
                "backend": backend_name or "objective_target",
                "backend_info": backend_info,
                "description": description,
            })
        return info

    # ──────────────────────────────────────────────────────────────────────────
    # 执行接口：使用 PyRIT 原生攻击
    # ──────────────────────────────────────────────────────────────────────────

    def execute_attack(
        self,
        attack_config: Dict[str, Any],
        target: PromptTarget,
        converters: Optional[List[PromptConverter]] = None,
        scorers: Optional[List[Scorer]] = None,
        tracker: Optional[Any] = None,
        profile_params: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        执行单次攻击（同步接口）

        根据 mode 选择执行策略：
        - smart_match: SmartMatcher 选择 PyRIT 原生攻击（支持侦察驱动）
        - presets: SequentialAttack (FIRST_SUCCESS) 或 PromptSendingAttack
        - chain: PromptSendingAttack (带重试)

        Args:
            profile_params: 侦察画像参数（来自 TargetProfile），用于驱动策略选择
        """
        mode = attack_config.get("mode", "chain")
        attack_name = attack_config.get("name", "unnamed_attack")
        logger.info("\n######## 执行攻击: %s (mode=%s) ########", attack_name, mode)

        if mode == "smart_match":
            return self._execute_smart_match_v3(
                attack_config, target, scorers, tracker,
                profile_params=profile_params,
            )
        elif mode == "presets":
            return self._execute_presets_v3(attack_config, target, scorers, tracker)
        else:
            return self._execute_chain_v3(attack_config, target, converters, scorers, tracker)

    def _execute_chain_v3(
        self,
        attack_config: Dict[str, Any],
        target: PromptTarget,
        converters: Optional[List[PromptConverter]],
        scorers: Optional[List[Scorer]],
        tracker: Optional[Any] = None,
    ) -> Dict[str, Any]:
        """
        chain 模式 v3.0：使用 PromptSendingAttack 内置重试

        不再手动循环，而是利用 PyRIT 的 max_attempts_on_failure
        支持并发执行：通过 RateController 控制并发数
        """
        attack_name = attack_config.get("name", "unnamed_attack")
        payloads = attack_config.get("payloads", [])
        asi_category = attack_config.get("asi_category", "")

        # 获取并发数
        concurrency = self._rate_controller.concurrency if self._rate_controller else 1
        logger.info(
            "Executing attack (chain v3.0): %s with %d payloads (concurrency=%d)",
            attack_name, len(payloads), concurrency,
        )

        results = {
            "attack_name": attack_name,
            "mode": "chain",
            "severity": attack_config.get("severity", ""),
            "payloads_tested": len(payloads),
            "results": [],
            "success_count": 0,
            "failure_count": 0,
        }

        # 构建 AttackConverterConfig
        attack_converter_config = AttackConverterConfig()
        if converters:
            attack_converter_config = AttackConverterConfig(request_converters=converters)

        # 构建 AttackScoringConfig
        attack_scoring_config = AttackScoringConfig()
        if scorers:
            attack_scoring_config = AttackScoringConfig(objective_scorer=scorers[0] if scorers else None)

        # 流水线追踪：记录评分器选择
        if tracker and scorers:
            scorer_meta = self._get_scorer_selection_meta(asi_category, scorers)
            tracker.log_scorer_selection(**scorer_meta)

        # 并发执行所有 payload
        async def _run_all():
            semaphore = self._rate_controller.semaphore if self._rate_controller else None

            async def _execute_one(payload: str) -> Dict[str, Any]:
                if semaphore:
                    await semaphore.acquire()
                try:
                    attack = PromptSendingAttack(
                        objective_target=target,
                        attack_converter_config=attack_converter_config,
                        attack_scoring_config=attack_scoring_config,
                        max_attempts_on_failure=2,
                    )
                    attack_result = await attack.execute_async(objective=payload)
                    outcome = attack_result.outcome
                    is_success = outcome.name == "SUCCESS"
                    response_text = str(attack_result)[:200]

                    return {
                        "payload": payload[:100],
                        "status": "success" if is_success else "failed",
                        "outcome": outcome.name,
                        "response": response_text,
                        "is_success": is_success,
                    }
                except Exception as e:
                    logger.error("Attack failed for payload '%s': %s", payload[:50], str(e))
                    return {
                        "payload": payload[:100],
                        "status": "error",
                        "error": str(e)[:200],
                        "is_success": False,
                    }
                finally:
                    if semaphore:
                        semaphore.release()

            tasks = [_execute_one(p) for p in payloads]
            return await asyncio.gather(*tasks)

        all_results = asyncio.run(_run_all())

        # 汇总结果
        for r in all_results:
            is_success = r.pop("is_success", False)
            results["results"].append(r)
            if is_success:
                results["success_count"] += 1
            else:
                results["failure_count"] += 1

            # 流水线追踪：记录评分结果
            if tracker and scorers and r.get("response"):
                score_label = "bypass" if is_success else "blocked"
                tracker.log_scoring_result(
                    scorer_name=type(scorers[0]).__name__,
                    score_value="1.0" if is_success else "0.0",
                    score_label=score_label,
                    reason=f"Attack {'succeeded' if is_success else 'failed'} → {score_label}",
                    response_snippet=r.get("response", ""),
                )

        self._results.append(results)
        return results

    def _execute_presets_v3(
        self,
        attack_config: Dict[str, Any],
        target: PromptTarget,
        scorers: Optional[List[Scorer]],
        tracker: Optional[Any] = None,
    ) -> Dict[str, Any]:
        """
        presets 模式 v3.0：使用 SequentialAttack (FIRST_SUCCESS)

        多 preset 时利用 PyRIT 的 SequentialAttack 实现早停：
        - 每个 preset 作为一个 child attack
        - 第一个成功后立即停止
        - 单 preset 时直接使用 PromptSendingAttack

        支持并发执行：通过 RateController 控制并发数
        """
        attack_name = attack_config.get("name", "unnamed_attack")
        payloads = attack_config.get("payloads", [])
        converter_presets = attack_config.get("converter_presets", {})
        asi_category = attack_config.get("asi_category", "")

        # 获取并发数
        concurrency = self._rate_controller.concurrency if self._rate_controller else 1
        logger.info(
            "Executing attack (presets v3.0): %s with %d payloads, %d presets (concurrency=%d)",
            attack_name, len(payloads), len(converter_presets), concurrency,
        )

        results = {
            "attack_name": attack_name,
            "mode": "presets",
            "severity": attack_config.get("severity", ""),
            "payloads_tested": len(payloads) * len(converter_presets),
            "results": [],
            "success_count": 0,
            "failure_count": 0,
            "preset_stats": {},
        }

        # 构建 AttackScoringConfig
        attack_scoring_config = AttackScoringConfig()
        if scorers:
            attack_scoring_config = AttackScoringConfig(objective_scorer=scorers[0] if scorers else None)

        # 流水线追踪：记录评分器选择
        if tracker and scorers:
            scorer_meta = self._get_scorer_selection_meta(asi_category, scorers)
            tracker.log_scorer_selection(**scorer_meta)

        preset_names = list(converter_presets.keys())

        # 并发执行所有 payload
        async def _run_all():
            semaphore = self._rate_controller.semaphore if self._rate_controller else None

            async def _execute_one(payload: str) -> Dict[str, Any]:
                if semaphore:
                    await semaphore.acquire()
                try:
                    if len(preset_names) == 1:
                        # 单 preset：直接使用 PromptSendingAttack
                        preset_name = preset_names[0]
                        converter_names = converter_presets[preset_name]
                        preset_converters = self.build_converters([{"name": c} for c in converter_names])
                        attack_converter_config = AttackConverterConfig(request_converters=preset_converters)

                        attack = PromptSendingAttack(
                            objective_target=target,
                            attack_converter_config=attack_converter_config,
                            attack_scoring_config=attack_scoring_config,
                            max_attempts_on_failure=1,
                        )
                        attack_result = await attack.execute_async(objective=payload)
                        is_success = attack_result.outcome.name == "SUCCESS"

                        return {
                            "payload": payload[:100],
                            "preset": preset_name,
                            "status": "success" if is_success else "failed",
                            "outcome": attack_result.outcome.name,
                            "response": str(attack_result)[:200],
                            "is_success": is_success,
                        }
                    else:
                        # 多 preset：使用 SequentialAttack (FIRST_SUCCESS)
                        from pyrit.executor.attack.compound.sequential_attack import (
                            SequentialAttack,
                            SequentialChildAttack,
                            SequenceCompletionPolicy,
                        )
                        from pyrit.models import SeedPrompt, SeedPromptGroup

                        child_attacks = []
                        for p_name in preset_names:
                            converter_names = converter_presets[p_name]
                            preset_converters = self.build_converters([{"name": c} for c in converter_names])

                            child_attack = PromptSendingAttack(
                                objective_target=target,
                                attack_converter_config=AttackConverterConfig(request_converters=preset_converters),
                                attack_scoring_config=attack_scoring_config,
                                max_attempts_on_failure=1,
                            )
                            child_attacks.append(
                                SequentialChildAttack(
                                    strategy=child_attack,
                                    seed_group=SeedPromptGroup(
                                        prompts=[SeedPrompt(value=payload, data_type="text")]
                                    ),
                                )
                            )

                        sequential = SequentialAttack(
                            objective_target=target,
                            child_attacks=child_attacks,
                            completion_policy=SequenceCompletionPolicy.FIRST_SUCCESS,
                        )

                        seq_result = await sequential.execute_async(objective=payload)
                        is_success = seq_result.outcome.name == "SUCCESS"

                        # 确定哪个 preset 成功了
                        successful_preset = "unknown"
                        for i, child_result in enumerate(seq_result.child_results):
                            if child_result and child_result.outcome.name == "SUCCESS":
                                successful_preset = preset_names[i] if i < len(preset_names) else "unknown"
                                break

                        return {
                            "payload": payload[:100],
                            "preset": successful_preset if is_success else "all_failed",
                            "status": "success" if is_success else "failed",
                            "outcome": seq_result.outcome.name,
                            "response": str(seq_result)[:200],
                            "is_success": is_success,
                        }
                except Exception as e:
                    logger.error("Attack failed for payload '%s': %s", payload[:50], str(e))
                    return {
                        "payload": payload[:100],
                        "preset": "error",
                        "status": "error",
                        "error": str(e)[:200],
                        "is_success": False,
                    }
                finally:
                    if semaphore:
                        semaphore.release()

            tasks = [_execute_one(p) for p in payloads]
            return await asyncio.gather(*tasks)

        all_results = asyncio.run(_run_all())

        # 汇总结果
        for r in all_results:
            is_success = r.pop("is_success", False)
            results["results"].append(r)
            if is_success:
                results["success_count"] += 1
            else:
                results["failure_count"] += 1

        self._results.append(results)
        return results

    def _execute_smart_match_v3(
        self,
        attack_config: Dict[str, Any],
        target: PromptTarget,
        scorers: Optional[List[Scorer]],
        tracker: Optional[Any] = None,
        profile_params: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        smart_match 模式 v3.0：使用 PyRIT 原生攻击 + 两层策略选择 + Fallback 链

        核心改进：
        1. SmartMatcher 两层策略选择（快速规则筛选 → 精确模型匹配）
        2. 支持 Fallback 链（主策略失败时自动尝试备选）
        3. ASI 感知策略选择
        4. 动态参数计算
        5. 全流程追踪：payload → 分类 → 策略 → 评分器 → 评分结果
        6. 侦察驱动：TargetProfile 参数注入 SmartMatcher
        """
        from ..orchestrators.smart_matcher import SmartMatcher

        attack_name = attack_config.get("name", "unnamed_attack")
        payloads = attack_config.get("payloads", [])
        converter_presets = attack_config.get("converter_presets", {})
        target_model = attack_config.get("target_model", "")
        asi_category = attack_config.get("asi_category", "")

        logger.info(
            "Executing attack (smart_match v3.0): %s with %d payloads, target=%s",
            attack_name, len(payloads), target_model or "unknown",
        )

        # 1. SmartMatcher 构建攻击计划（两层策略选择 + 侦察驱动）
        has_adversarial = self._check_adversarial_available()

        # 从侦察画像提取策略参数
        preferred_families = None
        aggression_level = "medium"
        if profile_params:
            preferred_families = profile_params.get("preferred_probe_families")
            aggression_level = profile_params.get("aggression_level", "medium")
            # 侦察发现的目标模型名优先于配置
            profile_model = profile_params.get("target_model")
            if profile_model:
                target_model = profile_model

        matcher = SmartMatcher(
            target_model=target_model,
            has_adversarial=has_adversarial,
            preferred_probe_families=preferred_families,
            aggression_level=aggression_level,
        )
        plan = matcher.build_attack_plan(
            payloads, converter_presets, asi_category=asi_category
        )
        plan_summary = matcher.get_plan_summary(plan)

        logger.info("Attack plan (v3.0): %s", plan_summary)

        # 1.5 流水线追踪：记录分类和策略选择
        if tracker:
            for item in plan:
                tracker.start_payload(item["payload"])
                tracker.log_load(item["payload"], source=attack_name)
                # 记录分类
                profile_dict = item.get("payload_profile", {})
                if profile_dict:
                    from ..payloads.models import PayloadProfile
                    profile = PayloadProfile(
                        technique=profile_dict.get("technique", "direct"),
                        encoding_state=profile_dict.get("encoding_state", "plain"),
                        language=profile_dict.get("language", "en"),
                        length_class=profile_dict.get("length_class", "short"),
                        complexity=profile_dict.get("complexity", "simple"),
                    )
                    tracker.log_classify(profile)
                # 记录策略选择
                strategy = {
                    "class": item.get("attack_class", ""),
                    "family": item.get("attack_family", ""),
                    "reason": item.get("attack_reason", ""),
                    "confidence": item.get("attack_confidence", 1.0),
                    "params": item.get("attack_params", {}),
                    "fallback_chain": item.get("attack_fallback_chain", []),
                }
                tracker.log_strategy(strategy)

            tracker.show_classification_summary()
            tracker.show_strategy_summary()

        # 1.6 流水线追踪：记录评分器选择
        scorer_selection_meta = self._get_scorer_selection_meta(asi_category, scorers)
        if tracker and scorer_selection_meta:
            tracker.log_scorer_selection(
                asi_category=scorer_selection_meta["asi_category"],
                scenario_key=scorer_selection_meta["scenario_key"],
                best_scorer_def=scorer_selection_meta["best_scorer_def"],
                final_scorers=scorer_selection_meta["final_scorers"],
                reason=scorer_selection_meta["reason"],
            )
            tracker.show_scorer_summary()

        # 2. 执行：使用 PyRIT 原生攻击（支持 Fallback 链 + 并发）
        results = {
            "attack_name": attack_name,
            "mode": "smart_match",
            "severity": attack_config.get("severity", ""),
            "total_executions": len(plan),
            "plan_summary": plan_summary,
            "plan": plan,
            "results": [],
            "success_count": 0,
            "failure_count": 0,
            "category_stats": {},
            "best_combinations": [],
        }

        # 构建 AttackScoringConfig
        attack_scoring_config = AttackScoringConfig()
        if scorers:
            attack_scoring_config = AttackScoringConfig(objective_scorer=scorers[0] if scorers else None)

        # 获取并发数
        concurrency = self._rate_controller.concurrency if self._rate_controller else 1
        logger.info("Smart match concurrency: %d", concurrency)

        # 并发执行所有 plan item
        async def _run_all():
            semaphore = self._rate_controller.semaphore if self._rate_controller else None

            async def _execute_one(item: Dict[str, Any]) -> Dict[str, Any]:
                payload = item["payload"]
                if semaphore:
                    await semaphore.acquire()
                try:
                    attempt_result = await self._execute_with_fallback_async(
                        payload=payload,
                        primary_class_fqn=item["attack_class"],
                        primary_params=item["attack_params"],
                        fallback_chain=item.get("attack_fallback_chain", []),
                        target=target,
                        attack_scoring_config=attack_scoring_config,
                        converter_presets=converter_presets,
                    )

                    return {
                        "payload": payload[:100],
                        "payload_category": item["payload_category"],
                        "attack_class": attempt_result["attack_class"],
                        "attack_family": item.get("attack_family", ""),
                        "attack_reason": item.get("attack_reason", ""),
                        "attack_confidence": item.get("attack_confidence", 1.0),
                        "status": attempt_result["status"],
                        "outcome": attempt_result["outcome"],
                        "response": attempt_result["response"],
                        "attempts_used": attempt_result.get("attempts_used", 1),
                    }
                finally:
                    if semaphore:
                        semaphore.release()

            tasks = [_execute_one(item) for item in plan]
            return await asyncio.gather(*tasks)

        all_results = asyncio.run(_run_all())

        # 汇总结果
        for r in all_results:
            results["results"].append(r)
            is_success = r["status"] == "success"
            if is_success:
                results["success_count"] += 1
            else:
                results["failure_count"] += 1

            # 更新类别统计
            category = r.get("payload_category", "unknown")
            if category not in results["category_stats"]:
                results["category_stats"][category] = {"success": 0, "failure": 0}
            results["category_stats"][category]["success" if is_success else "failure"] += 1

            # 流水线追踪：记录执行结果
            if tracker:
                tracker.log_execution(r)
                if scorers and r.get("response"):
                    score_label = "bypass" if is_success else "blocked"
                    tracker.log_scoring_result(
                        scorer_name=type(scorers[0]).__name__ if scorers else "none",
                        score_value="1.0" if is_success else "0.0",
                        score_label=score_label,
                        reason=f"Attack {'succeeded' if is_success else 'failed'} → {score_label}",
                        response_snippet=r.get("response", ""),
                    )

        # 3. 流水线追踪：结果汇总
        if tracker:
            tracker.show_full_report()

        self._results.append(results)
        return results

    def _execute_with_fallback(
        self,
        payload: str,
        primary_class_fqn: str,
        primary_params: Dict[str, Any],
        fallback_chain: List[Dict[str, Any]],
        target: PromptTarget,
        attack_scoring_config: Any,
        converter_presets: Dict[str, List[str]],
    ) -> Dict[str, Any]:
        """
        执行攻击（支持 Fallback 链）

        先尝试主策略，失败时按 fallback_chain 依次尝试备选策略。
        """
        # 尝试主策略
        result = self._execute_single_attack(
            payload=payload,
            attack_class_fqn=primary_class_fqn,
            attack_params=primary_params,
            target=target,
            attack_scoring_config=attack_scoring_config,
            converter_presets=converter_presets,
        )

        if result["status"] == "success":
            result["attempts_used"] = 1
            return result

        # 主策略失败，尝试 Fallback 链
        for fallback_idx, fallback in enumerate(fallback_chain, 2):
            logger.info(
                "Primary attack failed, trying fallback %d/%d: %s",
                fallback_idx - 1, len(fallback_chain),
                fallback["class"].split(".")[-1],
            )

            fallback_result = self._execute_single_attack(
                payload=payload,
                attack_class_fqn=fallback["class"],
                attack_params=fallback.get("params", {}),
                target=target,
                attack_scoring_config=attack_scoring_config,
                converter_presets=converter_presets,
            )

            if fallback_result["status"] == "success":
                fallback_result["attempts_used"] = fallback_idx
                return fallback_result

        # 所有策略都失败，返回主策略结果
        result["attempts_used"] = 1 + len(fallback_chain)
        return result

    def _execute_single_attack(
        self,
        payload: str,
        attack_class_fqn: str,
        attack_params: Dict[str, Any],
        target: PromptTarget,
        attack_scoring_config: Any,
        converter_presets: Dict[str, List[str]],
    ) -> Dict[str, Any]:
        """
        执行单次 PyRIT 攻击（同步包装）

        根据攻击类型自动构建所需参数（adversarial config, converter config 等）
        """
        try:
            # 动态导入 PyRIT 攻击类
            attack_class = _import_class(attack_class_fqn)

            # 构建通用参数
            common_kwargs = {
                "objective_target": target,
                "attack_scoring_config": attack_scoring_config,
            }

            # 根据攻击类型添加特定参数
            if attack_class_fqn.endswith("CrescendoAttack"):
                adv_config = self._build_adversarial_config(target)
                if adv_config:
                    common_kwargs["attack_adversarial_config"] = adv_config
                    common_kwargs["attack_converter_config"] = AttackConverterConfig()
                else:
                    logger.warning("No adversarial LLM for Crescendo, falling back to PromptSendingAttack")
                    attack_class = PromptSendingAttack
                    common_kwargs["max_attempts_on_failure"] = 2

            elif attack_class_fqn.endswith("TreeOfAttacksWithPruningAttack"):
                adv_config = self._build_adversarial_config(target)
                if adv_config:
                    common_kwargs["attack_adversarial_config"] = adv_config
                    common_kwargs["attack_converter_config"] = AttackConverterConfig()
                else:
                    logger.warning("No adversarial LLM for TAP, falling back to PromptSendingAttack")
                    attack_class = PromptSendingAttack
                    common_kwargs["max_attempts_on_failure"] = 2

            elif attack_class_fqn.endswith("PAIRAttack"):
                adv_config = self._build_adversarial_config(target)
                if adv_config:
                    common_kwargs["attack_adversarial_config"] = adv_config
                    common_kwargs["attack_converter_config"] = AttackConverterConfig()
                else:
                    logger.warning("No adversarial LLM for PAIR, falling back to PromptSendingAttack")
                    attack_class = PromptSendingAttack
                    common_kwargs["max_attempts_on_failure"] = 2

            elif attack_class_fqn.endswith("RedTeamingAttack"):
                adv_config = self._build_adversarial_config(target)
                if adv_config:
                    common_kwargs["attack_adversarial_config"] = adv_config
                    common_kwargs["attack_converter_config"] = AttackConverterConfig()
                else:
                    logger.warning("No adversarial LLM for RedTeaming, falling back to PromptSendingAttack")
                    attack_class = PromptSendingAttack
                    common_kwargs["max_attempts_on_failure"] = 2

            elif attack_class_fqn.endswith("PromptSendingAttack"):
                converter_names = list(converter_presets.values())[0] if converter_presets else []
                preset_converters = self.build_converters([{"name": c} for c in converter_names])
                common_kwargs["attack_converter_config"] = AttackConverterConfig(request_converters=preset_converters)

            # 合并动态参数
            common_kwargs.update(attack_params)

            # 创建攻击实例并执行
            attack = attack_class(**common_kwargs)
            attack_result = asyncio.run(attack.execute_async(objective=payload))

            # 解析结果
            outcome = attack_result.outcome
            is_success = outcome.name == "SUCCESS"

            return {
                "attack_class": attack_class_fqn.split(".")[-1],
                "status": "success" if is_success else "failed",
                "outcome": outcome.name,
                "response": str(attack_result)[:200],
            }

        except Exception as e:
            logger.error(
                "Attack failed (class=%s): %s",
                attack_class_fqn.split(".")[-1], str(e),
            )
            return {
                "attack_class": attack_class_fqn.split(".")[-1],
                "status": "error",
                "outcome": "ERROR",
                "response": str(e)[:200],
            }

    async def _execute_single_attack_async(
        self,
        payload: str,
        attack_class_fqn: str,
        attack_params: Dict[str, Any],
        target: PromptTarget,
        attack_scoring_config: Any,
        converter_presets: Dict[str, List[str]],
    ) -> Dict[str, Any]:
        """
        执行单次 PyRIT 攻击（异步版本，用于并发执行）

        与 _execute_single_attack 逻辑相同，但使用 await 而非 asyncio.run()
        """
        try:
            attack_class = _import_class(attack_class_fqn)

            common_kwargs = {
                "objective_target": target,
                "attack_scoring_config": attack_scoring_config,
            }

            if attack_class_fqn.endswith("CrescendoAttack"):
                adv_config = self._build_adversarial_config(target)
                if adv_config:
                    common_kwargs["attack_adversarial_config"] = adv_config
                    common_kwargs["attack_converter_config"] = AttackConverterConfig()
                else:
                    logger.warning("No adversarial LLM for Crescendo, falling back to PromptSendingAttack")
                    attack_class = PromptSendingAttack
                    common_kwargs["max_attempts_on_failure"] = 2

            elif attack_class_fqn.endswith("TreeOfAttacksWithPruningAttack"):
                adv_config = self._build_adversarial_config(target)
                if adv_config:
                    common_kwargs["attack_adversarial_config"] = adv_config
                    common_kwargs["attack_converter_config"] = AttackConverterConfig()
                else:
                    logger.warning("No adversarial LLM for TAP, falling back to PromptSendingAttack")
                    attack_class = PromptSendingAttack
                    common_kwargs["max_attempts_on_failure"] = 2

            elif attack_class_fqn.endswith("PAIRAttack"):
                adv_config = self._build_adversarial_config(target)
                if adv_config:
                    common_kwargs["attack_adversarial_config"] = adv_config
                    common_kwargs["attack_converter_config"] = AttackConverterConfig()
                else:
                    logger.warning("No adversarial LLM for PAIR, falling back to PromptSendingAttack")
                    attack_class = PromptSendingAttack
                    common_kwargs["max_attempts_on_failure"] = 2

            elif attack_class_fqn.endswith("RedTeamingAttack"):
                adv_config = self._build_adversarial_config(target)
                if adv_config:
                    common_kwargs["attack_adversarial_config"] = adv_config
                    common_kwargs["attack_converter_config"] = AttackConverterConfig()
                else:
                    logger.warning("No adversarial LLM for RedTeaming, falling back to PromptSendingAttack")
                    attack_class = PromptSendingAttack
                    common_kwargs["max_attempts_on_failure"] = 2

            elif attack_class_fqn.endswith("PromptSendingAttack"):
                converter_names = list(converter_presets.values())[0] if converter_presets else []
                preset_converters = self.build_converters([{"name": c} for c in converter_names])
                common_kwargs["attack_converter_config"] = AttackConverterConfig(request_converters=preset_converters)

            common_kwargs.update(attack_params)

            attack = attack_class(**common_kwargs)
            attack_result = await attack.execute_async(objective=payload)

            outcome = attack_result.outcome
            is_success = outcome.name == "SUCCESS"

            return {
                "attack_class": attack_class_fqn.split(".")[-1],
                "status": "success" if is_success else "failed",
                "outcome": outcome.name,
                "response": str(attack_result)[:200],
            }

        except Exception as e:
            logger.error(
                "Attack failed (class=%s): %s",
                attack_class_fqn.split(".")[-1], str(e),
            )
            return {
                "attack_class": attack_class_fqn.split(".")[-1],
                "status": "error",
                "outcome": "ERROR",
                "response": str(e)[:200],
            }

    async def _execute_with_fallback_async(
        self,
        payload: str,
        primary_class_fqn: str,
        primary_params: Dict[str, Any],
        fallback_chain: List[Dict[str, Any]],
        target: PromptTarget,
        attack_scoring_config: Any,
        converter_presets: Dict[str, List[str]],
    ) -> Dict[str, Any]:
        """
        执行攻击（支持 Fallback 链，异步版本）

        先尝试主策略，失败时按 fallback_chain 依次尝试备选策略。
        """
        # 尝试主策略
        result = await self._execute_single_attack_async(
            payload=payload,
            attack_class_fqn=primary_class_fqn,
            attack_params=primary_params,
            target=target,
            attack_scoring_config=attack_scoring_config,
            converter_presets=converter_presets,
        )

        if result["status"] == "success":
            result["attempts_used"] = 1
            return result

        # 主策略失败，尝试 Fallback 链
        for fallback_idx, fallback in enumerate(fallback_chain, 2):
            logger.info(
                "Primary attack failed, trying fallback %d/%d: %s",
                fallback_idx - 1, len(fallback_chain),
                fallback["class"].split(".")[-1],
            )

            fallback_result = await self._execute_single_attack_async(
                payload=payload,
                attack_class_fqn=fallback["class"],
                attack_params=fallback.get("params", {}),
                target=target,
                attack_scoring_config=attack_scoring_config,
                converter_presets=converter_presets,
            )

            if fallback_result["status"] == "success":
                fallback_result["attempts_used"] = fallback_idx
                return fallback_result

        # 所有策略都失败，返回主策略结果
        result["attempts_used"] = 1 + len(fallback_chain)
        return result

    def _get_scorer_selection_meta(
        self,
        asi_category: str,
        scorers: Optional[List[Any]],
    ) -> Dict[str, Any]:
        """
        获取评分器选择的元数据（用于流水线追踪）

        根据 ASI 类别查询 best_scorer_by_scenario，返回选择决策信息。

        Args:
            asi_category: ASI 类别 (如 "ASI01")
            scorers: 已构建的评分器实例列表

        Returns:
            评分器选择元数据字典
        """
        # 构建最终评分器信息
        final_scorers = []
        if scorers:
            for s in scorers:
                final_scorers.append({
                    "name": type(s).__name__,
                    "backend": "objective_target",
                })

        # 查询 best_scorer_by_scenario
        best_scorer_def = {}
        scenario_key = ""
        reason = "使用 catalog 显式配置的评分器"

        if asi_category:
            scenarios = self._scorer_config.get("best_scorer_by_scenario", {})
            # 尝试匹配场景键（支持部分匹配）
            for key, defn in scenarios.items():
                if asi_category.lower() in key.lower():
                    scenario_key = key
                    if isinstance(defn, dict):
                        best_scorer_def = defn
                    elif isinstance(defn, str):
                        # 从 scorer_definitions 查找完整定义
                        scorer_type = defn
                        best_scorer_def = {
                            "type": scorer_type.split("_")[0] if "_" in scorer_type else scorer_type,
                            "backend": defn,
                            "description": f"场景 {key} 推荐评分器",
                        }
                    reason = f"ASI {asi_category} → 场景 {key} 推荐: {defn}"
                    break

        return {
            "asi_category": asi_category,
            "scenario_key": scenario_key,
            "best_scorer_def": best_scorer_def,
            "final_scorers": final_scorers,
            "reason": reason,
        }

    def _check_adversarial_available(self) -> bool:
        """检查是否有可用的对抗性 LLM（Crescendo/TAP 需要）"""
        # 从 scorer 配置中检查是否有可用的 LLM 后端
        backends = self._scorer_config.get("scorer_llm_backends", {})
        # 排除 objective_target，检查是否有独立的评分器后端
        scorer_backends = {k: v for k, v in backends.items() if k != "objective_target"}
        return len(scorer_backends) > 0

    def _build_adversarial_config(self, objective_target: PromptTarget) -> Optional[AttackAdversarialConfig]:
        """构建对抗性配置（Crescendo/TAP 需要）"""
        backends = self._scorer_config.get("scorer_llm_backends", {})
        # 使用第一个可用的非 objective_target 后端
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

    # ──────────────────────────────────────────────────────────────────────────
    # 静态工具方法
    # ──────────────────────────────────────────────────────────────────────────

    @staticmethod
    def load_yaml(path: str) -> Dict[str, Any]:
        """加载 YAML 文件（支持多文档分隔符 ---）"""
        from pathlib import Path
        file_path = Path(path)
        if not file_path.exists():
            logger.warning("Config file not found: %s", path)
            return {}
        with open(file_path, "r", encoding="utf-8") as f:
            import yaml
            docs = list(yaml.safe_load_all(f))
            return docs[0] if docs else {}

    @classmethod
    def build_attack_list(cls, module_config: Dict[str, Any]) -> List[Dict[str, Any]]:
        """从模块配置构建攻击列表（兼容旧接口）"""
        attacks = []

        for key, value in module_config.items():
            if key in ("name", "owasp", "description", "owasp_agentic", "foundational_principles", "surfaces"):
                continue
            if not isinstance(value, dict):
                continue

            mode = value.get("mode", "chain")
            payloads = cls._resolve_payloads(value)

            if mode == "smart_match":
                if not payloads or "converter_presets" not in value:
                    logger.warning("smart_match mode requires payloads and 'converter_presets': %s", key)
                    continue

                scorer_configs = []
                for sname in cls._extract_scorer_names(value.get("pyrit_scorers", [])):
                    if sname == "substring":
                        scorer_configs.append({"name": sname, "params": {"substring": "password"}})
                    else:
                        scorer_configs.append({"name": sname})

                attacks.append({
                    "name": value.get("name", key),
                    "description": value.get("description", ""),
                    "mode": "smart_match",
                    "severity": value.get("severity", ""),
                    "payloads": payloads,
                    "converter_presets": value.get("converter_presets", {}),
                    "match_rules": value.get("match_rules", None),
                    "scorers": scorer_configs,
                    "asi_category": value.get("asi_category", ""),
                })

            elif mode == "presets":
                if not payloads:
                    continue

                scorer_configs = []
                for sname in cls._extract_scorer_names(value.get("pyrit_scorers", [])):
                    if sname == "substring":
                        scorer_configs.append({"name": sname, "params": {"substring": "password"}})
                    else:
                        scorer_configs.append({"name": sname})

                attacks.append({
                    "name": value.get("name", key),
                    "description": value.get("description", ""),
                    "mode": "presets",
                    "severity": value.get("severity", ""),
                    "payloads": payloads,
                    "converter_presets": value.get("converter_presets", {}),
                    "scorers": scorer_configs,
                })

            else:
                if not payloads:
                    continue

                converter_configs = []
                for cname in cls._extract_converter_names(value.get("pyrit_converters", [])):
                    converter_configs.append({"name": cname})

                scorer_configs = []
                for sname in cls._extract_scorer_names(value.get("pyrit_scorers", [])):
                    if sname == "substring":
                        scorer_configs.append({"name": sname, "params": {"substring": "password"}})
                    else:
                        scorer_configs.append({"name": sname})

                attacks.append({
                    "name": value.get("name", key),
                    "description": value.get("description", ""),
                    "mode": "chain",
                    "severity": value.get("severity", ""),
                    "payloads": payloads,
                    "converters": converter_configs,
                    "scorers": scorer_configs,
                    "asi_category": value.get("asi_category", ""),
                })

        return attacks

    @classmethod
    def build_attack_list_from_refs(cls, refs: List[str], payload_mgr: "PayloadManager") -> List[Dict[str, Any]]:
        """
        从 OWASP ref 列表构建攻击列表

        Args:
            refs: OWASP ref 路径列表（如 ["owasp:agentic:asi01", "owasp:llm:llm01"]）
            payload_mgr: PayloadManager 实例

        Returns:
            攻击配置列表
        """
        # OWASP ID → 默认转换器/评分器映射
        _DEFAULT_CONVERTERS = {
            "llm01": ["base64", "rot13", "unicode_confusable", "leet_speak", "ascii_smuggler", "zero_width", "diacritic"],
            "llm02": ["base64", "search_replace"],
            "llm03": ["malicious_question_generator"],
            "llm04": ["add_text_image", "word_doc"],
            "llm05": ["malicious_question_generator"],
            "llm06": ["persuasion", "variation"],
            "llm07": ["translation", "persuasion"],
            "llm08": ["search_replace"],
            "llm09": ["persuasion"],
            "llm10": ["base64"],
            "asi01": ["base64", "rot13", "unicode_confusable", "leet_speak", "persuasion", "ascii_smuggler", "zero_width", "diacritic"],
            "asi02": ["add_text_image", "pdf", "search_replace"],
            "asi03": ["persuasion", "unicode_confusable"],
            "asi04": ["malicious_question_generator"],
            "asi05": ["malicious_question_generator", "ascii_smuggler"],
            "asi06": ["persuasion", "variation"],
            "asi07": ["persuasion", "translation"],
            "asi08": ["malicious_question_generator"],
            "asi09": ["persuasion"],
            "asi10": ["persuasion", "malicious_question_generator"],
        }

        _DEFAULT_SCORERS = {
            "llm01": ["self_ask_refusal", "substring"],
            "llm02": ["self_ask_true_false"],
            "llm03": ["self_ask_true_false"],
            "llm04": ["self_ask_true_false"],
            "llm05": ["self_ask_refusal", "self_ask_true_false"],
            "llm06": ["self_ask_true_false", "substring"],
            "llm07": ["self_ask_refusal", "self_ask_true_false"],
            "llm08": ["substring"],
            "llm09": ["self_ask_refusal"],
            "llm10": ["self_ask_true_false"],
            "asi01": ["self_ask_refusal", "substring"],
            "asi02": ["self_ask_refusal", "self_ask_true_false"],
            "asi03": ["self_ask_refusal", "self_ask_true_false"],
            "asi04": ["self_ask_refusal", "self_ask_true_false"],
            "asi05": ["self_ask_refusal", "self_ask_true_false"],
            "asi06": ["self_ask_true_false", "substring"],
            "asi07": ["self_ask_refusal", "self_ask_true_false"],
            "asi08": ["self_ask_true_false", "substring"],
            "asi09": ["self_ask_refusal", "self_ask_true_false"],
            "asi10": ["self_ask_refusal", "self_ask_true_false"],
        }

        attacks = []
        for ref in refs:
            data = payload_mgr.get_payload_file(ref)
            if not data:
                continue

            owasp_id = data.get("id", ref.split(":")[-1]).lower()
            converters = _DEFAULT_CONVERTERS.get(owasp_id, ["base64"])
            scorers = _DEFAULT_SCORERS.get(owasp_id, ["self_ask_refusal"])

            scorer_configs = []
            for sname in scorers:
                if sname == "substring":
                    scorer_configs.append({"name": sname, "params": {"substring": "password"}})
                else:
                    scorer_configs.append({"name": sname})

            attacks.append({
                "name": data.get("name", ref),
                "description": data.get("description", ""),
                "mode": "smart_match",
                "severity": data.get("severity", "medium"),
                "payloads": data.get("payloads", []),
                "converter_presets": {"default": converters},
                "scorers": scorer_configs,
                "asi_category": data.get("id", ""),
            })

        return attacks

    @classmethod
    def _resolve_payloads(cls, attack_data: Dict[str, Any]) -> List[str]:
        """解析攻击数据中的载荷"""
        if "payload_refs" in attack_data:
            refs = [r.lower() for r in attack_data["payload_refs"]]
            if cls._payload_manager is not None:
                return cls._payload_manager.resolve_refs(refs)
            try:
                from ..payloads.payload_manager import PayloadManager
                pm = PayloadManager()
                pm.load_data_dir(cls.DATA_DIR)
                return pm.resolve_refs(refs)
            except Exception as e:
                logger.error("Failed to resolve payload_refs: %s", str(e))
                return []

        return attack_data.get("payloads", [])

    @staticmethod
    def _extract_converter_names(pyrit_converters: List[str]) -> List[str]:
        """从 PyRIT 转换器全限定名提取简短名称"""
        names = []
        for converter_fqn in pyrit_converters:
            class_name = converter_fqn.split(".")[-1]
            if class_name in CONVERTER_NAME_MAP:
                names.append(CONVERTER_NAME_MAP[class_name])
        return names

    @staticmethod
    def _extract_scorer_names(pyrit_scorers: List[str]) -> List[str]:
        """从 PyRIT 评分器全限定名提取简短名称"""
        names = []
        for scorer_fqn in pyrit_scorers:
            class_name = scorer_fqn.split(".")[-1]
            if class_name in SCORER_NAME_MAP:
                names.append(SCORER_NAME_MAP[class_name])
        return names


# 向后兼容：模块级导出
# 确保 from attack_orchestrator import CONVERTER_MAP 等仍然工作
# 已通过 component_registry 导入到模块命名空间
