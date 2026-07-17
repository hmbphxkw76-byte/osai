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
from pyrit.prompt_normalizer.prompt_converter_configuration import PromptConverterConfiguration
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
    CONVERTERS_NEEDING_TARGET,
)

# 速率控制器
from .rate_controller import RateController, create_rate_controller

logger = logging.getLogger(__name__)


def _import_class(fqn: str) -> type:
    """从全限定名导入类"""
    module_path, class_name = fqn.rsplit(".", 1)
    module = importlib.import_module(module_path)
    return getattr(module, class_name)


def _extract_payload_text(
    payload: Any,
    objective: Optional[str] = None,
    placeholders: Optional[Dict[str, str]] = None,
) -> str:
    """
    从载荷中提取文本（兼容字符串和字典格式）

    支持模板渲染：
    - {objective} / {goal} → 优先使用用户指定的 objective，否则替换为载荷文本本身
    - {base64_goal} → base64 编码的 objective
    - {french_goal} → 法语翻译的 objective（模拟，实际为前缀标记）
    - {ascii85_goal} → ASCII85 编码
    - {base32_goal} → Base32 编码
    - {bidi_override_goal} → Bidi 覆盖编码
    - {chain_encoded_goal} → 链式编码（base64 + reverse）
    - {unicode_tag_goal} → Unicode 标签字符编码
    - {zalgo_goal} → Zalgo 文字变形
    - {ascii_tag_deep_goal} → 深层 ASCII 标签编码
    - 其他占位符 → 从 placeholders 字典查找替换

    Args:
        payload: 载荷（字符串或字典）
        objective: 用户指定的攻击目标（可选，替换 {objective} 占位符）
        placeholders: 用户自定义占位符字典（可选，如 {"domain": "evil.com", "task": "whoami"}）

    Returns:
        载荷文本字符串
    """
    if isinstance(payload, dict):
        text = payload.get("payload", str(payload))
    else:
        text = str(payload)

    # 确定替换值
    if objective:
        replacement = objective
    else:
        # 未指定 objective，使用去除占位符后的载荷文本本身
        replacement = text.replace("{objective}", "").replace("{goal}", "").strip()
        replacement = replacement.rstrip("：: ")

    # 模板渲染：替换 {objective} / {goal} 占位符
    if "{objective}" in text or "{goal}" in text:
        text = text.replace("{objective}", replacement).replace("{goal}", replacement)

    # 编码变体占位符渲染
    text = _render_encoding_placeholders(text, replacement)

    # 用户自定义占位符渲染（Tier 3 领域参数）
    if placeholders:
        for key, value in placeholders.items():
            placeholder = "{" + key + "}"
            if placeholder in text:
                text = text.replace(placeholder, value)

    return text


def _render_encoding_placeholders(text: str, goal: str) -> str:
    """
    渲染编码变体占位符

    将 goal 进行各种编码转换后替换对应占位符。
    如果 goal 为空，使用原始文本去除已知占位符后的内容。

    Args:
        text: 载荷文本
        goal: 攻击目标文本

    Returns:
        渲染后的文本
    """
    import base64

    if not goal:
        return text

    # {base64_goal}
    if "{base64_goal}" in text:
        encoded = base64.b64encode(goal.encode()).decode()
        text = text.replace("{base64_goal}", encoded)

    # {base32_goal}
    if "{base32_goal}" in text:
        encoded = base64.b32encode(goal.encode()).decode()
        text = text.replace("{base32_goal}", encoded)

    # {ascii85_goal}
    if "{ascii85_goal}" in text:
        try:
            encoded = base64.a85encode(goal.encode()).decode()
        except Exception:
            encoded = base64.b85encode(goal.encode()).decode()
        text = text.replace("{ascii85_goal}", encoded)

    # {french_goal} — 模拟多语言翻译（标记前缀，实际翻译需调用翻译API）
    if "{french_goal}" in text:
        french_simulated = f"[FR] {goal}"
        text = text.replace("{french_goal}", french_simulated)

    # {bidi_override_goal} — Bidi 覆盖字符编码
    if "{bidi_override_goal}" in text:
        bidi_encoded = "\u202E" + goal + "\u202C"
        text = text.replace("{bidi_override_goal}", bidi_encoded)

    # {unicode_tag_goal} — Unicode 标签字符编码（U+E0000-U+E007F）
    if "{unicode_tag_goal}" in text:
        tag_chars = []
        for ch in goal:
            tag_chars.append(chr(0xE0000 + ord(ch) % 128))
        text = text.replace("{unicode_tag_goal}", "".join(tag_chars))

    # {zalgo_goal} — Zalgo 文字变形（添加组合变音符号）
    if "{zalgo_goal}" in text:
        zalgo_marks = [
            "\u0300", "\u0301", "\u0302", "\u0303", "\u0304", "\u0305",
            "\u0306", "\u0307", "\u0308", "\u0309", "\u030A", "\u030B",
            "\u030C", "\u030D", "\u030E", "\u030F", "\u0310", "\u0311",
        ]
        zalgo_text = []
        for i, ch in enumerate(goal):
            zalgo_text.append(ch)
            zalgo_text.append(zalgo_marks[i % len(zalgo_marks)])
            if i % 3 == 0:
                zalgo_text.append(zalgo_marks[(i + 5) % len(zalgo_marks)])
        text = text.replace("{zalgo_goal}", "".join(zalgo_text))

    # {chain_encoded_goal} — 链式编码（base64 + reverse）
    if "{chain_encoded_goal}" in text:
        b64 = base64.b64encode(goal.encode()).decode()
        reversed_b64 = b64[::-1]
        text = text.replace("{chain_encoded_goal}", reversed_b64)

    # {ascii_tag_deep_goal} — 深层 ASCII 标签编码
    if "{ascii_tag_deep_goal}" in text:
        deep_encoded = "".join(f"\\u{ord(ch):04X}" for ch in goal)
        text = text.replace("{ascii_tag_deep_goal}", deep_encoded)

    # {hex_goal} — 十六进制编码
    if "{hex_goal}" in text:
        hex_encoded = goal.encode().hex()
        text = text.replace("{hex_goal}", hex_encoded)

    # {rot13_goal} — ROT13 编码
    if "{rot13_goal}" in text:
        import codecs
        rot13_encoded = codecs.encode(goal, "rot_13")
        text = text.replace("{rot13_goal}", rot13_encoded)

    # {sneaky_bits_goal} — 零宽字符隐写编码
    if "{sneaky_bits_goal}" in text:
        sneaky_chars = []
        for ch in goal:
            bits = format(ord(ch), "08b")
            for bit in bits:
                sneaky_chars.append("\u200C" if bit == "1" else "\u200B")
        text = text.replace("{sneaky_bits_goal}", "".join(sneaky_chars))

    # {interlinear_ws_goal} — 行间空白编码（零宽字符 + 换行隐藏）
    if "{interlinear_ws_goal}" in text:
        interlinear_lines = []
        for ch in goal:
            bits = format(ord(ch), "08b")
            line = "".join("\u200C" if bit == "1" else "\u200B" for bit in bits)
            interlinear_lines.append(line)
        interlinear_encoded = "\n".join(interlinear_lines)
        text = text.replace("{interlinear_ws_goal}", interlinear_encoded)

    # {multi_tag_mix_goal} — 多标签混合编码（bidi + zero-width + tag 三层嵌套）
    if "{multi_tag_mix_goal}" in text:
        tag_chars = []
        for ch in goal:
            tag_chars.append(chr(0xE0000 + ord(ch) % 128))
            tag_chars.append("\u200B")
        multi_encoded = "\u202E" + "".join(tag_chars) + "\u202C"
        text = text.replace("{multi_tag_mix_goal}", multi_encoded)

    return text


class AttackOrchestrator:
    """
    攻击编排器 v3.0

    功能：
    1. 从配置加载攻击策略
    2. 自动组合 PyRIT 转换器链
    3. 使用 PyRIT 原生攻击执行（不再手动循环）
    4. 自动评分和结果存储
    5. 支持外部 LLM 评分器后端（config/scores.yaml + CLI 参数覆盖）

    核心改进：
    - SmartMatcher 选择 PyRIT 攻击策略
    - 执行全部交给 PyRIT 原生攻击
    - 继承 PyRIT 的全部能力（重试、升级、回退、剪枝、早停）
    """

    # 评分器配置目录（多文件模式：config/scores/*.yaml）
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
        scorer_url: Optional[str] = None,
        scorer_key: Optional[str] = None,
        scorer_model: Optional[str] = None,
    ):
        self.config = self._load_config(config_path, config_dict)
        self.memory_type = memory_type
        self._components_initialized = False
        self._results: List[Dict[str, Any]] = []
        self._scorer_config: Dict[str, Any] = {}
        self._scorer_config_path = scorer_config_path or self.SCORER_CONFIG_PATH
        self._data_dir = data_dir or self.DATA_DIR
        self._rate_controller: Optional[RateController] = None

        # 外部 LLM 评分器参数（CLI 传入，优先级最高）
        self._scorer_url = scorer_url
        self._scorer_key = scorer_key
        self._scorer_model = scorer_model

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

                if browser_type == "firefox":
                    browser = await p.firefox.launch(headless=headless)
                elif browser_type == "webkit":
                    browser = await p.webkit.launch(headless=headless)
                else:
                    browser = await p.chromium.launch(headless=headless)

                context = await browser.new_context()

                if auth_profile and auth_profile.has_auth():
                    from .auth import inject_auth
                    page = await context.new_page()
                    await inject_auth(context, page, auth_profile)
                else:
                    page = await context.new_page()

                url = connection.get("url", "")
                if url:
                    wait_until = connection.get("wait_until", "domcontentloaded")
                    await page.goto(url, wait_until=wait_until)

                page._browser_ref = browser  # noqa: SLF001
                return page

        page = asyncio.run(_launch())
        return page

    def build_converters(
        self,
        converter_configs: List[Dict[str, Any]],
        converter_target: Optional[PromptTarget] = None,
    ) -> List[PromptConverterConfiguration]:
        """
        根据配置列表构建转换器配置（PyRIT 0.14.0 兼容）

        Args:
            converter_configs: 转换器配置列表
            converter_target: 需要 LLM 后端的转换器目标（自动注入）

        Returns:
            List[PromptConverterConfiguration] - AttackConverterConfig 需要的格式
        """
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
                    if name in CONVERTERS_NEEDING_TARGET and "converter_target" not in params:
                        if converter_target:
                            params["converter_target"] = converter_target
                            logger.debug("Auto-injected converter_target for: %s", name)
                        else:
                            logger.warning(
                                "Converter '%s' requires converter_target (LLM backend), "
                                "but none available. Skipping.",
                                name,
                            )
                            continue

                    converter_instance = converter_class(**params)
                    converters.append(PromptConverterConfiguration(converters=[converter_instance]))
                    logger.debug("Added converter: %s", name)
                except TypeError as e:
                    logger.warning("Converter %s requires params: %s", name, e)
            else:
                logger.warning("Unknown converter: %s", name)
        return converters

    # ASI 类别 → 评分器类型自动映射（SmartMatcher 内部决策）
    _ASI_SCORER_MAP: Dict[str, str] = {
        "ASI01": "refusal",
        "ASI02": "true_false",
        "ASI03": "category",
        "ASI04": "true_false",
        "ASI05": "substring",
        "ASI06": "refusal",
        "ASI07": "true_false",
        "ASI08": "category",
        "ASI09": "refusal",
        "ASI10": "category",
        "LLM01": "refusal",
        "LLM02": "refusal",
        "LLM03": "true_false",
        "LLM04": "substring",
        "LLM05": "category",
        "LLM06": "true_false",
        "LLM07": "substring",
        "LLM08": "category",
        "LLM09": "refusal",
        "LLM10": "true_false",
    }

    def build_scorers(
        self,
        scorer_configs: List[Dict[str, Any]],
        objective_target: Optional[PromptTarget] = None,
        asi_category: str = "",
    ) -> List[Scorer]:
        """
        构建评分器（ASI 自动选择 + 外部 LLM 后端）

        逻辑：
        1. 如果 scorer_configs 非空，使用用户显式配置
        2. 否则根据 asi_category 自动选择评分器类型
        3. LLM 评分器使用 local_ollama 后端（或 CLI 覆盖的外部 LLM）

        Args:
            scorer_configs: 评分器配置列表（通常为空，由 ASI 自动选择）
            objective_target: 目标（用于 SelfAsk 评分器）
            asi_category: ASI 类别 (如 "ASI01")，用于自动选择评分器类型

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
            scorer_type = self._ASI_SCORER_MAP.get(asi_category, "refusal")

        if not scorer_type:
            logger.debug("No scorer type determined, skipping scorer creation")
            return scorers

        scorer_class = SCORER_MAP.get(scorer_type)
        if not scorer_class:
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
        objective: Optional[str] = None,
        placeholders: Optional[Dict[str, str]] = None,
    ) -> Dict[str, Any]:
        """
        执行单次攻击（同步接口）

        根据 mode 选择执行策略：
        - smart_match: SmartMatcher 选择 PyRIT 原生攻击（支持侦察驱动）
        - presets: SequentialAttack (FIRST_SUCCESS) 或 PromptSendingAttack
        - chain: PromptSendingAttack (带重试)

        Args:
            profile_params: 侦察画像参数（来自 TargetProfile），用于驱动策略选择
            objective: 自定义攻击目标（替换 payload 中的 {objective} 占位符）
            placeholders: 用户自定义占位符字典（如 {"domain": "evil.com"}）
        """
        mode = attack_config.get("mode", "chain")
        attack_name = attack_config.get("name", "unnamed_attack")
        logger.info("\n######## 执行攻击: %s (mode=%s) ########", attack_name, mode)

        if mode == "smart_match":
            return self._execute_smart_match_v3(
                attack_config, target, scorers, tracker,
                profile_params=profile_params,
                objective=objective,
                placeholders=placeholders,
            )
        elif mode == "presets":
            return self._execute_presets_v3(
                attack_config, target, scorers, tracker,
                objective=objective,
                placeholders=placeholders,
            )
        else:
            return self._execute_chain_v3(
                attack_config, target, converters, scorers, tracker,
                objective=objective,
                placeholders=placeholders,
            )

    def _execute_chain_v3(
        self,
        attack_config: Dict[str, Any],
        target: PromptTarget,
        converters: Optional[List[PromptConverter]],
        scorers: Optional[List[Scorer]],
        tracker: Optional[Any] = None,
        objective: Optional[str] = None,
        placeholders: Optional[Dict[str, str]] = None,
    ) -> Dict[str, Any]:
        """
        chain 模式 v3.0：使用 PromptSendingAttack 内置重试

        不再手动循环，而是利用 PyRIT 的 max_attempts_on_failure
        支持并发执行：通过 RateController 控制并发数

        Args:
            objective: 自定义攻击目标（替换 payload 中的 {objective} 占位符）
            placeholders: 用户自定义占位符字典
        """
        attack_name = attack_config.get("name", "unnamed_attack")
        payloads = attack_config.get("payloads", [])
        asi_category = attack_config.get("asi_category", "")

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

        attack_converter_config = AttackConverterConfig()
        if converters:
            attack_converter_config = AttackConverterConfig(request_converters=converters)

        attack_scoring_config = AttackScoringConfig()
        if scorers:
            attack_scoring_config = AttackScoringConfig(objective_scorer=scorers[0] if scorers else None)

        if tracker and scorers:
            scorer_type = type(scorers[0]).__name__ if scorers else ""
            tracker.log_scorer_selection(
                asi_category=asi_category,
                scorer_type=scorer_type,
                reason=f"ASI {asi_category} 自动选择评分器",
            )

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
                    attack_result = await attack.execute_async(objective=_extract_payload_text(payload, objective=objective, placeholders=placeholders))
                    outcome = attack_result.outcome
                    is_success = outcome.name == "SUCCESS"
                    response_text = str(attack_result)[:200]

                    return {
                        "payload": _extract_payload_text(payload, objective=objective, placeholders=placeholders)[:100],
                        "status": "success" if is_success else "failed",
                        "outcome": outcome.name,
                        "response": response_text,
                        "is_success": is_success,
                    }
                except Exception as e:
                    logger.error("Attack failed for payload '%s': %s", _extract_payload_text(payload, objective=objective, placeholders=placeholders)[:50], str(e))
                    return {
                        "payload": _extract_payload_text(payload, objective=objective, placeholders=placeholders)[:100],
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

        for r in all_results:
            is_success = r.pop("is_success", False)
            results["results"].append(r)
            if is_success:
                results["success_count"] += 1
            else:
                results["failure_count"] += 1

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
        objective: Optional[str] = None,
        placeholders: Optional[Dict[str, str]] = None,
    ) -> Dict[str, Any]:
        """
        presets 模式 v3.0：使用 SequentialAttack (FIRST_SUCCESS)

        多 preset 时利用 PyRIT 的 SequentialAttack 实现早停：
        - 每个 preset 作为一个 child attack
        - 第一个成功后立即停止
        - 单 preset 时直接使用 PromptSendingAttack

        支持并发执行：通过 RateController 控制并发数

        Args:
            objective: 自定义攻击目标（替换 payload 中的 {objective} 占位符）
            placeholders: 用户自定义占位符字典
        """
        attack_name = attack_config.get("name", "unnamed_attack")
        payloads = attack_config.get("payloads", [])
        converter_presets = attack_config.get("converter_presets", {})
        asi_category = attack_config.get("asi_category", "")

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

        attack_scoring_config = AttackScoringConfig()
        if scorers:
            attack_scoring_config = AttackScoringConfig(objective_scorer=scorers[0] if scorers else None)

        if tracker and scorers:
            scorer_type = type(scorers[0]).__name__ if scorers else ""
            tracker.log_scorer_selection(
                asi_category=asi_category,
                scorer_type=scorer_type,
                reason=f"ASI {asi_category} 自动选择评分器",
            )

        preset_names = list(converter_presets.keys())

        async def _run_all():
            semaphore = self._rate_controller.semaphore if self._rate_controller else None

            async def _execute_one(payload: str) -> Dict[str, Any]:
                if semaphore:
                    await semaphore.acquire()
                try:
                    if len(preset_names) == 1:
                        preset_name = preset_names[0]
                        converter_names = converter_presets[preset_name]
                        preset_converters = self.build_converters(
                            [{"name": c} for c in converter_names],
                            converter_target=target,
                        )
                        attack_converter_config = AttackConverterConfig(request_converters=preset_converters)

                        attack = PromptSendingAttack(
                            objective_target=target,
                            attack_converter_config=attack_converter_config,
                            attack_scoring_config=attack_scoring_config,
                            max_attempts_on_failure=1,
                        )
                        attack_result = await attack.execute_async(objective=_extract_payload_text(payload, objective=objective, placeholders=placeholders))
                        is_success = attack_result.outcome.name == "SUCCESS"

                        return {
                            "payload": _extract_payload_text(payload, objective=objective, placeholders=placeholders)[:100],
                            "preset": preset_name,
                            "status": "success" if is_success else "failed",
                            "outcome": attack_result.outcome.name,
                            "response": str(attack_result)[:200],
                            "is_success": is_success,
                        }
                    else:
                        from pyrit.executor.attack.compound.sequential_attack import (
                            SequentialAttack,
                            SequentialChildAttack,
                            SequenceCompletionPolicy,
                        )
                        from pyrit.models import SeedPrompt, SeedPromptGroup

                        child_attacks = []
                        for p_name in preset_names:
                            converter_names = converter_presets[p_name]
                            preset_converters = self.build_converters(
                                [{"name": c} for c in converter_names],
                                converter_target=target,
                            )

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
                                        prompts=[SeedPrompt(value=_extract_payload_text(payload, objective=objective, placeholders=placeholders), data_type="text")]
                                    ),
                                )
                            )

                        sequential = SequentialAttack(
                            objective_target=target,
                            child_attacks=child_attacks,
                            completion_policy=SequenceCompletionPolicy.FIRST_SUCCESS,
                        )

                        seq_result = await sequential.execute_async(objective=_extract_payload_text(payload, objective=objective, placeholders=placeholders))
                        is_success = seq_result.outcome.name == "SUCCESS"

                        successful_preset = "unknown"
                        for i, child_result in enumerate(seq_result.child_results):
                            if child_result and child_result.outcome.name == "SUCCESS":
                                successful_preset = preset_names[i] if i < len(preset_names) else "unknown"
                                break

                        return {
                            "payload": _extract_payload_text(payload, objective=objective, placeholders=placeholders)[:100],
                            "preset": successful_preset if is_success else "all_failed",
                            "status": "success" if is_success else "failed",
                            "outcome": seq_result.outcome.name,
                            "response": str(seq_result)[:200],
                            "is_success": is_success,
                        }
                except Exception as e:
                    logger.error("Attack failed for payload '%s': %s", _extract_payload_text(payload, objective=objective, placeholders=placeholders)[:50], str(e))
                    return {
                        "payload": _extract_payload_text(payload, objective=objective, placeholders=placeholders)[:100],
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

        for r in all_results:
            is_success = r.pop("is_success", False)
            results["results"].append(r)
            if is_success:
                results["success_count"] += 1
            else:
                results["failure_count"] += 1

        self._results.append(results)
        return results

    @staticmethod
    async def _probe_target_model(target: PromptTarget) -> str:
        """
        运行时模型探测：发送自识别 prompt 获取目标模型名称

        Args:
            target: PyRIT PromptTarget 实例

        Returns:
            探测到的模型名称，失败返回空字符串
        """
        probe_prompt = (
            "What is your model name? Respond with just the model name "
            "and nothing else (e.g., 'gpt-4o', 'claude-3-5-sonnet', 'qwen3:0.6b')."
        )

        try:
            attack = PromptSendingAttack(
                objective_target=target,
                max_attempts_on_failure=0,
            )
            result = await attack.execute_async(objective=probe_prompt)

            if result.outcome.name != "SUCCESS":
                logger.debug("Model probe: attack outcome=%s", result.outcome.name)
                return ""

            response_text = str(result).strip()
            if not response_text:
                return ""

            first_line = response_text.split("\n")[0].strip()
            for prefix in ["I am ", "I'm ", "Model:", "model:", "My name is "]:
                if first_line.startswith(prefix):
                    first_line = first_line[len(prefix):].strip()

            from ..payloads.payload_classifier import MODEL_CONTEXT_WINDOWS
            first_line_lower = first_line.lower()
            for model_key in MODEL_CONTEXT_WINDOWS:
                if model_key != "default" and model_key in first_line_lower:
                    logger.info("Model probe: detected '%s' from response '%s'", model_key, first_line[:80])
                    return model_key

            logger.info("Model probe: unknown model '%s', using as-is", first_line[:80])
            return first_line[:100]

        except Exception as e:
            logger.debug("Model probe failed: %s", str(e))
            return ""

    def _execute_smart_match_v3(
        self,
        attack_config: Dict[str, Any],
        target: PromptTarget,
        scorers: Optional[List[Scorer]],
        tracker: Optional[Any] = None,
        profile_params: Optional[Dict[str, Any]] = None,
        objective: Optional[str] = None,
        placeholders: Optional[Dict[str, str]] = None,
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
        7. 运行时模型探测：目标模型未知时自动探测
        8. 自定义攻击目标：替换 payload 中的 {objective} 占位符
        """
        from ..orchestrators.smart_matcher import SmartMatcher

        attack_name = attack_config.get("name", "unnamed_attack")
        payloads = attack_config.get("payloads", [])
        converter_presets = attack_config.get("converter_presets", {})
        target_model = attack_config.get("target_model", "")
        asi_category = attack_config.get("asi_category", "")

        if not target_model:
            logger.info("Target model unknown, probing...")
            target_model = asyncio.run(self._probe_target_model(target))
            if target_model:
                logger.info("Model probe result: '%s'", target_model)
            else:
                logger.info("Model probe: could not detect model, using defaults")

        logger.info(
            "Executing attack (smart_match v3.0): %s with %d payloads, target=%s",
            attack_name, len(payloads), target_model or "unknown",
        )

        has_adversarial = self._check_adversarial_available()

        preferred_families = None
        aggression_level = "medium"
        if profile_params:
            preferred_families = profile_params.get("preferred_probe_families")
            aggression_level = profile_params.get("aggression_level", "medium")
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

        if tracker:
            for item in plan:
                tracker.start_payload(_extract_payload_text(item["payload"], objective=objective, placeholders=placeholders))
                tracker.log_load(_extract_payload_text(item["payload"], objective=objective, placeholders=placeholders), source=attack_name)
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
                strategy = {
                    "class": item.get("attack_class", ""),
                    "family": item.get("attack_family", ""),
                    "reason": item.get("attack_reason", ""),
                    "confidence": item.get("attack_confidence", 1.0),
                    "params": item.get("attack_params", {}),
                    "fallback_chain": item.get("attack_fallback_chain", []),
                }
                tracker.log_strategy(strategy)

        if tracker and scorers:
            scorer_type = type(scorers[0]).__name__ if scorers else ""
            tracker.log_scorer_selection(
                asi_category=asi_category,
                scorer_type=scorer_type,
                reason=f"ASI {asi_category} 自动选择评分器",
            )

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

        attack_scoring_config = AttackScoringConfig()
        if scorers:
            attack_scoring_config = AttackScoringConfig(objective_scorer=scorers[0] if scorers else None)

        concurrency = self._rate_controller.concurrency if self._rate_controller else 1
        logger.info("Smart match concurrency: %d", concurrency)

        async def _run_all():
            semaphore = self._rate_controller.semaphore if self._rate_controller else None

            async def _execute_one(item: Dict[str, Any]) -> Dict[str, Any]:
                payload = _extract_payload_text(item["payload"], objective=objective, placeholders=placeholders)
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
                        "payload": _extract_payload_text(payload)[:100],
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

        for r in all_results:
            results["results"].append(r)
            is_success = r["status"] == "success"
            if is_success:
                results["success_count"] += 1
            else:
                results["failure_count"] += 1

            category = r.get("payload_category", "unknown")
            if category not in results["category_stats"]:
                results["category_stats"][category] = {"success": 0, "failure": 0}
            results["category_stats"][category]["success" if is_success else "failure"] += 1

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

        if tracker:
            tracker.show_full_report()

        self._results.append(results)
        return results

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

        根据攻击类型自动构建所需参数（adversarial config, converter config 等）
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
                preset_converters = self.build_converters(
                    [{"name": c} for c in converter_names],
                    converter_target=target,
                )
                common_kwargs["attack_converter_config"] = AttackConverterConfig(request_converters=preset_converters)

            common_kwargs.update(attack_params)

            attack = attack_class(**common_kwargs)
            attack_result = await attack.execute_async(objective=_extract_payload_text(payload))

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

        result["attempts_used"] = 1 + len(fallback_chain)
        return result

    def _check_adversarial_available(self) -> bool:
        """检查是否有可用的对抗性 LLM（Crescendo/TAP 需要）"""
        backends = self._scorer_config.get("scorer_llm_backends", {})
        scorer_backends = {k: v for k, v in backends.items() if k != "objective_target"}
        return len(scorer_backends) > 0

    def _build_adversarial_config(self, objective_target: PromptTarget) -> Optional[AttackAdversarialConfig]:
        """构建对抗性配置（Crescendo/TAP 需要）"""
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
    def build_attack_list_from_refs(
        cls,
        refs: List[str],
        payload_mgr: "PayloadManager",
        target_model: str = "",
    ) -> List[Dict[str, Any]]:
        """
        从 OWASP ref 列表构建攻击列表

        Args:
            refs: OWASP ref 路径列表（如 ["owasp:agentic:asi01", "owasp:llm:llm01"]）
            payload_mgr: PayloadManager 实例
            target_model: 目标模型名称（传递给 SmartMatcher）

        Returns:
            攻击配置列表
        """
        # OWASP ID → 默认转换器/评分器映射
        _DEFAULT_CONVERTERS = {
            "llm01": ["base64", "rot13", "unicode_confusable", "leetspeak", "ascii_smuggler", "zero_width", "diacritic"],
            "llm02": ["base64"],
            "llm03": ["malicious_question_generator"],
            "llm04": ["add_text_image", "word_doc"],
            "llm05": ["malicious_question_generator"],
            "llm06": ["persuasion", "variation"],
            "llm07": ["translation", "persuasion"],
            "llm08": ["base64"],
            "llm09": ["persuasion"],
            "llm10": ["base64"],
            "asi01": ["base64", "rot13", "unicode_confusable", "leetspeak", "persuasion", "ascii_smuggler", "zero_width", "diacritic"],
            "asi02": ["add_text_image", "pdf"],
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
            "llm01": ["refusal", "substring"],
            "llm02": ["true_false"],
            "llm03": ["true_false"],
            "llm04": ["true_false"],
            "llm05": ["refusal", "true_false"],
            "llm06": ["true_false", "substring"],
            "llm07": ["refusal", "true_false"],
            "llm08": ["substring"],
            "llm09": ["refusal"],
            "llm10": ["true_false"],
            "asi01": ["refusal", "substring"],
            "asi02": ["refusal", "true_false"],
            "asi03": ["refusal", "true_false"],
            "asi04": ["refusal", "true_false"],
            "asi05": ["refusal", "true_false"],
            "asi06": ["true_false", "substring"],
            "asi07": ["refusal", "true_false"],
            "asi08": ["true_false", "substring"],
            "asi09": ["refusal", "true_false"],
            "asi10": ["refusal", "true_false"],
        }

        attacks = []
        for ref in refs:
            data = payload_mgr.get_payload_file(ref)
            if not data:
                continue

            owasp_id = data.get("id", ref.split(":")[-1]).lower()
            converters = _DEFAULT_CONVERTERS.get(owasp_id, ["base64"])
            scorers = _DEFAULT_SCORERS.get(owasp_id, ["refusal"])

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
                "target_model": target_model,
            })

        return attacks
