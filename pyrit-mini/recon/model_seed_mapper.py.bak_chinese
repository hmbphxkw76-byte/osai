"""Model Seed Mapper — 加载模型指纹 → 最优种子映射配置。

学术依据:
    - Greshake et al. (arXiv:2302.12173) — 模型族 → 种子定制
    - Mazeika et al. (arXiv:2406.18510) — WILDTEAMING: 模型族差异适配
    - RedAmon Julius probe pack — API 行为指纹 → 攻击策略映射

使用方式:
    >>> from recon.model_seed_mapper import ModelSeedMapper
    >>> mapper = ModelSeedMapper()
    >>> prefs = mapper.get_seeds_for_model("gpt-4o")
    >>> # prefs = {"preferred_templates": [...], "avoid_templates": [...], ...}
    >>>
    >>> # 获取检测到的模型族
    >>> family = mapper.detect_family("gpt-4o-2024-08-06")
    >>> # family = "gpt-4o"
"""
from __future__ import annotations

import logging
import re
from pathlib import Path
from typing import Any

import yaml as _yaml

logger = logging.getLogger(__name__)

# SSOT 路径
_MAPPING_PATH = Path(__file__).resolve().parent.parent / "config" / "model_seed_mapping.yaml"


class ModelSeedMapper:
    """模型种子映射加载器。

    从 config/model_seed_mapping.yaml 加载 90+ 模型的种子偏好配置,
    提供模型名 → 族 → 最优种子的查询接口。

    特性:
        - 自动模糊匹配 (版本号/gpt-4o-2024-08-06 → gpt-4o)
        - 缓存配置 (避免重复读取文件)
        - 降级策略 (未知模型 → __default__)
    """

    def __init__(self, mapping_path: Path | None = None) -> None:
        """初始化映射器。

        Args:
            mapping_path: YAML 文件路径 (默认使用内置路径)。
        """
        self._mapping_path = mapping_path or _MAPPING_PATH
        self._config: dict[str, Any] | None = None
        self._cache: dict[str, dict[str, Any]] = {}

    @property
    def _raw(self) -> dict[str, Any]:
        """延迟加载 YAML 配置。"""
        if self._config is None:
            self._config = self._load_config()
        return self._config

    def _load_config(self) -> dict[str, Any]:
        """从 YAML 文件加载配置。"""
        try:
            if self._mapping_path.exists():
                with open(self._mapping_path, encoding="utf-8") as f:
                    config = _yaml.safe_load(f)
                if isinstance(config, dict):
                    return config
        except Exception as e:
            logger.warning("Failed to load model seed mapping: %s", e)
        return {}

    # ════════════════════════════════════════════════════════════
    # 公共接口
    # ════════════════════════════════════════════════════════════

    def get_seeds_for_model(self, model_name: str) -> dict[str, Any]:
        """获取模型的最优种子配置。

        查询流程:
            1. 精确匹配 (gpt-4o)
            2. 版本号剥离 (gpt-4o-2024-08-06 → gpt-4o)
            3. 子串匹配 (my-gpt-4o-custom → gpt-4o)
            4. 默认兜底 (__default__)

        Args:
            model_name: 模型 ID / 名称 (如 "gpt-4o", "claude-3-opus-20240229")。

        Returns:
            种子配置字典:
            {
                "preferred_templates": list[str],
                "avoid_templates": list[str],
                "optimal_converters": list[str],
                "notes": str,
                "source": str,  # 匹配来源: "exact" / "fuzzy" / "prefix" / "default"
            }
        """
        if not model_name:
            return self._get_default(seed_source="empty_name")

        model_lower = model_name.lower().strip()

        # 缓存命中
        if model_lower in self._cache:
            return self._cache[model_lower]

        model_families = self._raw.get("model_families", {})

        # 1. 精确匹配
        if model_lower in model_families:
            result = model_families[model_lower]
            result["source"] = "exact"
            self._cache[model_lower] = result
            return result

        # 2. 版本号剥离 + 再次匹配
        family = self.detect_family(model_lower)
        if family and family != "__default__":
            if family in model_families:
                result = model_families[family]
                result["source"] = "fuzzy"
                self._cache[model_lower] = result
                return result

        # 3. 子串匹配 (e.g., "my-gpt-4o-api")
        for key in model_families:
            if key in model_lower:
                result = model_families[key]
                result["source"] = "substring"
                self._cache[model_lower] = result
                return result

        # 4. 默认兜底
        default_result = self._get_default(source="fallback")
        self._cache[model_lower] = default_result
        return default_result

    def detect_family(self, model_name: str) -> str:
        """从模型版本号剥离出模型族。

        示例:
            "gpt-4o-2024-08-06" → "gpt-4o"
            "claude-3-opus-20240229" → "claude-3-opus"
            "qwen2.5-72b-instruct" → "qwen2.5-72b"
            "deepseek-v2-chat" → "deepseek-v2"

        Args:
            model_name: 完整模型名。

        Returns:
            模型族名称。
        """
        if not model_name:
            return "__default__"

        # 版本号剥离模式
        version_patterns = [
            r"(gpt-(?:4|3\.5)(?:\w+(?:\-\w+)?)?)(?:\-\d{4})",
            r"(claude(?:\-\d+\.\d+|\-\d+)\-\w+)(?:\-\d+)",
            r"(qwen\d*\.?\d*\-\d+b)(?:\-\w+)?",
            r"(llama\-\d+\-\d+b)(?:\-\w+)?",
            r"(mistral\-\w+)(?:\-\d+b)?",
            r"(gemini\-\d+\.\d+\-\w+)(?:\-\d+)?",
            r"(deepseek\-\w+)(?:\-\w+)?",
            r"(ernie(?:\-\d+\.\d+|\-\d+))",
            r"(glm(?:\-\d+\.\d+|\-\d+))",
            r"(baichuan\d+\-\d+b)",
            r"(yi\-\w+)(?:\-\d+b)?",
            r"(internlm\d+\-\d+b)",
            r"(falcon\-\d+b)",
        ]

        for pattern in version_patterns:
            match = re.search(pattern, model_name, re.I)
            if match:
                family = match.group(1).lower()
                logger.debug("Model '%s' mapped to family '%s'", model_name, family)
                return family

        logger.debug("Model '%s' could not be stripped to a known family", model_name)
        return "__default__"

    def get_template_characteristics(self, template_name: str) -> dict[str, Any]:
        """获取种子模板的特征属性。

        Args:
            template_name: 模板名称 (如 "authority_inference_key_given")。

        Returns:
            模板特征字典:
            {
                "stealth_level": str,  # paranoid / low / moderate / high
                "guardrail_evasion": float,
                "notes": str,
            }
        """
        template_chars = self._raw.get("template_characteristics", {})
        return template_chars.get(template_name, {})

    def get_all_model_names(self) -> list[str]:
        """获取所有已注册的模型名称列表。"""
        return list(self._raw.get("model_families", {}).keys())

    def get_all_template_names(self) -> list[str]:
        """获取所有已注册的模板名称列表。"""
        return list(self._raw.get("template_characteristics", {}).keys())

    def get_optimal_converter_chain(
        self,
        model_name: str,
        guardrail_report: dict[str, Any] | None = None,
    ) -> list[str]:
        """获取模型的最优转换链 (考虑护栏)。

        如果目标有高护栏, 避免低隐蔽性 converter (如 rot13).
        如果护栏宽松/无, 可以使用更激进的 converter 组合.

        Args:
            model_name: 模型名称。
            guardrail_report: 护栏检测报告 (可选)。

        Returns:
            Converter 名称列表 (按执行顺序)。
        """
        seeds_config = self.get_seeds_for_model(model_name)

        if guardrail_report and guardrail_report.get("has_guardrail"):
            severity = guardrail_report.get("severity", "moderate")
            if severity == "strict":
                # 严格护栏: 只用高隐蔽性 converter
                stealth_required = "high"
            elif severity == "moderate":
                stealth_required = "moderate"
            else:
                stealth_required = "low"
        else:
            stealth_required = "low"

        converters = seeds_config.get("optimal_converters", ["base64"])

        # 根据隐蔽性需求筛选
        CONVERTER_STEALTH_MAP = {
            "base64": "high",
            "rot13": "paranoid",  # 易于被识别, 低隐蔽性
            "leet_speak": "low",
            "humanizer": "high",
            "unicode_smuggling": "high",
            "accent_obfuscation": "high",
            "homoglyph_chinese": "high",
        }

        filtered = []
        for conv in converters:
            conv_stealth = CONVERTER_STEALTH_MAP.get(conv, "low")
            # paranoid < low < moderate < high
            stealth_order = {"paranoid": 0, "low": 1, "moderate": 2, "high": 3}
            if stealth_order.get(conv_stealth, 0) >= stealth_order.get(stealth_required, 0):
                filtered.append(conv)

        return filtered or ["base64"]  # fallback: 至少 base64

    # ════════════════════════════════════════════════════════════
    # 内部辅助函数
    # ════════════════════════════════════════════════════════════

    def _get_default(self, source: str = "fallback") -> dict[str, Any]:
        """获取默认配置。"""
        default = self._raw.get("model_families", {}).get("__default__", {})
        if default:
            default["source"] = source
            return default
        # Hardcoded fallback (文件加载失败时)
        return {
            "preferred_templates": [
                "authority_inference_key_given",
                "step_by_step_analysis",
                "direct_instruction",
            ],
            "avoid_templates": [],
            "optimal_converters": ["base64", "humanizer"],
            "notes": "Hardcoded fallback — YAML loading failed",
            "source": "hardcoded",
        }


# ════════════════════════════════════════════════════════════════════
# 全局单例 (方便快速访问)
# ════════════════════════════════════════════════════════════════════

_default_mapper: ModelSeedMapper | None = None


def get_mapper() -> ModelSeedMapper:
    """获取全局 ModelSeedMapper 单例。"""
    global _default_mapper
    if _default_mapper is None:
        _default_mapper = ModelSeedMapper()
    return _default_mapper


def get_seeds_for_model(model_name: str) -> dict[str, Any]:
    """快捷函数: 获取模型的最优种子配置。

    使用全局单例, 避免重复加载 YAML。
    """
    return get_mapper().get_seeds_for_model(model_name)


def detect_model_family(model_name: str) -> str:
    """快捷函数: 检测模型族。"""
    return get_mapper().detect_family(model_name)
