# -*- coding: utf-8 -*-
"""
AI-300 Framework - Intelligent Encoding Selector v1.0
智能编码选择器：两级过滤 + 目标自适应探测 + 语言感知分组

架构：
  第1级（静态过滤）：OWASP 类别 → 兼容转换器子集（离线，一次性）
  第2级（动态探测）：目标过滤画像 → 有效编码（运行时探测）
  第3级（语言感知）：payload 语言特征 → 排除不兼容编码

设计原则：
  - 复用 PyRIT 原生转换器，不重复造轮子
  - 复用 PayloadClassifier 进行 payload 特征分析
  - 静态映射数据驱动，新增转换器只需添加映射条目

PyRIT 0.14.0 兼容
"""

from __future__ import annotations

import asyncio
import logging
import os
import sys
from typing import Any, Dict, List, Optional, Set

if sys.platform == "win32":
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    os.environ["PYTHONIOENCODING"] = "utf-8"

logger = logging.getLogger(__name__)


# ──────────────────────────────────────────────────────────────────────────────
# 第1级：静态映射 — 转换器 → 兼容 OWASP 类别
# ──────────────────────────────────────────────────────────────────────────────
# 新增转换器只需在此字典添加条目，自动参与所有相关攻击类别

CONVERTER_OWASP_COMPATIBILITY: Dict[str, List[str]] = {
    # ── 编码混淆类（注入/绕过类攻击）──
    "base64": ["LLM01", "LLM02", "LLM03", "LLM04", "LLM05", "LLM06", "LLM07", "LLM08", "LLM09", "LLM10"],
    "rot13": ["LLM01", "LLM06", "LLM09"],
    "unicode_confusable": ["LLM01", "LLM03", "LLM06"],
    "leetspeak": ["LLM01", "LLM09"],
    "ascii_smuggler": ["LLM01", "LLM03", "LLM06"],
    "zero_width": ["LLM01", "LLM02", "LLM03", "LLM06"],
    "diacritic": ["LLM01", "LLM09"],
    "atbash": ["LLM01", "LLM06"],
    "caesar": ["LLM01"],
    "binary": ["LLM01", "LLM03"],
    "morse": ["LLM01"],
    "braille": ["LLM01"],
    "ecoji": ["LLM01"],
    "base2048": ["LLM01"],
    "char_swap": ["LLM01", "LLM06"],
    "random_capital": ["LLM01"],
    "first_letter": ["LLM01"],
    "unicode_substitution": ["LLM01", "LLM03"],
    "unicode_replacement": ["LLM01"],
    "ask_to_decode": ["LLM01", "LLM06"],
    "sneaky_bits": ["LLM01", "LLM03"],
    "variation_selector_smuggler": ["LLM01"],

    # ── 越狱/说服类（注入/操纵类攻击）──
    "persuasion": ["LLM01", "LLM05", "LLM06", "LLM07", "LLM09", "LLM10"],
    "text_jailbreak": ["LLM01", "LLM05", "LLM06", "LLM09"],
    "malicious_question_generator": ["LLM01", "LLM03", "LLM05", "LLM06"],

    # ── 翻译类（多语言绕过）──
    "translation": ["LLM01", "LLM02", "LLM07"],
    "random_translation": ["LLM01", "LLM07"],

    # ── 变异类（Agent 操纵）──
    "variation": ["LLM01", "LLM06", "LLM10"],

    # ── 多模态/文档类（投毒/RAG）──
    "add_text_image": ["LLM04", "LLM08"],
    "pdf": ["LLM04"],
    "word_doc": ["LLM04"],
    "qr_code": ["LLM04", "LLM08"],

    # ── 代码伪装类（供应链）──
    "code_chameleon": ["LLM03"],
    "math_obfuscation": ["LLM03"],

    # ── 搜索替换类（参数操纵）──
    "search_replace": ["LLM02", "LLM06"],

    # ── 否定陷阱类 ──
    "denylist": ["LLM01", "LLM06"],

    # ── 风格变异类 ──
    "tense": ["LLM01", "LLM06"],
    "tone": ["LLM01", "LLM06"],
    "colloquial_swap": ["LLM01"],
}


# ──────────────────────────────────────────────────────────────────────────────
# 语言不兼容映射 — 特定语言下应排除的转换器
# ──────────────────────────────────────────────────────────────────────────────

LANGUAGE_INCOMPATIBLE_CONVERTERS: Dict[str, Set[str]] = {
    # 中文/日文/韩文等 CJK 文本
    "zh": {"rot13", "leetspeak", "atbash", "caesar", "first_letter", "char_swap", "random_capital"},
    "ja": {"rot13", "leetspeak", "atbash", "caesar", "first_letter", "char_swap", "random_capital"},
    "ko": {"rot13", "leetspeak", "atbash", "caesar", "first_letter", "char_swap", "random_capital"},
    # 阿拉伯文
    "ar": {"rot13", "leetspeak", "atbash", "caesar", "first_letter", "char_swap", "random_capital"},
    # 俄文（Cyrillic）
    "ru": {"rot13", "leetspeak", "atbash", "caesar", "first_letter", "char_swap", "random_capital"},
    # 混合语言
    "mixed": {"rot13", "leetspeak", "atbash", "caesar"},
}

# 默认英文不排除任何转换器
LANGUAGE_INCOMPATIBLE_CONVERTERS["en"] = set()


# ──────────────────────────────────────────────────────────────────────────────
# 目标过滤画像 — 运行时探测结果
# ──────────────────────────────────────────────────────────────────────────────

class TargetProfile:
    """
    目标过滤画像：记录哪些编码能绕过目标模型的过滤
    
    通过探测阶段发送探针，统计每种编码的通过率。
    """

    def __init__(self):
        self.converter_pass_rates: Dict[str, float] = {}
        self.probe_count: int = 0
        self.is_built: bool = False

    def record_result(self, converter_name: str, is_success: bool) -> None:
        """记录单次探测结果"""
        if converter_name not in self.converter_pass_rates:
            self.converter_pass_rates[converter_name] = 0.0
        # 增量更新通过率
        current = self.converter_pass_rates[converter_name]
        # 简单累计：成功+1，失败+0，最后除以总数
        # 使用列表存储原始结果更精确
        if not hasattr(self, '_raw_results'):
            self._raw_results: Dict[str, List[bool]] = {}
        if converter_name not in self._raw_results:
            self._raw_results[converter_name] = []
        self._raw_results[converter_name].append(is_success)

    def finalize(self) -> None:
        """计算最终通过率"""
        if hasattr(self, '_raw_results'):
            for converter, results in self._raw_results.items():
                self.converter_pass_rates[converter] = sum(results) / len(results)
            del self._raw_results
        self.is_built = True

    def is_effective(self, converter: str, threshold: float = 0.3) -> bool:
        """判断编码是否有效（通过率 >= 阈值）"""
        return self.converter_pass_rates.get(converter, 0.0) >= threshold

    def get_effective_converters(self, threshold: float = 0.3) -> List[str]:
        """获取所有有效编码（按通过率降序）"""
        effective = [
            (name, rate) for name, rate in self.converter_pass_rates.items()
            if rate >= threshold
        ]
        effective.sort(key=lambda x: x[1], reverse=True)
        return [name for name, _ in effective]

    def get_summary(self) -> str:
        """获取画像摘要"""
        if not self.is_built:
            return "TargetProfile (not built)"
        effective = self.get_effective_converters()
        total = len(self.converter_pass_rates)
        return f"TargetProfile ({len(effective)}/{total} converters effective)"


# ──────────────────────────────────────────────────────────────────────────────
# 第1级：静态过滤函数
# ──────────────────────────────────────────────────────────────────────────────

def filter_converters_by_owasp(owasp_id: str) -> List[str]:
    """
    根据 OWASP 类别过滤兼容的转换器
    
    Args:
        owasp_id: OWASP ID（如 "LLM01", "ASI01"）
    
    Returns:
        兼容的转换器名称列表
    """
    owasp_upper = owasp_id.upper()
    compatible = []
    for converter, categories in CONVERTER_OWASP_COMPATIBILITY.items():
        if owasp_upper in categories:
            compatible.append(converter)
    return compatible


def filter_converters_by_language(converters: List[str], language: str) -> List[str]:
    """
    根据 payload 语言排除不兼容的转换器
    
    Args:
        converters: 转换器名称列表
        language: 语言代码（如 "en", "zh", "mixed"）
    
    Returns:
        过滤后的转换器列表
    """
    incompatible = LANGUAGE_INCOMPATIBLE_CONVERTERS.get(language, set())
    return [c for c in converters if c not in incompatible]


def get_converter_candidates(
    owasp_id: str,
    language: str = "en",
    registered_converters: Optional[Set[str]] = None,
) -> List[str]:
    """
    获取指定 OWASP 类别和语言下的候选转换器
    
    合并两级静态过滤：
    1. OWASP 类别过滤
    2. 语言兼容性过滤
    3. 已注册转换器过滤（只返回实际可用的）
    
    Args:
        owasp_id: OWASP ID
        language: payload 语言代码
        registered_converters: 已注册的转换器名称集合（可选）
    
    Returns:
        候选转换器名称列表
    """
    # 第1级：OWASP 类别过滤
    candidates = filter_converters_by_owasp(owasp_id)
    
    # 第2级：语言兼容性过滤
    candidates = filter_converters_by_language(candidates, language)
    
    # 第3级：只保留已注册的转换器
    if registered_converters is not None:
        candidates = [c for c in candidates if c in registered_converters]
    
    return candidates


# ──────────────────────────────────────────────────────────────────────────────
# 第2级：运行时探测
# ──────────────────────────────────────────────────────────────────────────────

async def probe_target_model(
    target: Any,
    converters: List[str],
    probe_payloads: List[str],
    build_converters_func,
    max_attempts: int = 1,
) -> TargetProfile:
    """
    探测目标模型的过滤策略
    
    发送探针 payload（应用不同编码），统计哪种编码能绕过过滤。
    
    Args:
        target: PyRIT PromptTarget 实例
        converters: 要测试的转换器名称列表
        probe_payloads: 探针 payload 列表
        build_converters_func: 构建转换器的函数 (converter_names) -> List[PromptConverterConfiguration]
        max_attempts: 最大重试次数
    
    Returns:
        TargetProfile 实例
    """
    from pyrit.executor.attack import PromptSendingAttack, AttackConverterConfig, AttackScoringConfig
    
    profile = TargetProfile()
    
    logger.info("Probing target model with %d converters × %d payloads...", len(converters), len(probe_payloads))
    
    for converter_name in converters:
        # 构建单个转换器
        try:
            converter_configs = build_converters_func([converter_name], converter_target=target)
        except Exception as e:
            logger.debug("Failed to build converter '%s': %s", converter_name, e)
            continue
        
        if not converter_configs:
            continue
        
        # 对每个探针 payload 测试
        for payload in probe_payloads:
            try:
                attack = PromptSendingAttack(
                    objective_target=target,
                    attack_converter_config=AttackConverterConfig(request_converters=converter_configs),
                    attack_scoring_config=AttackScoringConfig(),
                    max_attempts_on_failure=max_attempts,
                )
                result = await attack.execute_async(objective=payload)
                is_success = result.outcome.name == "SUCCESS"
                profile.record_result(converter_name, is_success)
                
            except Exception as e:
                logger.debug("Probe failed for converter '%s': %s", converter_name, e)
                profile.record_result(converter_name, False)
    
    profile.finalize()
    logger.info("Target profile built: %s", profile.get_summary())
    
    return profile


# ──────────────────────────────────────────────────────────────────────────────
# 第3级：智能编码选择
# ──────────────────────────────────────────────────────────────────────────────

def select_encodings_for_payload(
    payload: str,
    owasp_id: str,
    target_profile: TargetProfile,
    registered_converters: Set[str],
    language: str = "en",
    max_encodings: int = 5,
    threshold: float = 0.3,
) -> List[str]:
    """
    为单个 payload 选择最优编码组合
    
    综合三级过滤：
    1. OWASP 类别 → 候选编码
    2. 语言特征 → 排除不兼容编码
    3. 目标画像 → 只选实际有效的编码
    
    Args:
        payload: payload 文本
        owasp_id: OWASP ID
        target_profile: 目标过滤画像
        registered_converters: 已注册的转换器集合
        language: payload 语言代码
        max_encodings: 最大编码数量
        threshold: 通过率阈值
    
    Returns:
        选中的编码名称列表
    """
    # 获取候选编码（OWASP + 语言过滤）
    candidates = get_converter_candidates(owasp_id, language, registered_converters)
    
    if not candidates:
        logger.debug("No candidate encodings for %s (lang=%s)", owasp_id, language)
        return []
    
    # 如果有目标画像，按通过率筛选
    if target_profile.is_built:
        effective = [c for c in candidates if target_profile.is_effective(c, threshold)]
        if effective:
            # 按通过率降序，取前 N 个
            effective.sort(key=lambda c: target_profile.converter_pass_rates.get(c, 0), reverse=True)
            return effective[:max_encodings]
        else:
            # 没有有效编码，回退到候选列表前 N 个
            return candidates[:max_encodings]
    else:
        # 无画像，返回候选列表前 N 个
        return candidates[:max_encodings]


def select_encodings_batch(
    payloads: List[str],
    owasp_id: str,
    target_profile: TargetProfile,
    registered_converters: Set[str],
    classifier: Any,
    max_encodings: int = 5,
) -> Dict[int, List[str]]:
    """
    批量为 payloads 选择编码
    
    按语言分组，每组使用不同的编码策略。
    
    Args:
        payloads: payload 文本列表
        owasp_id: OWASP ID
        target_profile: 目标过滤画像
        registered_converters: 已注册的转换器集合
        classifier: PayloadClassifier 实例
        max_encodings: 每个 payload 最大编码数
    
    Returns:
        {payload_index: [encoding_names]} 映射
    """
    results: Dict[int, List[str]] = {}
    
    for idx, payload in enumerate(payloads):
        # 使用 classifier 检测语言
        try:
            from ...payloads.payload_classifier import analyze_payload
            profile = analyze_payload(payload)
            language = profile.language
        except Exception:
            language = "en"
        
        encodings = select_encodings_for_payload(
            payload=payload,
            owasp_id=owasp_id,
            target_profile=target_profile,
            registered_converters=registered_converters,
            language=language,
            max_encodings=max_encodings,
        )
        results[idx] = encodings
    
    return results


# ──────────────────────────────────────────────────────────────────────────────
# 便捷函数：一键构建目标画像 + 选择编码
# ──────────────────────────────────────────────────────────────────────────────

async def build_profile_and_select(
    target: Any,
    owasp_id: str,
    payloads: List[str],
    build_converters_func,
    registered_converters: Set[str],
    classifier: Any,
    probe_sample_size: int = 20,
    max_encodings: int = 5,
) -> Tuple[TargetProfile, Dict[int, List[str]]]:
    """
    完整流程：探测 → 画像 → 选择编码
    
    Args:
        target: PyRIT PromptTarget
        owasp_id: OWASP ID
        payloads: 全量 payload 列表
        build_converters_func: 构建转换器的函数
        registered_converters: 已注册的转换器集合
        classifier: PayloadClassifier 实例
        probe_sample_size: 探测采样数量
        max_encodings: 每个 payload 最大编码数
    
    Returns:
        (target_profile, encoding_selections)
    """
    # 获取候选编码
    candidates = get_converter_candidates(owasp_id, "en", registered_converters)
    
    if not candidates:
        logger.warning("No candidate converters for %s", owasp_id)
        return TargetProfile(), {i: [] for i in range(len(payloads))}
    
    # 采样探针 payload
    step = max(1, len(payloads) // probe_sample_size)
    probe_payloads = payloads[:probe_sample_size * step:step][:probe_sample_size]
    
    if not probe_payloads:
        probe_payloads = payloads[:5]  # 保底
    
    # 探测目标
    profile = await probe_target_model(
        target=target,
        converters=candidates,
        probe_payloads=probe_payloads,
        build_converters_func=build_converters_func,
    )
    
    # 批量选择编码
    selections = select_encodings_batch(
        payloads=payloads,
        owasp_id=owasp_id,
        target_profile=profile,
        registered_converters=registered_converters,
        classifier=classifier,
        max_encodings=max_encodings,
    )
    
    return profile, selections
