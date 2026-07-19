# -*- coding: utf-8 -*-
"""
AI-300 Framework - Payload Classifier v3.0
载荷分析器：多维标签系统 + 置信度评分 + 目标模型感知 + 归一化预处理

核心改进（v3.0）：
1. Token 估算：优先 tiktoken，回退到改进启发式
2. 编码检测扩展：Base64/ROT13/Hex/URL/Unicode/HTML entities
3. 技术类别补充：indirect_injection/context_splitting/multi_encoding/instruction_override/payload_splitting
4. 目标模型感知：context_window 字段，长度分类基于占比
5. 置信度评分：每个维度 0.0-1.0，低置信度触发多策略
6. 归一化预处理：分析前解码已知编码
7. ASI 类别关联：payload 可绑定 ASI 编号

模块拆分（v3.1）：
- models.py: ThreatModel, PayloadProfile 数据类
- patterns.py: 所有检测模式定义 + YAML 加载
- normalizer.py: normalize_payload() 归一化预处理
- payload_classifier.py: 核心分析函数（本文件）

设计原则（v3.0）：
- 借鉴 Promptfoo 分层思想：快速规则筛选 → 精确模型匹配
- 借鉴 garak 探针族概念：按载荷类别自动选择攻击探针族
- 借鉴 DeepTeam 框架映射：OWASP/ASI 分类作为策略约束

PyRIT 0.14.0 兼容
"""

import base64
import logging
import re
import sys
import unicodedata
import os
from typing import Dict, List, Optional, Tuple

if sys.platform == "win32":
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    os.environ["PYTHONIOENCODING"] = "utf-8"

logger = logging.getLogger(__name__)

# 从独立模块导入
from .models import ThreatModel, PayloadProfile
from .patterns import (
    ROLE_PLAY_PATTERNS,
    PROMPT_LEAKING_PATTERNS,
    MARKDOWN_INJECTION_PATTERNS,
    INDIRECT_INJECTION_PATTERNS,
    INSTRUCTION_OVERRIDE_PATTERNS,
    PAYLOAD_SPLITTING_PATTERNS,
    CONTEXT_SPLITTING_PATTERNS,
    DATA_EXFILTRATION_PATTERNS,
    CROSS_CONTEXT_CONTAMINATION_PATTERNS,
    CONTEXT_MANIPULATION_PATTERNS,
    ENCODED_PATTERNS,
    NON_ASCII_PATTERN,
    LANGUAGE_PATTERNS,
)
from .normalizer import normalize_payload


# ──────────────────────────────────────────────────────────────────────────────
# 目标模型上下文窗口配置（用于相对长度分类）
# ──────────────────────────────────────────────────────────────────────────────

MODEL_CONTEXT_WINDOWS: Dict[str, int] = {
    # OpenAI
    "gpt-4o": 128000,
    "gpt-4o-mini": 128000,
    "gpt-4-turbo": 128000,
    "gpt-4": 8192,
    "gpt-3.5-turbo": 16385,
    "o1": 200000,
    "o1-mini": 128000,
    "o3": 200000,
    # Anthropic
    "claude-3-5-sonnet": 200000,
    "claude-3-opus": 200000,
    "claude-3-haiku": 200000,
    "claude-2": 100000,
    # Meta
    "llama-3.1-70b": 128000,
    "llama-3.1-8b": 128000,
    "llama-3-8b": 8192,
    "llama-2-70b": 4096,
    "llama-2-13b": 4096,
    # Mistral
    "mistral-large": 128000,
    "mistral-7b": 32768,
    "mixtral-8x7b": 32768,
    # Google
    "gemini-1.5-pro": 1000000,
    "gemini-1.5-flash": 1000000,
    "gemini-1.0-pro": 32768,
    # DeepSeek
    "deepseek-chat": 128000,
    "deepseek-coder": 128000,
    # Qwen
    "qwen-plus": 128000,
    "qwen-turbo": 128000,
    "qwen-72b": 32768,
    "qwen-7b": 32768,
    # 默认
    "default": 8192,
}

# 长度分类阈值（占上下文窗口的比例）
LENGTH_THRESHOLDS = {
    "short": 0.01,       # <1% context
    "medium": 0.05,      # 1-5% context
    "long": 0.15,        # 5-15% context
    # >15% context = context_overflow
}


# ──────────────────────────────────────────────────────────────────────────────
# Token 估算器
# ──────────────────────────────────────────────────────────────────────────────

_tokenizer = None


def _get_tokenizer():
    """获取 tokenizer（延迟加载，优先 tiktoken）"""
    global _tokenizer
    if _tokenizer is None:
        try:
            import tiktoken
            _tokenizer = tiktoken.get_encoding("cl100k_base")
            logger.debug("Using tiktoken cl100k_base for token estimation")
        except ImportError:
            _tokenizer = "fallback"
            logger.debug("tiktoken not available, using heuristic fallback")
    return _tokenizer


def _estimate_tokens(text: str) -> int:
    """
    估算 token 数

    优先级：
    1. tiktoken（cl100k_base，GPT-4/3.5 通用）
    2. 改进启发式（按语言加权）
    """
    tokenizer = _get_tokenizer()

    if tokenizer != "fallback":
        try:
            return len(tokenizer.encode(text))
        except Exception:
            pass

    # 改进启发式：按 Unicode 范围分别估算
    total = 0
    for char in text:
        cp = ord(char)
        if cp < 128:
            # ASCII: ~4 chars per token
            total += 0.25
        elif 0x4e00 <= cp <= 0x9fff:
            # CJK Unified Ideographs: ~1.2 chars per token
            total += 0.8
        elif 0x3040 <= cp <= 0x30ff:
            # Japanese Hiragana/Katakana: ~1.5 chars per token
            total += 0.67
        elif 0xac00 <= cp <= 0xd7af:
            # Korean Hangul: ~1.5 chars per token
            total += 0.67
        elif 0x0400 <= cp <= 0x04ff:
            # Cyrillic: ~2 chars per token
            total += 0.5
        elif 0x0600 <= cp <= 0x06ff:
            # Arabic: ~2 chars per token
            total += 0.5
        else:
            # Other: ~2 chars per token
            total += 0.5

    return max(1, int(total))


# ──────────────────────────────────────────────────────────────────────────────
# 核心分析函数
# ──────────────────────────────────────────────────────────────────────────────

def analyze_payload(
    text: str,
    context_window: int = 8192,
    asi_category: str = "",
    threat_model: Optional[ThreatModel] = None,
) -> PayloadProfile:
    """
    多维载荷分析（v3.0 主入口）

    Args:
        text: 载荷文本
        context_window: 目标模型上下文窗口大小
        asi_category: 关联的 ASI 类别（可选，如 "ASI01"）
        threat_model: 威胁模型（可选）

    Returns:
        PayloadProfile 多维分析结果
    """
    if not text or not isinstance(text, str):
        return PayloadProfile()

    text_stripped = text.strip()

    # 归一化预处理
    normalized_text, detected_encodings = normalize_payload(text_stripped)

    # 使用归一化后的文本进行分析（如果解码成功）
    analysis_text = normalized_text if detected_encodings else text_stripped

    profile = PayloadProfile(
        char_count=len(text_stripped),
        token_count=_estimate_tokens(analysis_text),
        context_window=context_window,
        asi_category=asi_category,
        normalized_text=normalized_text,
        threat_model=threat_model,
    )

    # 五维独立判断 + 置信度
    profile.encoding_state, profile.confidence["encoding"] = _detect_encoding(
        text_stripped, normalized_text, detected_encodings
    )
    profile.language, profile.confidence["language"] = _detect_language(analysis_text)
    profile.technique, profile.confidence["technique"] = _detect_technique(analysis_text)
    profile.length_class, profile.confidence["length"] = _classify_length(
        profile.token_count, context_window
    )
    profile.complexity, profile.confidence["complexity"] = _assess_complexity(
        analysis_text, profile
    )

    # 标签集合
    profile.tags = _build_tags(profile, analysis_text)

    logger.debug(
        "Payload analyzed: %s (tokens=%d, technique=%s, encoding=%s, lang=%s, conf=%.2f)",
        text_stripped[:30], profile.token_count, profile.technique,
        profile.encoding_state, profile.language, profile.avg_confidence,
    )

    return profile


def classify_payload(text: str, **kwargs) -> str:
    """向后兼容接口：返回单一主类别"""
    return analyze_payload(text, **kwargs).primary_category


def classify_payloads(payloads: List[str], **kwargs) -> Dict[str, List[str]]:
    """批量分类载荷（向后兼容）"""
    categorized: Dict[str, List[str]] = {}
    for payload in payloads:
        category = classify_payload(payload, **kwargs)
        if category not in categorized:
            categorized[category] = []
        categorized[category].append(payload)
    return categorized


def analyze_payloads(
    payloads: List[str],
    context_window: int = 8192,
    asi_category: str = "",
) -> Dict[str, List[PayloadProfile]]:
    """批量分析载荷（v2.0+ 接口）"""
    categorized: Dict[str, List[PayloadProfile]] = {}
    for payload in payloads:
        profile = analyze_payload(payload, context_window=context_window, asi_category=asi_category)
        cat = profile.primary_category
        if cat not in categorized:
            categorized[cat] = []
        categorized[cat].append(profile)
    return categorized


def get_category_description(category: str) -> str:
    """获取分类描述"""
    descriptions = {
        "direct_short": "直接注入短文本 - 适合编码+单轮攻击",
        "role_play": "角色扮演类 - 需要多轮对话建立角色上下文",
        "multilingual": "多语言载荷 - 利用语言切换绕过过滤",
        "encoded": "已编码载荷 - 直接投递或上下文包装",
        "long_context": "长文本载荷 - 需要分段或多轮注入",
        "prompt_leaking": "提示泄露 - 直接投递（禁止编码）",
        "adversarial": "对抗性后缀 - 保持原样投递",
        "markdown_injection": "Markdown注入 - 利用格式绕过过滤",
        "indirect_injection": "间接注入 - 嵌入外部数据源绕过检测",
        "context_splitting": "上下文拆分 - 多轮渐进式注入",
        "multi_encoding": "多层编码 - 需要逐层解码",
        "instruction_override": "指令覆盖 - 非角色扮演的指令替换",
        "payload_splitting": "载荷拆分 - 拆分到多个消息投递",
        "data_exfiltration": "数据渗出 - 窃取系统提示/凭证/敏感信息",
        "cross_context_contamination": "跨上下文污染 - 跨会话/上下文持久化攻击",
        "context_manipulation": "上下文操纵 - 篡改对话历史/记忆/语境",
    }
    return descriptions.get(category, "未知类别")


# ──────────────────────────────────────────────────────────────────────────────
# 维度检测函数
# ──────────────────────────────────────────────────────────────────────────────

def _detect_encoding(
    original_text: str,
    normalized_text: str,
    detected_encodings: List[str],
) -> Tuple[str, float]:
    """
    检测编码状态

    Returns:
        (encoding_state, confidence)
    """
    # 如果归一化检测到多层编码
    if len(detected_encodings) > 1:
        return "multi_encoded", 0.95
    if len(detected_encodings) == 1:
        return "encoded", 0.9

    # 尝试 Base64 解码（更宽松的条件）
    try:
        text_clean = original_text.strip()
        if len(text_clean) >= 16:
            # 尝试补齐 padding
            padded = text_clean + '=' * (4 - len(text_clean) % 4) if len(text_clean) % 4 else text_clean
            if re.match(r'^[A-Za-z0-9+/]+=*$', padded):
                decoded = base64.b64decode(padded).decode("utf-8", errors="strict")
                if all(c.isprintable() or c.isspace() for c in decoded):
                    return "encoded", 0.85
    except Exception:
        pass

    # 匹配编码模式
    for pattern, enc_type in ENCODED_PATTERNS:
        if re.match(pattern, original_text.strip()):
            return "encoded", 0.8

    # 检测混淆特征
    if _is_partially_obfuscated(original_text):
        return "obfuscated", 0.7

    return "plain", 0.95


def _is_partially_obfuscated(text: str) -> bool:
    """检测是否为部分混淆"""
    # Leet speak 特征
    leet_pattern = re.compile(r'[a-zA-Z0-9]*[0-9][a-zA-Z0-9]*')
    leet_matches = leet_pattern.findall(text)
    if len(leet_matches) > 5:
        return True

    # 大量特殊字符（排除 CJK 字符，避免误判中文/日文/韩文为混淆）
    def _is_special_char(c) -> bool:
        """判断是否为特殊字符（排除 CJK、日文、韩文等正常文字）"""
        cp = ord(c)
        # CJK Unified Ideographs
        if 0x4e00 <= cp <= 0x9fff:
            return False
        # Japanese Hiragana/Katakana
        if 0x3040 <= cp <= 0x30ff:
            return False
        # Korean Hangul
        if 0xac00 <= cp <= 0xd7af:
            return False
        # Cyrillic
        if 0x0400 <= cp <= 0x04ff:
            return False
        # Arabic
        if 0x0600 <= cp <= 0x06ff:
            return False
        # Other non-alphanumeric, non-space
        return not c.isalnum() and not c.isspace()

    special_chars = sum(1 for c in text if _is_special_char(c))
    if len(text) > 0 and special_chars / len(text) > 0.3:
        return True

    # 检测不可见字符（零宽字符等）
    invisible_chars = sum(1 for c in text if unicodedata.category(c) in ('Cf', 'Cc', 'Cn'))
    if invisible_chars > 2:
        return True

    return False


def _detect_language(text: str) -> Tuple[str, float]:
    """
    检测主要语言

    Returns:
        (language_code, confidence)
    """
    detected_langs = []
    for pattern, lang_code in LANGUAGE_PATTERNS:
        if re.search(pattern, text):
            detected_langs.append(lang_code)

    if len(detected_langs) > 1:
        return "mixed", 0.8
    if len(detected_langs) == 1:
        return detected_langs[0], 0.9

    # 检测非 ASCII 比例
    non_ascii_count = len(NON_ASCII_PATTERN.findall(text))
    if len(text) > 0 and non_ascii_count / len(text) > 0.3:
        return "other", 0.6

    return "en", 0.85


def _detect_technique(text: str) -> Tuple[str, float]:
    """
    检测攻击技术类别（+ 置信度）

    Returns:
        (technique, confidence)

    优先级设计：
    1. 对抗性后缀（不可编码，最高优先级）
    2. Prompt Leaking（明确意图）
    3. 数据渗出（明确意图）
    4. 间接注入（需要外部数据源）
    5. Markdown 注入（格式相关）
    6. 跨上下文污染
    7. 上下文操纵
    8. 指令覆盖（非角色扮演的指令替换）
    9. 角色扮演（身份替换）
    10. 上下文拆分（多轮渐进）
    11. 载荷拆分（片段化）
    12. 通用注入（兜底）
    """
    text_lower = text.lower()

    # 1. 对抗性后缀（最高优先级：不可编码）
    is_adv, adv_conf = _is_adversarial_suffix(text)
    if is_adv:
        return "adversarial", adv_conf

    # 2. Prompt Leaking
    pl_conf = _match_patterns(text_lower, PROMPT_LEAKING_PATTERNS)
    if pl_conf > 0.5:
        return "prompt_leaking", pl_conf

    # 3. 数据渗出
    de_conf = _match_patterns(text_lower, DATA_EXFILTRATION_PATTERNS)
    if de_conf > 0.5:
        return "data_exfiltration", de_conf

    # 4. 间接注入
    ii_conf = _match_patterns(text_lower, INDIRECT_INJECTION_PATTERNS)
    if ii_conf > 0.5:
        return "indirect_injection", ii_conf

    # 5. Markdown 注入
    md_conf = _match_patterns(text, MARKDOWN_INJECTION_PATTERNS)
    if md_conf > 0.5:
        return "markdown_injection", md_conf

    # 6. 跨上下文污染
    cc_conf = _match_patterns(text_lower, CROSS_CONTEXT_CONTAMINATION_PATTERNS)
    if cc_conf > 0.5:
        return "cross_context_contamination", cc_conf

    # 7. 上下文操纵
    cm_conf = _match_patterns(text_lower, CONTEXT_MANIPULATION_PATTERNS)
    if cm_conf > 0.5:
        return "context_manipulation", cm_conf

    # 8. 指令覆盖
    io_conf = _match_patterns(text_lower, INSTRUCTION_OVERRIDE_PATTERNS)
    if io_conf > 0.5:
        return "instruction_override", io_conf

    # 9. 角色扮演（降低优先级，避免与通用注入冲突）
    rp_conf = _match_patterns(text_lower, ROLE_PLAY_PATTERNS)
    if rp_conf > 0.5:
        return "role_play", rp_conf

    # 10. 上下文拆分
    cs_conf = _match_patterns(text_lower, CONTEXT_SPLITTING_PATTERNS)
    if cs_conf > 0.5:
        return "context_splitting", cs_conf

    # 11. 载荷拆分
    ps_conf = _match_patterns(text, PAYLOAD_SPLITTING_PATTERNS)
    if ps_conf > 0.5:
        return "payload_splitting", ps_conf

    # 12. 通用注入
    inj_conf = _is_injection(text_lower)
    if inj_conf > 0.5:
        return "injection", inj_conf

    return "direct", 0.8


def _match_patterns(text: str, patterns: List[Tuple[str, float]]) -> float:
    """匹配模式列表，返回最高置信度"""
    max_conf = 0.0
    for pattern, conf in patterns:
        if re.search(pattern, text):
            max_conf = max(max_conf, conf)
    return max_conf


def _is_adversarial_suffix(text: str) -> Tuple[bool, float]:
    """检测是否为对抗性后缀（GCG 风格）"""
    # 排除已编码文本
    try:
        if len(text) >= 16 and re.match(r'^[A-Za-z0-9+/]+=*$', text):
            padded = text + '=' * (4 - len(text) % 4) if len(text) % 4 else text
            decoded = base64.b64decode(padded).decode("utf-8", errors="strict")
            if all(c.isprintable() or c.isspace() for c in decoded):
                return False, 0.0
    except Exception:
        pass

    # 排除纯 CJK 文本
    cjk_chars = sum(1 for c in text if '\u4e00' <= c <= '\u9fff' or '\u3040' <= c <= '\u30ff' or '\uac00' <= c <= '\ud7af')
    if cjk_chars > 0 and cjk_chars / max(len(text), 1) > 0.3:
        return False, 0.0

    # 控制字符
    control_chars = re.findall(r'[\x00-\x08\x0e-\x1f]', text)
    if len(control_chars) > 0:
        return True, 0.9

    # 连续特殊字符
    if re.search(r'[!@#$%^&*]{5,}', text):
        return True, 0.85

    # 超长无意义单词（GCG 风格）
    words = text.split()
    long_gibberish = 0
    for w in words:
        if len(w) > 15:
            # 纯字母长词
            if re.match(r'^[a-zA-Z]+$', w):
                unique_ratio = len(set(w.lower())) / len(w)
                if unique_ratio < 0.3:  # 重复字符
                    long_gibberish += 1
                elif len(w) > 20:  # 超长随机字符串
                    long_gibberish += 1
            # 字母数字混合长词
            elif re.match(r'^[a-zA-Z0-9+/=]+$', w) and len(w) > 20:
                long_gibberish += 1
    if long_gibberish > 0:
        return True, 0.75

    return False, 0.0


def _is_injection(text_lower: str) -> float:
    """检测是否为通用注入攻击，返回置信度"""
    injection_patterns = [
        (r"\bignore\b.*\b(all\s+)?(previous|above|prior)\b", 0.9),
        (r"\bdisregard\b.*\b(instructions?|rules?)\b", 0.85),
        (r"\boverride\b.*\b(safety|security|filter)\b", 0.9),
        (r"\bbypass\b.*\b(filter|safety|restriction)\b", 0.85),
    ]
    return _match_patterns(text_lower, injection_patterns)


def _classify_length(token_count: int, context_window: int) -> Tuple[str, float]:
    """
    基于 token 数和目标模型上下文窗口分类长度

    Returns:
        (length_class, confidence)
    """
    if context_window <= 0:
        context_window = 8192

    ratio = token_count / context_window

    if ratio > LENGTH_THRESHOLDS["long"]:
        return "context_overflow", 0.95
    elif ratio > LENGTH_THRESHOLDS["medium"]:
        return "long", 0.85
    elif ratio > LENGTH_THRESHOLDS["short"]:
        return "medium", 0.8
    else:
        return "short", 0.9


def _assess_complexity(text: str, profile: PayloadProfile) -> Tuple[str, float]:
    """
    评估载荷复杂度（多维加权 + 置信度）

    Returns:
        (complexity, confidence)
    """
    score = 0

    # 编码状态
    if profile.encoding_state == "multi_encoded":
        score += 3
    elif profile.encoding_state == "encoded":
        score += 2
    elif profile.encoding_state == "obfuscated":
        score += 1

    # 技术复杂度
    technique_scores = {
        "direct": 0,
        "multilingual": 1,
        "prompt_leaking": 0,
        "markdown_injection": 1,
        "role_play": 1,
        "injection": 1,
        "instruction_override": 2,
        "context_splitting": 2,
        "payload_splitting": 2,
        "indirect_injection": 2,
        "adversarial": 2,
        # v3.1 新增技术类别（之前遗漏，导致复杂度被低估）
        "data_exfiltration": 2,
        "cross_context_contamination": 3,
        "context_manipulation": 2,
    }
    score += technique_scores.get(profile.technique, 1)

    # 长度（基于占比）
    length_ratio = profile.token_count / max(profile.context_window, 1)
    if length_ratio > 0.2:
        score += 2
    elif length_ratio > 0.05:
        score += 1

    # 多语言混合
    if profile.language == "mixed":
        score += 1

    # 归一化置信度
    if score >= 4:
        return "complex", min(0.95, 0.6 + score * 0.05)
    elif score >= 2:
        return "moderate", min(0.85, 0.5 + score * 0.05)
    else:
        return "simple", min(0.9, 0.6 + score * 0.05)


def _build_tags(profile: PayloadProfile, text: str) -> set:
    """构建标签集合"""
    tags = set()

    # 基础维度标签
    tags.add(f"length:{profile.length_class}")
    tags.add(f"encoding:{profile.encoding_state}")
    tags.add(f"lang:{profile.language}")
    tags.add(f"technique:{profile.technique}")
    tags.add(f"complexity:{profile.complexity}")

    # 长度相关标签
    if profile.length_class == "context_overflow":
        tags.add("needs_chunking")
    if profile.token_count > profile.context_window * 0.5:
        tags.add("exceeds_half_context")

    # 编码相关标签
    if profile.encoding_state in ("encoded", "multi_encoded"):
        tags.add("pre_encoded")
    if profile.encoding_state == "multi_encoded":
        tags.add("multi_layer_encoding")

    # 技术相关标签
    if profile.technique == "adversarial":
        tags.add("no_transform")
    if profile.technique == "prompt_leaking":
        tags.add("no_encoding")
    if profile.technique == "indirect_injection":
        tags.add("external_source")
    if profile.technique == "context_splitting":
        tags.add("multi_turn_required")
    if profile.technique == "payload_splitting":
        tags.add("fragment_assembly")
    if profile.technique == "data_exfiltration":
        tags.add("data_theft")
        tags.add("no_encoding")
    if profile.technique == "cross_context_contamination":
        tags.add("persistent_attack")
        tags.add("multi_session")
    if profile.technique == "context_manipulation":
        tags.add("memory_poisoning")
        tags.add("context_tampering")

    # 置信度标签
    if profile.needs_multi_strategy:
        tags.add("low_confidence")

    # ASI 标签
    if profile.asi_category:
        tags.add(f"asi:{profile.asi_category}")

    return tags



