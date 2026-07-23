# -*- coding: utf-8 -*-
"""
AI-300 Framework - Defense Profile
靶机防御机制建模：从靶机响应中学习防御规则，驱动自适应载荷生成。

核心洞察（来自 DonkAI + AIVP 源码分析）：

1. DonkAI 防御机制：
   - RegexChallengeEngine: blocked_patterns (正则黑名单) + success_patterns (正则白名单)
   - PromptInjectionDetector: 分级模式检测 (CRITICAL/HIGH/MEDIUM)
   - Backdoor triggers: TRIGGER_SECRET_123, BACKDOOR_ACTIVATE, ADMIN_OVERRIDE_999
   - 响应包含: blocked (bool), reason (含被拦截词), score

2. AIVP 防御机制：
   - DetectionV1: 5 路信号加权检测 (TRANSFORMATION_INTENT, INSTRUCTION_OVERRIDE_INTENT,
     SECRET_TARGETING, OUTPUT_CONSTRAINT_ABUSE, MULTI_STEP_EXTRACTION)
   - MitigationV1: secret redaction (替换敏感值为 [REDACTED])
   - 响应包含: detection_triggered, detection_signals, mitigation_applied
   - Phase 3: proof_token 验证 (非明文 secret)

设计目标：
- 从靶机响应中提取防御信号（blocked/reason/signals）
- 建模防御规则，预测哪些载荷会被拦截
- 为 AdaptivePayloadStrategy 提供决策依据

PyRIT 0.14.0 兼容
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional, Set

logger = logging.getLogger(__name__)


class DefenseType(str, Enum):
    """防御类型枚举"""
    REGEX_BLACKLIST = "regex_blacklist"        # DonkAI: 正则黑名单
    SIGNAL_DETECTOR = "signal_detector"         # AIVP: 信号检测器
    SECRET_REDACTION = "secret_redaction"        # AIVP: 密钥脱敏
    PROOF_TOKEN = "proof_token"                  # AIVP Phase3: proof-token 验证
    BACKDOOR_TRIGGER = "backdoor_trigger"        # DonkAI: 后门触发器
    NONE = "none"


@dataclass
class DefenseSignal:
    """单次防御信号（从靶机响应中提取）"""
    blocked: bool = False
    blocked_reason: str = ""
    blocked_patterns_hit: List[str] = field(default_factory=list)
    detection_triggered: bool = False
    detection_signals: List[str] = field(default_factory=list)
    detection_confidence: float = 0.0
    mitigation_applied: bool = False
    mitigation_type: str = ""
    raw_response_metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class DefenseProfile:
    """
    靶机防御机制画像

    从多次攻击响应中累积学习防御规则，包括：
    - 已知的拦截词/模式列表
    - 检测信号类型和阈值
    - 脱敏策略
    - 成功/失败历史

    使用方式：
        profile = DefenseProfile(target_type="rest_api")
        profile.update(signal)  # 每次攻击后更新
        if profile.should_bypass(payload):
            payload = profile.suggest_bypass(payload)
    """
    target_type: str = ""
    defense_type: DefenseType = DefenseType.NONE
    known_blocked_words: Set[str] = field(default_factory=set)
    known_blocked_patterns: List[str] = field(default_factory=list)
    known_detection_signals: Set[str] = field(default_factory=set)
    detection_threshold: float = 0.60
    has_secret_redaction: bool = False
    has_proof_token: bool = False
    backdoor_triggers: List[str] = field(default_factory=list)
    success_history: List[Dict[str, Any]] = field(default_factory=list)
    blocked_history: List[Dict[str, Any]] = field(default_factory=list)
    _total_attempts: int = 0
    _blocked_count: int = 0

    @property
    def block_rate(self) -> float:
        """拦截率"""
        return self._blocked_count / self._total_attempts if self._total_attempts > 0 else 0.0

    @property
    def total_attempts(self) -> int:
        return self._total_attempts

    def update(self, signal: DefenseSignal, payload: str = "") -> None:
        """
        从防御信号更新画像

        Args:
            signal: 从靶机响应提取的防御信号
            payload: 对应的载荷文本（用于记录哪些词被拦截）
        """
        self._total_attempts += 1

        if signal.blocked:
            self._blocked_count += 1
            self.blocked_history.append({
                "payload": payload[:200],
                "reason": signal.blocked_reason,
                "patterns": signal.blocked_patterns_hit,
            })
            # 学习新的拦截词
            for word in signal.blocked_patterns_hit:
                self.known_blocked_words.add(word.lower())
            # DonkAI 的 reason 通常包含被拦截的词
            if signal.blocked_reason:
                extracted = self._extract_blocked_words(signal.blocked_reason)
                self.known_blocked_words.update(extracted)

        if signal.detection_triggered:
            self._blocked_count += 1
            self.blocked_history.append({
                "payload": payload[:200],
                "signals": signal.detection_signals,
                "confidence": signal.detection_confidence,
            })
            self.known_detection_signals.update(signal.detection_signals)
            self.defense_type = DefenseType.SIGNAL_DETECTOR

        if signal.mitigation_applied:
            self.has_secret_redaction = True
            self.defense_type = DefenseType.SECRET_REDACTION

        if not signal.blocked and not signal.detection_triggered:
            self.success_history.append({
                "payload": payload[:200],
            })

    def predict_block(self, payload: str) -> Optional[str]:
        """
        预测载荷是否会被拦截

        Returns:
            拦截原因（如果会被拦截），None 表示不会拦截
        """
        payload_lower = payload.lower()

        # 检查已知拦截词
        for word in self.known_blocked_words:
            if word and word in payload_lower:
                return f"contains blocked word: '{word}'"

        # 检查已知拦截模式
        for pattern in self.known_blocked_patterns:
            try:
                if re.search(pattern, payload, re.IGNORECASE):
                    return f"matches blocked pattern: {pattern[:50]}"
            except re.error:
                continue

        return None

    def suggest_bypass_strategy(self, payload: str) -> str:
        """
        基于防御画像建议绕过策略

        Returns:
            策略名称: "synonym_substitution" / "encoding" / "structural_reference" /
                     "multi_step" / "role_play" / "indirect_reference" / "none"
        """
        block_reason = self.predict_block(payload)

        if block_reason is None:
            return "none"

        # 如果是关键词拦截 → 同义词替换或编码
        if "blocked word" in block_reason:
            # 如果已经尝试过同义词仍被拦截 → 编码
            if self._has_tried_synonym_for(payload):
                return "encoding"
            return "synonym_substitution"

        # 如果是信号检测拦截
        if self.defense_type == DefenseType.SIGNAL_DETECTOR:
            known_signals = self.known_detection_signals
            if "INSTRUCTION_OVERRIDE_INTENT" in known_signals:
                return "role_play"
            if "SECRET_TARGETING" in known_signals:
                return "indirect_reference"
            if "TRANSFORMATION_INTENT" in known_signals:
                return "structural_reference"
            if "MULTI_STEP_EXTRACTION" in known_signals:
                return "multi_step"

        # 如果是脱敏 → 需要间接提取
        if self.has_secret_redaction:
            return "indirect_reference"

        return "synonym_substitution"

    def get_blocked_words_for_category(self, owasp_id: str) -> Set[str]:
        """获取特定 OWASP 类别的已知拦截词"""
        return {
            w for w in self.known_blocked_words
            if any(
                w in entry.get("payload", "").lower()
                for entry in self.blocked_history
            )
        }

    def to_dict(self) -> Dict[str, Any]:
        """序列化为字典"""
        return {
            "target_type": self.target_type,
            "defense_type": self.defense_type.value,
            "known_blocked_words": sorted(self.known_blocked_words),
            "known_blocked_patterns": self.known_blocked_patterns,
            "known_detection_signals": sorted(self.known_detection_signals),
            "detection_threshold": self.detection_threshold,
            "has_secret_redaction": self.has_secret_redaction,
            "has_proof_token": self.has_proof_token,
            "backdoor_triggers": self.backdoor_triggers,
            "total_attempts": self._total_attempts,
            "blocked_count": self._blocked_count,
            "block_rate": round(self.block_rate, 4),
            "success_count": len(self.success_history),
        }

    @staticmethod
    def _extract_blocked_words(reason: str) -> List[str]:
        """从拦截原因中提取被拦截的词"""
        # DonkAI 格式: "The word/phrase 'xxx' is on the blacklist."
        words = []
        matches = re.findall(r"['\"]([^'\"]+)['\"]", reason)
        words.extend(matches)
        return [w.lower() for w in words if len(w) < 50]

    def _has_tried_synonym_for(self, payload: str) -> bool:
        """检查是否已经对类似载荷尝试过同义词替换"""
        # 简化判断：如果成功历史中有同义词替换的记录
        return len(self.success_history) > 0 and self.block_rate > 0.5


# ──────────────────────────────────────────────────────────────────────────────
# 防御信号提取器
# ──────────────────────────────────────────────────────────────────────────────

class DefenseSignalExtractor:
    """
    从靶机响应中提取防御信号

    支持两种靶机响应格式：
    1. DonkAI (REST JSON): {"success": bool, "blocked": bool, "reason": "...", "score": int}
    2. AIVP (SSE + meta): {"detection_triggered": bool, "detection_signals": [...], ...}
    """

    @staticmethod
    def extract_from_donkai(response_data: Dict[str, Any]) -> DefenseSignal:
        """
        从 DonkAI 响应中提取防御信号

        DonkAI /chat 响应:
            {"response": "...", "session_id": 1, "vulnerability_detected": null}

        DonkAI /challenges/{id}/attempt 响应:
            {"success": bool, "blocked": bool, "reason": "...", "score": int}
        """
        signal = DefenseSignal()

        # 挑战提交端点的响应
        if "blocked" in response_data:
            signal.blocked = bool(response_data.get("blocked", False))
            signal.blocked_reason = response_data.get("reason", "")
            signal.blocked_patterns_hit = DefenseSignalExtractor._extract_blocked_words_from_reason(
                signal.blocked_reason
            )

        # 成功标志
        if response_data.get("success"):
            signal.raw_response_metadata["success"] = True

        # 通用聊天端点的响应（vulnerability_detected 字段）
        vuln = response_data.get("vulnerability_detected")
        if vuln:
            signal.raw_response_metadata["vulnerability_detected"] = vuln

        return signal

    @staticmethod
    def extract_from_aivp(
        response_text: str,
        meta_event: Optional[Dict[str, Any]] = None,
        run_summary: Optional[Dict[str, Any]] = None,
    ) -> DefenseSignal:
        """
        从 AIVP 响应中提取防御信号

        AIVP SSE 响应包含:
        - meta 事件: {"request_id": "...", "lab_id": "...", "control_mode": "..."}
        - data 事件: {"content": "..."}
        - 可选: run summary (detection_triggered, mitigation_applied 等)
        """
        signal = DefenseSignal()

        if run_summary:
            signal.detection_triggered = run_summary.get("detection_triggered", False)
            signal.detection_signals = run_summary.get("detection_signals", [])
            signal.detection_confidence = run_summary.get("detection_confidence", 0.0)
            signal.mitigation_applied = run_summary.get("mitigation_applied", False)
            signal.mitigation_type = run_summary.get("mitigation_type", "")

            # 如果响应中包含 [REDACTED]，说明脱敏生效
            if "[REDACTED]" in response_text:
                signal.mitigation_applied = True
                signal.mitigation_type = "redaction"

        if meta_event:
            signal.raw_response_metadata["control_mode"] = meta_event.get("control_mode", "off")

        return signal

    @staticmethod
    def extract_from_response(
        response_text: str,
        response_format: str = "json",
        raw_response: Optional[Dict[str, Any]] = None,
    ) -> DefenseSignal:
        """
        通用防御信号提取（自动判断靶机类型）

        Args:
            response_text: 解析后的响应文本
            response_format: 响应格式 ("json" / "sse" / "text")
            raw_response: 原始响应数据（如果可用）
        """
        if raw_response:
            if "blocked" in raw_response or "success" in raw_response:
                return DefenseSignalExtractor.extract_from_donkai(raw_response)
            if "detection_triggered" in raw_response or "detection_signals" in raw_response:
                return DefenseSignalExtractor.extract_from_aivp(
                    response_text, run_summary=raw_response
                )

        # 回退：从响应文本中推断
        signal = DefenseSignal()

        # DonkAI 特征：包含 "BLOCKED" / "blacklist" 关键词
        if any(kw in response_text for kw in ["BLOCKED", "blacklist", "FILTER"]):
            signal.blocked = True
            signal.blocked_reason = "Filter blocked (inferred from response text)"

        # AIVP 特征：包含 [REDACTED]
        if "[REDACTED]" in response_text:
            signal.mitigation_applied = True
            signal.mitigation_type = "redaction"

        return signal

    @staticmethod
    def _extract_blocked_words_from_reason(reason: str) -> List[str]:
        """从拦截原因中提取被拦截的词/模式"""
        words = []
        # DonkAI 格式: "🛡️ FILTER BLOCKED: The word/phrase 'xxx' is on the blacklist."
        matches = re.findall(r"['\"]([^'\"]+)['\"]", reason)
        words.extend(matches)
        # 也提取模式描述
        if "blocked" in reason.lower():
            pattern_match = re.search(r"pattern[:\s]+(.+?)(?:\.|$)", reason, re.IGNORECASE)
            if pattern_match:
                words.append(pattern_match.group(1).strip())
        return [w.lower() for w in words if 2 < len(w) < 100]


# ──────────────────────────────────────────────────────────────────────────────
# 预置防御画像工厂
# ──────────────────────────────────────────────────────────────────────────────

def create_donkai_defense_profile() -> DefenseProfile:
    """
    创建 DonkAI 预置防御画像

    基于 DonkAI 源码分析：
    - LLM01: blocks ignore, disregard, forget, bypass, skip
    - LLM02: blocks api key, password, credential, secret, token, authentication, auth
    - LLM07: blocks system prompt, configuration (partial)
    - 后门: TRIGGER_SECRET_123, BACKDOOR_ACTIVATE, ADMIN_OVERRIDE_999
    """
    profile = DefenseProfile(target_type="rest_api")
    profile.defense_type = DefenseType.REGEX_BLACKLIST
    profile.known_blocked_words = {
        "ignore", "disregard", "forget", "bypass", "skip",
        "api key", "api_key", "apikey", "password", "credential",
        "secret", "token", "authentication", "auth",
        "system prompt", "configuration",
    }
    profile.backdoor_triggers = [
        "TRIGGER_SECRET_123",
        "BACKDOOR_ACTIVATE",
        "ADMIN_OVERRIDE_999",
    ]
    return profile


def create_aivp_defense_profile() -> DefenseProfile:
    """
    创建 AIVP 预置防御画像

    基于 AIVP 源码分析：
    - DetectionV1: 5 路信号加权，阈值 0.60
    - MitigationV1: secret redaction
    - Phase 3 (MM): proof_token 验证
    """
    profile = DefenseProfile(target_type="sse_chat")
    profile.defense_type = DefenseType.SIGNAL_DETECTOR
    profile.detection_threshold = 0.60
    profile.known_detection_signals = {
        "TRANSFORMATION_INTENT",
        "INSTRUCTION_OVERRIDE_INTENT",
        "SECRET_TARGETING",
        "OUTPUT_CONSTRAINT_ABUSE",
        "MULTI_STEP_EXTRACTION",
    }
    profile.has_secret_redaction = True
    profile.has_proof_token = True
    return profile


def create_defense_profile_for_target(target_type: str) -> DefenseProfile:
    """根据目标类型创建预置防御画像"""
    if target_type == "rest_api":
        return create_donkai_defense_profile()
    elif target_type == "sse_chat":
        return create_aivp_defense_profile()
    else:
        return DefenseProfile(target_type=target_type)
