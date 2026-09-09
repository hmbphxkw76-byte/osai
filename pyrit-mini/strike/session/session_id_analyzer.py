# -*- coding: utf-8 -*-
"""session_id_analyzer.py — Session ID 可预测性分析器

分析任意 stateful agent 的 session identifier 生成模式, 评估可预测性风险,
推荐自动化枚举策略。

支持模式:
    - 结构化序列: PREFIX-YYYYMMDD-COUNTER
    - 时间戳派生: unix_timestamp_ms / unix_timestamp_s
    - UUID v1/v4: 版本检测与熵值评估
    - 弱哈希派生: MD5/SHA1 长度识别
    - 纯数值递增: 检测增量模式

Academic basis:
    - OWASP A07: Identification and Authentication Failures
    - CWE-330: Use of Insufficiently Random Values
    - RFC 4086: Randomness Requirements for Security
    - NIST SP 800-63B: Digital Identity Guidelines

使用示例:
    analyzer = SessionIDAnalyzer()
    sessions = collect_samples(target, count=5)
    result = analyzer.analyze(sessions)
"""
from __future__ import annotations

import math
import re

from strike.session.session_id_types import AnalysisResult, PatternType, RiskLevel


class SessionIDAnalyzer:
    """Session ID 可预测性分析器

    通过收集多个 session ID 样本, 自动识别生成模式并评估风险。
    完全配置驱动, 不硬编码目标适配逻辑 — 适用于任意 stateful agent。

    使用流程:
        1. 发送 3-5 次请求收集 session_id 样本
        2. 调用 analyzer.analyze(samples)
        3. 根据 result.attack_vectors 选择枚举策略
        4. 使用 result 驱动 SessionEnumerator 执行枚举
    """

    # 模式正则 (优先级从高到低)
    _STRUCTURED_PATTERN = re.compile(
        r"^(?P<prefix>[A-Za-z][A-Za-z0-9]{0,4})-"
        r"(?P<date>\d{8}|\d{10}|\d{13})-"
        r"(?P<counter>\d{2,8})$"
    )
    _UUID_V1_PATTERN = re.compile(
        r"^[0-9a-f]{8}-[0-9a-f]{4}-1[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$"
    )
    _UUID_V4_PATTERN = re.compile(
        r"^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$"
    )
    _MD5_PATTERN = re.compile(r"^[0-9a-f]{32}$")
    _SHA1_PATTERN = re.compile(r"^[0-9a-f]{40}$")

    def analyze(
        self,
        session_ids: list[str],
        request_timestamps: list[float] | None = None,
    ) -> AnalysisResult:
        """分析 session ID 集合的可预测性

        Args:
            session_ids: 收集到的 session ID 列表 (建议 ≥ 3 个)
            request_timestamps: 可选, 请求时间戳列表 (用于时间相关性分析)

        Returns:
            AnalysisResult 完整分析结果
        """
        if len(session_ids) < 2:
            return self._insufficient_result()

        # Step 1: 模式识别
        pattern = self._detect_pattern(session_ids)

        # Step 2: 增量分析 (数值型后缀)
        increments = self._analyze_increments(session_ids)

        # Step 3: 时间相关性 (如果提供时间戳)
        time_corr = 0.0
        if request_timestamps and len(request_timestamps) == len(session_ids):
            time_corr = self._compute_time_correlation(session_ids, request_timestamps)

        # Step 4: 根据模式构建详细结果
        return self._build_result(pattern, session_ids, increments, time_corr)

    def _detect_pattern(self, session_ids: list[str]) -> PatternType:
        """识别 session ID 生成模式"""
        sample = session_ids[0]

        # 结构化序列模式 (优先, 最易被利用)
        if self._STRUCTURED_PATTERN.match(sample):
            # 验证所有样本都是相同模式
            if all(self._STRUCTURED_PATTERN.match(s) for s in session_ids):
                return PatternType.STRUCTURED_SEQ

        # UUID 模式
        if self._UUID_V1_PATTERN.match(sample):
            return PatternType.UUID_V1
        if self._UUID_V4_PATTERN.match(sample):
            return PatternType.UUID_V4

        # 哈希模式
        if self._MD5_PATTERN.match(sample):
            return PatternType.MD5_HASH
        if self._SHA1_PATTERN.match(sample):
            return PatternType.SHA1_HASH

        # 时间戳模式 (纯数字, 10-13 位)
        if sample.isdigit():
            if len(sample) == 13:
                return PatternType.TIMESTAMP_MS
            if len(sample) == 10:
                return PatternType.TIMESTAMP_S

        # 纯整数递增
        if all(s.isdigit() for s in session_ids):
            return PatternType.INCREMENTAL_INT

        # 用户名派生
        if "_" in sample and not sample.startswith("http"):
            prefix = sample.split("_")[0]
            if prefix.isalpha() and prefix.lower() in {"user", "admin", "session", "sess"}:
                return PatternType.USER_DERIVED

        return PatternType.UNKNOWN

    def _analyze_increments(self, session_ids: list[str]) -> list[int]:
        """分析序列增量模式"""
        increments: list[int] = []

        for i in range(1, len(session_ids)):
            prev_num = self._extract_numeric_suffix(session_ids[i - 1])
            curr_num = self._extract_numeric_suffix(session_ids[i])

            if prev_num is not None and curr_num is not None:
                increments.append(curr_num - prev_num)

        return increments

    def _build_result(
        self,
        pattern: PatternType,
        session_ids: list[str],
        increments: list[int],
        time_correlation: float,
    ) -> AnalysisResult:
        """根据检测到的模式构建分析结果"""
        prefix = date_fmt = ""
        counter_width = search_space = 0
        risk = RiskLevel.MEDIUM
        attack_vectors: list[str] = []
        recommendations: list[str] = []

        if pattern == PatternType.STRUCTURED_SEQ:
            match = self._STRUCTURED_PATTERN.match(session_ids[0])
            if match:
                prefix = match.group("prefix")
                date_fmt = match.group("date")
                counter_width = len(match.group("counter"))
                search_space = 10 ** counter_width
                inc_val = increments[0] if increments else 1
                risk = RiskLevel.CRITICAL
                attack_vectors = ["enumerate_counter_range", "brute_force_low_counter", "predict_future_sessions"]
                recommendations = [
                    f"枚举范围: {prefix}-{{date}}-0001 到 {prefix}-{{date}}-{counter_width * '9'}",
                    f"增量步长: {inc_val}",
                    f"搜索空间: {search_space}",
                    "验证 IDOR: 使用 stolen session_id 访问其他用户数据",
                ]
        elif pattern == PatternType.TIMESTAMP_MS:
            search_space = 86_400_000
            risk = RiskLevel.HIGH
            attack_vectors = ["time_window_enumeration", "session_prediction"]
            recommendations = ["利用时间窗口: 限定在目标活跃时段", "预测模式: 根据当前时间推算有效 session", f"搜索空间: {search_space} / day"]
        elif pattern == PatternType.TIMESTAMP_S:
            search_space = 86_400
            risk = RiskLevel.HIGH
            attack_vectors = ["time_window_enumeration"]
            recommendations = ["秒级时间戳: 限定时间窗口可大幅降低搜索空间", f"搜索空间: {search_space} / day"]
        elif pattern == PatternType.UUID_V1:
            risk = RiskLevel.MEDIUM
            search_space = 1_000_000
            attack_vectors = ["time_correlation_attack"]
            recommendations = ["UUID v1 含时间戳和 MAC 地址信息", "需收集样本分析时间相关性"]
        elif pattern == PatternType.UUID_V4:
            risk = RiskLevel.MINIMAL
            search_space = 2 ** 122
            recommendations = ["UUID v4 (随机): 暴力破解不可行", "寻找侧信道: 日志泄露、Referer 头等"]
        elif pattern in (PatternType.MD5_HASH, PatternType.SHA1_HASH):
            risk = RiskLevel.MEDIUM
            search_space = 10_000
            attack_vectors = ["hash_crack", "input_analysis"]
            recommendations = [f"哈希模式: {pattern.value}", "分析输入种子: 用户名+时间戳?", "使用 hashcat/字典攻击"]
        elif pattern == PatternType.INCREMENTAL_INT:
            search_space = self._extract_numeric_suffix(session_ids[-1]) or 10000
            risk = RiskLevel.CRITICAL
            attack_vectors = ["sequential_enumeration"]
            recommendations = ["纯整数递增: 预测性极高", f"已观察到最大 ID: {search_space}", f"推荐枚举: 1 到 {search_space}"]
        elif pattern == PatternType.USER_DERIVED:
            risk = RiskLevel.CRITICAL
            search_space = 100
            attack_vectors = ["user_enumeration"]
            recommendations = ["用户名派生: 字典攻击即可", "准备用户名列表: admin, user1, user2..."]
        else:
            recommendations = ["未知模式: 收集更多样本分析"]

        entropy = self._calculate_entropy(session_ids)
        predictability = self._compute_predictability(pattern, risk, entropy, time_correlation)

        return AnalysisResult(
            pattern_type=pattern, risk_level=risk, entropy_bits=entropy,
            predictability_score=predictability, search_space=search_space,
            sample_count=len(session_ids), prefix=prefix, date_format=date_fmt,
            counter_width=counter_width, time_correlation=time_correlation,
            increment_value=increments[0] if increments else 0,
            attack_vectors=attack_vectors, recommendations=recommendations,
        )

    def _compute_time_correlation(
        self, session_ids: list[str], timestamps: list[float]
    ) -> float:
        """计算 session ID 与请求时间的相关性"""
        if len(session_ids) < 2 or len(timestamps) < 2:
            return 0.0

        # 提取数值部分
        nums: list[int] = []
        for sid in session_ids:
            n = self._extract_numeric_suffix(sid)
            if n is not None:
                nums.append(n)

        if len(nums) < 2:
            return 0.0

        # 计算 Pearson 相关系数
        n = len(nums)
        if n != len(timestamps[:n]):
            return 0.0

        sum_x = sum(timestamps[:n])
        sum_y = sum(nums)
        sum_xy = sum(t * s for t, s in zip(timestamps[:n], nums))
        sum_x2 = sum(t * t for t in timestamps[:n])
        sum_y2 = sum(s * s for s in nums)

        denom = math.sqrt((n * sum_x2 - sum_x ** 2) * (n * sum_y2 - sum_y ** 2))
        if denom == 0:
            return 0.0

        return (n * sum_xy - sum_x * sum_y) / denom

    def _calculate_entropy(self, session_ids: list[str]) -> float:
        """计算 session ID 集合的熵值 (bits)"""
        if not session_ids:
            return 0.0

        # 计算字符频率分布
        char_freq: dict[str, int] = {}
        total_chars = 0

        for sid in session_ids:
            for char in sid.lower():
                char_freq[char] = char_freq.get(char, 0) + 1
                total_chars += 1

        if total_chars == 0:
            return 0.0

        # Shannon entropy
        entropy = 0.0
        for count in char_freq.values():
            prob = count / total_chars
            if prob > 0:
                entropy -= prob * math.log2(prob)

        # 乘以平均长度得到总熵
        avg_len = sum(len(s) for s in session_ids) / len(session_ids)
        return entropy * avg_len

    @staticmethod
    def _compute_predictability(
        pattern: PatternType,
        risk: RiskLevel,
        entropy: float,
        time_correlation: float,
    ) -> float:
        """计算综合可预测性分数 (0.0-1.0)"""
        # 基础分数来自风险等级
        risk_scores = {
            RiskLevel.CRITICAL: 0.9,
            RiskLevel.HIGH: 0.7,
            RiskLevel.MEDIUM: 0.4,
            RiskLevel.LOW: 0.2,
            RiskLevel.MINIMAL: 0.05,
        }
        base = risk_scores.get(risk, 0.5)

        # 根据熵值调整 (< 32 bits = 低熵)
        if entropy < 32:
            entropy_factor = 1.0
        elif entropy < 64:
            entropy_factor = 0.7
        else:
            entropy_factor = 0.3

        # 时间相关性增强
        time_factor = min(abs(time_correlation), 1.0)

        score = base * 0.5 + entropy_factor * 0.3 + time_factor * 0.2
        return min(score, 1.0)

    @staticmethod
    def _extract_numeric_suffix(text: str) -> int | None:
        """提取字符串末尾的数字"""
        match = re.search(r"(\d+)$", text)
        return int(match.group(1)) if match else None

    @staticmethod
    def _insufficient_result() -> AnalysisResult:
        """返回样本不足的结果"""
        return AnalysisResult(
            pattern_type=PatternType.UNKNOWN,
            risk_level=RiskLevel.MEDIUM,
            sample_count=0,
            recommendations=["收集至少 3 个 session ID 样本以进行分析"],
        )

    def generate_candidates(
        self,
        result: AnalysisResult,
        known_session: str,
        max_candidates: int = 10000,
    ) -> list[str]:
        """根据分析结果生成候选 session ID 列表

        委托给 SessionIDCandidateGenerator 执行。
        """
        from strike.session.session_id_candidates import SessionIDCandidateGenerator
        return SessionIDCandidateGenerator().generate(result, known_session, max_candidates)


def analyze_session_ids(
    session_ids: list[str],
    request_timestamps: list[float] | None = None,
) -> AnalysisResult:
    """便捷函数: 快速分析 session ID 可预测性"""
    return SessionIDAnalyzer().analyze(session_ids, request_timestamps)
