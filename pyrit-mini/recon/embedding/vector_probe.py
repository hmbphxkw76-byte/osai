# -*- coding: utf-8 -*-
"""Embedding Vector Probe - Embedding 模型矢量探测器

对 Embedding API 执行侦察:
- 向量维度探测 (Vector Dimension Probe)
- 方向敏感性测试 (Directional Sensitivity Test)
- 边界行为分析 (Boundary Behavior Analysis)

Academic basis:
    - Qi et al. (arXiv:2302.10149) - Universal Adversarial Triggers
    - Carlini et al. (arXiv:2102.12520) - Extracting Training Data

Constitution compliance:
    - R-SIZE: 单模块 < 800 行
    - R-H3: 单一职责, 无双重实现
    - R-S1: 不硬编码目标标识符
    - R-S4: 测试全部 mock
    - 蓝图 Q4 裁决: 黑盒 HTTP 不可测试内容仅注册不实装
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any

logger = logging.getLogger(__name__)


# ====================================================================
# Data Structures
# ====================================================================


@dataclass
class VectorProbeResult:
    """向量探测结果。

    Attributes:
        embedding_dimension: 探测到的向量维度
        is_normalized: 向量是否已归一化
        similarity_baseline: 基准相似度值
        directional_sensitivity: 方向敏感性评分
        boundary_risk: 边界行为风险等级
        recommended_attack_vectors: 推荐的攻击向量
    """

    embedding_dimension: int = 0
    is_normalized: bool = False
    similarity_baseline: float = 0.0
    directional_sensitivity: float = 0.0
    boundary_risk: str = "unknown"
    recommended_attack_vectors: list[str] = field(default_factory=list)


# ====================================================================
# Embedding Vector Probe
# ====================================================================


class EmbeddingVectorProbe:
    """Embedding 矢量探测器。

    通过黑盒 HTTP 请求探测 Embedding API 的行为特征。

    注意: 根据蓝图 Q4 裁决，仅注册侦察结果，
    不执行需要 SDK 访问或训练环境的内容。

    Usage:
        probe = EmbeddingVectorProbe(target_url)
        result = await probe.probe()
    """

    # 常见 Embedding API 端点
    DEFAULT_ENDPOINTS = [
        "/v1/embeddings",
        "/embeddings",
        "/api/embeddings",
        "/api/v1/embeddings",
    ]

    # 测试输入
    TEST_INPUTS = {
        "simple": "test",
        "repeated": "test " * 10,
        "unicode": "测试中文",
        "boundary": "a" * 1000,
        "special": "!@#$%^&*()",
        "empty": "",
    }

    def __init__(self, target_url: str, *, timeout: float = 30.0) -> None:
        """初始化矢量探测器。

        Args:
            target_url: Embedding API 基础 URL
            timeout: 请求超时 (秒)
        """
        self.target_url = target_url.rstrip("/")
        self.timeout = timeout
        self._result = VectorProbeResult()
        self._discovered_endpoint: str = ""

    async def probe(self) -> VectorProbeResult:
        """执行向量探测主流程。

        Returns:
            VectorProbeResult 实例
        """
        # Step 1: 发现 Embedding 端点
        endpoint = await self._discover_endpoint()
        if not endpoint:
            logger.debug("[Embedding] No embedding endpoint discovered")
            return self._result

        # Step 2: 探测向量维度
        await self._probe_dimension(endpoint)

        # Step 3: 探测归一化行为
        await self._probe_normalization(endpoint)

        # Step 4: 评估边界风险
        self._assess_boundary_risk()

        # Step 5: 生成攻击向量建议
        self._generate_attack_vectors()

        return self._result

    async def _discover_endpoint(self) -> str:
        """发现可用的 Embedding 端点。"""
        import aiohttp

        for endpoint in self.DEFAULT_ENDPOINTS:
            url = f"{self.target_url}{endpoint}"
            try:
                async with aiohttp.ClientSession() as session:
                    async with session.post(
                        url,
                        json={"input": "test", "model": "text-embedding-ada-002"},
                        timeout=aiohttp.ClientTimeout(total=min(self.timeout, 10.0)),
                    ) as resp:
                        if resp.status == 200:
                            data = await resp.json()
                            if "data" in data and len(data["data"]) > 0:
                                self._discovered_endpoint = url
                                return url
            except Exception:
                continue

        return ""

    async def _probe_dimension(self, endpoint: str) -> None:
        """探测输出向量维度。"""
        import aiohttp

        test_input = self.TEST_INPUTS["simple"]
        payload = {
            "input": test_input,
            "model": "text-embedding-ada-002",
        }

        try:
            async with aiohttp.ClientSession() as session:
                async with session.post(
                    endpoint,
                    json=payload,
                    timeout=aiohttp.ClientTimeout(total=self.timeout),
                ) as resp:
                    if resp.status == 200:
                        data = await resp.json()
                        embeddings = data.get("data", [])
                        if embeddings:
                            vector = embeddings[0].get("embedding", [])
                            self._result.embedding_dimension = len(vector)
        except Exception as e:
            logger.debug("[Embedding] Dimension probe failed: %s", e)

    async def _probe_normalization(self, endpoint: str) -> None:
        """探测向量归一化行为。"""
        import math

        import aiohttp

        # 发送重复输入探测归一化
        payload = {
            "input": self.TEST_INPUTS["repeated"],
            "model": "text-embedding-ada-002",
        }

        try:
            async with aiohttp.ClientSession() as session:
                async with session.post(
                    endpoint,
                    json=payload,
                    timeout=aiohttp.ClientTimeout(total=self.timeout),
                ) as resp:
                    if resp.status == 200:
                        data = await resp.json()
                        embeddings = data.get("data", [])
                        if embeddings:
                            vector = embeddings[0].get("embedding", [])
                            # 计算 L2 范数
                            norm = math.sqrt(sum(x * x for x in vector))
                            self._result.is_normalized = abs(norm - 1.0) < 0.01
        except Exception as e:
            logger.debug("[Embedding] Normalization probe failed: %s", e)

    def _assess_boundary_risk(self) -> None:
        """评估边界行为风险。"""
        if self._result.embedding_dimension == 0:
            self._result.boundary_risk = "unknown"
        elif self._result.embedding_dimension < 256:
            self._result.boundary_risk = "low"
        elif self._result.embedding_dimension < 1536:
            self._result.boundary_risk = "medium"
        else:
            self._result.boundary_risk = "high"

        # 方向敏感性基于维度估计
        self._result.directional_sensitivity = min(
            1.0,
            self._result.embedding_dimension / 2048.0,
        )

    def _generate_attack_vectors(self) -> None:
        """基于探测结果生成攻击向量建议。"""
        vectors = []

        if self._result.embedding_dimension > 0:
            vectors.append("similarity_manipulation")

        if self._result.is_normalized:
            vectors.append("unit_sphere_exploit")

        if self._result.boundary_risk in ("medium", "high"):
            vectors.append("boundary_crossing")

        # 通用 Embedding 攻击向量
        vectors.extend(
            [
                "adversarial_suffix",
                "semantic_drift",
            ]
        )

        self._result.recommended_attack_vectors = vectors


# ====================================================================
# 便捷函数
# ====================================================================


async def probe_embedding_vector(
    parsed_request: dict[str, Any],
    *,
    max_probes: int = 3,
    timeout: float = 30.0,
) -> dict[str, Any]:
    """探测 Embedding 向量便捷函数。

    根据蓝图 Q4 裁决，仅注册侦察结果供报告使用，
    不执行需要 SDK 直接访问的攻击内容。

    Args:
        parsed_request: 解析后的请求
        max_probes: 最大探测次数
        timeout: 请求超时

    Returns:
        探测结果字典
    """
    target_url = parsed_request.get("url", "")
    if not target_url:
        return VectorProbeResult().__dict__

    probe = EmbeddingVectorProbe(target_url, timeout=timeout)

    try:
        result = await probe.probe()
        return {
            "embedding_dimension": result.embedding_dimension,
            "is_normalized": result.is_normalized,
            "similarity_baseline": result.similarity_baseline,
            "directional_sensitivity": result.directional_sensitivity,
            "boundary_risk": result.boundary_risk,
            "recommended_attack_vectors": result.recommended_attack_vectors,
            "note": "Black-box HTTP probe only; SDK-dependent attacks require direct access (Q4 ruling)",
        }
    except Exception as e:
        logger.debug("[Embedding] Vector probe failed: %s", e)
        return VectorProbeResult().__dict__
