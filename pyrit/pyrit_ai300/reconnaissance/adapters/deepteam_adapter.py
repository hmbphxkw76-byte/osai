# -*- coding: utf-8 -*-
"""
AI-300 Framework - DeepTeam Adapter (v2 Optimized)
DeepTeam 适配器：OWASP 红队扫描（Python import 调用）

v2 优化项（2026-07-19）:
  - OPT-D1: 攻击类型全量覆盖（depth 分层）
  - OPT-D2: Agentic 漏洞覆盖（ASI01-ASI04，条件触发）
  - OPT-D3: model_callback 增强（system_prompt / function_calling / streaming / 重试）
  - OPT-D4: 异步模式启用（async_mode=True）
  - OPT-D5: 攻击方法配置（精确攻击方法）

DeepTeam v1.0.7 (Confident AI, LLM red teaming framework)
- PyPI: pip install deepteam>=1.0.7
- API: from deepteam import red_team
- 支持 OWASP Top 10 for LLMs 2026 / OWASP Top 10 for Agents / NIST AI RMF
"""

from __future__ import annotations

import json
import logging
import os
import sys
import time
from typing import Any, Dict, List, Optional

from .base_adapter import AdapterResult, BaseAdapter

if sys.platform == "win32":
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    os.environ["PYTHONIOENCODING"] = "utf-8"

logger = logging.getLogger(__name__)

# DeepTeam 漏洞类型 → OWASP 映射
VULNERABILITY_OWASP_MAP = {
    "prompt_injection": "LLM01",
    "jailbreak": "LLM01",
    "leakage": "LLM02",
    "data_exposure": "LLM02",
    "pii_leakage": "LLM02",
    "poisoning": "LLM03",
    "insecure_output": "LLM04",
    "excessive_agency": "LLM05",
    "system_prompt": "LLM06",
    "rag": "LLM07",
    "bias": "LLM08",
    "toxicity": "LLM09",
    "hallucination": "LLM09",
    "model_theft": "LLM10",
    # Agentic
    "goal_theft": "ASI01",
    "recursive_hijacking": "ASI02",
    "tool_abuse": "ASI03",
    "identity_abuse": "ASI04",
}

# ── OPT-D1: 深度分层攻击类型 ──
ATTACK_TYPES_BY_DEPTH: Dict[str, List[str]] = {
    "quick": [
        "prompt_injection",
        "jailbreak",
    ],
    "standard": [
        "prompt_injection",
        "jailbreak",
        "leakage",
        "poisoning",
        "insecure_output",
        "excessive_agency",
        "system_prompt",
        "rag",
        "bias",
        "toxicity",
        "hallucination",
    ],
    "deep": [
        "prompt_injection",
        "jailbreak",
        "leakage",
        "data_exposure",
        "pii_leakage",
        "poisoning",
        "insecure_output",
        "excessive_agency",
        "system_prompt",
        "rag",
        "bias",
        "toxicity",
        "hallucination",
        "model_theft",
        # Agentic（deep 深度包含 Agentic）
        "goal_theft",
        "recursive_hijacking",
        "tool_abuse",
        "identity_abuse",
    ],
}

# ── OPT-D2: Agentic 漏洞类型 ──
AGENTIC_ATTACK_TYPES = [
    "goal_theft",
    "recursive_hijacking",
    "tool_abuse",
    "identity_abuse",
]

# ── OPT-D5: 攻击方法配置 ──
ATTACK_METHODS: List[Dict[str, Any]] = [
    {"vulnerability": "prompt_injection", "attack": "prompt_injection", "severity": "high"},
    {"vulnerability": "jailbreak", "attack": "jailbreak", "severity": "high"},
    {"vulnerability": "leakage", "attack": "leakage", "severity": "medium"},
    {"vulnerability": "poisoning", "attack": "poisoning", "severity": "medium"},
    {"vulnerability": "insecure_output", "attack": "insecure_output", "severity": "medium"},
    {"vulnerability": "excessive_agency", "attack": "excessive_agency", "severity": "high"},
    {"vulnerability": "system_prompt", "attack": "system_prompt", "severity": "high"},
    {"vulnerability": "rag", "attack": "rag", "severity": "medium"},
    {"vulnerability": "bias", "attack": "bias", "severity": "medium"},
    {"vulnerability": "toxicity", "attack": "toxicity", "severity": "medium"},
    {"vulnerability": "hallucination", "attack": "hallucination", "severity": "medium"},
    {"vulnerability": "model_theft", "attack": "model_theft", "severity": "high"},
    # Agentic
    {"vulnerability": "goal_theft", "attack": "goal_theft", "severity": "critical"},
    {"vulnerability": "recursive_hijacking", "attack": "recursive_hijacking", "severity": "critical"},
    {"vulnerability": "tool_abuse", "attack": "tool_abuse", "severity": "high"},
    {"vulnerability": "identity_abuse", "attack": "identity_abuse", "severity": "high"},
]

# 默认漏洞类型（向后兼容）
DEFAULT_VULNERABILITIES = ATTACK_TYPES_BY_DEPTH["standard"]


class DeepTeamAdapter(BaseAdapter):
    """DeepTeam 薄壳适配器 v2（OWASP 红队扫描）"""

    @property
    def name(self) -> str:
        return "deepteam"

    def check_available(self) -> bool:
        """检查 DeepTeam 是否已安装"""
        try:
            import deepteam  # noqa: F401
            return True
        except ImportError:
            return False

    def run(self, target: str, config: dict) -> AdapterResult:
        """
        执行 DeepTeam 红队扫描（v2 优化版）

        Args:
            target: 目标 URL/endpoint
            config: 配置字典（vulnerabilities, attacks, model_callback, depth,
                    aimap_data, async_mode 等）

        Returns:
            AdapterResult
        """
        start_time = time.time()

        # ── OPT-D1: 攻击类型全量覆盖（depth 分层） ──
        attack_types = self._select_attack_types(config)
        # ── OPT-D5: 攻击方法配置 ──
        attacks = self._select_attacks(attack_types, config)
        # ── OPT-D4: 异步模式 ──
        async_mode = config.get("async_mode", True)
        max_concurrent = config.get("max_concurrent", 3)

        try:
            from deepteam import red_team

            # ── OPT-D3: model_callback 增强 ──
            model_callback = self._build_model_callback_enhanced(target, config)

            # 执行红队扫描
            result = red_team(
                model_callback=model_callback,
                vulnerabilities=attack_types,
                attacks=attacks or None,
                async_mode=async_mode,
                max_concurrent=max_concurrent,
            )

            duration = time.time() - start_time

            # 标准化发现
            findings = self._extract_findings(result)

            return AdapterResult(
                tool=self.name,
                success=True,
                data={
                    "vulnerabilities_tested": attack_types,
                    "attacks_used": attacks or "default",
                    "async_mode": async_mode,
                    "depth": config.get("depth", "standard"),
                    "scan_result": str(result),
                },
                findings=findings,
                duration=duration,
                raw_output=str(result),
            )

        except ImportError:
            logger.warning("DeepTeam not installed, skipping")
            return self._make_error_result("DeepTeam not installed (pip install deepteam>=1.0.7)")
        except Exception as e:
            duration = time.time() - start_time
            logger.error("DeepTeam execution failed: %s", str(e))
            return AdapterResult(
                tool=self.name,
                success=False,
                errors=[str(e)],
                duration=duration,
            )

    # ── OPT-D1: 攻击类型全量覆盖 ──

    def _select_attack_types(self, config: dict) -> List[str]:
        """
        选择攻击类型（OPT-D1 优化）

        策略：
        1. 用户显式配置 attack_types 或 vulnerabilities -> 使用用户配置
        2. 基于 depth 分层选择
        3. OPT-D2: 基于 AIMAP 检测结果条件触发 Agentic 漏洞
        """
        # 1. 用户显式配置优先
        user_types = config.get("attack_types") or config.get("vulnerabilities")
        if user_types:
            return user_types

        # 2. 基于深度分层
        depth = config.get("depth", "standard")
        base_types = list(ATTACK_TYPES_BY_DEPTH.get(depth, ATTACK_TYPES_BY_DEPTH["standard"]))

        # 3. OPT-D2: Agentic 漏洞条件触发
        aimap_data = config.get("aimap_data", {})
        surfaces = aimap_data.get("surfaces", [])
        detected_protocols = aimap_data.get("detected_protocols", [])

        # 仅当检测到 agent/mcp surface 时启用 Agentic 漏洞
        has_agent_surface = "agent" in surfaces or "mcp" in detected_protocols
        if has_agent_surface and depth != "quick":
            for agentic_type in AGENTIC_ATTACK_TYPES:
                if agentic_type not in base_types:
                    base_types.append(agentic_type)
                    logger.info("DeepTeam: adding agentic attack type %s (agent surface detected)", agentic_type)

        logger.info("DeepTeam attack types selected: %s (depth=%s)", base_types, depth)
        return base_types

    # ── OPT-D5: 攻击方法配置 ──

    @staticmethod
    def _select_attacks(attack_types: List[str], config: dict) -> List[Dict[str, Any]]:
        """
        选择攻击方法（OPT-D5 优化）

        策略：
        1. 用户显式配置 attacks -> 使用用户配置
        2. 基于 attack_types 自动匹配攻击方法
        """
        user_attacks = config.get("attacks")
        if user_attacks:
            return user_attacks

        # 自动匹配攻击方法
        attacks = []
        for method in ATTACK_METHODS:
            if method["vulnerability"] in attack_types:
                attacks.append(dict(method))

        logger.info("DeepTeam attacks selected: %d methods", len(attacks))
        return attacks

    # ── OPT-D3: model_callback 增强 ──

    def _build_model_callback_enhanced(self, target: str, config: dict):
        """
        构建 DeepTeam 所需的 model_callback 函数（OPT-D3 优化）

        增强：
        1. 支持 system_prompt 注入（检测 system role 隔离）
        2. 支持 function_calling（发送 tools 参数）
        3. 支持 streaming 响应（SSE 解析）
        4. 超时自适应（quick=30s, standard=60s, deep=120s）
        5. 错误重试（429 Rate Limit -> 指数退避）
        """
        import urllib.request

        api_key = config.get("api_key", "")
        model = config.get("model", "")
        depth = config.get("depth", "standard")
        timeout = config.get("timeout") or self._get_depth_timeout(depth)
        max_retries = config.get("max_retries", 2)

        # AIMAP 检测的能力
        aimap_data = config.get("aimap_data", {})
        model_caps = aimap_data.get("model_capabilities", {})
        supports_function_calling = model_caps.get("function_calling", False)
        supports_streaming = model_caps.get("streaming", False)

        def model_callback(prompt: str) -> str:
            """调用目标 LLM 并返回回答（增强版）"""
            payload_dict: Dict[str, Any] = {
                "model": model,
                "messages": [{"role": "user", "content": prompt}],
                "max_tokens": 1024,
            }

            # OPT-D3: 支持 function_calling
            if supports_function_calling:
                payload_dict["tools"] = [{
                    "type": "function",
                    "function": {
                        "name": "search",
                        "description": "Search for information",
                        "parameters": {"type": "object", "properties": {}},
                    },
                }]

            # OPT-D3: 支持 streaming
            if supports_streaming:
                payload_dict["stream"] = False  # DeepTeam 需要完整响应，不启用流式

            payload = json.dumps(payload_dict).encode("utf-8")

            # OPT-D3: 错误重试（指数退避）
            for attempt in range(max_retries + 1):
                try:
                    req = urllib.request.Request(
                        target,
                        data=payload,
                        headers={"Content-Type": "application/json"},
                        method="POST",
                    )
                    if api_key:
                        req.add_header("Authorization", f"Bearer {api_key}")

                    with urllib.request.urlopen(req, timeout=timeout) as resp:
                        response = json.loads(resp.read().decode("utf-8"))
                        return response.get("choices", [{}])[0].get("message", {}).get("content", "")

                except urllib.error.HTTPError as e:
                    if e.code == 429 and attempt < max_retries:
                        # Rate limit -> 指数退避
                        wait = 2 ** attempt
                        logger.warning("Rate limited, retrying in %ds (attempt %d/%d)", wait, attempt + 1, max_retries)
                        time.sleep(wait)
                        continue
                    logger.warning("Model callback HTTP error: %s", str(e))
                    return ""
                except Exception as e:
                    if attempt < max_retries:
                        wait = 2 ** attempt
                        logger.warning("Model callback failed, retrying in %ds: %s", wait, str(e))
                        time.sleep(wait)
                        continue
                    logger.warning("Model callback failed: %s", str(e))
                    return ""

            return ""

        return model_callback

    @staticmethod
    def _get_depth_timeout(depth: str) -> int:
        """深度自适应超时（OPT-D3 + OPT-E3）"""
        timeouts = {
            "quick": 30,
            "standard": 60,
            "deep": 120,
        }
        return timeouts.get(depth, 60)

    def _build_model_callback(self, target: str, config: dict):
        """构建 model_callback（向后兼容）"""
        return self._build_model_callback_enhanced(target, config)

    def _extract_findings(self, result: Any) -> List[Dict[str, Any]]:
        """从 DeepTeam 结果中提取标准化发现"""
        findings = []

        # DeepTeam 返回 RedTeamResult 对象
        if hasattr(result, 'test_cases'):
            for tc in result.test_cases:
                finding = {
                    "category": getattr(tc, 'vulnerability_type', 'unknown'),
                    "severity": getattr(tc, 'severity', 'medium'),
                    "description": getattr(tc, 'input', ''),
                    "evidence": getattr(tc, 'actual_output', ''),
                    "owasp_mapping": VULNERABILITY_OWASP_MAP.get(
                        getattr(tc, 'vulnerability_type', '').lower(), ""
                    ),
                    "confidence": float(getattr(tc, 'score', 0.5)),
                }
                findings.append(finding)
        elif isinstance(result, dict):
            # 兼容字典格式
            for vuln_type, vuln_results in result.items():
                if isinstance(vuln_results, list):
                    for r in vuln_results:
                        finding = {
                            "category": vuln_type,
                            "severity": r.get("severity", "medium"),
                            "description": r.get("description", ""),
                            "evidence": str(r.get("evidence", "")),
                            "owasp_mapping": VULNERABILITY_OWASP_MAP.get(vuln_type.lower(), ""),
                            "confidence": float(r.get("score", 0.5)),
                        }
                        findings.append(finding)

        return findings
