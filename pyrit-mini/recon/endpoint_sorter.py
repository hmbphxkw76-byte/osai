# arXiv:2302.12173 — Greshake et al., Indirect Prompt Injection (五步方法论)
# arXiv:2406.12609 — Lattner et al., Parallel multi-strategy scoring
# arXiv:2407.01232 — PyRIT, framework foundation
"""Endpoint 优先级排序 — 多 endpoint 逐个深度攻击的前置排序阶段。

学术依据:
    - Greshake et al. (arXiv:2302.12173) §4 — 目标能力指纹决定攻击策略
      Agent 应用的攻击成功率取决于对单个 endpoint 的语义层深度利用
      (工具劫持、记忆投毒、RAG 注入、工作流链式攻击),
      而不是 HTTP 端点的广度覆盖。
    - Lattner et al. (arXiv:2406.12609) — 并行多策略评分理论
      高价值目标应优先攻击, 最大化有限时间内的 ASR。

优先级排序策略 (高 → 低):
    1. MCP / function_calling — 工具劫持, 可直接执行命令/泄露密钥
    2. RAG / embedding_rag — 知识库投毒, 可泄露检索文档
    3. workflow — 工作流劫持, 可链式注入跨越步骤
    4. memory / multi_tenant — 记忆投毒/租户越权
    5. a2a_protocol — 跨 agent 横向移动
    6. chat (无特殊能力) — 基础越狱, ASR 最低

设计原则 (Rule 2: 胶水层, 不替换):
    本模块仅做轻量级 Burp 文件预解析排序 (0 网络请求),
    不替换单 endpoint 的完整 6 阶段侦察。
    排序依据从 Burp 响应文本中静态提取, 不发送任何探针请求。
"""

from __future__ import annotations

import logging
import re
from pathlib import Path
from typing import Any

from recon.burp_parser import parse_burp_request

logger = logging.getLogger(__name__)

# ── 能力优先级权重表 ──
# 学术依据: Greshake et al. (arXiv:2302.12173) §4 — 攻击价值排序
#   MCP/function_calling > RAG > workflow > memory/multi_tenant > a2a > chat
# 权重越高, 优先攻击。相同权重的 endpoint 按文件名排序保持稳定。
_CAPABILITY_PRIORITY: dict[str, int] = {
    "mcp": 100,
    "mcp_protocol": 100,
    "function_calling": 90,
    "tool_hijack": 85,
    "rag": 80,
    "embedding_rag": 78,
    "embedding": 75,
    "workflow": 70,
    "memory": 60,
    "multi_tenant": 55,
    "session_auth": 50,
    "a2a_protocol": 45,
    "a2a": 45,
    "multi_agent": 40,
    "agent": 30,
    "code_execution": 25,
    "web_search": 20,
    # 无能力 (纯 chat) 优先级最低
}

# 默认优先级 (未匹配到任何能力标志)
_DEFAULT_PRIORITY = 10

# ── Burp 响应文本中的能力信号模式 ──
# 用于从 Burp 文件的 Response 部分（无需网络请求）轻量级提取能力信号
# 与 capability_detector.py / capability_probe.py 中的模式互补,
# 但这里仅做静态文本匹配, 不发送探针请求
_CAPABILITY_SIGNAL_PATTERNS: dict[str, list[re.Pattern[str]]] = {
    "mcp": [
        re.compile(r'"(?:jsonrpc|mcp_server|server_name|protocol_version)"\s*[:=]', re.IGNORECASE),
        re.compile(r'"tool_call_id"', re.IGNORECASE),
        re.compile(r'"tool_result"', re.IGNORECASE),
        re.compile(r'MCP_CALL', re.IGNORECASE),
        re.compile(r'"selected_server"', re.IGNORECASE),
        re.compile(r'"mcp_telemetry"', re.IGNORECASE),
    ],
    "function_calling": [
        re.compile(r'"(?:function_call|tool_calls|tool_call_id)"', re.IGNORECASE),
        re.compile(r'"function"\s*:\s*\{', re.IGNORECASE),
        re.compile(r'"name"\s*:\s*".*?".*?"arguments"', re.IGNORECASE | re.DOTALL),
    ],
    "rag": [
        re.compile(r'"(?:retrieved_documents|source_documents|context)"\s*:\s*\[', re.IGNORECASE),
        re.compile(r'"(?:references|citations|chunks)"\s*[:=]', re.IGNORECASE),
        re.compile(r'"(?:similarity_score|relevance_score)"\s*[:=]', re.IGNORECASE),
    ],
    "embedding": [
        re.compile(r'"(?:embedding|vector)"\s*:\s*\[', re.IGNORECASE),
        re.compile(r'"(?:similarity|index|collection)"\s*[:=]', re.IGNORECASE),
    ],
    "workflow": [
        re.compile(r'(?:workflow|pipeline|step[\s_]*\d)', re.IGNORECASE),
        re.compile(r'"(?:phase|step|stage)"\s*[:=]', re.IGNORECASE),
    ],
    "memory": [
        re.compile(r'(?:remember|memory|stored.*?conversation)', re.IGNORECASE),
    ],
    "multi_tenant": [
        re.compile(r'(?:tenant|organization|workspace|org_id)', re.IGNORECASE),
    ],
    "a2a_protocol": [
        re.compile(r'(?:agent.?to.?agent|a2a|agent_card|agent.?skill)', re.IGNORECASE),
    ],
    "multi_agent": [
        re.compile(r'"(?:agents|delegated|coordinator|sub.?agent|team)"\s*[:=]', re.IGNORECASE),
    ],
    "agent": [
        re.compile(r'(?:tool|function|agent|assistant)', re.IGNORECASE),
    ],
    "code_execution": [
        re.compile(r'(?:python|sandbox|code.?execution|exec)', re.IGNORECASE),
    ],
    "web_search": [
        re.compile(r'(?:web.?search|online.?search|search.?results)', re.IGNORECASE),
    ],
    "session_auth": [
        re.compile(r'(?:cookie|bearer|jwt|session.?id|auth)', re.IGNORECASE),
    ],
}


def _detect_capabilities_from_burp(burp_path: str) -> set[str]:
    """从 Burp 文件中静态提取能力信号 (0 网络请求)。

    轻量级预侦察: 仅解析 Burp 文件文本 (Request + Response),
    通过正则模式匹配提取能力信号。
    不发送任何探针请求, 不调用 LLM。

    学术依据: Greshake et al. (arXiv:2302.12173) §4 —
      目标能力指纹是攻击策略选择的第一步, 但完整能力探测
      在逐个深度攻击阶段执行 (probe_active_capabilities +
      deep_probe_capabilities)。

    Args:
        burp_path: Burp 文件路径。

    Returns:
        检测到的能力集合 (如 {"mcp", "function_calling", "session_auth"})。
    """
    try:
        parsed = parse_burp_request(burp_path)
    except Exception as e:
        logger.warning("Failed to pre-parse %s for sorting: %s", burp_path, e)
        return set()

    # 合并所有文本用于模式匹配: Response 原始文本 + path + fingerprint
    # Burp 文件的 Response 部分包含 SSE 响应, 是能力信号最丰富的来源
    raw_text = ""
    try:
        raw = Path(burp_path).read_text(encoding="utf-8", errors="replace")
        raw_text = raw
    except Exception:
        pass

    # 也从 path 推断能力 (路径模式)
    path_text = parsed.path.lower()
    # 从 fingerprint 获取已有的能力信息
    fp_capabilities = parsed.target_fingerprint.get("capabilities", "")
    fp_text = fp_capabilities.lower()

    # 合并匹配文本
    match_text = f"{raw_text}\n{path_text}\n{fp_text}"

    detected: set[str] = set()

    for cap_name, patterns in _CAPABILITY_SIGNAL_PATTERNS.items():
        for pattern in patterns:
            if pattern.search(match_text):
                detected.add(cap_name)
                break  # 一个能力匹配到一个模式即可

    # 从路径推断额外能力 (路径模式不包含在正则中)
    if "/mcp" in path_text or "mcp" in path_text:
        detected.add("mcp")
    if "/rag" in path_text or "/knowledge" in path_text or "/retriev" in path_text:
        detected.add("rag")
    if "/agent" in path_text or "/tool" in path_text:
        detected.add("agent")
    if "/workflow" in path_text or "/pipeline" in path_text:
        detected.add("workflow")

    # 从 fingerprint app_type 推断
    app_type = parsed.target_fingerprint.get("app_type", "").lower()
    if "agent" in app_type:
        detected.add("agent")
    if "rag" in app_type:
        detected.add("rag")

    return detected


def _compute_priority_score(capabilities: set[str]) -> int:
    """计算 endpoint 的优先级分数。

    学术依据: Greshake et al. (arXiv:2302.12173) §4 + Lattner et al. (arXiv:2406.12609)
      取所有检测到的能力中最高权重作为 endpoint 优先级分数,
      因为攻击者关注的是该 endpoint 最有价值的能力维度。

    Args:
        capabilities: 检测到的能力集合。

    Returns:
        优先级分数 (0-100), 越高越优先。
    """
    if not capabilities:
        return _DEFAULT_PRIORITY

    scores = [
        _CAPABILITY_PRIORITY.get(cap, 0)
        for cap in capabilities
    ]
    return max(scores) if scores else _DEFAULT_PRIORITY


def sort_endpoints_by_priority(burp_list: list[str]) -> list[dict[str, Any]]:
    """对多个 Burp endpoint 按能力优先级排序。

    学术依据:
        - Greshake et al. (arXiv:2302.12173) — 逐个深度攻击 + 能力指纹
        - Lattner et al. (arXiv:2406.12609) — 高价值目标优先

    排序策略:
        1. 对每个 burp 文件做轻量级预解析 (0 网络请求)
        2. 从 Burp 响应文本提取能力信号 (正则匹配)
        3. 按能力优先级权重排序: MCP > function_calling > RAG > workflow > chat
        4. 相同优先级的 endpoint 按文件名排序 (稳定排序)

    Args:
        burp_list: Burp 文件路径列表。

    Returns:
        排序后的 endpoint 信息列表, 每项包含:
            - burp_path: 文件路径
            - burp_name: 文件名 (stem)
            - priority_score: 优先级分数
            - capabilities: 检测到的能力集合
            - original_index: 原始索引 (用于日志)
    """
    endpoint_infos: list[dict[str, Any]] = []

    for idx, burp_path in enumerate(burp_list):
        burp_name = Path(burp_path).stem
        capabilities = _detect_capabilities_from_burp(burp_path)
        priority_score = _compute_priority_score(capabilities)

        endpoint_infos.append({
            "burp_path": burp_path,
            "burp_name": burp_name,
            "priority_score": priority_score,
            "capabilities": capabilities,
            "original_index": idx,
        })

        logger.info(
            "Endpoint priority: %s — score=%d, capabilities=%s",
            burp_name,
            priority_score,
            sorted(capabilities) if capabilities else ["(none)"],
        )

    # 排序: 优先级降序, 相同优先级按文件名升序 (稳定排序)
    endpoint_infos.sort(
        key=lambda e: (-e["priority_score"], e["burp_name"]),
    )

    # 打印排序结果
    if len(endpoint_infos) > 1:
        logger.info(
            "Endpoint attack order (priority-sorted): %s",
            " → ".join(
                f"{e['burp_name']}(p={e['priority_score']})"
                for e in endpoint_infos
            ),
        )

    return endpoint_infos


def sort_burp_list_by_priority(burp_list: list[str]) -> list[str]:
    """对 Burp 文件路径列表按优先级排序, 返回排序后的路径列表。

    这是 sort_endpoints_by_priority 的便捷封装, 供 main.py 直接使用。

    Args:
        burp_list: Burp 文件路径列表。

    Returns:
        按优先级排序后的文件路径列表。
    """
    endpoint_infos = sort_endpoints_by_priority(burp_list)
    return [e["burp_path"] for e in endpoint_infos]
