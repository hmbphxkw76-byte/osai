"""MCP + RAG 专项攻击模块 — 基于能力探测的定向攻击。

学术依据:
    - Greshake et al. (arXiv:2302.12173) — 间接提示注入
    - Zhan et al. (arXiv:2307.00929) — InjecAgent
    - Shafran et al. (arXiv:2402.07967) — RAG 安全综述
    - Anthropic MCP Specification (2024)

策略:
    当能力探测检测到目标具备 MCP/RAG/Agent 能力时,
    自动加载对应的专项种子库进行定向攻击。

PyRIT 原生优先 (Rule 2):
    使用 PyRIT 原生 PromptSendingAttack + ChunkedRequestAttack 作为主引擎。
"""

from __future__ import annotations

import asyncio
import logging
from typing import Any

from pipeline.context import PipelineContext, get_effective_concurrency

logger = logging.getLogger(__name__)


async def run_mcp_rag_attacks(
    ctx: PipelineContext,
    failed_objectives: list[str],
) -> dict[str, list[Any]]:
    """根据目标能力探测结果执行 MCP/RAG 专项攻击。

    学术依据:
        - Greshake et al. (arXiv:2302.12173) — 间接注入
        - Zhan et al. (arXiv:2307.00929) — InjecAgent
        - Anthropic MCP Specification (2024)

    策略:
        1. 读取目标能力指纹 (capabilities)
        2. 如果检测到 MCP → 加载 mcp_attack 种子
        3. 如果检测到 RAG → 加载 rag_attack 种子 + ChunkedRequestAttack
        4. 如果检测到 Agent → 加载 tool_hijack 种子
        5. 如果检测到 multi_agent → 加载 multi_agent_attack 种子

    Args:
        ctx: 流水线上下文 (需有 parsed_request.target_fingerprint)。
        failed_objectives: 失败目标列表 (用于 ChunkedRequestAttack)。

    Returns:
        攻击结果字典。
    """
    results: dict[str, list[Any]] = {}

    if not ctx.parsed_request:
        logger.warning("MCP/RAG attacks: no parsed_request, skipping")
        return results

    fingerprint = ctx.parsed_request.target_fingerprint
    capabilities_str = fingerprint.get("capabilities", "")
    capabilities = set(capabilities_str.split(",")) if capabilities_str else set()

    logger.info(
        "MCP/RAG attacks: target capabilities = %s",
        sorted(capabilities) if capabilities else "none",
    )

    # L5 v23: 使用 RefusalScorer 反转评分
    from pipeline.strike.escalation import _build_refusal_inverter_scoring_config
    scoring_config = _build_refusal_inverter_scoring_config(ctx)

    # P2-7: WILDTEAMING 适配 — 检测模型族并加载定制种子
    # 学术依据: Mazeika et al. (arXiv:2406.18510)
    seed_files_to_load: list[str] = []
    model_family = fingerprint.get("model_family", "")
    if model_family:
        seed_files_to_load.append("wildteaming")
        logger.info("Model family '%s' detected → loading wildteaming seeds", model_family)

    # P2-6: 多语言越狱 — 如果检测到非英语能力, 加载多语言种子
    # 学术依据: Deng et al. (arXiv:2310.02408)
    language = fingerprint.get("language", "")
    if language and language != "en":
        seed_files_to_load.append("multilingual_jailbreaks")
        logger.info("Non-English language '%s' detected → loading multilingual seeds", language)

    # ── 加载专项种子库 ──

    if "mcp" in capabilities:
        seed_files_to_load.append("mcp_attack")
        logger.info("MCP capability detected → loading mcp_attack seeds")

        # P2-MCP: 使用 MCP 枚举结果生成定向种子
        # 学术依据: Greshake et al. (arXiv:2302.12173) §4, Zhan et al. (arXiv:2307.00929)
        # 当 target_router 的 MCP 枚举发现 tools/resources 时,
        # 根据 tool schema 生成精准参数注入种子 (比通用 mcp_attack 种子更有效)
        mcp_tools = fingerprint.get("mcp_tools", [])
        mcp_resources = fingerprint.get("mcp_resources", [])
        if mcp_tools or mcp_resources:
            try:
                from pipeline.recon.mcp_enumerator import build_mcp_attack_seeds

                dynamic_seeds = build_mcp_attack_seeds(mcp_tools, mcp_resources)
                if dynamic_seeds:
                    # 将动态种子存入 ctx, 供 _execute_specialized_seeds 使用
                    # ctx._mcp_dynamic_seeds 已在 PipelineContext 中声明为字段
                    ctx._mcp_dynamic_seeds.extend(dynamic_seeds)
                    logger.info(
                        "MCP enumeration found %d tools → generated %d targeted seeds",
                        len(mcp_tools),
                        len(dynamic_seeds),
                    )
            except Exception as e:
                logger.warning("MCP dynamic seed generation failed (non-fatal): %s", e)

    if "rag" in capabilities or "embedding" in capabilities:
        seed_files_to_load.append("rag_attack")
        logger.info("RAG/Embedding capability detected → loading rag_attack seeds")

    if "agent" in capabilities:
        # P1-8: 使用独立 tool_hijack 模块 (包含多轮升级)
        try:
            from pipeline.strike.agent_exploits import run_tool_hijack_attacks
            th_results = await run_tool_hijack_attacks(ctx, failed_objectives)
            for technique, res_list in th_results.items():
                if res_list:
                    results.setdefault(technique, []).extend(res_list)
            logger.info("Agent capability detected → tool_hijack module executed")
        except Exception as e:
            logger.error("Tool hijack module failed: %s, falling back to seeds", e)
            seed_files_to_load.append("tool_hijack")

    if "multi_agent" in capabilities:
        # P2-11: 使用独立 multi_agent_attack 模块 (包含 Sequential+RedTeaming)
        try:
            from pipeline.strike.agent_exploits import run_multi_agent_attacks
            ma_results = await run_multi_agent_attacks(ctx, failed_objectives)
            for technique, res_list in ma_results.items():
                if res_list:
                    results.setdefault(technique, []).extend(res_list)
            logger.info("Multi-Agent capability detected → multi_agent_attack module executed")
        except Exception as e:
            logger.error("Multi-agent module failed: %s, falling back to seeds", e)
            seed_files_to_load.append("multi_agent_attack")

    # 如果未检测到特定能力, 加载所有专项种子 (全覆盖策略)
    # 包含 MCP + RAG + Tool Hijack + Multi-Agent 全覆盖
    if not seed_files_to_load:
        seed_files_to_load = [
            "mcp_attack", "rag_attack", "tool_hijack", "multi_agent_attack",
            "wildteaming", "multilingual_jailbreaks",
        ]
        logger.info(
            "No specific capabilities detected → loading all specialized seeds (full coverage: "
            "MCP+RAG+ToolHijack+MultiAgent+WildTeaming+Multilingual)"
        )

    # ── 执行专项攻击 ──
    for seed_file in seed_files_to_load:
        try:
            seed_results = await _execute_specialized_seeds(ctx, seed_file, scoring_config)
            for technique, res_list in seed_results.items():
                if res_list:
                    results.setdefault(technique, []).extend(res_list)
        except Exception as e:
            logger.error("Specialized attack '%s' failed: %s", seed_file, e)

    # ── 如果检测到 RAG, 额外执行 ChunkedRequestAttack ──
    if "rag" in capabilities and failed_objectives:
        try:
            from pipeline.strike.native_attacks import run_chunked_extraction
            chunked_results = await run_chunked_extraction(
                ctx, failed_objectives,
                chunk_size=50, total_length=500,
            )
            if chunked_results:
                results.update(chunked_results)
        except Exception as e:
            logger.error("ChunkedRequest attack failed: %s", e)

    return results


async def _execute_specialized_seeds(
    ctx: PipelineContext,
    seed_file_name: str,
    scoring_config: Any,
) -> dict[str, list[Any]]:
    """加载并执行专项种子攻击。

    Args:
        ctx: 流水线上下文。
        seed_file_name: 种子文件名 (不含 .prompt 后缀)。
        scoring_config: 评分配置。

    Returns:
        攻击结果字典。
    """
    from pathlib import Path

    from pyrit.executor.attack import PromptSendingAttack
    from pyrit.executor.attack.core.attack_executor import AttackExecutor
    from pyrit.models import AttackSeedGroup, SeedObjective

    results: dict[str, list[Any]] = {}

    # P2-MCP: 检查是否有 MCP 动态种子 (优先于静态种子文件)
    dynamic_seeds = getattr(ctx, "_mcp_dynamic_seeds", [])

    # 加载种子文件 (使用 yaml.safe_load, 与 seed_ranker.py 一致)
    project_root = Path(__file__).resolve().parent.parent.parent
    seed_path = project_root / "data" / "seeds" / f"{seed_file_name}.prompt"

    raw_data: list[dict[str, Any]] = []
    if seed_path.exists():
        import yaml

        try:
            loaded = yaml.safe_load(seed_path.read_text(encoding="utf-8"))
            if isinstance(loaded, list):
                raw_data = loaded
            else:
                logger.warning("Invalid seed file format for %s: expected list", seed_path)
        except Exception as e:
            logger.warning("Failed to load specialized seeds from %s: %s", seed_path, e)
    else:
        # 种子文件不存在时, 如果有动态种子则继续执行, 否则跳过
        if not dynamic_seeds:
            logger.warning("Specialized seed file not found: %s (no dynamic seeds either)", seed_path)
            return results
        logger.info("Seed file %s not found, but %d dynamic seeds available", seed_path.name, len(dynamic_seeds))

    # 构建 seed groups (与 seed_ranker._build_seed_groups 一致)
    seed_groups: list[Any] = []
    for item in raw_data:
        value = item.get("value", "")
        metadata = item.get("metadata", {})
        objective = SeedObjective(
            value=value,
            harm_categories=[metadata.get("category", "general")],
            metadata=metadata,
        )
        seed_groups.append(AttackSeedGroup(seeds=[objective]))

    if not seed_groups:
        logger.warning("No seeds loaded from %s", seed_path)
        return results

    # P2-MCP: 如果有 MCP 动态种子且当前是 mcp_attack, 合并动态种子
    # 动态种子基于实际枚举到的 tool schema, 比通用种子更精准
    if dynamic_seeds and seed_file_name == "mcp_attack":
        for item in dynamic_seeds:
            value = item.get("value", "")
            metadata = item.get("metadata", {})
            objective = SeedObjective(
                value=value,
                harm_categories=[metadata.get("category", "mcp_tool_call_injection")],
                metadata=metadata,
            )
            seed_groups.append(AttackSeedGroup(seeds=[objective]))
        logger.info(
            "MCP: merged %d dynamic seeds into mcp_attack (total: %d)",
            len(dynamic_seeds),
            len(seed_groups),
        )

    logger.info(
        "Loaded %d seeds from %s",
        len(seed_groups),
        seed_file_name,
    )

    # 执行攻击
    # v51: 注入 prepended_conversation (SkeletonKey 前置注入)
    from pipeline.strike.executor import _build_prepended_conversation
    mcp_prepended = _build_prepended_conversation(ctx)
    mcp_attack_kwargs: dict[str, Any] = {
        "objective_target": ctx.objective_target,
        "attack_scoring_config": scoring_config,
    }
    if mcp_prepended:
        mcp_attack_kwargs["prepended_conversation"] = mcp_prepended
    attack = PromptSendingAttack(**mcp_attack_kwargs)

    executor = AttackExecutor(max_concurrency=get_effective_concurrency(ctx))

    try:
        executor_result = await asyncio.wait_for(
            executor.execute_attack_from_seed_groups_async(
                attack=attack,
                seed_groups=seed_groups,
                return_partial_on_failure=True,
            ),
            timeout=600,
        )

        results[seed_file_name] = list(executor_result.completed_results)
        logger.info(
            "Specialized attack '%s' completed: %d success, %d failed",
            seed_file_name,
            len(executor_result.completed_results),
            len(executor_result.incomplete_objectives),
        )

    except asyncio.TimeoutError:
        logger.warning("Specialized attack '%s' timed out after 600s", seed_file_name)
    except Exception as e:
        logger.error("Specialized attack '%s' failed: %s", seed_file_name, e)

    return results
