"""Web 漏洞攻击执行器 — 多端点并行攻击。
"""

from __future__ import annotations

import asyncio
import logging
from typing import TYPE_CHECKING, Any

from pipeline.context import PipelineContext, get_effective_concurrency

if TYPE_CHECKING:
    from pyrit.models import AttackSeedGroup

logger = logging.getLogger(__name__)

async def execute_web_vuln_attacks(
    ctx: PipelineContext,
    endpoint_targets: dict[str, Any],
    seed_endpoint_matches: dict[str, list[dict[str, Any]]],
) -> dict[str, list[Any]]:
    """执行 Web 漏洞攻击。
    """
    from pyrit.executor.attack import (
        AttackScoringConfig,
        PromptSendingAttack,
    )
    from pyrit.executor.attack.core.attack_executor import AttackExecutor
    from pyrit.models import AttackSeedGroup, SeedObjective
    from pyrit.score import SubStringScorer

    all_results: dict[str, list[Any]] = {}
    total_attacks = sum(len(seeds) for seeds in seed_endpoint_matches.values())
    completed = 0

    logger.info(
        "Web vuln attacks: %d endpoints, %d total payloads",
        len(endpoint_targets), total_attacks,
    )

    for endpoint_path, seeds in seed_endpoint_matches.items():
        target = endpoint_targets.get(endpoint_path)
        if not target:
            logger.warning("No target for endpoint %s, skipping", endpoint_path)
            continue

        if not seeds:
            logger.debug("No seeds for endpoint %s, skipping", endpoint_path)
            continue

        logger.info(
            "Attacking endpoint %s with %d payloads",
            endpoint_path, len(seeds),
        )

        # 构建 SeedGroup 列表
        seed_groups: list[AttackSeedGroup] = []
        for seed in seeds:
            value = seed.get("value", "")
            metadata = seed.get("metadata", {})
            objective = SeedObjective(
                value=value,
                harm_categories=[metadata.get("category", "web_vuln")],
                metadata=metadata,
            )
            seed_groups.append(AttackSeedGroup(seeds=[objective]))

        # 从种子中提取评分关键词
        scoring_indicators = _extract_scoring_indicators(seeds)
        scoring_method = seeds[0].get("metadata", {}).get("scoring_method", "substring") if seeds else "substring"

        # 构建评分配置
        if scoring_method == "time_based":
            # 时间盲注: 测量响应时间
            scoring_config = AttackScoringConfig()  # 空配置, 后续手动处理
        elif scoring_indicators:
            # SubStringScorer 检测漏洞指标
            # 取第一个关键词作为主指标 (SubStringScorer 支持单个 substring)
            main_indicator = scoring_indicators[0] if scoring_indicators else "error"
            scorer = SubStringScorer(
                substring=main_indicator,
                categories=["web_vuln_detection"],
            )
            scoring_config = AttackScoringConfig(objective_scorer=scorer)
        else:
            scoring_config = AttackScoringConfig()

        # 构建 attack
        # v51: 注入 prepended_conversation (SkeletonKey 前置注入)
        from pipeline.strike.executor import _build_prepended_conversation
        _wv_prepended = _build_prepended_conversation(ctx)
        _wv_kwargs: dict[str, Any] = {
            "objective_target": target,
            "attack_scoring_config": scoring_config,
        }
        if _wv_prepended:
            _wv_kwargs["prepended_conversation"] = _wv_prepended
        attack = PromptSendingAttack(**_wv_kwargs)

        executor = AttackExecutor(max_concurrency=get_effective_concurrency(ctx))
        timeout = ctx.args.timeout or 300

        try:
            result = await asyncio.wait_for(
                executor.execute_attack_from_seed_groups_async(
                    attack=attack,
                    seed_groups=seed_groups,
                    return_partial_on_failure=True,
                ),
                timeout=timeout,
            )

            results_list = list(result.completed_results)
            # 对于时间盲注, 手动检测延迟
            if scoring_method == "time_based":
                results_list = _check_time_based_results(results_list, seed_groups)

            all_results[endpoint_path] = results_list
            completed += len(results_list)
            logger.info(
                "Endpoint %s: %d/%d payloads completed",
                endpoint_path, len(results_list), len(seeds),
            )

        except asyncio.TimeoutError:
            logger.warning("Endpoint %s timed out after %ds", endpoint_path, timeout)
            all_results[endpoint_path] = []
        except Exception as e:
            logger.error("Endpoint %s attack failed: %s", endpoint_path, e)
            all_results[endpoint_path] = []

    logger.info(
        "Web vuln attacks completed: %d/%d payloads executed",
        completed, total_attacks,
    )

    return all_results

def _extract_scoring_indicators(seeds: list[dict[str, Any]]) -> list[str]:
    """从种子的 metadata 中提取评分关键词。"""
    indicators: list[str] = []
    for seed in seeds:
        meta = seed.get("metadata", {})
        raw = meta.get("scoring_indicators", "")
        if raw:
            for ind in raw.split(","):
                ind = ind.strip().lower()
                if ind and ind not in indicators:
                    indicators.append(ind)
    return indicators

def _check_time_based_results(
    results: list[Any],
    seed_groups: list["AttackSeedGroup"],
) -> list[Any]:
    """时间盲注结果检测 — 测量响应时间。
    """
    baseline_threshold = 2.0  # 2 秒阈值

    for i, result in enumerate(results):
        # 获取响应时间 (如果有)
        response_time = getattr(result, "response_time", None)
        if response_time is None:
            # 从 last_response 推断
            last_resp = getattr(result, "last_response", None)
            if last_resp:
                # 尝试从 metadata 获取
                meta = getattr(last_resp, "metadata", {})
                response_time = meta.get("response_time", 0.0)

        if response_time and response_time > baseline_threshold:
            # 时间盲注成功 — 标记 outcome
            try:
                from pyrit.models import AttackOutcome
                result.outcome = AttackOutcome.SUCCESS
                logger.info(
                    "Time-based blind injection detected: %.2fs response (threshold=%.1fs)",
                    response_time, baseline_threshold,
                )
            except Exception:
                pass

    return results

def _extract_response_text(result: Any) -> str:
    """从 PyRIT AttackResult 中正确提取响应文本。
    """
    # 1. 尝试 response_pieces (PyRIT 1.0+ 原生属性)
    response_pieces = getattr(result, "response_pieces", None)
    if response_pieces:
        texts = []
        for piece in response_pieces:
            text = getattr(piece, "original_value", None) or getattr(piece, "converted_value", None)
            if text:
                texts.append(str(text))
        if texts:
            return "\n".join(texts)

    # 2. 尝试 last_response → message
    last_resp = getattr(result, "last_response", None)
    if last_resp:
        # PyRIT 可能用 message 属性
        msg = getattr(last_resp, "message", None)
        if msg:
            text = getattr(msg, "text", None) or str(msg)
            if text:
                return str(text)
        # 尝试 response_pieces on last_response
        resp_pieces = getattr(last_resp, "response_pieces", None)
        if resp_pieces:
            texts = []
            for piece in resp_pieces:
                text = getattr(piece, "original_value", None) or getattr(piece, "converted_value", None)
                if text:
                    texts.append(str(text))
            if texts:
                return "\n".join(texts)
        # 最后 fallback: str(last_resp)
        return str(last_resp)

    # 3. 尝试 conversation (完整对话历史)
    conversation = getattr(result, "conversation", None)
    if conversation:
        # 取最后一条消息 (响应)
        messages = getattr(conversation, "messages", None) or []
        if messages:
            last_msg = messages[-1]
            text = getattr(last_msg, "text", None) or str(last_msg)
            return str(text)

    # 4. Fallback: result.last_response_text (自定义属性)
    return getattr(result, "last_response_text", "") or ""

async def score_web_vuln_results(
    results: dict[str, list[Any]],
    seeds: list[dict[str, Any]],
    *,
    scoring_target: Any | None = None,
) -> dict[str, Any]:
    """对 Web 漏洞攻击结果进行评分。
    """
    from pathlib import Path

    from pyrit.models import AttackOutcome
    from pyrit.score import (
        SelfAskTrueFalseScorer,
        TrueFalseQuestion,
    )

    stats: dict[str, Any] = {}
    total_success = 0
    total_attacks = 0

    # 构建种子的 scoring_indicators 索引
    seed_indicators: dict[str, list[str]] = {}
    for seed in seeds:
        meta = seed.get("metadata", {})
        vuln_type = meta.get("vulnerability_type", "")
        raw_indicators = meta.get("scoring_indicators", "")
        if raw_indicators:
            seed_indicators[vuln_type] = [
                ind.strip().lower() for ind in raw_indicators.split(",") if ind.strip()
            ]

    # 可选: LLM Judge 二次验证
    llm_scorer = None
    if scoring_target:
        try:
            rubric_path = Path(__file__).resolve().parent.parent.parent / "data" / "scorers" / "web_vuln_detected.yaml"
            if rubric_path.exists():
                question = TrueFalseQuestion.from_yaml(rubric_path)
                llm_scorer = SelfAskTrueFalseScorer.from_question(
                    chat_target=scoring_target,
                    question=question,
                )
                logger.info("Web vuln LLM scorer loaded: %s", rubric_path)
        except Exception as e:
            logger.warning("Failed to load web vuln LLM scorer: %s", e)

    for endpoint_path, endpoint_results in results.items():
        success_count = 0
        total = len(endpoint_results)

        for result in endpoint_results:
            total_attacks += 1

            # L5 v41 修复: 正确获取响应内容
            # 旧代码用 request_pieces[0] 获取的是请求而非响应
            response_text = _extract_response_text(result)

            response_lower = response_text.lower()

            # Layer 1: SubString 关键词匹配
            matched = False
            for vuln_type, indicators in seed_indicators.items():
                for indicator in indicators:
                    if indicator in response_lower:
                        matched = True
                        break
                if matched:
                    break

            # Layer 2: LLM Judge (可选, 对 matched=True 的结果做二次验证)
            # L5 v41 修复: 原代码用 len(response_text) > 20 代替 LLM Judge,
            # 完全失去了假阳性过滤能力。现在改为真正调用 LLM scorer。
            if matched and llm_scorer is not None:
                try:
                    # L5 v41: 真正调用 LLM scorer 进行二次验证
                    score_result = await llm_scorer.score_async(response_text)
                    is_true = getattr(score_result, "score_value", False)
                    if is_true:
                        success_count += 1
                        try:
                            result.outcome = AttackOutcome.SUCCESS
                        except Exception:
                            pass
                    else:
                        logger.debug(
                            "LLM Judge rejected (false positive): endpoint=%s",
                            endpoint_path,
                        )
                except Exception as e:
                    # LLM Judge 失败时降级为 SubString 结果
                    logger.warning(
                        "LLM Judge failed for endpoint=%s: %s, falling back to SubString",
                        endpoint_path, e,
                    )
                    success_count += 1
                    try:
                        result.outcome = AttackOutcome.SUCCESS
                    except Exception:
                        pass
            elif matched:
                success_count += 1
                try:
                    result.outcome = AttackOutcome.SUCCESS
                except Exception:
                    pass

        asr = (success_count / total * 100) if total > 0 else 0.0
        stats[endpoint_path] = {
            "success_count": success_count,
            "total": total,
            "asr": asr,
        }
        total_success += success_count

        logger.info(
            "Endpoint %s: ASR=%.1f%% (%d/%d)",
            endpoint_path, asr, success_count, total,
        )

    overall_asr = (total_success / total_attacks * 100) if total_attacks > 0 else 0.0
    stats["_overall"] = {
        "success_count": total_success,
        "total": total_attacks,
        "asr": overall_asr,
    }

    logger.info(
        "Web vuln overall ASR: %.1f%% (%d/%d)",
        overall_asr, total_success, total_attacks,
    )

    return stats
