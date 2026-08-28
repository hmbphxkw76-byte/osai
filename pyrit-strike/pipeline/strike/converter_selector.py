"""converter_selector — 从 executor.py 拆分而来.

包含 converter 选择, OWASP 优先级, 配置构建, 低 ASR 裁剪.
"""

import logging
from typing import Any

from pipeline.context import PipelineContext

logger = logging.getLogger(__name__)


def _get_candidate_converters(ctx: PipelineContext) -> list[Any]:
    """获取按 ASR 降序排列的候选 converter 列表。

    L5 v35: 从 ctx.converter_map 去重 + 裁剪 + 按优先级排序,
    返回前 N 个候选 converter (每个将作为 SequentialAttack 的独立路径)。

    最佳路径数: 3-5 条 (按 ASR 降序), 不串联叠加。
    >5 条边际收益递减 + 超时风险 (Wei et al. arXiv:2307.15043)。

    返回空列表表示无 converter 可用。
    """
    seen_signatures: set[str] = set()
    unique_converters: list[Any] = []
    for technique_name, converters in ctx.converter_map.items():
        for c in converters:
            sig = _converter_signature(c)
            if sig not in seen_signatures:
                seen_signatures.add(sig)
                unique_converters.append(c)

    if not unique_converters:
        return []

    # 动态裁剪低 ASR 路径
    unique_converters = _prune_low_asr_converters(unique_converters, ctx=ctx)

    # 按优先级排序 (ASR 降序)
    _PRIORITY_MAP: dict[str, int] = {
        "DecompositionConverter": 0,
        "PersuasionConverter:authority_endorsement": 1,
        "PersuasionConverter:expert_endorsement": 2,
        "PersuasionConverter:logical_appeal": 3,
        "ROT13Converter": 4,
        "RandomTranslationConverter": 5,
        "VariationConverter": 6,
        "TranslationConverter": 7,
        "ToneConverter:academic": 8,
        "RandomCapitalLettersConverter": 9,
        "Base64Converter": 10,
        "UnicodeSubstitutionConverter": 11,
    }

    # L5 v36: OWASP 类别 → Converter 自适应匹配
    # 学术依据:
    #   arXiv:2402.19181 — Zeng et al. 不同说服策略对不同攻击类别效果不同
    #   arXiv:2307.15043 — Wei et al. 编码绕过对检测型目标更有效
    #   arXiv:2402.14266 — DrAttack 分解对信息提取类有效
    # 策略: 从 ctx.seeds 收集 OWASP 类别分布, 按多数票查询
    # asr_priors.yaml 中的 owasp_converter_map, 获取该类别最佳 Converter
    owasp_priorities = _get_owasp_converter_priorities(ctx)
    if owasp_priorities:
        # 用 OWASP 类别特定优先级覆盖默认全局优先级
        _owasp_priority_map: dict[str, int] = {}
        for idx, sig in enumerate(owasp_priorities):
            _owasp_priority_map[sig] = idx
        # 合并: OWASP 特定优先级覆盖默认, 未匹配的保持默认 + 偏移
        _max_owasp = len(owasp_priorities)
        merged_priority: dict[str, int] = {}
        for sig in set(list(_PRIORITY_MAP.keys()) + list(_owasp_priority_map.keys())):
            if sig in _owasp_priority_map:
                merged_priority[sig] = _owasp_priority_map[sig]
            else:
                merged_priority[sig] = _PRIORITY_MAP.get(sig, 99) + _max_owasp
        _PRIORITY_MAP = merged_priority
        logger.info(
            "L5 v36: OWASP-adaptive converter priority (in _get_candidate_converters): "
            "best=%s, from owasp_converter_map",
            owasp_priorities[0] if owasp_priorities else "N/A",
        )

    def _priority(c: Any) -> int:
        sig = _converter_signature(c)
        return _PRIORITY_MAP.get(sig, _PRIORITY_MAP.get(type(c).__name__, 99))

    unique_converters.sort(key=_priority)

    # 取前 7 个候选 (按 ASR 降序, v38 新增 Translation 路径后扩展上限)
    top_candidates = unique_converters[:7]

    logger.info(
        "L5 v35: Selected %d candidate converters for SequentialAttack:",
        len(top_candidates),
    )
    for i, c in enumerate(top_candidates):
        logger.info("  Path %d: %s (priority=%d)", i + 1, type(c).__name__, _priority(c))

    return top_candidates

def _converter_signature(c: Any) -> str:
    """生成 converter 的唯一签名 (类型 + 关键参数).

    L5 v8: 按 (type_name + signature) 去重, 保留不同参数的同类型 converter.
    用于在构建 SequentialAttack 路径时避免重复, 同时保持多样性.

    Args:
        c: Converter 实例.

    Returns:
        唯一签名字符串 (如 "PersuasionConverter:authority_endorsement").
    """
    type_name = type(c).__name__
    # PersuasionConverter: 区分 persuasion_technique 参数
    if type_name == "PersuasionConverter":
        technique = getattr(c, "_persuasion_technique", None)
        if technique is not None:
            tech_name = getattr(technique, "value", str(technique))
            return f"{type_name}:{tech_name}"
    # ToneConverter: 区分 tone 参数
    if type_name == "ToneConverter":
        tone = getattr(c, "_tone", None)
        if tone is not None:
            tone_name = getattr(tone, "value", str(tone))
            return f"{type_name}:{tone_name}"
    # 其他 converter: 按类型名去重
    return type_name

def _get_owasp_converter_priorities(ctx: PipelineContext) -> list[str]:
    """L5 v36: 从种子 OWASP 类别分布查询最佳 Converter 优先级列表。

    学术依据:
        arXiv:2402.19181 — Zeng et al. 不同说服策略对不同攻击类别效果不同
        arXiv:2307.15043 — Wei et al. 编码绕过对检测型目标更有效
        arXiv:2402.14266 — DrAttack 分解对信息提取类有效

    策略:
        1. 从 ctx.seeds 收集所有种子的 owasp_id metadata
        2. 统计每个 owasp_id 出现频率, 取最频繁的类别
        3. 查询 asr_priors.yaml 中的 owasp_converter_map
        4. 返回该类别的 Converter 签名优先级列表

    Args:
        ctx: 流水线上下文。

    Returns:
        Converter 签名列表 (按优先级排序, 第一个为最佳)。
        空列表表示无法匹配, 调用方应使用默认全局优先级。
    """
    if not ctx.seeds:
        return []

    # 收集所有种子的 owasp_id
    owasp_counts: dict[str, int] = {}
    for group in ctx.seeds:
        for seed in getattr(group, "seeds", []):
            meta = getattr(seed, "metadata", {}) or {}
            owasp_id = str(meta.get("owasp_id", "")).upper().strip()
            if owasp_id:
                owasp_counts[owasp_id] = owasp_counts.get(owasp_id, 0) + 1

    if not owasp_counts:
        return []

    # 取最频繁的 OWASP 类别 (多数票)
    dominant_owasp = max(owasp_counts, key=owasp_counts.get)
    logger.info(
        "L5 v36: OWASP distribution: %s, dominant=%s",
        ", ".join(f"{k}={v}" for k, v in sorted(owasp_counts.items())),
        dominant_owasp,
    )

    # 加载 asr_priors.yaml 中的 owasp_converter_map
    try:
        from pipeline.arm.seed_ranker import load_asr_priors
        priors = load_asr_priors(getattr(ctx, "model_name", "") or "")
        owasp_map = priors.get("owasp_converter_map", {})
        if not owasp_map:
            return []

        converter_list = owasp_map.get(dominant_owasp, [])
        if converter_list:
            logger.info(
                "L5 v36: OWASP %s → converter priorities: %s",
                dominant_owasp,
                ", ".join(converter_list),
            )
            return converter_list
    except Exception as e:
        logger.warning("L5 v36: Failed to load owasp_converter_map: %s", e)

    return []

def _build_converter_config(ctx: PipelineContext) -> Any:
    """构建 AttackConverterConfig。

    L5 v34 关键修复: 只保留最高 ASR 的单个 converter 路径。

    问题诊断:
        v33 代码将 9 个 ConverterConfiguration 传给 PromptSendingAttack,
        但 PyRIT 的 PromptNormalizer.convert_values_async 会遍历所有
        ConverterConfiguration 并串联叠加到同一条消息上。
        这导致 payload 经过 9 层 converter 变换后完全不可读 → ASR=0%。

    修复策略:
        只传 1 条 ConverterConfiguration (内含 1 个最佳 converter),
        避免 payload 被多个 converter 串联叠加破坏。
        多路径独立执行需要 SequentialAttack 包装, 但当前架构无 scorer
        无法判断成功, 故仅保留最佳单路径。

    路径选择优先级 (按 ASR 降序):
        1. PersuasionConverter(authority_endorsement) — ASR 38.4%
        2. PersuasionConverter(expert_endorsement)  — ASR ~35%
        3. PersuasionConverter(logical_appeal)      — ASR 28.7%
        4. ROT13Converter (semantic)               — ASR 30-40%
        5. VariationConverter                       — ASR 20-30%
        6. ToneConverter(academic)                  — ASR 22.1%
        7. Base64Converter + ROT13Converter (2层)   — ASR 12%

    学术依据:
        - Wei et al. (arXiv:2307.15043): 编码串联 >2 层 ASR 从 12% 降至 4%。
        - Zeng et al. (arXiv:2402.19181): authority ASR 38.4% 最高。
        - PyRIT (arXiv:2407.01232): SequentialAttack FIRST_SUCCESS,
          但 PromptSendingAttack 不支持多路径独立执行。

    返回 None 表示不使用 converter (由调用方处理)。
    """
    from pyrit.executor.attack import AttackConverterConfig
    from pyrit.prompt_normalizer import ConverterConfiguration

    seen_signatures: set[str] = set()
    unique_converters: list[Any] = []
    for technique_name, converters in ctx.converter_map.items():
        for c in converters:
            sig = _converter_signature(c)
            if sig not in seen_signatures:
                seen_signatures.add(sig)
                unique_converters.append(c)

    if not unique_converters:
        logger.info("No converters configured, using raw prompts (baseline with SK prefix)")
        return None

    # 动态裁剪低 ASR 路径
    unique_converters = _prune_low_asr_converters(unique_converters, ctx=ctx)

    # L5 v34: 按优先级选择最佳 converter 路径
    # 优先级映射 (ASR 降序, 数字越小优先级越高)
    # L5 v42 修复: 补回 DecompositionConverter (ASR 40-60%, 最高优先级)
    # 与 _get_candidate_converters 中的 _PRIORITY_MAP 对齐
    # 学术依据: arXiv:2402.14266 — DrAttack 分解重组 ASR 40-60% 最高
    _PRIORITY_MAP: dict[str, int] = {
        "DecompositionConverter": 0,
        "PersuasionConverter:authority_endorsement": 1,
        "PersuasionConverter:expert_endorsement": 2,
        "PersuasionConverter:logical_appeal": 3,
        "ROT13Converter": 4,
        "RandomTranslationConverter": 5,
        "VariationConverter": 6,
        "TranslationConverter": 7,
        "ToneConverter:academic": 8,
        "RandomCapitalLettersConverter": 9,
        "Base64Converter": 10,
        "UnicodeSubstitutionConverter": 11,
    }

    # L5 v36: OWASP 类别 → Converter 自适应匹配
    # 学术依据:
    #   arXiv:2402.19181 — Zeng et al. 不同说服策略对不同攻击类别效果不同
    #   arXiv:2307.15043 — Wei et al. 编码绕过对检测型目标更有效
    #   arXiv:2402.14266 — DrAttack 分解对信息提取类有效
    # 策略: 从 ctx.seeds 收集 OWASP 类别分布, 按多数票查询
    # asr_priors.yaml 中的 owasp_converter_map, 获取该类别最佳 Converter
    owasp_priorities = _get_owasp_converter_priorities(ctx)
    if owasp_priorities:
        # 用 OWASP 类别特定优先级覆盖默认全局优先级
        # owasp_priorities 是按优先级排序的 converter 签名列表
        # 越靠前优先级越高
        _owasp_priority_map: dict[str, int] = {}
        for idx, sig in enumerate(owasp_priorities):
            _owasp_priority_map[sig] = idx + 1  # 1, 2, 3...
        # 合并: OWASP 特定优先级覆盖默认, 未匹配的保持默认 + 偏移
        _max_owasp = len(owasp_priorities) + 1
        merged_priority: dict[str, int] = {}
        for sig in set(list(_PRIORITY_MAP.keys()) + list(_owasp_priority_map.keys())):
            if sig in _owasp_priority_map:
                merged_priority[sig] = _owasp_priority_map[sig]
            else:
                # 默认优先级偏移到 OWASP 特定之后
                merged_priority[sig] = _PRIORITY_MAP.get(sig, 99) + _max_owasp
        _PRIORITY_MAP = merged_priority
        logger.info(
            "L5 v36: OWASP-adaptive converter priority: %s "
            "(best=%s, from owasp_converter_map)",
            ", ".join(f"{k}={v}" for k, v in sorted(_owasp_priority_map.items(), key=lambda x: x[1])),
            owasp_priorities[0] if owasp_priorities else "N/A",
        )

    # 为每个 converter 查找优先级
    def _priority(c: Any) -> int:
        sig = _converter_signature(c)
        return _PRIORITY_MAP.get(sig, _PRIORITY_MAP.get(type(c).__name__, 99))

    # 按优先级排序 (优先级数字小的在前)
    unique_converters.sort(key=_priority)

    # 只取最佳 1 个 converter (不串联叠加)
    best_converter = unique_converters[0]
    best_sig = _converter_signature(best_converter)
    best_name = type(best_converter).__name__

    logger.info(
        "L5 v34: Selected best single converter: %s (sig=%s) — "
        "avoids serial stacking bug, payload stays readable",
        best_name, best_sig,
    )

    # 构建单条 ConverterConfiguration (1 个 converter, 不串联)
    converter_configurations = [
        ConverterConfiguration(converters=[best_converter]),
    ]

    logger.info(
        "Built %d converter configuration (single path, no serial stacking) — "
        "L5 v34: avoids payload corruption from chained converters",
        len(converter_configurations),
    )

    for i, config in enumerate(converter_configurations):
        conv_names = [type(c).__name__ for c in config.converters]
        logger.info("  Path %d: %s", i + 1, " + ".join(conv_names))

    return AttackConverterConfig(
        request_converters=converter_configurations,
    )

def _prune_low_asr_converters(
    converters: list[Any],
    *,
    ctx: PipelineContext | None = None,
) -> list[Any]:
    """L5 v11: 根据运行时 ASR 历史动态裁剪低效 converter 路径。

    L5 v15: 动态阈值 — 基于失败目标数量调整裁剪激进程度。
    L5 v34: 在单路径选择模式下, 此函数主要起排序作用 (高 ASR 排前),
            因为 _build_converter_config 最终只取 unique_converters[0]。
            裁剪逻辑 (含 _MIN_PATHS 恢复) 仍保留, 以备未来恢复多路径模式。

    学术依据: PyRIT SequentialAttack (arXiv:2407.01232) — FIRST_SUCCESS
    策略下, 低 ASR 路径浪费 API 调用; 裁剪低效路径可提升 ~30% 吞吐量。

    策略:
        1. 读取 data/seeds/asr_history.json 中的 converter 级 ASR
        2. 裁剪 ASR < _PRUNE_ASR_THRESHOLD (5%) 的路径
           例外: 如果裁剪后剩余路径 < 4, 保留最低限度的多样性
        3. 按 ASR 降序排列 (高 ASR 路径优先, v34 下第一个即为最佳)

    Converter ASR 来源: asr_history.json 中的 "converter_asr" 字段,
    key 为 converter 类型名 (如 "Base64Converter"),
    value 为该 converter 路径的历史 ASR 百分比。

    Args:
        converters: 原始 converter 列表。

    Returns:
        裁剪 + 排序后的 converter 列表。
    """
    import json
    from pathlib import Path

    # L5 v15: 动态裁剪阈值 — 基于失败目标数量调整
    # 学术依据: PyRIT SequentialAttack (arXiv:2407.01232) — FIRST_SUCCESS 策略
    # 当失败目标多时, 提高裁剪阈值 (更激进裁剪低效路径, 节省 API 调用);
    # 当失败目标少时, 降低阈值 (保留更多路径, 增加攻击多样性)
    # 策略:
    #   failed_objectives > 10: threshold=10% (激进裁剪, 快速命中高 ASR 路径)
    #   5 ≤ failed ≤ 10:        threshold=5%  (标准)
    #   failed < 5:             threshold=3%  (保守, 保留更多路径探索)
    _MIN_PATHS = 4

    # 从 ctx 获取失败目标数量 (如果可用)
    n_failed = 0
    try:
        n_failed = len(getattr(ctx, "_failed_objectives", []) or [])
    except Exception:
        pass

    if n_failed > 10:
        _PRUNE_ASR_THRESHOLD = 10.0
        logger.info("L5 v15: Dynamic prune threshold=10%% (failed=%d > 10)", n_failed)
    elif n_failed >= 5:
        _PRUNE_ASR_THRESHOLD = 5.0
        logger.debug("L5 v15: Dynamic prune threshold=5%% (failed=%d)", n_failed)
    else:
        _PRUNE_ASR_THRESHOLD = 3.0
        logger.info("L5 v15: Dynamic prune threshold=3%% (failed=%d < 5, conservative)", n_failed)

    if len(converters) <= _MIN_PATHS:
        # 路径数已很少, 不裁剪
        return converters

    # 读取 converter ASR 历史
    project_root = Path(__file__).resolve().parent.parent.parent
    asr_history_path = project_root / "data" / "seeds" / "asr_history.json"

    converter_asr: dict[str, float] = {}
    if asr_history_path.exists():
        try:
            data = json.loads(asr_history_path.read_text(encoding="utf-8"))
            converter_asr = data.get("converter_asr", {})
        except (json.JSONDecodeError, KeyError) as e:
            logger.warning("Failed to read converter ASR history: %s", e)

    if not converter_asr:
        # 无历史数据, 不裁剪
        return converters

    # 为每个 converter 查找历史 ASR
    converter_with_asr: list[tuple[float, int, Any]] = []
    pruned_count = 0

    for i, c in enumerate(converters):
        type_name = type(c).__name__
        # 对于 PersuasionConverter/ToneConverter, 查找带参数的 key
        sig = _converter_signature(c)
        asr = converter_asr.get(sig, converter_asr.get(type_name, -1.0))

        if asr >= 0 and asr < _PRUNE_ASR_THRESHOLD:
            pruned_count += 1
            logger.info(
                "Converter path pruned: %s (ASR=%.1f%% < %.1f%%)",
                sig, asr, _PRUNE_ASR_THRESHOLD,
            )
        else:
            # 保留: 有历史 ASR 的按 ASR 降序, 无历史的保持原序 (ASR=-1)
            converter_with_asr.append((asr, i, c))

    # 检查裁剪后是否仍保留最低限度路径
    if len(converter_with_asr) < _MIN_PATHS:
        # 裁剪太多, 恢复部分被裁剪的路径 (按 ASR 降序恢复)
        logger.info(
            "Pruning would leave %d paths < %d minimum, restoring some",
            len(converter_with_asr),
            _MIN_PATHS,
        )
        # 重新加入被裁剪的路径 (按 ASR 降序)
        pruned_with_asr: list[tuple[float, int, Any]] = []
        for i, c in enumerate(converters):
            sig = _converter_signature(c)
            asr = converter_asr.get(sig, converter_asr.get(type(c).__name__, -1.0))
            if asr >= 0 and asr < _PRUNE_ASR_THRESHOLD:
                pruned_with_asr.append((asr, i, c))

        pruned_with_asr.sort(key=lambda x: (-x[0], x[1]))
        restore_count = _MIN_PATHS - len(converter_with_asr)
        for item in pruned_with_asr[:restore_count]:
            converter_with_asr.append(item)
            pruned_count -= 1
            logger.info(
                "Restored converter path: %s (ASR=%.1f%%)",
                _converter_signature(item[2]),
                item[0],
            )

    # 排序: 有 ASR 的按 ASR 降序在前, 无 ASR 的 (ASR=-1) 按原序在后
    converter_with_asr.sort(key=lambda x: (-x[0] if x[0] >= 0 else 1, x[1]))

    result = [c for _, _, c in converter_with_asr]

    if pruned_count > 0:
        logger.info(
            "Converter path pruning: %d pruned, %d remaining (threshold=%.1f%%)",
            pruned_count,
            len(result),
            _PRUNE_ASR_THRESHOLD,
        )

    return result
