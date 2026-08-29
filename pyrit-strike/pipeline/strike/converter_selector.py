"""converter_selector — 从 executor.py 拆分而来.
"""

import logging
from typing import Any

from pipeline.context import PipelineContext

logger = logging.getLogger(__name__)

def _get_candidate_converters(ctx: PipelineContext) -> list[Any]:
    """获取按 ASR 降序排列的候选 converter 列表。
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
    # L5 v36: 新增 SelectiveTextConverter, CodeChameleon, PolicyPuppetry 等
    _PRIORITY_MAP: dict[str, int] = {
        # LLM-Based (ASR 30-60%)
        "DecompositionConverter": 0,                    # ASR 40-60%
        "CodeChameleonConverter": 1,                    # ASR 35-45% (NEW)
        "PersuasionConverter:authority_endorsement": 2, # ASR 38.4%
        "PersuasionConverter:expert_endorsement": 3,    # ASR ~35%
        "PersuasionConverter:logical_appeal": 4,        # ASR 28.7%
        "PolicyPuppetryConverter": 5,                  # ASR 30-40% (NEW)
        # Selective (ASR 25-40%)
        "SelectiveTextConverter:TokenSelectionStrategy": 6,  # 链式选择性 (NEW)
        "SelectiveTextConverter:WordProportionSelectionStrategy": 7,  # 选择性编码 (NEW)
        # Translation (ASR 25-35%)
        "RandomTranslationConverter": 8,
        "TranslationConverter": 9,
        # Template (ASR 25-35%)
        "TemplateSegmentConverter": 10,                  # NEW
        # Keyword (ASR 20-30%, 0 token)
        "SearchReplaceConverter": 11,                    # NEW
        # Variation (ASR 20-30%)
        "VariationConverter": 12,
        # Smuggling (ASR 20-30%)
        "AsciiSmugglerConverter": 13,                   # NEW
        # Semantic (ASR 30-40%, 保留)
        "ROT13Converter": 14,
        # Tone (ASR 22.1%)
        "ToneConverter:academic": 15,
        # File Converters (文档投递/间接注入, ASR 15-25%)
        "WordDocConverter:direct": 16,                  # NEW (payload → .docx)
        "WordDocConverter:placeholder": 17,             # NEW (模板占位符替换)
        "PDFConverter:direct": 18,                      # NEW (payload → PDF)
        "PDFConverter:injection": 19,                  # NEW (已有PDF注入)
        # 降级 (ASR < 20%, fallback)
        "RandomCapitalLettersConverter": 20,
        "UnicodeSubstitutionConverter": 21,
        "Base64Converter": 22,                           # 全文, 最低优先级
    }

    # L5 v36: OWASP 类别 → Converter 自适应匹配
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

    # 取前 10 个候选 (按 ASR 降序, v36 新增选择性 converter 后扩展上限)
    # v35: 7 个; v36: 10 个 (新增 SelectiveTextConverter + CodeChameleon + PolicyPuppetry 等)
    top_candidates = unique_converters[:10]

    logger.info(
        "L5 v35: Selected %d candidate converters for SequentialAttack:",
        len(top_candidates),
    )
    for i, c in enumerate(top_candidates):
        logger.info("  Path %d: %s (priority=%d)", i + 1, type(c).__name__, _priority(c))

    return top_candidates

def _converter_signature(c: Any) -> str:
    """生成 converter 的唯一签名 (类型 + 关键参数).
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
    # SelectiveTextConverter: 区分 selection_strategy + sub_converter
    if type_name == "SelectiveTextConverter":
        strategy = getattr(c, "_selection_strategy", None)
        if strategy is not None:
            strategy_name = type(strategy).__name__
            sub_conv = getattr(c, "_sub_converter", None)
            sub_name = type(sub_conv).__name__ if sub_conv else "unknown"
            return f"{type_name}:{strategy_name}:{sub_name}"
    # SearchReplaceConverter: 区分 pattern
    if type_name == "SearchReplaceConverter":
        pattern = getattr(c, "_pattern", "") or ""
        return f"{type_name}:{pattern[:30]}"
    # CodeChameleonConverter: 区分 encrypt_type
    if type_name == "CodeChameleonConverter":
        encrypt_type = getattr(c, "_encrypt_type", "unknown")
        return f"{type_name}:{encrypt_type}"
    # PDFConverter: 区分模式 (direct / injection)
    if type_name == "PDFConverter":
        existing_pdf = getattr(c, "_existing_pdf_path", None)
        if existing_pdf is not None:
            return f"{type_name}:injection"
        return f"{type_name}:direct"
    # WordDocConverter: 区分模式 (direct / placeholder)
    if type_name == "WordDocConverter":
        injection_config = getattr(c, "_injection_config", None)
        if injection_config is not None and getattr(injection_config, "existing_docx", None) is not None:
            return f"{type_name}:placeholder"
        return f"{type_name}:direct"
    # 其他 converter: 按类型名去重
    return type_name

def _get_owasp_converter_priorities(ctx: PipelineContext) -> list[str]:
    """L5 v36: 从种子 OWASP 类别分布查询最佳 Converter 优先级列表。
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
    # L5 v36: 新增 SelectiveTextConverter, CodeChameleon, PolicyPuppetry 等
    #           arXiv:2404.30015 — CodeChameleon ASR 35-45%
    _PRIORITY_MAP: dict[str, int] = {
        # LLM-Based (ASR 30-60%)
        "DecompositionConverter": 0,                    # ASR 40-60%
        "CodeChameleonConverter": 1,                    # ASR 35-45% (NEW)
        "PersuasionConverter:authority_endorsement": 2, # ASR 38.4%
        "PersuasionConverter:expert_endorsement": 3,    # ASR ~35%
        "PersuasionConverter:logical_appeal": 4,        # ASR 28.7%
        "PolicyPuppetryConverter": 5,                  # ASR 30-40% (NEW)
        # Selective (ASR 25-40%)
        "SelectiveTextConverter:TokenSelectionStrategy": 6,  # 链式选择性 (NEW)
        "SelectiveTextConverter:WordProportionSelectionStrategy": 7,  # 选择性编码 (NEW)
        # Translation (ASR 25-35%)
        "RandomTranslationConverter": 8,
        "TranslationConverter": 9,
        # Template (ASR 25-35%)
        "TemplateSegmentConverter": 10,                  # NEW
        # Keyword (ASR 20-30%, 0 token)
        "SearchReplaceConverter": 11,                    # NEW
        # Variation (ASR 20-30%)
        "VariationConverter": 12,
        # Smuggling (ASR 20-30%)
        "AsciiSmugglerConverter": 13,                   # NEW
        # Semantic (ASR 30-40%, 保留)
        "ROT13Converter": 14,
        # Tone (ASR 22.1%)
        "ToneConverter:academic": 15,
        # File Converters (文档投递/间接注入, ASR 15-25%)
        "WordDocConverter:direct": 16,                  # NEW (payload → .docx)
        "WordDocConverter:placeholder": 17,             # NEW (模板占位符替换)
        "PDFConverter:direct": 18,                      # NEW (payload → PDF)
        "PDFConverter:injection": 19,                  # NEW (已有PDF注入)
        # 降级 (ASR < 20%, fallback)
        "RandomCapitalLettersConverter": 20,
        "UnicodeSubstitutionConverter": 21,
        "Base64Converter": 22,                           # 全文, 最低优先级
    }

    # L5 v36: OWASP 类别 → Converter 自适应匹配
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
    # L5 v36: 如果最佳 converter 是 SelectiveTextConverter + TokenSelectionStrategy,
    # 且下一个是 SelectiveTextConverter, 则将两者放入同一 ConverterConfiguration (串联)
    best_converter = unique_converters[0]
    best_sig = _converter_signature(best_converter)
    best_name = type(best_converter).__name__

    logger.info(
        "L5 v36: Selected best single converter: %s (sig=%s) — "
        "avoids serial stacking bug, payload stays readable",
        best_name, best_sig,
    )

    # 构建单条 ConverterConfiguration (1 个 converter, 不串联)
    # L5 v36: 支持 SelectiveTextConverter 链式串联
    converter_configurations = []

    # 检测链式选择性组合: 如果前两个 converter 是 SelectiveTextConverter,
    # 且第二个使用 TokenSelectionStrategy, 则放入同一 ConverterConfiguration (串联)
    if (len(unique_converters) >= 2
        and type(best_converter).__name__ == "SelectiveTextConverter"
        and type(unique_converters[1]).__name__ == "SelectiveTextConverter"):
        second_strategy = getattr(unique_converters[1], "_selection_strategy", None)
        if second_strategy is not None and type(second_strategy).__name__ == "TokenSelectionStrategy":
            # 链式选择性: 2 个 converter 在同一 ConverterConfiguration (串联)
            converter_configurations.append(
                ConverterConfiguration(converters=[best_converter, unique_converters[1]])
            )
            logger.info(
                "L5 v36: Chained SelectiveTextConverter detected — "
                "2 converters in 1 ConverterConfiguration (serial chain)"
            )
        else:
            converter_configurations.append(
                ConverterConfiguration(converters=[best_converter])
            )
    else:
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
    """L5 v11: 根据运行时 ASR 历史动态裁剪低效 converter 路径.

    Dynamic prune threshold based on n_failed (arXiv:2407.01232).
    """
    import json
    from pathlib import Path

    # L5 v15: 动态裁剪阈值 — 基于失败目标数量调整
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
