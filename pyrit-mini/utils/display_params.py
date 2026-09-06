"""display_params.py — 技术展示参数逻辑 (从 YAML 配置读取).

T0-10 拆分: 将 display.py 的三项参数展示职责下沉到独立模块.
    - _get_technique_category: 技术分类标签
    - _get_technique_params: 技术特定参数 (标签和值均从 YAML 读取)
    - _get_converter_summary: 技术对应 converter 描述 (从 YAML 读取)

架构: 展示层不再硬编码任何技术元数据, 所有配置集中在 config/defaults.yaml.
"""

from __future__ import annotations

import logging
from typing import Any

logger = logging.getLogger(__name__)


def _load_display_config() -> dict:
    """加载 display 相关配置节 (technique_param_labels, technique_converter_descriptions, technique_categories)."""
    try:
        from pathlib import Path
        import yaml
        config_path = Path(__file__).resolve().parent.parent / "config" / "defaults.yaml"
        if config_path.exists():
            with open(config_path, encoding="utf-8") as f:
                cfg = yaml.safe_load(f) or {}
        else:
            cfg = {}
    except Exception:
        cfg = {}
    return cfg


def _get_technique_category(tech: str) -> str:
    """技术分类标签 (从 YAML 读取).

    Args:
        tech: 技术名称

    Returns:
        分类标签: baseline / multi-turn / context-semantic / encoding / infrastructure / other
    """
    cfg = _load_display_config()
    categories = cfg.get("technique_categories", {})

    for cat_name, tech_list in categories.items():
        for pattern in tech_list:
            if tech == pattern or tech.startswith(pattern):
                return cat_name

    return "other"


def _get_technique_params(tech: str, ctx: Any = None) -> str:
    """从 ctx.args / defaults.yaml 读取技术特定参数, 展示关键配置.

    标签和技术键均从 config/defaults.yaml 的 technique_param_labels 节读取,
    避免在展示层硬编码任何映射关系.

    Args:
        tech: 技术名称
        ctx: PipelineContext (可选, 用于读取运行时覆盖)

    Returns:
        格式化的参数字符串, 如 "turns=10, backtrack=5"
    """
    cfg = _load_display_config()
    param_labels = cfg.get("technique_param_labels", {})

    def _resolve(key: str, default: float) -> float:
        """优先从 ctx.args 读取, 其次 yaml, 最后 fallback."""
        if ctx is not None:
            args = getattr(ctx, "args", None)
            if args is not None:
                val = getattr(args, key, None)
                if val is not None and isinstance(val, (int, float)):
                    return float(val)
        return float(cfg.get(key, default))

    def _fmt(key: str, default: float) -> str | None:
        """获取参数标签+值, 如果标签未配置则返回 None."""
        label = param_labels.get(key)
        if label is None:
            return None
        return f"{label}={int(_resolve(key, default))}"

    # 技术参数映射: 技术名 → [(yaml_key, default), ...]
    tech_param_map: dict[str, list[tuple[str, float]]] = {
        "crescendo": [("crescendo_max_turns", 10), ("crescendo_max_backtracks", 5)],
        "tap": [("tap_tree_width", 4), ("tap_tree_depth", 4)],
        "pair": [("pair_tree_width", 1), ("pair_tree_depth", 4)],
        "red_teaming": [("red_teaming_max_turns", 3)],
        "best_of_n": [("best_of_n_retries", 5)],
        "many_shot": [("many_shot_example_count", 100)],
        "many_shot_cot": [("many_shot_example_count", 100)],
        "chunked_request": [("chunked_request_chunk_size", 50)],
        "gcg": [("gcg_suffix_len", 20), ("gcg_max_iterations", 500)],
        "cair": [("cair_max_iterations", 10)],
        "cot_hijack": [("cot_hijack_max_turns", 5)],
    }

    # 特殊参数 (固定值, 不在 YAML 中)
    static_params: dict[str, list[str]] = {
        "skeleton_key": ["prefix=system_prompt"],
        "skeleton_key_native": ["prefix=system_prompt"],
        "encoded_injection": ["encoding=base64+unicode"],
        "embedding_inversion": ["recovery=cosine_sim"],
        "mcp_rag": ["phase2=active", "vector=indirect_injection"],
        "rogue_agent": ["protocol=A2A"],
        "multi_model_pair": ["strategy=cross_model"],
    }

    params: list[str] = []

    # 处理带前缀匹配的技术
    for prefix, key_defaults in tech_param_map.items():
        if tech.startswith(prefix):
            for key, default in key_defaults:
                val = _fmt(key, default)
                if val is not None:
                    params.append(val)
            break

    # 处理固定值参数
    if tech in static_params:
        params.extend(static_params[tech])

    return ", ".join(params) if params else ""


def _get_converter_summary(tech: str, ctx: Any) -> str:
    """获取技术对应的 converter 摘要 (从 YAML 读取).

    Args:
        tech: 技术名称
        ctx: PipelineContext (用于读取 converter_map)

    Returns:
        converter 描述字符串
    """
    # 优先从 ctx.converter_map 读取
    if ctx.converter_map and tech in ctx.converter_map:
        converters = ctx.converter_map[tech]
        if converters:
            from utils.display_stages import _get_converter_chain_names
            return _get_converter_chain_names(converters, max_display=5)
        return "none (raw payload)"

    # 从 YAML 读取静态描述
    cfg = _load_display_config()
    converter_descs = cfg.get("technique_converter_descriptions", {})
    native_desc = converter_descs.get(tech)
    if native_desc:
        return native_desc

    return "none (raw payload)"
