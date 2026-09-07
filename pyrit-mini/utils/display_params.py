"""display_params.py —  (imports YAML ).

T0-10 :  display.py .
    - _get_technique_category: 
    - _get_technique_params:  (imports YAML )
    - _get_converter_summary:  converter  (imports YAML )

: Layer, all config/defaults.yaml.
"""

from __future__ import annotations

import logging
from typing import Any

logger = logging.getLogger(__name__)


def _load_display_config() -> dict:
    """Load display  (technique_param_labels, technique_converter_descriptions, technique_categories)."""
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
    """ (imports YAML ).

    Args:
        tech: 

    Returns:
        : baseline / multi-turn / context-semantic / encoding / infrastructure / other
    """
    cfg = _load_display_config()
    categories = cfg.get("technique_categories", {})

    for cat_name, tech_list in categories.items():
        for pattern in tech_list:
            if tech == pattern or tech.startswith(pattern):
                return cat_name

    return "other"


def _get_technique_params(tech: str, ctx: Any = None) -> str:
    """imports ctx.args / defaults.yaml , .

    imports config/defaults.yaml  technique_param_labels ,
    Layer.

    Args:
        tech: 
        ctx: PipelineContext (, )

    Returns:
        ,  "turns=10, backtrack=5"
    """
    cfg = _load_display_config()
    param_labels = cfg.get("technique_param_labels", {})

    def _resolve(key: str, default: float) -> float:
        """imports ctx.args ,  yaml,  fallback."""
        if ctx is not None:
            args = getattr(ctx, "args", None)
            if args is not None:
                val = getattr(args, key, None)
                if val is not None and isinstance(val, (int, float)):
                    return float(val)
        return float(cfg.get(key, default))

    def _fmt(key: str, default: float) -> str | None:
        """+,  None."""
        label = param_labels.get(key)
        if label is None:
            return None
        return f"{label}={int(_resolve(key, default))}"

    # :  → [(yaml_key, default), ...]
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

    #  (,  YAML )
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

    # 
    for prefix, key_defaults in tech_param_map.items():
        if tech.startswith(prefix):
            for key, default in key_defaults:
                val = _fmt(key, default)
                if val is not None:
                    params.append(val)
            break

    # 
    if tech in static_params:
        params.extend(static_params[tech])

    return ", ".join(params) if params else ""


def _get_converter_summary(tech: str, ctx: Any) -> str:
    """ converter  (imports YAML ).

    Args:
        tech: 
        ctx: PipelineContext ( converter_map)

    Returns:
        converter 
    """
    #  ctx.converter_map 
    if ctx.converter_map and tech in ctx.converter_map:
        converters = ctx.converter_map[tech]
        if converters:
            from utils.display_primitives import _get_converter_chain_names
            return _get_converter_chain_names(converters, max_display=5)
        return "none (raw payload)"

    #  YAML 
    cfg = _load_display_config()
    converter_descs = cfg.get("technique_converter_descriptions", {})
    native_desc = converter_descs.get(tech)
    if native_desc:
        return native_desc

    return "none (raw payload)"
