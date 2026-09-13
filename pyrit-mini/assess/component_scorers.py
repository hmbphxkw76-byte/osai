"""assess/component_scorers — component T0 heuristics registry (object-axis refactor).

The per-object T0 scorers now live in `assess/<object>/t0.py` (e.g. `assess/mcp/t0.py`).
This module is kept at its original path and re-exports the scorers so that:

  * all existing `from assess.component_scorers import t0_*_check` imports keep working
  * `tools/architecture_validator.py`'s hardcoded
    `assess.component_scorers.t0_{component_type}_check` checks keep passing
  * the `_COMPONENT_RUBRIC_DIR` resolution (relative to THIS file) is unchanged

This is the backward-compatible façade; logic is owned by the object subpackages.
"""

from __future__ import annotations

import logging
from pathlib import Path

from assess.a2a.t0 import t0_a2a_agent_integrity_check
from assess.agent.t0 import t0_agent_check
from assess.mcp.t0 import t0_mcp_tool_poisoning_check
from assess.model.t0 import t0_model_behavior_shift_check
from assess.multimodal_upload.t0 import t0_multimodal_upload_check
from assess.rag.t0 import t0_rag_pipeline_check
from assess.session.t0 import t0_session_memory_check
from assess.web.t0 import t0_web_api_check

logger = logging.getLogger(__name__)

# Component T0 checkers registry (component_type -> function)
_COMPONENT_T0_FUNCTIONS = [
    ("mcp_tool_poisoning", t0_mcp_tool_poisoning_check),
    ("a2a_agent_integrity", t0_a2a_agent_integrity_check),
    ("model_behavior_shift", t0_model_behavior_shift_check),
    ("rag_pipeline", t0_rag_pipeline_check),
    ("session_memory", t0_session_memory_check),
    ("web_api", t0_web_api_check),
    ("multimodal_upload", t0_multimodal_upload_check),
    ("agent", t0_agent_check),
]


def get_t0_checker(component_type: str):
    """Get the T0 checker function for a component type.

    Args:
        component_type: Component type name (e.g., "mcp_tool_poisoning")

    Returns:
        Callable or None if not found
    """
    for ct, func in _COMPONENT_T0_FUNCTIONS:
        if ct == component_type:
            return func
    return None


# Component rubric directory (relative to this file -> repo/data/scorers/component_scorers)
_COMPONENT_RUBRIC_DIR = Path(__file__).resolve().parent.parent / "data" / "scorers" / "component_scorers"


def get_component_rubric_path(component_type: str, rubric_dir: Path | None = None) -> Path | None:
    """Get the rubric file path for a component type.

    Args:
        component_type: Component type name
        rubric_dir: Optional override directory (defaults to _COMPONENT_RUBRIC_DIR)

    Returns:
        Path to rubric file if exists, None otherwise
    """
    rubric_dir = rubric_dir or _COMPONENT_RUBRIC_DIR
    # 兼容双命名约定：新版 façade 约定 `{component_type}_rubric.yaml`，但历史 rubric
    # 文件仍命名 `{component_type}.yaml`（且组件 YAML 的 `rubric:` 字段也用后者）。
    # 这里优先新约定、回退旧约定，避免分类因命名不一致而全盘返回 None。
    for name in (f"{component_type}_rubric.yaml", f"{component_type}.yaml"):
        rubric_path = rubric_dir / name
        if rubric_path.exists():
            return rubric_path
    return None


def is_component_rubric_available(component_type: str) -> bool:
    """Check if a component has a rubric file available."""
    return get_component_rubric_path(component_type) is not None


def get_all_component_types() -> list[str]:
    """Get all supported component types."""
    return [ct for ct, _ in _COMPONENT_T0_FUNCTIONS]
