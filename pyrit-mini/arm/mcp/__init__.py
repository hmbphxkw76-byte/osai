"""arm/mcp — object-axis converter façade for `mcp`.

Re-exports the generic converter API from arm.converter_presets so that
`arm.mcp` is a valid, object-keyed entry point for `--converters mcp`.
"""
from arm.converter_presets import (  # noqa: F401
    _classify_target_type,
    _is_file_converter,
    build_converter_map,
    l5_optimal,
    l5_optimal_for_model,
)

OBJECT = "mcp"
