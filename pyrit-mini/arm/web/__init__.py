"""arm/web — object-axis converter façade for `web`.

Re-exports the generic converter API from arm.converter_presets so that
`arm.web` is a valid, object-keyed entry point for `--converters web`.
"""
from arm.converter_presets import (  # noqa: F401
    _classify_target_type,
    _is_file_converter,
    build_converter_map,
    l5_optimal,
    l5_optimal_for_model,
)

OBJECT = "web"
