"""arm/a2a — object-axis converter façade for `a2a`.

Re-exports the generic converter API from arm.converter_presets so that
`arm.a2a` is a valid, object-keyed entry point for `--converters a2a`.
"""
from arm.converter_presets import (  # noqa: F401
    _classify_target_type,
    _is_file_converter,
    build_converter_map,
    l5_optimal,
    l5_optimal_for_model,
)

OBJECT = "a2a"
