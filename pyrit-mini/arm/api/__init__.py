"""arm/api — object-axis converter façade for `api`.

Re-exports the generic converter API from arm.converter_presets so that
`arm.api` is a valid, object-keyed entry point for `--converters api`.
"""
from arm.converter_presets import (  # noqa: F401
    _classify_target_type,
    _is_file_converter,
    build_converter_map,
    l5_optimal,
    l5_optimal_for_model,
)

OBJECT = "api"
