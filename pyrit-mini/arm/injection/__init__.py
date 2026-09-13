"""arm/injection — object-axis converter façade for `injection`.

Re-exports the generic converter API from arm.converter_presets so that
`arm.injection` is a valid, object-keyed entry point for `--converters injection`.
"""
from arm.converter_presets import (  # noqa: F401
    _classify_target_type,
    _is_file_converter,
    build_converter_map,
    l5_optimal,
    l5_optimal_for_model,
)
from arm.injection.preset import TARGET_TYPE, build_converters, candidate_converters  # noqa: F401

OBJECT = "injection"
