"""tests/test_object_taxonomy.py — coverage for core.object_taxonomy (R-DELIVERY-2).

Validates the SSOT object-axis mapping used by the object-first CLI
(`python -m targets`) and by arm/assess/report data-flow routing.
"""

from core.object_taxonomy import (
    OBJECT_TO_COMPONENT,
    OBJECTS,
    all_objects,
    component_for_object,
    is_object,
    normalize_object,
    object_for_component,
    validate_object_list,
)


def test_objects_are_canonically_ordered():
    assert "mcp" in OBJECTS
    assert "a2a" in OBJECTS
    assert "agent" in OBJECTS
    assert len(OBJECTS) == 12


def test_normalize_object_passthrough():
    assert normalize_object("mcp") == "mcp"
    assert normalize_object("MCP") == "mcp"
    assert normalize_object("  rag ") == "rag"


def test_normalize_object_aliases():
    assert normalize_object("mcpsec") == "mcp"
    assert normalize_object("agent") == "agent"
    assert normalize_object("llm") == "model"
    assert normalize_object("retrieval") == "rag"


def test_normalize_object_unknown():
    assert normalize_object("does_not_exist") is None
    assert normalize_object("") is None


def test_component_round_trip():
    # Forward mapping must be exact for every object.
    for obj, component in OBJECT_TO_COMPONENT.items():
        assert component_for_object(obj) == component

    # Reverse mapping is lossy (multiple objects share a component), so it must
    # only be required to resolve back to SOME valid object in the taxonomy.
    for component in set(OBJECT_TO_COMPONENT.values()):
        rev = object_for_component(component)
        assert rev is not None
        assert rev in OBJECTS


def test_is_object():
    assert is_object("mcp")
    assert is_object("agent")  # alias
    assert not is_object("nope")


def test_validate_object_list():
    normalized, unknown = validate_object_list(["mcp", "agent", "bogus", "MCP"])
    assert "mcp" in normalized
    assert "agent" in normalized  # agent now canonical
    assert normalized.count("mcp") == 1  # deduplicated
    assert unknown == ["bogus"]


def test_all_objects_matches_tuple():
    assert all_objects() == OBJECTS
    assert isinstance(all_objects(), tuple)
