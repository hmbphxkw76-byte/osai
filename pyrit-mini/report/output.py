"""output ?ュ.

?config.py ? ュ.
"""

from __future__ import annotations

from pathlib import Path


def ensure_output_dir(output_dir: Path | str) -> Path:
    """.

    ?
        - evidence/ ? (evidence.json, EVD-*.json)
        - db/ ?SQLite ?

    Args:
        output_dir: .

    Returns:
        ?
    """
    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    (output_dir / "evidence").mkdir(parents=True, exist_ok=True)
    (output_dir / "db").mkdir(parents=True, exist_ok=True)
    return output_dir

