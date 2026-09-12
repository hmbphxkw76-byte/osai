"""CLI Parameter parsing + Environment initialization + Output directory

This module owns the environment / output-directory concerns. The CLI argument
parsing (`parse_args` / `_warn_ineffective_args`) was split out (SRP) into
`core/_arg_parser.py` and is re-exported here so `core.config` keeps its original
public surface.
"""

from __future__ import annotations

import argparse
import logging
import os
from datetime import datetime
from pathlib import Path
from typing import Any

# CLI parsing (split out) + the parsed-defaults helpers re-exported for the public API.
from core._arg_parser import (
    _warn_ineffective_args,
    parse_args,
)
from core._config_parsers import (
    _apply_config_file,
    _apply_defaults,
    _flatten_nested_defaults,
    _load_config_file,
    _load_defaults,
    _parse_components,
    _parse_converter_global,
    _parse_converter_overrides,
    _parse_escalation_levels,
    _parse_initializer_specs,
    _parse_memory_labels,
    _parse_seed_filters,
)

logger = logging.getLogger(__name__)
_PROJECT_ROOT = Path(__file__).resolve().parent.parent
_DEFAULTS_YAML = _PROJECT_ROOT / "config" / "defaults.yaml"


def get_output_dir(args: argparse.Namespace) -> Path:
    """Output directory."""
    if args.output_dir is not None:
        return Path(args.output_dir)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    return _PROJECT_ROOT / "outputs" / f"strike_{timestamp}"


def ensure_output_dir(output_dir: Path) -> Path:
    """Output directory (evidence/, db/, poc/)."""
    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    (output_dir / "evidence").mkdir(parents=True, exist_ok=True)
    (output_dir / "db").mkdir(parents=True, exist_ok=True)
    return output_dir


async def setup_environment(output_dir: Path) -> None:
    """PyRIT - SQLite WAL + .

    Production-grade:  endpoint ,  Singleton cache +
     DB , Ensureconverter(s) endpoint  SQLite DB

     (PyRIT 1.0.1 Singleton ):
        SQLiteMemory  metaclass=Singleton,  SQLiteMemory(db_path=...)
        , Singleton.__call__ , __init__ , db_path
        CentralMemory._memory_instance ,

         dispose_engine()  SQLAlchemy  -
        Singleton._instances ,  db_path

    :
        1.  MemoryInterface  SQLAlchemy engine (dispose_engine)
        2. imports Singleton._instances  SQLiteMemory cache
        3.  CentralMemory._memory_instance

    Academic basis: PyRIT (arXiv:2407.01232) - dispose_db_engine()
    """
    try:
        from dotenv import load_dotenv

        load_dotenv()
    except ImportError:
        pass

    from pyrit.setup.initialization import initialize_pyrit_async

    db_path = Path(output_dir) / "db" / "pyrit.db"
    db_path.parent.mkdir(parents=True, exist_ok=True)

    os.environ["PYRIT_DB_URL"] = f"sqlite:///{db_path}"
    os.environ.setdefault("PYRIT_SQLITE_JOURNAL_MODE", "WAL")
    os.environ.setdefault("PYRIT_SQLITE_BUSY_TIMEOUT", "5000")

    # == : Ensure endpoint DB ==
    # , SQLiteMemory Singleton , db_path ,
    # endpoint DB (Layer db/pyrit.db)
    try:
        from pyrit.common.singleton import Singleton
        from pyrit.memory import CentralMemory
        from pyrit.memory.sqlite_memory import SQLiteMemory

        # Step 1: MemoryInterface SQLAlchemy engine
        _old_memory = CentralMemory._memory_instance
        if _old_memory is not None:
            try:
                _old_memory.dispose_engine()
                logger.debug("Disposed previous SQLAlchemy engine")
            except Exception as e:
                logger.debug("Engine dispose skipped (non-fatal): %s", e)

        # Step 2: SQLiteMemory Singleton
        # - SQLiteMemory(db_path=...) __init__
        if SQLiteMemory in Singleton._instances:
            del Singleton._instances[SQLiteMemory]
            logger.debug("Cleared SQLiteMemory Singleton cache")

        # Step 3: CentralMemory
        # initialize_pyrit_async set_memory_instance
        CentralMemory._memory_instance = None
        logger.debug("Cleared CentralMemory singleton reference")
    except ImportError as e:
        logger.debug("Singleton cache clear skipped (import): %s", e)
    except Exception as e:
        logger.debug("Singleton cache clear skipped (non-fatal): %s", e)

    await initialize_pyrit_async(
        memory_db_type="SQLite",
        silent=True,
        db_path=str(db_path),
    )
    logger.info("PyRIT environment initialized (DB: %s)", db_path)
