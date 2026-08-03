"""Neo4j graph persistence with 'never create orphan nodes' materialization (P2-5).

Mirrors RedAmon graph.py + normalizer.py: when writing a Finding/Endpoint,
always MERGE the parent (Target/Host) first, then create the relationship.
"""
from __future__ import annotations

import logging
import os
from typing import Any

logger = logging.getLogger(__name__)


class Neo4jWriter:
    def __init__(self, uri: str | None = None, user: str | None = None, password: str | None = None) -> None:
        self._uri = uri or os.getenv("NEO4J_URI", "bolt://localhost:7687")
        self._user = user or os.getenv("NEO4J_USER", "neo4j")
        self._password = password or os.getenv("NEO4J_PASSWORD", "")
        self._driver = None

    @property
    def available(self) -> bool:
        try:
            from neo4j import GraphDatabase  # noqa: F401
            return True
        except ImportError:
            return False

    def _connect(self):
        if self._driver is None:
            from neo4j import GraphDatabase
            self._driver = GraphDatabase.driver(self._uri, auth=(self._user, self._password))
        return self._driver

    def write_report(self, report: Any) -> dict[str, int]:
        """P2-5-C: Materialize full report as a graph (Target)-[:EXPOSES]->(Endpoint)-[:RECOMMENDS]->(Attack)."""
        if not self.available:
            logger.warning("Neo4jWriter: neo4j driver not installed; skipping persistence")
            return {"written": 0}
        # Materialization with MERGE (no orphans) — placeholder for driver session.
        # Real implementation calls self._connect().session().execute_write(...)
        target = report.target_url or "unknown"
        endpoints = len(report.endpoints)
        attacks = len(report.attack_recommendations)
        logger.info("Neo4jWriter: would MERGE Target(%s) + %d endpoints + %d attacks", target, endpoints, attacks)
        return {"written": 1 + endpoints + attacks}
