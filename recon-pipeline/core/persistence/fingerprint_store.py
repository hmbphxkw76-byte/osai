# Copyright (c) 2026 OSAI Project.
# Licensed under the MIT license.

"""Fingerprint Store — SQLite-backed persistent fingerprint storage.

Enables cross-scan fingerprint comparison, change history tracking,
and baseline management for agent tool output deduplication.

Non-LLM guarantee: pure SQLite + SHA256, zero ML dependencies.

Academic basis:
  - Supply-chain integrity: cryptographic pinning of tool behavior
  - OWASP LLM06: tool behavior changes signal compromise
"""

from __future__ import annotations

import json
import sqlite3
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


@dataclass
class FingerprintRecord:
    """A single fingerprint observation in the store."""

    key: str = ""
    fingerprint: str = ""
    body_hash: str = ""
    status_code: int | None = None
    scan_label: str = ""
    observed_at: float = 0.0

    def to_dict(self) -> dict[str, Any]:
        return {
            "key": self.key,
            "fingerprint": self.fingerprint,
            "body_hash": self.body_hash,
            "status_code": self.status_code,
            "scan_label": self.scan_label,
            "observed_at": self.observed_at,
        }


class FingerprintStore:
    """SQLite-backed persistent fingerprint database.

    Stores fingerprints across scans for:
      - Change detection (has a tool response changed since last scan?)
      - Dedup across sessions (seen this exact response before?)
      - Baseline management (what's the "known good" fingerprint?)

    Usage::
        store = FingerprintStore("outputs/fingerprints.db")
        store.record("endpoint-a", "abc123", scan_label="scan-01")
        changed = store.has_changed("endpoint-a", "def456")
        history = store.get_history("endpoint-a")
    """

    def __init__(self, db_path: str | Path = "outputs/fingerprints.db") -> None:
        self._db_path = Path(db_path)
        self._db_path.parent.mkdir(parents=True, exist_ok=True)
        self._init_db()

    def _init_db(self) -> None:
        """Create tables if they don't exist."""
        with sqlite3.connect(str(self._db_path)) as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS fingerprints (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    key TEXT NOT NULL,
                    fingerprint TEXT NOT NULL,
                    body_hash TEXT NOT NULL DEFAULT '',
                    status_code INTEGER,
                    scan_label TEXT NOT NULL DEFAULT '',
                    observed_at REAL NOT NULL,
                    UNIQUE(key, fingerprint, scan_label)
                )
            """)
            conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_fp_key ON fingerprints(key);
            """)
            conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_fp_scan ON fingerprints(scan_label);
            """)
            conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_fp_observed ON fingerprints(observed_at);
            """)
            conn.commit()

    def record(
        self,
        key: str,
        fingerprint: str,
        *,
        body_hash: str = "",
        status_code: int | None = None,
        scan_label: str = "",
    ) -> None:
        """Store a fingerprint observation.

        Args:
            key: Unique endpoint/tool identifier.
            fingerprint: SHA256 fingerprint hex string.
            body_hash: Optional body content hash.
            status_code: HTTP status code.
            scan_label: Label for this scan session.
        """
        now = time.time()
        with sqlite3.connect(str(self._db_path)) as conn:
            conn.execute(
                """INSERT OR IGNORE INTO fingerprints
                   (key, fingerprint, body_hash, status_code, scan_label, observed_at)
                   VALUES (?, ?, ?, ?, ?, ?)""",
                (key, fingerprint, body_hash, status_code, scan_label, now),
            )
            conn.commit()

    def record_batch(
        self,
        items: list[dict[str, Any]],
        scan_label: str = "",
    ) -> int:
        """Store multiple fingerprints at once.

        Args:
            items: List of {key, fingerprint, body_hash?, status_code?} dicts.
            scan_label: Label for this batch.

        Returns:
            Number of records inserted.
        """
        count = 0
        with sqlite3.connect(str(self._db_path)) as conn:
            for item in items:
                conn.execute(
                    """INSERT OR IGNORE INTO fingerprints
                       (key, fingerprint, body_hash, status_code, scan_label, observed_at)
                       VALUES (?, ?, ?, ?, ?, ?)""",
                    (
                        item["key"],
                        item["fingerprint"],
                        item.get("body_hash", ""),
                        item.get("status_code"),
                        scan_label,
                        time.time(),
                    ),
                )
                count += 1
            conn.commit()
        return count

    def get_latest(self, key: str) -> FingerprintRecord | None:
        """Get the most recent fingerprint for a key."""
        with sqlite3.connect(str(self._db_path)) as conn:
            row = conn.execute(
                """SELECT key, fingerprint, body_hash, status_code, scan_label, observed_at
                   FROM fingerprints WHERE key = ?
                   ORDER BY observed_at DESC LIMIT 1""",
                (key,),
            ).fetchone()

        if row:
            return FingerprintRecord(
                key=row[0],
                fingerprint=row[1],
                body_hash=row[2],
                status_code=row[3],
                scan_label=row[4],
                observed_at=row[5],
            )
        return None

    def has_changed(self, key: str, current_fp: str) -> bool:
        """Check if fingerprint changed from the most recent observation.

        Args:
            key: Endpoint/tool identifier.
            current_fp: Current fingerprint to compare.

        Returns:
            True if the latest stored fingerprint differs from current_fp.
        """
        latest = self.get_latest(key)
        if latest is None:
            return False  # No baseline yet
        return latest.fingerprint != current_fp

    def get_history(
        self,
        key: str,
        limit: int = 100,
    ) -> list[FingerprintRecord]:
        """Get fingerprint history for a key, most recent first."""
        with sqlite3.connect(str(self._db_path)) as conn:
            rows = conn.execute(
                """SELECT key, fingerprint, body_hash, status_code, scan_label, observed_at
                   FROM fingerprints WHERE key = ?
                   ORDER BY observed_at DESC LIMIT ?""",
                (key, limit),
            ).fetchall()

        return [
            FingerprintRecord(
                key=r[0], fingerprint=r[1], body_hash=r[2],
                status_code=r[3], scan_label=r[4], observed_at=r[5],
            )
            for r in rows
        ]

    def get_all_keys(self) -> list[str]:
        """Get all unique keys in the store."""
        with sqlite3.connect(str(self._db_path)) as conn:
            rows = conn.execute(
                "SELECT DISTINCT key FROM fingerprints ORDER BY key"
            ).fetchall()
        return [r[0] for r in rows]

    def get_scan_labels(self) -> list[str]:
        """Get all unique scan labels."""
        with sqlite3.connect(str(self._db_path)) as conn:
            rows = conn.execute(
                "SELECT DISTINCT scan_label FROM fingerprints WHERE scan_label != '' ORDER BY scan_label"
            ).fetchall()
        return [r[0] for r in rows]

    def get_changed_since(
        self,
        scan_label: str,
    ) -> list[dict[str, Any]]:
        """Find all keys whose fingerprint changed since a given scan.

        Compares the last fingerprint before the given scan label
        with the latest fingerprint overall.

        Args:
            scan_label: Reference scan label.

        Returns:
            List of {key, old_fp, new_fp, old_scan, new_scan} changes.
        """
        changes: list[dict[str, Any]] = []
        keys = self.get_all_keys()

        for key in keys:
            history = self.get_history(key)
            if len(history) < 2:
                continue

            # Find the latest fingerprint at or before this scan
            old_record = None
            new_record = history[0]  # Most recent overall

            for r in history:
                if r.scan_label <= scan_label:
                    old_record = r
                    break

            if old_record and old_record.fingerprint != new_record.fingerprint:
                changes.append({
                    "key": key,
                    "old_fingerprint": old_record.fingerprint,
                    "new_fingerprint": new_record.fingerprint,
                    "old_scan": old_record.scan_label,
                    "new_scan": new_record.scan_label,
                })

        return changes

    def count(self) -> int:
        """Total number of records in the store."""
        with sqlite3.connect(str(self._db_path)) as conn:
            row = conn.execute("SELECT COUNT(*) FROM fingerprints").fetchone()
        return row[0] if row else 0

    def close(self) -> None:
        """No-op; SQLite connections are managed per-operation."""
        pass
