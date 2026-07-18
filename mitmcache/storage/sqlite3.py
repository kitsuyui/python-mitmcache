from __future__ import annotations

import importlib.metadata
import io
import logging
import sqlite3
from datetime import datetime, timezone

import mitmproxy.io as mio
from mitmproxy import http

_MITMPROXY_VERSION = importlib.metadata.version("mitmproxy")
logger = logging.getLogger(__name__)


def _now() -> str:
    # mypy.ini pins python_version=3.10 where datetime.UTC is unavailable,
    # so keep timezone.utc and silence ruff's UP017 modernization here.
    return datetime.now(tz=timezone.utc).isoformat()  # noqa: UP017


class SQLiteStorage:
    def __init__(self, db_path: str, max_entries: int | None = None) -> None:
        self.max_entries = max_entries
        self.conn = sqlite3.connect(db_path)
        self.conn.row_factory = sqlite3.Row
        try:
            cursor = self.conn.cursor()
            cursor.execute(
                """
                CREATE TABLE IF NOT EXISTS cache (
                    id INTEGER PRIMARY KEY,
                    cache_key TEXT UNIQUE,
                    url TEXT,
                    method TEXT,
                    flow BLOB,
                    flow_format_version TEXT,
                    last_accessed_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
                )
                """
            )
            # Migrate existing databases that lack the
            # flow_format_version column.
            try:
                cursor.execute(
                    "ALTER TABLE cache ADD COLUMN flow_format_version TEXT"
                )
            except sqlite3.OperationalError:
                pass  # column already exists
            self.conn.commit()
            # Migrate existing databases that predate last_accessed_at.
            try:
                cursor.execute(
                    "ALTER TABLE cache ADD COLUMN "
                    "last_accessed_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP"
                )
                self.conn.commit()
            except sqlite3.OperationalError:
                pass  # column already exists
        except Exception:
            self.conn.close()
            raise

    def get(self, cache_key: str) -> http.HTTPFlow | None:
        cursor = self.conn.cursor()
        cursor.execute("SELECT * FROM cache WHERE cache_key=?", (cache_key,))
        row = cursor.fetchone()
        if row:
            stored_version = row["flow_format_version"]
            # Skip entries whose BLOB was written by a different mitmproxy
            # version; deserialization may silently fail or raise.
            if stored_version != _MITMPROXY_VERSION:
                self._purge_with_cursor(cursor, cache_key)
                return None
            cursor.execute(
                "UPDATE cache SET last_accessed_at = ? WHERE cache_key = ?",
                (_now(), cache_key),
            )
            self.conn.commit()
            try:
                with io.BytesIO(row["flow"]) as buf:
                    return next(  # type: ignore[return-value]
                        iter(mio.FlowReader(buf).stream()),
                        None,
                    )
            except Exception:
                self._purge_with_cursor(cursor, cache_key)
                return None

        return None

    def store(self, cache_key: str, flow: http.HTTPFlow) -> None:
        request = flow.request
        cursor = self.conn.cursor()
        f = io.BytesIO()
        w = mio.FlowWriter(f)
        w.add(flow)
        sql = """\
        INSERT INTO cache
                  ( cache_key
                  , url
                  , method
                  , flow
                  , flow_format_version
                  , last_accessed_at
                  )
             VALUES (?, ?, ?, ?, ?, ?)"""
        cursor.execute(
            sql,
            (
                cache_key,
                request.url,
                request.method,
                f.getvalue(),
                _MITMPROXY_VERSION,
                _now(),
            ),
        )
        if self.max_entries is not None:
            self._evict()
        self.conn.commit()

    def update(self, cache_key: str, flow: http.HTTPFlow) -> None:
        request = flow.request
        cursor = self.conn.cursor()
        f = io.BytesIO()
        w = mio.FlowWriter(f)
        w.add(flow)
        sql = """\
        UPDATE cache
           SET url = ?
             , method = ?
             , flow = ?
             , flow_format_version = ?
             , last_accessed_at = ?
         WHERE cache_key = ?"""
        cursor.execute(
            sql,
            (
                request.url,
                request.method,
                f.getvalue(),
                _MITMPROXY_VERSION,
                _now(),
                cache_key,
            ),
        )
        if cursor.rowcount == 0:
            logger.warning("update() noop: cache_key %r not found", cache_key)
        if self.max_entries is not None:
            self._evict()
        self.conn.commit()

    def upsert(self, cache_key: str, flow: http.HTTPFlow) -> None:
        request = flow.request
        cursor = self.conn.cursor()
        f = io.BytesIO()
        w = mio.FlowWriter(f)
        w.add(flow)
        sql = """\
        INSERT OR REPLACE INTO cache
                  ( cache_key
                  , url
                  , method
                  , flow
                  , flow_format_version
                  , last_accessed_at
                  )
             VALUES (?, ?, ?, ?, ?, ?)"""
        cursor.execute(
            sql,
            (
                cache_key,
                request.url,
                request.method,
                f.getvalue(),
                _MITMPROXY_VERSION,
                _now(),
            ),
        )
        if self.max_entries is not None:
            self._evict()
        self.conn.commit()

    def _evict(self) -> None:
        if self.max_entries is None:
            return
        cursor = self.conn.cursor()
        # Keep the max_entries most-recently-accessed entries; evict the rest.
        # Secondary sort by id DESC breaks ties deterministically (newer insert wins).
        cursor.execute(
            "DELETE FROM cache WHERE id NOT IN "
            "(SELECT id FROM cache ORDER BY last_accessed_at DESC, id DESC LIMIT ?)",
            (self.max_entries,),
        )

    def purge(self, cache_key: str) -> None:
        cursor = self.conn.cursor()
        self._purge_with_cursor(cursor, cache_key)

    def _purge_with_cursor(
        self, cursor: sqlite3.Cursor, cache_key: str
    ) -> None:
        cursor.execute("DELETE FROM cache WHERE cache_key=?", (cache_key,))
        self.conn.commit()

    def close(self) -> None:
        self.conn.close()
