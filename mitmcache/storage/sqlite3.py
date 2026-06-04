from __future__ import annotations

import importlib.metadata
import io
import logging
import sqlite3

import mitmproxy.io as mio
from mitmproxy import http

_MITMPROXY_VERSION = importlib.metadata.version("mitmproxy")
logger = logging.getLogger(__name__)


class SQLiteStorage:
    def __init__(self, db_path: str) -> None:
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
                    flow_format_version TEXT
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
                return None
            try:
                with io.BytesIO(row["flow"]) as buf:
                    return next(  # type: ignore[return-value]
                        iter(mio.FlowReader(buf).stream()),
                        None,
                    )
            except Exception:
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
                  )
             VALUES (?, ?, ?, ?, ?)"""
        cursor.execute(
            sql,
            (
                cache_key,
                request.url,
                request.method,
                f.getvalue(),
                _MITMPROXY_VERSION,
            ),
        )
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
         WHERE cache_key = ?"""
        cursor.execute(
            sql,
            (
                request.url,
                request.method,
                f.getvalue(),
                _MITMPROXY_VERSION,
                cache_key,
            ),
        )
        if cursor.rowcount == 0:
            logger.warning("update() noop: cache_key %r not found", cache_key)
        self.conn.commit()

    def purge(self, cache_key: str) -> None:
        cursor = self.conn.cursor()
        cursor.execute("DELETE FROM cache WHERE cache_key=?", (cache_key,))
        self.conn.commit()

    def close(self) -> None:
        self.conn.close()
