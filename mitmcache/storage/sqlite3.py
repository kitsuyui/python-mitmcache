from __future__ import annotations

import io
import sqlite3
from datetime import datetime, timezone

import mitmproxy.io as mio
from mitmproxy import http


def _now() -> str:
    return datetime.now(tz=timezone.utc).isoformat()


class SQLiteStorage:
    def __init__(self, db_path: str, max_entries: int | None = None) -> None:
        self.max_entries = max_entries
        self.conn = sqlite3.connect(db_path)
        self.conn.row_factory = sqlite3.Row
        cursor = self.conn.cursor()
        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS cache (
                id INTEGER PRIMARY KEY,
                cache_key TEXT UNIQUE,
                url TEXT,
                method TEXT,
                flow BLOB,
                last_accessed_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            )
            """
        )
        self.conn.commit()
        # Migrate existing databases that predate the last_accessed_at column.
        try:
            cursor.execute(
                "ALTER TABLE cache ADD COLUMN "
                "last_accessed_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP"
            )
            self.conn.commit()
        except sqlite3.OperationalError:
            pass  # column already exists

    def get(self, cache_key: str) -> http.HTTPFlow | None:
        cursor = self.conn.cursor()
        cursor.execute("SELECT * FROM cache WHERE cache_key=?", (cache_key,))
        row = cursor.fetchone()
        if row:
            cursor.execute(
                "UPDATE cache SET last_accessed_at = ? WHERE cache_key = ?",
                (_now(), cache_key),
            )
            self.conn.commit()
            for flow in mio.FlowReader(io.BytesIO(row["flow"])).stream():
                return flow  # type: ignore

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
                  , last_accessed_at
                  )
             VALUES (?, ?, ?, ?, ?)"""
        cursor.execute(
            sql,
            (
                cache_key,
                request.url,
                request.method,
                f.getvalue(),
                _now(),
            ),
        )
        self.conn.commit()
        if self.max_entries is not None:
            self._evict()

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
             , last_accessed_at = ?
         WHERE cache_key = ?"""
        cursor.execute(
            sql,
            (
                request.url,
                request.method,
                f.getvalue(),
                _now(),
                cache_key,
            ),
        )
        self.conn.commit()
        if self.max_entries is not None:
            self._evict()

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
        self.conn.commit()

    def purge(self, cache_key: str) -> None:
        cursor = self.conn.cursor()
        cursor.execute("DELETE FROM cache WHERE cache_key=?", (cache_key,))
        self.conn.commit()

    def close(self) -> None:
        self.conn.close()
