import io
import sqlite3

import mitmproxy.io as mio
from mitmproxy import http


class SQLiteCacheStorage:
    def __init__(self, db_path: str) -> None:
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
                flow BLOB
            )
            """
        )
        self.conn.commit()

    def get_response(self, cache_key: str) -> http.Response | None:
        cursor = self.conn.cursor()
        cursor.execute("SELECT * FROM cache WHERE cache_key=?", (cache_key,))
        row = cursor.fetchone()
        if row:
            for flow in mio.FlowReader(io.BytesIO(row["flow"])).stream():
                return flow.response  # type: ignore

        return None

    def store_response(self, cache_key: str, flow: http.HTTPFlow) -> None:
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
                  )
             VALUES (?, ?, ?, ?)"""
        cursor.execute(
            sql,
            (
                cache_key,
                request.method,
                request.url,
                f.getvalue(),
            ),
        )
        self.conn.commit()

    def close(self) -> None:
        self.conn.close()
