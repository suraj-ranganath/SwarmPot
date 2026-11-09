from __future__ import annotations

import sqlite3
import threading
from pathlib import Path
from typing import Any, Dict, List, Optional

from .util import now_iso


class BoardBudgetExceeded(RuntimeError):
    pass


class Board:
    """Tiny namespaced team board backed by SQLite.

    The board is a message bus only: monotonic sequence, timestamps, per-team
    message cap. It is private to the defender team in an episode.
    """

    def __init__(self, path: Path, episode_id: str, team: str, max_messages: int):
        self.path = Path(path)
        self.episode_id = episode_id
        self.team = team
        self.max_messages = max_messages
        self._lock = threading.Lock()
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._conn = sqlite3.connect(str(self.path), check_same_thread=False)
        self._conn.execute(
            """
            CREATE TABLE IF NOT EXISTS messages (
                seq INTEGER PRIMARY KEY AUTOINCREMENT,
                episode TEXT NOT NULL,
                team TEXT NOT NULL,
                sender TEXT NOT NULL,
                ts TEXT NOT NULL,
                body TEXT NOT NULL
            )
            """
        )
        self._conn.commit()

    def count(self) -> int:
        with self._lock:
            row = self._conn.execute(
                "SELECT COUNT(*) FROM messages WHERE episode=? AND team=?",
                (self.episode_id, self.team),
            ).fetchone()
            return int(row[0])

    def post(self, sender: str, body: str) -> Dict[str, Any]:
        with self._lock:
            used = self._conn.execute(
                "SELECT COUNT(*) FROM messages WHERE episode=? AND team=?",
                (self.episode_id, self.team),
            ).fetchone()[0]
            if used >= self.max_messages:
                raise BoardBudgetExceeded(f"board message budget exhausted ({used}/{self.max_messages})")
            ts = now_iso()
            cursor = self._conn.execute(
                "INSERT INTO messages (episode, team, sender, ts, body) VALUES (?, ?, ?, ?, ?)",
                (self.episode_id, self.team, sender, ts, body),
            )
            self._conn.commit()
            return {
                "seq": cursor.lastrowid,
                "sender": sender,
                "ts": ts,
                "body": body,
                "used": used + 1,
                "limit": self.max_messages,
            }

    def read_since(self, since_seq: int = 0, limit: int = 200) -> List[Dict[str, Any]]:
        with self._lock:
            rows = self._conn.execute(
                "SELECT seq, sender, ts, body FROM messages "
                "WHERE episode=? AND team=? AND seq>? ORDER BY seq ASC LIMIT ?",
                (self.episode_id, self.team, int(since_seq), int(limit)),
            ).fetchall()
        return [{"seq": r[0], "sender": r[1], "ts": r[2], "body": r[3]} for r in rows]

    def close(self) -> None:
        with self._lock:
            self._conn.close()
