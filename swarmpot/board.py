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
        self._conn.executescript("""
            CREATE TABLE IF NOT EXISTS notifications (
                message_seq INTEGER NOT NULL REFERENCES messages(seq),
                recipient TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'queued',
                reason TEXT,
                PRIMARY KEY (message_seq, recipient)
            );
            CREATE TABLE IF NOT EXISTS context_deliveries (
                message_seq INTEGER NOT NULL REFERENCES messages(seq),
                recipient TEXT NOT NULL,
                request_id TEXT NOT NULL,
                ts TEXT NOT NULL,
                PRIMARY KEY (message_seq, recipient)
            );
        """)
        self._conn.commit()

    def count(self) -> int:
        with self._lock:
            row = self._conn.execute(
                "SELECT COUNT(*) FROM messages WHERE episode=? AND team=?",
                (self.episode_id, self.team),
            ).fetchone()
            return int(row[0])

    def post(self, sender: str, body: str, notify_to: Optional[str] = None) -> Dict[str, Any]:
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
            if notify_to and notify_to != sender:
                self._conn.execute(
                    "INSERT INTO notifications (message_seq, recipient) VALUES (?, ?)",
                    (cursor.lastrowid, notify_to),
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

    def pending(self, recipient: str) -> List[int]:
        with self._lock:
            return [r[0] for r in self._conn.execute(
                "SELECT n.message_seq FROM notifications n JOIN messages m ON m.seq=n.message_seq "
                "WHERE m.episode=? AND m.team=? AND n.recipient=? AND n.status='queued' "
                "ORDER BY n.message_seq", (self.episode_id, self.team, recipient),
            )]

    def delivery_batch(self, recipient: str, limit: int = 8, max_chars: int = 6500) -> List[Dict[str, Any]]:
        """Wake-causing rows first, then bounded unread rows; never split a message.

        A sparse durable receipt table handles partial batches without moving a
        high-water cursor past omitted messages. Passive messages cannot schedule.
        """
        with self._lock:
            rows = self._conn.execute(
                "SELECT m.seq,m.sender,m.ts,m.body FROM messages m "
                "LEFT JOIN context_deliveries d ON d.message_seq=m.seq AND d.recipient=? "
                "LEFT JOIN notifications n ON n.message_seq=m.seq AND n.recipient=? "
                "WHERE m.episode=? AND m.team=? AND m.sender!=? AND d.message_seq IS NULL "
                "ORDER BY CASE WHEN n.status='queued' THEN 0 ELSE 1 END,m.seq LIMIT ?",
                (recipient, recipient, self.episode_id, self.team, recipient, limit),
            ).fetchall()
        import json
        batch: List[Dict[str, Any]] = []
        size = 0
        for seq, sender, ts, body in rows:
            row = dict(seq=seq, sender=sender, ts=ts, body=body)
            length = len(json.dumps(row))
            if size + length > max_chars:
                continue
            batch.append(row)
            size += length
        return sorted(batch, key=lambda row: row['seq'])

    def delivered(self, recipient: str, seqs: List[int], request_id: str) -> None:
        with self._lock, self._conn:
            for seq in seqs:
                # Only persist receipts for this namespace and another sender.
                self._conn.execute(
                    "INSERT OR IGNORE INTO context_deliveries "
                    "SELECT seq,?,?,? FROM messages WHERE seq=? AND episode=? AND team=? AND sender!=?",
                    (recipient, request_id, now_iso(), seq, self.episode_id, self.team, recipient),
                )
                self._conn.execute(
                    "UPDATE notifications SET status='delivered' WHERE message_seq=? AND recipient=? "
                    "AND EXISTS (SELECT 1 FROM context_deliveries WHERE message_seq=? AND recipient=?)",
                    (seq, recipient, seq, recipient),
                )

    def deny_pending(self, recipient: str, reason: str) -> List[int]:
        with self._lock, self._conn:
            rows = self._conn.execute(
                "SELECT n.message_seq FROM notifications n JOIN messages m ON n.message_seq=m.seq "
                "WHERE m.episode=? AND m.team=? AND n.recipient=? AND n.status='queued'",
                (self.episode_id, self.team, recipient),
            ).fetchall()
            seqs = [row[0] for row in rows]
            for seq in seqs:
                self._conn.execute(
                    "UPDATE notifications SET status='denied',reason=? WHERE message_seq=? AND recipient=?",
                    (reason, seq, recipient),
                )
            return seqs

    def close(self) -> None:
        with self._lock:
            self._conn.close()
