from __future__ import annotations

import base64
import json
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from .util import iter_jsonl_incremental


class CowrieIndex:
    """Incremental reader + per-defender session attribution.

    Cowrie's proxy backend does not log individual commands. The decoy's
    audited login shell appends `(timestamp, session-tag, base64(command))` rows
    to a shared TSV; `session-tag` is the backend SSH client port, which Cowrie
    records as `local_port` on `cowrie.proxy.backend_connected`. This index
    merges both streams into one ordered, per-session event view.
    """

    def __init__(
        self,
        log_path: Path,
        defenders: List[str],
        command_log_path: Optional[Path] = None,
    ):
        self.log_path = Path(log_path)
        self.command_log_path = Path(command_log_path) if command_log_path else None
        self.defenders = list(defenders)
        self.offset = 0
        self.command_offset = 0
        self.rows: List[Dict[str, Any]] = []
        self._next = 0
        self.session_owner: Dict[str, str] = {}
        self.local_port_to_session: Dict[str, str] = {}
        self._pending_commands: List[Tuple[str, str, str]] = []
        self._rr = 0

    # -------------------------------------------------------------- scanning
    def poll(self) -> List[Dict[str, Any]]:
        added: List[Dict[str, Any]] = []
        records, self.offset = iter_jsonl_incremental(self.log_path, self.offset)
        for record in records:
            self._ingest_cowrie(record, added)

        if self.command_log_path is not None:
            self._poll_commands(added)
        return added

    def _ingest_cowrie(self, record: Dict[str, Any], added: List[Dict[str, Any]]) -> None:
        record = dict(record)
        session = record.get("session")
        eventid = record.get("eventid")

        if eventid == "cowrie.proxy.backend_connected" and record.get("local_port") is not None:
            self.local_port_to_session[str(record["local_port"])] = str(session)

        if eventid == "cowrie.session.connect" and session:
            if session not in self.session_owner and self.defenders:
                self.session_owner[session] = self.defenders[self._rr % len(self.defenders)]
                self._rr += 1

        if session and session in self.session_owner:
            record["_owner"] = self.session_owner[session]
        self._append(record, added)

        # A backend connection may have been logged in this same poll; drain any
        # commands that arrived before the mapping was visible.
        if self._pending_commands and self.local_port_to_session:
            self._drain_pending(added)

    def _poll_commands(self, added: List[Dict[str, Any]]) -> None:
        rows, self.command_offset = self._read_tsv(self.command_log_path, self.command_offset)
        for ts, tag, command in rows:
            self._pending_commands.append((ts, tag, command))
        self._drain_pending(added)

    def _drain_pending(self, added: List[Dict[str, Any]]) -> None:
        remaining: List[Tuple[str, str, str]] = []
        for ts, tag, command in self._pending_commands:
            port = tag[5:] if tag.startswith("port-") else tag
            session = self.local_port_to_session.get(port)
            if not session:
                remaining.append((ts, tag, command))
                continue
            record: Dict[str, Any] = {
                "eventid": "cowrie.command.input",
                "timestamp": ts,
                "session": session,
                "input": command,
                "message": f"CMD: {command}",
                "_source": "decoy_audit",
            }
            if session in self.session_owner:
                record["_owner"] = self.session_owner[session]
            self._append(record, added)
        self._pending_commands = remaining

    def _append(self, record: Dict[str, Any], added: List[Dict[str, Any]]) -> None:
        self._next += 1
        record["_seq"] = self._next
        self.rows.append(record)
        added.append(record)

    @staticmethod
    def _read_tsv(path: Path, offset: int) -> Tuple[List[Tuple[str, str, str]], int]:
        out: List[Tuple[str, str, str]] = []
        try:
            size = path.stat().st_size
        except FileNotFoundError:
            return out, offset
        if size < offset:
            offset = 0
        with open(path, "rb") as handle:
            handle.seek(offset)
            while True:
                line_start = handle.tell()
                raw = handle.readline()
                if not raw:
                    break
                if not raw.endswith(b"\n"):
                    handle.seek(line_start)
                    break
                parts = raw.decode("utf-8", errors="replace").rstrip("\n").split("\t")
                if len(parts) != 3:
                    continue
                ts, tag, encoded = parts
                try:
                    command = base64.b64decode(encoded).decode("utf-8", errors="replace")
                except (ValueError, TypeError):
                    continue
                out.append((ts, tag, command))
            return out, handle.tell()

    # --------------------------------------------------------------- queries
    def owner(self, session: str) -> Optional[str]:
        return self.session_owner.get(session)

    def events_for(
        self,
        defender_id: str,
        since_seq: int = 0,
        session_id: Optional[str] = None,
        limit: int = 50,
    ) -> List[Dict[str, Any]]:
        out: List[Dict[str, Any]] = []
        for row in self.rows:
            if row["_seq"] <= since_seq:
                continue
            if row.get("_owner") != defender_id:
                continue
            if session_id and row.get("session") != session_id:
                continue
            out.append(row)
            if len(out) >= limit:
                break
        return out

    def latest_seq(self) -> int:
        return self._next

    def new_for_defender(self, defender_id: str, since_seq: int) -> List[Dict[str, Any]]:
        return self.events_for(defender_id, since_seq=since_seq, limit=1000)

    def first_connect_ts(self) -> Optional[str]:
        for row in self.rows:
            if row.get("eventid") == "cowrie.session.connect":
                return row.get("timestamp")
        return None

    def first_success_login_ts(self) -> Optional[str]:
        for row in self.rows:
            if row.get("eventid") == "cowrie.login.success":
                return row.get("timestamp")
        return None

    def first_command_ts(self) -> Optional[str]:
        for row in self.rows:
            if row.get("eventid") == "cowrie.command.input":
                return row.get("timestamp")
        return None

    def command_count(self) -> int:
        return sum(1 for row in self.rows if row.get("eventid") == "cowrie.command.input")

    def sessions(self) -> Dict[str, int]:
        counts: Dict[str, int] = {}
        for row in self.rows:
            session = row.get("session")
            if session:
                counts[session] = counts.get(session, 0) + 1
        return counts

    def commands_for_session(self, session: str) -> List[str]:
        return [
            row.get("input", "")
            for row in self.rows
            if row.get("eventid") == "cowrie.command.input" and row.get("session") == session
        ]
