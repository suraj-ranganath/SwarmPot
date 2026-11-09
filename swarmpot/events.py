from __future__ import annotations

import threading
import time
from pathlib import Path
from typing import Any, Dict, List, Optional

from .util import append_jsonl, now_iso
from .run_records import phase_for_stage

SCHEMA_VERSION = 2
PRODUCER = "swarmpot-controller"

_TEAM_BY_ACTOR = {
    "system": "evaluator",
    "attacker": "attacker",
    "defender": "defender",
}


class EventLog:
    """Append-only, immutable episode event stream.

    Schema v2 adds stable event IDs, parent/reference links, explicit action
    status, and a process-scoped monotonic clock so that cross-log traces
    (SSH -> observation -> model call -> edit -> exposure) can be reconstructed.
    The stream is the evaluator-readable index; large payloads live beside it
    and are referenced by path and hash.
    """

    def __init__(self, episode_dir: Path, episode_id: str, arm: str, attempt_id: Optional[str] = None):
        self.episode_dir = Path(episode_dir)
        self.episode_id = episode_id
        self.attempt_id = attempt_id or episode_id
        self.arm = arm
        self.path = self.episode_dir / "events.jsonl"
        self._lock = threading.Lock()
        self._seq = self._last_seq()
        self._clock_scope = f"{PRODUCER}:{id(self):x}"

    def _last_seq(self) -> int:
        """Resume sequence numbers so multiple writers in one episode never
        reuse an event id."""
        import json

        try:
            size = self.path.stat().st_size
        except OSError:
            return 0
        try:
            with open(self.path, "rb") as handle:
                start = max(0, size - 1024 * 1024)
                handle.seek(start)
                chunk = handle.read().decode("utf-8", errors="replace")
        except OSError:
            return 0
        for line in reversed(chunk.splitlines()):
            line = line.strip()
            if not line:
                continue
            try:
                value = int(json.loads(line).get("seq", 0))
                return value
            except (ValueError, TypeError, json.JSONDecodeError):
                continue
        return 0

    def emit(
        self,
        actor: str,
        kind: str,
        *,
        agent_id: Optional[str] = None,
        tool: Optional[str] = None,
        target_class: str = "other",
        payload: Optional[Dict[str, Any]] = None,
        usage: Optional[Dict[str, Any]] = None,
        budget: Optional[Dict[str, Any]] = None,
        parent_event_id: Optional[str] = None,
        refs: Optional[List[str]] = None,
        status: Optional[str] = None,
        reason: Optional[str] = None,
        occurred_at: Optional[str] = None,
        duration_ms: Optional[float] = None,
    ) -> Dict[str, Any]:
        with self._lock:
            self._seq += 1
            event_id = f"evt-{self.episode_id}-{self._seq:06d}"
            received = now_iso()
            record: Dict[str, Any] = {
                "schema_version": SCHEMA_VERSION,
                "seq": self._seq,
                "event_id": event_id,
                "episode_id": self.episode_id,
                "attempt_id": self.attempt_id,
                "ts": received,
                "received_at": received,
                "arm": self.arm,
                "team": _TEAM_BY_ACTOR.get(actor, "other"),
                "actor": actor,
                "agent_id": agent_id,
                "kind": kind,
                "tool": tool,
                "target_class": target_class,
                "producer": PRODUCER,
                "clock_scope": self._clock_scope,
                "monotonic_ns": time.monotonic_ns(),
            }
            if parent_event_id:
                record["parent_event_id"] = parent_event_id
            if refs:
                record["refs"] = list(refs)
            if status:
                record["status"] = status
            if reason:
                record["reason"] = reason
            if occurred_at:
                record["occurred_at"] = occurred_at
            if duration_ms is not None:
                record["duration_ms"] = duration_ms
            payload = dict(payload or {})
            payload.setdefault("schema_version", SCHEMA_VERSION)
            record["payload"] = payload
            if usage is not None:
                record["usage"] = usage
            if budget is not None:
                record["budget"] = budget
            append_jsonl(self.path, record)
            return record

    # Convenience wrappers used across the harness.
    def lifecycle(self, stage: str, **payload: Any) -> Dict[str, Any]:
        return self.emit("system", "lifecycle", payload={"stage": stage, "phase": phase_for_stage(stage), **payload})

    def grader(self, verdict: Dict[str, Any]) -> Dict[str, Any]:
        return self.emit(
            "system",
            "grader",
            target_class="real",
            tool="official_grader",
            payload=verdict,
            status="graded",
        )

    def artifact(self, name: str, path: Path, **payload: Any) -> Dict[str, Any]:
        from .util import sha256_bytes

        try:
            digest = sha256_bytes(Path(path).read_bytes())
            size = Path(path).stat().st_size
        except OSError:
            digest, size = None, None
        return self.emit(
            "system",
            "artifact",
            payload={"name": name, "path": str(path), "sha256": digest, "bytes": size, **payload},
            status="recorded" if digest else "missing",
        )
