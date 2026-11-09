from __future__ import annotations

import threading
from pathlib import Path
from typing import Any, Dict, Optional

from .util import append_jsonl, now_iso


class EventLog:
    """Append-only, immutable episode event stream.

    Every record is a flat JSON object. The schema is deliberately small so that
    downstream metrics can be recomputed without re-running an episode.
    """

    def __init__(self, episode_dir: Path, episode_id: str, arm: str):
        self.episode_dir = Path(episode_dir)
        self.episode_id = episode_id
        self.arm = arm
        self.path = self.episode_dir / "events.jsonl"
        self._lock = threading.Lock()
        self._seq = 0

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
    ) -> Dict[str, Any]:
        with self._lock:
            self._seq += 1
            record: Dict[str, Any] = {
                "seq": self._seq,
                "ts": now_iso(),
                "episode_id": self.episode_id,
                "arm": self.arm,
                "actor": actor,
                "agent_id": agent_id,
                "kind": kind,
                "tool": tool,
                "target_class": target_class,
            }
            if payload is not None:
                record["payload"] = payload
            if usage is not None:
                record["usage"] = usage
            if budget is not None:
                record["budget"] = budget
            append_jsonl(self.path, record)
            return record

    # Convenience wrappers used across the harness.
    def lifecycle(self, stage: str, **payload: Any) -> Dict[str, Any]:
        return self.emit("system", "lifecycle", payload={"stage": stage, **payload})

    def grader(self, verdict: Dict[str, Any]) -> Dict[str, Any]:
        return self.emit(
            "system",
            "grader",
            target_class="real",
            tool="official_grader",
            payload=verdict,
        )
