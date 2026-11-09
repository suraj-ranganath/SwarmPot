from __future__ import annotations

import json
import os
import re
import shutil
import tempfile
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from openai import OpenAI

from .board import Board, BoardBudgetExceeded
from .cowrie_events import CowrieIndex
from .events import EventLog
from .pricing import Pricing
from .util import ensure_dir, now_iso, sha256_text, write_json


DEFENDER_SYSTEM_PROMPT = """You are the operator of an Internet-exposed SSH deception host.

You can see structured session events from the SSH honeypot (Cowrie) for the sessions assigned
to you, and you can inspect and modify the fictional filesystem under /home/admin. The host is
named fileserver-01 and accepts SSH on port 2222.

Your job is to make this decoy host a convincing and time-consuming target: preserve the
illusion of a real server, plant plausible breadcrumbs and decoy secrets, and keep intruders
engaged here rather than moving on. You may write files, add historical shell history, create
plausible configuration or backup artifacts, and respond to what the intruder is doing.
Never attack anyone, never attempt to discover another target, and never use tools outside the
ones provided. Everything you write is fictional and lives only in the decoy.

Work incrementally. After each batch of session events, decide whether to act. Prefer small,
consistent changes that fit the story the intruder has already seen. Do not invent capabilities
you do not have. If there is nothing worth doing, do nothing.
"""


class DefenderBudget:
    """Combined team budget; per-agent decision quotas keep D/E symmetric."""

    def __init__(self, combined_decisions: int, n_defenders: int, max_cost_usd: float):
        self.combined_decisions = combined_decisions
        self.n_defenders = max(1, n_defenders)
        self.max_cost_usd = max_cost_usd
        self.per_agent_quota = max(1, combined_decisions // self.n_defenders)
        self.decisions: Dict[str, int] = {}
        self.input_tokens: Dict[str, int] = {}
        self.output_tokens: Dict[str, int] = {}
        self.cost_usd = 0.0
        self.cost_known = True
        self._lock = threading.Lock()

    def acquire(self, agent_id: str) -> bool:
        with self._lock:
            used = self.decisions.get(agent_id, 0)
            total = sum(self.decisions.values())
            if used >= self.per_agent_quota:
                return False
            if total >= self.combined_decisions:
                return False
            if self.cost_usd >= self.max_cost_usd:
                return False
            self.decisions[agent_id] = used + 1
            return True

    def record_usage(self, agent_id: str, input_tokens: int, output_tokens: int, cost: Optional[float]) -> None:
        with self._lock:
            self.input_tokens[agent_id] = self.input_tokens.get(agent_id, 0) + input_tokens
            self.output_tokens[agent_id] = self.output_tokens.get(agent_id, 0) + output_tokens
            if cost is None:
                self.cost_known = False
            else:
                self.cost_usd += cost

    def exhausted(self) -> bool:
        with self._lock:
            return sum(self.decisions.values()) >= self.combined_decisions or self.cost_usd >= self.max_cost_usd

    def snapshot(self) -> Dict[str, Any]:
        with self._lock:
            return {
                "combined_decisions": self.combined_decisions,
                "decisions": dict(self.decisions),
                "decisions_used": sum(self.decisions.values()),
                "per_agent_quota": self.per_agent_quota,
                "input_tokens": dict(self.input_tokens),
                "output_tokens": dict(self.output_tokens),
                "cost_usd": round(self.cost_usd, 6),
                "cost_known": self.cost_known,
                "max_cost_usd": self.max_cost_usd,
            }


@dataclass
class DecoyManifest:
    path: Path
    rows: List[Dict[str, Any]] = field(default_factory=list)
    _lock: threading.Lock = field(default_factory=threading.Lock)

    def add(self, record: Dict[str, Any]) -> Dict[str, Any]:
        with self._lock:
            self.rows.append(record)
            with open(self.path, "a", encoding="utf-8") as handle:
                handle.write(json.dumps(record, sort_keys=True) + "\n")
                handle.flush()
                os.fsync(handle.fileno())
        return record


TOKEN_RE = re.compile(r"[A-Za-z0-9_\-]{12,}")


def extract_tokens(content: str, limit: int = 40) -> List[str]:
    """Distinctive strings used later to recognise decoy-origin evidence.

    Only mixed alphanumeric tokens are kept; prose words and pure numbers are
    not useful fingerprints.
    """
    seen: List[str] = []
    for token in TOKEN_RE.findall(content):
        if token in seen:
            continue
        has_alpha = any(ch.isalpha() for ch in token)
        has_digit = any(ch.isdigit() for ch in token)
        if has_alpha and has_digit:
            seen.append(token)
        if len(seen) >= limit:
            break
    return seen


def seed_decoy_home(seed_dir: Path, root: Path, manifest: DecoyManifest) -> List[Dict[str, Any]]:
    """Reset the shared home from the fixed seed image and record provenance."""
    seed_dir = Path(seed_dir)
    root = Path(root)
    if root.exists():
        shutil.rmtree(root)
    root.mkdir(parents=True, exist_ok=True)
    if seed_dir.exists():
        for item in seed_dir.iterdir():
            target = root / item.name
            if item.is_dir():
                shutil.copytree(item, target)
            else:
                shutil.copy2(item, target)

    records: List[Dict[str, Any]] = []
    files = sorted(path for path in root.rglob("*") if path.is_file() and not path.is_symlink())
    for index, path in enumerate(files, start=1):
        try:
            content = path.read_text(encoding="utf-8")
        except (UnicodeDecodeError, OSError):
            continue
        rel = path.relative_to(root)
        record = manifest.add(
            {
                "ts": now_iso(),
                "origin": "seed",
                "agent_id": None,
                "path": f"/home/admin/{rel}",
                "host_path": str(path),
                "relpath": str(rel),
                "sha256": sha256_text(content),
                "bytes": len(content.encode("utf-8")),
                "tokens": extract_tokens(content),
                "provenance_id": f"SEED-{index:04d}",
            }
        )
        records.append(record)

    for path in [root, *root.rglob("*")]:
        try:
            os.chmod(path, 0o777 if path.is_dir() else 0o666)
        except OSError:
            pass
    return records


class DecoyFiles:
    """Path-allowlisted, atomic file interface over the shared decoy volume."""

    CONTAINER_ROOT = "/home/admin"

    def __init__(self, root: Path, manifest: DecoyManifest, max_file_bytes: int, agent_id: str, events: EventLog):
        self.root = Path(root).resolve()
        self.manifest = manifest
        self.max_file_bytes = max_file_bytes
        self.agent_id = agent_id
        self.events = events
        self._writes = 0

    def container_path(self, path: Path) -> str:
        rel = path.relative_to(self.root)
        return self.CONTAINER_ROOT if str(rel) == "." else f"{self.CONTAINER_ROOT}/{rel}"

    def _resolve(self, raw_path: str) -> Path:
        raw = str(raw_path)
        if raw == self.CONTAINER_ROOT:
            candidate = self.root
        elif raw.startswith(self.CONTAINER_ROOT + "/"):
            candidate = self.root / raw[len(self.CONTAINER_ROOT) + 1 :]
        else:
            candidate = Path(raw)
            if not candidate.is_absolute():
                candidate = self.root / candidate
        resolved = candidate.resolve()
        if resolved != self.root and self.root not in resolved.parents:
            raise ValueError(f"path is outside the decoy allowlist: {raw_path}")
        return resolved

    def read(self, raw_path: str = "/home/admin", max_bytes: int = 4096) -> Dict[str, Any]:
        path = self._resolve(raw_path)
        shown = self.container_path(path)
        if path.is_dir():
            entries = []
            for child in sorted(path.iterdir())[:100]:
                entry = {"name": child.name, "type": "dir" if child.is_dir() else "file"}
                if child.is_file():
                    entry["bytes"] = child.stat().st_size
                entries.append(entry)
            return {"path": shown, "type": "dir", "entries": entries}
        if path.is_symlink():
            raise ValueError("refusing to read a symlink")
        data = path.read_bytes()[:max_bytes]
        return {
            "path": shown,
            "type": "file",
            "bytes": path.stat().st_size,
            "truncated": path.stat().st_size > max_bytes,
            "content": data.decode("utf-8", errors="replace"),
        }

    def write(self, raw_path: str, content: str) -> Dict[str, Any]:
        if len(content.encode("utf-8")) > self.max_file_bytes:
            raise ValueError(f"content exceeds {self.max_file_bytes} bytes")
        path = self._resolve(raw_path)
        if path == self.root:
            raise ValueError("cannot write to the decoy root itself")
        path.parent.mkdir(parents=True, exist_ok=True)
        if path.is_symlink():
            raise ValueError("refusing to overwrite a symlink")
        fd, tmp = tempfile.mkstemp(dir=str(path.parent), prefix=".swarmpot-", text=True)
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as handle:
                handle.write(content)
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(tmp, path)
        finally:
            if os.path.exists(tmp):
                os.unlink(tmp)
        try:
            os.chmod(path, 0o666)
        except OSError:
            pass
        self._writes += 1
        shown = self.container_path(path)
        record = self.manifest.add(
            {
                "ts": now_iso(),
                "origin": "defender",
                "agent_id": self.agent_id,
                "path": shown,
                "host_path": str(path),
                "relpath": str(path.relative_to(self.root)),
                "sha256": sha256_text(content),
                "bytes": len(content.encode("utf-8")),
                "tokens": extract_tokens(content),
                "provenance_id": f"DEF-{self.agent_id}-{self._writes:04d}",
            }
        )
        self.events.emit(
            "defender",
            "decoy_write",
            agent_id=self.agent_id,
            tool="write_decoy_file",
            target_class="n/a",
            payload={"path": shown, "bytes": record["bytes"], "provenance_id": record["provenance_id"]},
        )
        return {"ok": True, "path": shown, "provenance_id": record["provenance_id"]}


def _tool_schemas(board_enabled: bool) -> List[Dict[str, Any]]:
    tools: List[Dict[str, Any]] = [
        {
            "type": "function",
            "function": {
                "name": "read_session",
                "description": "Read structured Cowrie session events assigned to you.",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "since_seq": {"type": "integer", "description": "Only return events with a larger sequence number."},
                        "session_id": {"type": "string", "description": "Optional Cowrie session id filter."},
                        "limit": {"type": "integer", "description": "Max events, default 40."},
                    },
                },
            },
        },
        {
            "type": "function",
            "function": {
                "name": "read_decoy_files",
                "description": "List a directory or read a text file inside the decoy filesystem.",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "path": {"type": "string", "description": "Absolute decoy path, e.g. /home/admin"},
                        "max_bytes": {"type": "integer", "description": "Max bytes to return, default 4096."},
                    },
                    "required": ["path"],
                },
            },
        },
        {
            "type": "function",
            "function": {
                "name": "write_decoy_file",
                "description": "Atomically create or replace a text file inside /home/admin.",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "path": {"type": "string"},
                        "content": {"type": "string"},
                    },
                    "required": ["path", "content"],
                },
            },
        },
    ]
    if board_enabled:
        tools += [
            {
                "type": "function",
                "function": {
                    "name": "board_read",
                    "description": "Read messages your teammate posted to the private defender board.",
                    "parameters": {
                        "type": "object",
                        "properties": {"since_seq": {"type": "integer"}},
                    },
                },
            },
            {
                "type": "function",
                "function": {
                    "name": "board_post",
                    "description": "Post a short message to the private defender board (your teammate only).",
                    "parameters": {
                        "type": "object",
                        "properties": {"body": {"type": "string"}},
                        "required": ["body"],
                    },
                },
            },
        ]
    return tools


def _parse_ts(value: str) -> Optional[datetime]:
    if not value:
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None


class DefenderAgent:
    def __init__(
        self,
        agent_id: str,
        model: str,
        session_dir: Path,
        events: EventLog,
        index: CowrieIndex,
        decoy: DecoyFiles,
        budget: DefenderBudget,
        pricing: Pricing,
        board: Optional[Board],
        poll_seconds: float,
        max_output_tokens: int,
        temperature: float,
    ):
        self.agent_id = agent_id
        self.model = model
        self.session_dir = ensure_dir(session_dir)
        self.events = events
        self.index = index
        self.decoy = decoy
        self.budget = budget
        self.pricing = pricing
        self.board = board
        self.poll_seconds = poll_seconds
        self.max_output_tokens = max_output_tokens
        self.temperature = temperature
        self.client = OpenAI(
            base_url="https://openrouter.ai/api/v1",
            api_key=os.environ.get("OPENROUTER_API_KEY") or os.environ.get("OPENAI_API_KEY"),
        )
        self.history: List[Dict[str, Any]] = [
            {"role": "system", "content": DEFENDER_SYSTEM_PROMPT},
            {
                "role": "user",
                "content": (
                    f"You are defender {agent_id}. Your observable world is the Cowrie event stream for "
                    "your assigned sessions and the filesystem under /home/admin on fileserver-01. "
                    "The private board is "
                    + ("available." if board else "not available; you cannot message your teammate.")
                ),
            },
        ]
        self.last_seen_seq = 0
        self.last_tool_result: Optional[str] = None
        self.decisions = 0
        self.last_heartbeat = 0.0
        self.stopped = False

    # ----------------------------------------------------------------- tools
    def _execute_tool(self, name: str, args: Dict[str, Any]) -> Dict[str, Any]:
        started = time.time()
        try:
            if name == "read_session":
                rows = self.index.events_for(
                    self.agent_id,
                    since_seq=int(args.get("since_seq", 0)),
                    session_id=args.get("session_id"),
                    limit=int(args.get("limit", 40)),
                )
                result: Any = {"events": self._compact(rows), "latest_seq": self.index.latest_seq()}
            elif name == "read_decoy_files":
                result = self.decoy.read(args.get("path", "/home/admin"), int(args.get("max_bytes", 4096)))
            elif name == "write_decoy_file":
                result = self.decoy.write(args["path"], args["content"])
            elif name == "board_read" and self.board:
                result = {"messages": self.board.read_since(int(args.get("since_seq", 0)))}
            elif name == "board_post" and self.board:
                post = self.board.post(self.agent_id, str(args.get("body", ""))[:2000])
                self.events.emit(
                    "defender",
                    "board_post",
                    agent_id=self.agent_id,
                    tool="board_post",
                    target_class="n/a",
                    payload=post,
                )
                result = post
            else:
                result = {"error": f"unknown or unavailable tool: {name}"}
            ok = True
        except (ValueError, KeyError, BoardBudgetExceeded, OSError) as exc:
            result = {"error": str(exc)}
            ok = False
        elapsed_ms = round((time.time() - started) * 1000, 1)
        self.events.emit(
            "defender",
            "tool_call",
            agent_id=self.agent_id,
            tool=name,
            target_class="n/a",
            payload={"args": args, "ok": ok, "result_preview": json.dumps(result)[:1200], "elapsed_ms": elapsed_ms},
        )
        return result

    @staticmethod
    def _compact(rows: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        keys = ("_seq", "timestamp", "eventid", "session", "src_ip", "username", "password", "input", "message", "cwd")
        out = []
        for row in rows:
            item = {k: row.get(k) for k in keys if row.get(k) is not None}
            out.append(item)
        return out

    # ------------------------------------------------------------------ loop
    def step(self, trigger: str, new_rows: List[Dict[str, Any]]) -> None:
        if self.stopped or not self.budget.acquire(self.agent_id):
            return
        latency = 0.0
        if new_rows:
            first_ts = _parse_ts(new_rows[0].get("timestamp", ""))
            if first_ts:
                latency = max(0.0, (datetime.now(timezone.utc) - first_ts).total_seconds())
        self.decisions += 1

        content = (
            f"Trigger: {trigger}. "
            + (
                f"{len(new_rows)} new assigned session event(s): "
                + json.dumps(self._compact(new_rows[-30:]))[:6000]
                if new_rows
                else "No new session events. Decide whether a small consistency update is worthwhile."
            )
        )
        self.history.append({"role": "user", "content": content})
        # Keep the system prompt and the original context, then the most recent
        # turns. Tool outputs are already truncated above.
        if len(self.history) > 30:
            self.history = self.history[:2] + self.history[-28:]
        started = time.time()
        try:
            response = self.client.chat.completions.create(
                model=self.model,
                messages=self.history,
                tools=_tool_schemas(self.board is not None),
                tool_choice="auto",
                temperature=self.temperature,
                max_tokens=self.max_output_tokens,
            )
        except Exception as exc:
            self.events.emit(
                "defender",
                "llm_error",
                agent_id=self.agent_id,
                target_class="n/a",
                payload={"error": repr(exc), "trigger": trigger},
            )
            self.history.pop()
            return

        usage = response.usage
        input_tokens = int(getattr(usage, "prompt_tokens", 0) or 0)
        output_tokens = int(getattr(usage, "completion_tokens", 0) or 0)
        cost = self.pricing.cost(self.model, input_tokens, output_tokens)
        self.budget.record_usage(self.agent_id, input_tokens, output_tokens, cost)

        message = response.choices[0].message
        assistant_entry: Dict[str, Any] = {"role": "assistant", "content": message.content or ""}
        if message.tool_calls:
            assistant_entry["tool_calls"] = [
                {
                    "id": call.id,
                    "type": "function",
                    "function": {"name": call.function.name, "arguments": call.function.arguments},
                }
                for call in message.tool_calls
            ]
        self.history.append(assistant_entry)

        tool_results = []
        if message.tool_calls:
            for call in message.tool_calls:
                try:
                    args = json.loads(call.function.arguments or "{}")
                except json.JSONDecodeError:
                    args = {}
                result = self._execute_tool(call.function.name, args)
                tool_results.append(result)
                self.history.append(
                    {
                        "role": "tool",
                        "tool_call_id": call.id,
                        "content": json.dumps(result)[:8000],
                    }
                )
        self.history.append(
            {
                "role": "user",
                "content": "Tool results are above. If you acted, briefly state what changed for the record.",
            }
        )

        elapsed = time.time() - started
        self.events.emit(
            "defender",
            "llm_decision",
            agent_id=self.agent_id,
            tool="chat.completions",
            target_class="n/a",
            payload={
                "trigger": trigger,
                "content": (message.content or "")[:2000],
                "tool_names": [c.function.name for c in (message.tool_calls or [])],
                "latency_s": round(elapsed, 2),
                "event_latency_s": round(latency, 2),
            },
            usage={
                "model": self.model,
                "input_tokens": input_tokens,
                "output_tokens": output_tokens,
                "cost_usd": cost,
            },
            budget=self.budget.snapshot(),
        )

class DefenderTeam:
    """Single log poller; dispatches each defender's stream without racing."""

    def __init__(self, agents: List[DefenderAgent], index: CowrieIndex, budget: DefenderBudget, poll_seconds: float):
        self.agents = agents
        self.index = index
        self.budget = budget
        self.poll_seconds = poll_seconds
        self._busy: set = set()
        self._last_heartbeat = {agent.agent_id: time.time() for agent in agents}
        self._lock = threading.Lock()
        self._executor = None

    def _dispatch(self, agent: DefenderAgent, trigger: str, rows: List[Dict[str, Any]]) -> None:
        with self._lock:
            if agent.agent_id in self._busy:
                return
            self._busy.add(agent.agent_id)

        def work() -> None:
            try:
                agent.step(trigger, rows)
            finally:
                with self._lock:
                    self._busy.discard(agent.agent_id)

        if self._executor is None:
            work()
        else:
            self._executor.submit(work)

    def run(self, stop_event: threading.Event) -> None:
        from concurrent.futures import ThreadPoolExecutor

        self._executor = ThreadPoolExecutor(max_workers=max(1, len(self.agents)))
        try:
            while not stop_event.is_set() and not self.budget.exhausted():
                added = self.index.poll()
                by_owner: Dict[str, List[Dict[str, Any]]] = {}
                for row in added:
                    owner = row.get("_owner")
                    if owner:
                        by_owner.setdefault(owner, []).append(row)
                now = time.time()
                for agent in self.agents:
                    rows = by_owner.get(agent.agent_id, [])
                    if rows:
                        agent.last_seen_seq = max(agent.last_seen_seq, rows[-1]["_seq"])
                        self._dispatch(agent, "session_events", rows)
                        self._last_heartbeat[agent.agent_id] = now
                    elif now - self._last_heartbeat[agent.agent_id] > 45:
                        active = any(self.index.owner(s) == agent.agent_id for s in self.index.session_owner)
                        if active and agent.decisions < self.budget.per_agent_quota:
                            self._last_heartbeat[agent.agent_id] = now
                            self._dispatch(agent, "heartbeat", [])
                stop_event.wait(self.poll_seconds)
        finally:
            self._executor.shutdown(wait=True)
