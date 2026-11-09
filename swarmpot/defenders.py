from __future__ import annotations

import json
import os
import re
import shutil
import tempfile
import threading
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from openai import OpenAI

from .board import Board, BoardBudgetExceeded
from .cowrie_events import CowrieIndex
from .defender_scheduler import DefenderTeam
from .events import EventLog
from .pricing import Pricing
from .util import ensure_dir, now_iso, sha256_bytes, sha256_text, write_json


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
consistent changes that fit the story the intruder has already seen. When you edit, prefer a
resource the intruder has already accessed or is likely to inspect next, and keep its story
consistent; an unrelated new file is less useful. Do not invent capabilities you do not have.
If there is nothing worth doing, do nothing.

If a private teammate board is available (the next message says so), use it: read it before
making overlapping changes, and post concise notes about what you observed and what you changed
so your teammate does not duplicate or contradict your work. After any file change, post a
one-line note describing it. board_post defaults to notify=false. Set notify=true only when
your teammate needs to make a timely decision; it spends their existing allowance. Do not
send notification-only acknowledgements or automatically reply to a wake-up. If the board is not available, you cannot message anyone; work alone.
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
        self.failed_requests: Dict[str, int] = {}
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

    def available(self, agent_id: str) -> bool:
        with self._lock:
            return (self.decisions.get(agent_id, 0) < self.per_agent_quota
                    and sum(self.decisions.values()) < self.combined_decisions
                    and self.cost_usd < self.max_cost_usd)

    def record_usage(self, agent_id: str, input_tokens: int, output_tokens: int, cost: Optional[float]) -> None:
        with self._lock:
            self.input_tokens[agent_id] = self.input_tokens.get(agent_id, 0) + input_tokens
            self.output_tokens[agent_id] = self.output_tokens.get(agent_id, 0) + output_tokens
            if cost is None:
                self.cost_known = False
            else:
                self.cost_usd += cost

    def record_failed_request(self, agent_id: str) -> None:
        with self._lock:
            self.failed_requests[agent_id] = self.failed_requests.get(agent_id, 0) + 1
            self.cost_known = False  # failed provider requests may have been billed

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
                "failed_requests": dict(self.failed_requests),
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
        self._reads = 0

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

    def _read_counter(self) -> int:
        self._reads += 1
        return self._reads

    def read(self, raw_path: str = "/home/admin", max_bytes: int = 4096) -> Dict[str, Any]:
        path = self._resolve(raw_path)
        shown = self.container_path(path)
        observation_id = f"obs-{self.agent_id}-{self._read_counter():04d}"
        if path.is_dir():
            entries = []
            for child in sorted(path.iterdir())[:100]:
                entry = {"name": child.name, "type": "dir" if child.is_dir() else "file"}
                if child.is_file():
                    entry["bytes"] = child.stat().st_size
                entries.append(entry)
            listing_hash = sha256_text(json.dumps(entries, sort_keys=True))
            return {
                "path": shown,
                "type": "dir",
                "entries": entries,
                "observation_id": observation_id,
                "sha256": listing_hash,
                "version": f"sha256:{listing_hash}",
                "bytes": None,
            }
        if path.is_symlink():
            raise ValueError("refusing to read a symlink")
        raw = path.read_bytes()
        digest = sha256_bytes(raw)
        return {
            "path": shown,
            "type": "file",
            "bytes": len(raw),
            "truncated": len(raw) > max_bytes,
            "content": raw[:max_bytes].decode("utf-8", errors="replace"),
            "observation_id": observation_id,
            "sha256": digest,
            "version": f"sha256:{digest}",
        }

    def write(
        self,
        raw_path: str,
        content: str,
        *,
        decision_event_id: Optional[str] = None,
        request_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        if len(content.encode("utf-8")) > self.max_file_bytes:
            raise ValueError(f"content exceeds {self.max_file_bytes} bytes")
        path = self._resolve(raw_path)
        if path == self.root:
            raise ValueError("cannot write to the decoy root itself")
        path.parent.mkdir(parents=True, exist_ok=True)
        if path.is_symlink():
            raise ValueError("refusing to overwrite a symlink")
        before: Optional[Dict[str, Any]] = None
        if path.is_file():
            try:
                before_bytes = path.read_bytes()
                before = {"sha256": sha256_bytes(before_bytes), "bytes": len(before_bytes)}
            except OSError:
                before = None
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
        after_sha256 = sha256_text(content)
        before_sha256 = before["sha256"] if before else None
        edit_id = f"edit-{self.agent_id}-{self._writes:04d}"
        record = self.manifest.add(
            {
                "ts": now_iso(),
                "origin": "defender",
                "agent_id": self.agent_id,
                "path": shown,
                "host_path": str(path),
                "relpath": str(path.relative_to(self.root)),
                "sha256": after_sha256,
                "after_sha256": after_sha256,
                "before_sha256": before_sha256,
                "bytes": len(content.encode("utf-8")),
                "tokens": extract_tokens(content),
                "provenance_id": f"DEF-{self.agent_id}-{self._writes:04d}",
                "edit_id": edit_id,
                "decision_event_id": decision_event_id,
                "request_id": request_id,
                "commit_status": "committed",
            }
        )
        self.events.emit(
            "defender",
            "decoy_edit",
            agent_id=self.agent_id,
            tool="write_decoy_file",
            target_class="n/a",
            status="committed",
            parent_event_id=decision_event_id,
            refs=[request_id] if request_id else None,
            payload={
                "edit_id": edit_id,
                "path": shown,
                "before_sha256": before_sha256,
                "after_sha256": after_sha256,
                "bytes": record["bytes"],
                "provenance_id": record["provenance_id"],
                "commit_status": "committed",
                "source_decision_event_id": decision_event_id,
                "request_id": request_id,
            },
        )
        return {
            "ok": True,
            "path": shown,
            "provenance_id": record["provenance_id"],
            "edit_id": edit_id,
            "before_sha256": before_sha256,
            "after_sha256": after_sha256,
            "bytes": record["bytes"],
        }


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
                        "properties": {
                            "body": {"type": "string"},
                            "notify": {"type": "boolean", "default": False,
                                       "description": "Queue a budgeted teammate decision; avoid acknowledgement loops."},
                        },
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
        reasoning_effort: Optional[str] = None,
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
        self.reasoning_effort = reasoning_effort
        self.client = OpenAI(
            base_url="https://openrouter.ai/api/v1",
            api_key=os.environ.get("OPENROUTER_API_KEY") or os.environ.get("OPENAI_API_KEY"),
            max_retries=0,
            timeout=120.0,
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
        self.teammate_id: Optional[str] = None
        self._request_id: Optional[str] = None
        self._explicit_board_seqs: List[int] = []
        self._retry_of: Optional[str] = None
        self.prompt_version = f"defender-prompt-{sha256_text(DEFENDER_SYSTEM_PROMPT)[:12]}"
        self._board_context_seqs: List[Any] = []

    # ----------------------------------------------------------------- tools
    def _execute_tool(
        self,
        name: str,
        args: Dict[str, Any],
        *,
        decision_event_id: Optional[str] = None,
        request_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        started = time.time()
        extra: Dict[str, Any] = {}
        status = "ok"
        reason: Optional[str] = None
        local_request_id = request_id or self._request_id
        notify = bool(args.get("notify")) if name == "board_post" else False
        try:
            if self.stopped:
                raise ValueError("defender stopped")
            if name == "read_session":
                rows = self.index.events_for(
                    self.agent_id,
                    since_seq=int(args.get("since_seq", 0)),
                    session_id=args.get("session_id"),
                    limit=int(args.get("limit", 40)),
                )
                result: Any = {"events": self._compact(rows), "latest_seq": self.index.latest_seq()}
                path_re = re.compile(r"(?:/home/admin/[A-Za-z0-9_.\-/]+|~/[A-Za-z0-9_.\-/]+)")
                referenced = []
                latest = None
                for row in rows:
                    command = str(row.get("input") or "")
                    referenced.extend(path_re.findall(command))
                    ts = _parse_ts(row.get("timestamp", ""))
                    if ts and (latest is None or ts > latest):
                        latest = ts
                result["paths_referenced"] = sorted(set(referenced))[:20]
                result["latest_command_ts"] = latest.isoformat() if latest else None
                result["latest_command_age_s"] = (
                    round((datetime.now(timezone.utc) - latest).total_seconds(), 1) if latest else None
                )
                extra = {
                    "observed_observation_ids": [r.get("_observation_id") for r in rows if r.get("_observation_id")],
                    "observed_trace_event_ids": [r.get("_trace_event_id") for r in rows if r.get("_trace_event_id")],
                    "session_ids": sorted({r.get("session") for r in rows if r.get("session")}),
                    "since_seq": int(args.get("since_seq", 0)),
                }
                if result["paths_referenced"]:
                    extra["paths_referenced"] = result["paths_referenced"]
                status = "observed"
            elif name == "read_decoy_files":
                result = self.decoy.read(args.get("path", "/home/admin"), int(args.get("max_bytes", 4096)))
                extra = {
                    "observation_id": result.get("observation_id"),
                    "path": result.get("path"),
                    "sha256": result.get("sha256"),
                    "version": result.get("version"),
                    "bytes": result.get("bytes"),
                    "file_type": result.get("type"),
                }
                status = "observed"
            elif name == "write_decoy_file":
                result = self.decoy.write(
                    args["path"],
                    args["content"],
                    decision_event_id=decision_event_id,
                    request_id=local_request_id,
                )
                extra = {
                    "edit_id": result.get("edit_id"),
                    "path": result.get("path"),
                    "before_sha256": result.get("before_sha256"),
                    "after_sha256": result.get("after_sha256"),
                    "bytes": result.get("bytes"),
                }
                status = "committed"
            elif name == "board_read" and self.board:
                since = int(args.get("since_seq", 0))
                messages = []
                for row in self.board.read_since(since, limit=8):
                    if len(json.dumps({"messages": messages + [row]})) > 6500:
                        break
                    messages.append(row)
                self._explicit_board_seqs = [row["seq"] for row in messages]
                self._board_context_seqs = [row["seq"] for row in messages] or self._board_context_seqs
                result = {"messages": messages, "since_seq": since}
                extra = {"message_seqs": [row["seq"] for row in messages], "since_seq": since}
                self.events.emit(
                    "defender",
                    "board_read",
                    agent_id=self.agent_id,
                    target_class="n/a",
                    status="observed",
                    parent_event_id=decision_event_id,
                    payload={
                        "message_seqs": extra["message_seqs"],
                        "request_id": local_request_id,
                        "since_seq": since,
                    },
                )
                status = "observed"
            elif name == "board_post" and self.board:
                if not isinstance(args.get("notify", False), bool):
                    raise ValueError("notify must be a boolean")
                body = str(args.get("body", ""))[:2000]
                if len(json.dumps(body)) > 5500:
                    raise ValueError("board body exceeds bounded context size")
                post = self.board.post(
                    self.agent_id, body, notify_to=self.teammate_id if notify else None
                )
                result = post
                extra = {
                    "message_id": post.get("seq"),
                    "body_sha256": sha256_text(body),
                    "used": post.get("used"),
                    "limit": post.get("limit"),
                }
                status = "committed"
                self.events.emit(
                    "defender",
                    "board_post",
                    agent_id=self.agent_id,
                    tool="board_post",
                    target_class="n/a",
                    status="committed",
                    parent_event_id=decision_event_id,
                    payload={**post, "message_id": post.get("seq"),
                             "body_sha256": sha256_text(body), "request_id": local_request_id},
                )
                if notify:
                    self.events.emit(
                        "defender",
                        "board_notification",
                        agent_id=self.agent_id,
                        target_class="n/a",
                        status="queued" if self.teammate_id else "denied",
                        reason=None if self.teammate_id else "no_teammate",
                        payload={
                            "message_seqs": [post["seq"]], "origin": self.agent_id,
                            "recipient": self.teammate_id,
                            "status": "queued" if self.teammate_id else "denied",
                            "reason": None if self.teammate_id else "no_teammate",
                            "request_id": local_request_id,
                        },
                    )
            else:
                result = {"error": f"unknown or unavailable tool: {name}"}
                status = "denied"
                reason = "unknown_or_unavailable_tool"
        except BoardBudgetExceeded as exc:
            result = {"error": str(exc)}
            status = "denied"
            reason = "board_budget_exceeded"
        except ValueError as exc:
            result = {"error": str(exc)}
            status = "denied"
            reason = "allowlist_or_validation"
        except (KeyError, OSError, TypeError) as exc:
            result = {"error": str(exc)}
            status = "error"
            reason = type(exc).__name__
        if name == "board_post" and notify and "error" in result:
            self.events.emit(
                "defender",
                "board_notification",
                agent_id=self.agent_id,
                target_class="n/a",
                status="denied",
                reason=str(result.get("error")),
                payload={
                    "status": "denied",
                    "reason": result.get("error"),
                    "origin": self.agent_id,
                    "recipient": self.teammate_id,
                    "message_seqs": [],
                    "request_id": local_request_id,
                },
            )
        elapsed_ms = round((time.time() - started) * 1000, 1)
        self.events.emit(
            "defender",
            "tool_call",
            agent_id=self.agent_id,
            tool=name,
            target_class="n/a",
            status=status,
            reason=reason,
            parent_event_id=decision_event_id,
            refs=[local_request_id] if local_request_id else None,
            payload={
                "request_id": local_request_id,
                "args": args,
                "ok": status in ("observed", "committed"),
                "status": status,
                "reason": reason,
                "result_preview": json.dumps(result)[:1200],
                "elapsed_ms": elapsed_ms,
                "source_decision_event_id": decision_event_id,
                **extra,
            },
        )
        return result

    @staticmethod
    def _compact(rows: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        keys = (
            "_seq", "_observation_id", "_trace_event_id", "_owner",
            "timestamp", "eventid", "session", "src_ip", "username",
            "password", "input", "message", "cwd",
        )
        out = []
        for row in rows:
            item = {k: row.get(k) for k in keys if row.get(k) is not None}
            out.append(item)
        return out

    def _persist_call(
        self,
        call_index: int,
        request: Dict[str, Any],
        response: Any,
        *,
        attempts: List[str],
        started_at: str,
        completed_at: str,
        latency_s: float,
    ) -> Dict[str, Any]:
        import hashlib

        message = response.choices[0].message
        usage = response.usage
        record = {
            "schema_version": 1,
            "call_index": call_index,
            "agent_id": self.agent_id,
            "model_requested": self.model,
            "model_served": getattr(response, "model", None),
            "provider": "openrouter",
            "request_id": getattr(response, "id", None),
            "started_at": started_at,
            "completed_at": completed_at,
            "latency_s": round(latency_s, 3),
            "attempts": attempts,
            "request": {
                "messages": request.get("messages"),
                "tools": request.get("tools"),
                "tool_choice": request.get("tool_choice"),
                "temperature": request.get("temperature"),
                "max_tokens": request.get("max_tokens"),
                "extra_body": request.get("extra_body"),
            },
            "response": {
                "content": message.content,
                "tool_calls": [
                    {"id": c.id, "name": c.function.name, "arguments": c.function.arguments}
                    for c in (message.tool_calls or [])
                ],
                "finish_reason": response.choices[0].finish_reason,
            },
            "usage": {
                "input_tokens": int(getattr(usage, "prompt_tokens", 0) or 0),
                "output_tokens": int(getattr(usage, "completion_tokens", 0) or 0),
                "total_tokens": int(getattr(usage, "total_tokens", 0) or 0),
                "cached_tokens": int(
                    getattr(getattr(usage, "prompt_tokens_details", None), "cached_tokens", 0) or 0
                ),
            },
            "prompt_version": self.prompt_version,
            "system_prompt_sha256": sha256_text(DEFENDER_SYSTEM_PROMPT),
            "tools_sha256": sha256_text(json.dumps(_tool_schemas(self.board is not None), sort_keys=True)),
        }
        path = ensure_dir(self.session_dir / "decisions") / f"{call_index:04d}.json"
        write_json(path, record)
        digest = hashlib.sha256(path.read_bytes()).hexdigest()
        return {"payload_ref": str(path), "payload_sha256": digest, "record": record}

    # ------------------------------------------------------------------ loop
    def step(self, trigger: str, new_rows: List[Dict[str, Any]]) -> bool:
        if self.stopped or not self.budget.acquire(self.agent_id):
            self.events.emit("defender", "decision_denied", agent_id=self.agent_id,
                             target_class="n/a", payload={"trigger": trigger,
                             "reason": "stopped" if self.stopped else "budget_exhausted"})
            return False
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
                + json.dumps(self._compact(new_rows))
                if new_rows
                else "No new session events. Decide whether a small consistency update is worthwhile."
            )
        )
        board_rows = self.board.delivery_batch(self.agent_id) if self.board else []
        message_seqs = [row["seq"] for row in board_rows]
        if board_rows:
            content += "\nPrivate board messages (automatic context delivery, not board_read): " + json.dumps(board_rows)
        self._request_id = "defender-request-" + uuid.uuid4().hex
        self.history.append({"role": "user", "content": content})
        # Keep the system prompt and the original context, then the most recent
        # turns. Tool outputs are already truncated above.
        if len(self.history) > 30:
            self.history = self.history[:2] + self.history[-28:]
        started = time.time()
        started_at = now_iso()
        attempts: List[str] = []
        request: Dict[str, Any] = {
            "model": self.model,
            "messages": self.history,
            "tools": _tool_schemas(self.board is not None),
            "tool_choice": "auto",
            "temperature": self.temperature,
            "max_tokens": self.max_output_tokens,
        }
        if self.reasoning_effort:
            request["extra_body"] = {"reasoning": {"effort": self.reasoning_effort}}
        self.events.emit("defender", "llm_request", agent_id=self.agent_id, target_class="n/a",
                         payload={"request_id": self._request_id, "trigger": trigger, "retry_of": self._retry_of,
                                  "board_message_seqs": message_seqs,
                                  "observation_seqs": [row["_seq"] for row in new_rows]},
                         budget=self.budget.snapshot())
        try:
            response = self.client.chat.completions.create(**request)
            attempts.append("ok")
        except Exception as exc:
            attempts.append(repr(exc))
            self.budget.record_failed_request(self.agent_id)
            self._retry_of = self._request_id
            self.events.emit(
                "defender",
                "llm_error",
                agent_id=self.agent_id,
                target_class="n/a",
                status="error",
                reason="provider_error",
                payload={"error": repr(exc), "attempts": attempts, "trigger": trigger,
                         "request_id": self._request_id,
                         "request_sha256": sha256_text(json.dumps(self.history, sort_keys=True, default=str))},
                usage={"input_tokens": None, "output_tokens": None, "cost_usd": None, "reason": "provider_error"},
                budget=self.budget.snapshot(),
            )
            self.history.pop()
            if message_seqs:
                self.events.emit("defender", "board_delivery", agent_id=self.agent_id,
                                 target_class="n/a", payload={"request_id": self._request_id,
                                 "message_seqs": message_seqs, "status": "failed",
                                 "reason": "provider_error; exposure unknown; IDs retained for retry"})
            return False

        self._retry_of = None
        if self._explicit_board_seqs:
            self.events.emit("defender", "board_read_context", agent_id=self.agent_id,
                             target_class="n/a", payload={"request_id": self._request_id,
                             "message_seqs": list(self._explicit_board_seqs), "status": "delivered"})
            self._explicit_board_seqs = []
        if message_seqs:
            self.board.delivered(self.agent_id, message_seqs, self._request_id)
            self.events.emit("defender", "board_delivery", agent_id=self.agent_id,
                             target_class="n/a", payload={"request_id": self._request_id,
                             "message_seqs": message_seqs, "status": "delivered",
                             "meaning": "included in successful request; understanding/influence unknown"})
        usage = response.usage
        input_tokens = int(getattr(usage, "prompt_tokens", 0) or 0)
        output_tokens = int(getattr(usage, "completion_tokens", 0) or 0)
        cached_tokens = int(getattr(getattr(usage, "prompt_tokens_details", None), "cached_tokens", 0) or 0)
        cost = self.pricing.cost(self.model, input_tokens, output_tokens)
        self.budget.record_usage(self.agent_id, input_tokens, output_tokens, cost)

        call = self._persist_call(
            self.decisions,
            request,
            response,
            attempts=attempts,
            started_at=started_at,
            completed_at=now_iso(),
            latency_s=time.time() - started,
        )
        record = call["record"]
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

        board_context = sorted(set(list(message_seqs) + list(self._board_context_seqs)))
        observation_ids = [r.get("_observation_id") for r in new_rows if r.get("_observation_id")]
        trace_ids = [r.get("_trace_event_id") for r in new_rows if r.get("_trace_event_id")]
        decision_event = self.events.emit(
            "defender",
            "llm_decision",
            agent_id=self.agent_id,
            tool="chat.completions",
            target_class="n/a",
            status="ok",
            refs=[x for x in (trace_ids + board_context) if x],
            payload={
                "request_id": self._request_id,
                "provider_request_id": record["request_id"],
                "trigger": trigger,
                "content": (message.content or "")[:2000],
                "tool_names": [c.function.name for c in (message.tool_calls or [])],
                "latency_s": round(time.time() - started, 3),
                "event_latency_s": round(latency, 2),
                "model_requested": self.model,
                "model_served": record["model_served"],
                "provider": "openrouter",
                "prompt_version": self.prompt_version,
                "payload_ref": call["payload_ref"],
                "payload_sha256": call["payload_sha256"],
                "request_sha256": sha256_text(json.dumps(request, sort_keys=True, default=str)),
                "attempts": attempts,
                "retries": max(0, len(attempts) - 1),
                "observation_ids": observation_ids,
                "trace_event_ids": trace_ids,
                "board_context_message_seqs": board_context,
            },
            usage={
                "model": record["model_served"] or self.model,
                "requested_model": self.model,
                "provider": "openrouter",
                "input_tokens": input_tokens,
                "output_tokens": output_tokens,
                "cached_tokens": cached_tokens,
                "cost_usd": cost,
                "cost_known": cost is not None,
                "payload_ref": call["payload_ref"],
            },
            budget=self.budget.snapshot(),
        )

        tool_results = []
        if message.tool_calls:
            for call in message.tool_calls:
                try:
                    args = json.loads(call.function.arguments or "{}")
                except json.JSONDecodeError:
                    args = {}
                result = self._execute_tool(
                    call.function.name,
                    args,
                    decision_event_id=decision_event["event_id"],
                    request_id=self._request_id,
                )
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
        return True
