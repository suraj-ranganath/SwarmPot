from __future__ import annotations

import hashlib
import json
import os
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional


ROOT = Path(__file__).resolve().parent.parent
RUNS_DIR = Path(os.environ.get("SWARMPOT_RUNS_DIR", ROOT / "runs"))
DOCKER_DIR = ROOT / "docker"
CONFIGS_DIR = ROOT / "configs"


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds")


def utc_stamp() -> str:
    return datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")


def ensure_dir(path: Path) -> Path:
    path.mkdir(parents=True, exist_ok=True)
    return path


def sha256_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def atomic_write(path: Path, text: str) -> None:
    """Write text atomically inside the target directory."""
    ensure_dir(path.parent)
    fd, tmp = tempfile.mkstemp(dir=str(path.parent), prefix=".tmp-", text=True)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(text)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(tmp, path)
    finally:
        if os.path.exists(tmp):
            os.unlink(tmp)


def read_json(path: Path, default: Any = None) -> Any:
    try:
        with open(path, "r", encoding="utf-8") as handle:
            return json.load(handle)
    except (FileNotFoundError, json.JSONDecodeError):
        return default


def write_json(path: Path, payload: Any) -> None:
    atomic_write(path, json.dumps(payload, indent=2, sort_keys=True, default=str) + "\n")


def append_jsonl(path: Path, payload: Dict[str, Any]) -> None:
    ensure_dir(path.parent)
    line = json.dumps(payload, sort_keys=True, default=str)
    with open(path, "a", encoding="utf-8") as handle:
        handle.write(line + "\n")
        handle.flush()
        os.fsync(handle.fileno())


def read_jsonl(path: Path) -> List[Dict[str, Any]]:
    rows: List[Dict[str, Any]] = []
    try:
        with open(path, "r", encoding="utf-8") as handle:
            for line in handle:
                line = line.strip()
                if not line:
                    continue
                try:
                    rows.append(json.loads(line))
                except json.JSONDecodeError:
                    continue
    except FileNotFoundError:
        return []
    return rows


def iter_jsonl_incremental(path: Path, offset: int) -> "tuple[List[Dict[str, Any]], int]":
    """Read JSONL records appended after byte *offset*.

    Returns (records, new_offset). A partially written trailing line is left for
    the next call: the returned offset is advanced only past complete lines.
    """
    rows: List[Dict[str, Any]] = []
    try:
        size = path.stat().st_size
    except FileNotFoundError:
        return rows, offset
    if size < offset:
        # File was truncated/replaced (e.g. container restart).
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
            try:
                rows.append(json.loads(raw.decode("utf-8")))
            except (json.JSONDecodeError, UnicodeDecodeError):
                pass
        new_offset = handle.tell()
    return rows, new_offset


def clamp(value: float, low: float, high: float) -> float:
    return max(low, min(high, value))


def pct(numerator: Optional[float], denominator: Optional[float]) -> Optional[float]:
    if numerator is None or denominator in (None, 0):
        return None
    return float(numerator) / float(denominator)


def mean(values: Iterable[float]) -> Optional[float]:
    values = list(values)
    if not values:
        return None
    return sum(values) / len(values)


def safe_host_path(path: str) -> Path:
    """Resolve a user/agent supplied path and guarantee it stays under runs/."""
    candidate = Path(path).expanduser()
    if not candidate.is_absolute():
        candidate = RUNS_DIR / candidate
    resolved = candidate.resolve()
    if RUNS_DIR.resolve() not in resolved.parents and resolved != RUNS_DIR.resolve():
        raise ValueError(f"path escapes runs directory: {path}")
    return resolved
