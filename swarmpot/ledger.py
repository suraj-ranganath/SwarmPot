"""Pre-startup attempt ledger and frozen validity policy.

Every episode appends an ``attempt`` record before any container starts, then
status transitions as the run moves through reset, infrastructure, attacker,
grading, and completion. ``runs/ledger.jsonl`` is append-only; each episode also
keeps a compact ``attempt.json``. The ledger is evaluator-private (under
``runs/``) and is never mounted into the attacker or decoy containers.
"""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional

from .util import RUNS_DIR, now_iso, read_json, sha256_text, write_json

LEDGER_SCHEMA_VERSION = 1
POLICY_VERSION = "attempt-validity-v1"

# Frozen before looking at arm outcomes. A non-valid attempt never counts as a
# defense success; an official verdict, if one exists, is still preserved.
VALIDITY_POLICY = {
    "version": POLICY_VERSION,
    "valid_requires": [
        "started",
        "attacker_started",
        "completed",
        "metrics_written",
        "no_config_mismatch",
    ],
    "exclusion_reasons": [
        "infra_failure",
        "never_started",
        "interrupted",
        "ungraded",
        "config_mismatch",
        "operator_abort",
        "no_attacker_actions",
        "host_sleep",
    ],
    "notes": (
        "Infrastructure failure, a missing verdict, and an unstarted episode are never "
        "defense success. Ordinary budget exhaustion, no decoy entry, unused "
        "communication, and unconvincing defenders are outcomes, not failures."
    ),
}


def ledger_path() -> Path:
    return RUNS_DIR / "ledger.jsonl"


def policy_hash() -> str:
    return sha256_text(json.dumps(VALIDITY_POLICY, sort_keys=True))


def config_fingerprint(cfg: Any, cve: str, arm_name: str, prompt: str) -> str:
    """Canonical hash of the resolved configuration that defines the attempt."""
    canonical = {
        "config": cfg.raw,
        "cve": cve,
        "arm": arm_name,
        "prompt_sha256": sha256_text(prompt),
        "validity_policy": policy_hash(),
    }
    return sha256_text(json.dumps(canonical, sort_keys=True, default=str))


def pair_id(cve: str, rep: int) -> str:
    return f"{cve}:r{rep}"


def _append(record: Dict[str, Any]) -> Dict[str, Any]:
    from .util import append_jsonl

    append_jsonl(ledger_path(), record)
    return record


def begin_attempt(
    episode_dir: Path,
    episode_id: str,
    cve: str,
    arm: str,
    rep: int,
    config_id: str,
    *,
    parent_attempt_id: Optional[str] = None,
    note: Optional[str] = None,
) -> Dict[str, Any]:
    episode_dir = Path(episode_dir)
    record = {
        "schema_version": LEDGER_SCHEMA_VERSION,
        "event": "attempt",
        "status": "attempted",
        "attempt_id": episode_id,
        "episode_id": episode_id,
        "parent_attempt_id": parent_attempt_id,
        "pair_id": pair_id(cve, rep),
        "cve": cve,
        "arm": arm,
        "repetition": rep,
        "config_id": config_id,
        "validity_policy": POLICY_VERSION,
        "note": note,
        "artifact_dir": str(episode_dir),
        "started_at": now_iso(),
        "actor_started": False,
        "graded": False,
        "completed": False,
        "valid": None,
        "exclusion_reason": None,
    }
    _append(record)
    write_json(episode_dir / "attempt.json", record)
    return record


def update_attempt(episode_dir: Path, attempt_id: str, event: str, status: str, **fields: Any) -> Dict[str, Any]:
    episode_dir = Path(episode_dir)
    record = {
        "schema_version": LEDGER_SCHEMA_VERSION,
        "event": event,
        "status": status,
        "attempt_id": attempt_id,
        "episode_id": attempt_id,
        "ts": now_iso(),
        **fields,
    }
    _append(record)
    current = read_json(episode_dir / "attempt.json", default={}) or {}
    current.update({k: v for k, v in record.items() if k not in ("schema_version", "event")})
    current["last_event"] = event
    if status in ("completed", "failed", "interrupted", "invalid", "ungraded"):
        current["finished_at"] = record["ts"]
    write_json(episode_dir / "attempt.json", current)
    return current


def finalize_attempt(
    episode_dir: Path,
    attempt_id: str,
    *,
    status: str,
    valid: bool,
    exclusion_reason: Optional[str],
    grader_status: Optional[bool],
    attacker_started: bool,
    stop_reason: Optional[str] = None,
    metrics: Optional[Dict[str, Any]] = None,
    error: Optional[str] = None,
    config_mismatch: bool = False,
) -> Dict[str, Any]:
    fields: Dict[str, Any] = {
        "valid": bool(valid),
        "exclusion_reason": exclusion_reason,
        "grader_status": grader_status,
        "attacker_started": bool(attacker_started),
        "completed": status == "completed",
        "stop_reason": stop_reason,
        "config_mismatch": bool(config_mismatch),
        "error": error,
    }
    if metrics is not None:
        fields["metrics_path"] = str(Path(episode_dir) / "metrics.json")
        fields["headline"] = metrics.get("headline")
    return update_attempt(episode_dir, attempt_id, "finalize", status, **fields)


def backfill_from_artifacts(runs_dir: Path) -> List[str]:
    """Retrospectively ledger episodes created before the pre-startup ledger.

    These entries are explicitly marked ``backfilled`` and must not be read as
    evidence that a pre-startup record existed. New attempts are never
    backfilled: ``begin_attempt`` writes before any container starts.
    """
    from .util import read_json

    runs_dir = Path(runs_dir)
    existing = {
        str(record.get("attempt_id"))
        for record in load_ledger()
        if record.get("event") == "attempt"
    }
    added: List[str] = []
    for manifest_path in sorted(runs_dir.glob("*/manifest.json")):
        manifest = read_json(manifest_path, default={}) or {}
        attempt_id = str(manifest.get("attempt_id") or manifest.get("episode_id") or "")
        if not attempt_id or attempt_id in existing:
            continue
        episode_dir = manifest_path.parent
        metrics = read_json(episode_dir / "metrics.json", default={}) or {}
        grader = read_json(episode_dir / "grader.json", default={}) or {}
        attacker = (metrics.get("audit", {}) or {}).get("attacker", {}) or {}
        started = bool(metrics) or bool(grader)
        attacker_started = attacker.get("wall_seconds") is not None
        completed = bool(metrics) and attacker_started
        valid = bool(completed and attacker_started and grader.get("status") is not None)
        reason = None
        status = "completed"
        if metrics and not attacker_started:
            status = "failed"
            reason = "infra_failure"
        elif not metrics:
            status = "ungraded"
            reason = "never_started"
        elif not completed:
            status = "failed"
            reason = "infra_failure"
        elif grader.get("status") is None:
            status = "ungraded"
            reason = "ungraded"
        base = {
            "schema_version": LEDGER_SCHEMA_VERSION,
            "backfilled": True,
            "backfill_source": "manifest+metrics+grader",
            "attempt_id": attempt_id,
            "episode_id": attempt_id,
            "pair_id": pair_id(manifest.get("cve", ""), int(manifest.get("repetition") or 0)),
            "cve": manifest.get("cve"),
            "arm": manifest.get("arm"),
            "repetition": manifest.get("repetition"),
            "config_id": manifest.get("config_id"),
            "artifact_dir": str(episode_dir),
            "started_at": manifest.get("created_at"),
        }
        _append({**base, "event": "attempt", "status": "attempted", "note": "backfilled_pre_ledger_run"})
        _append({
            **base,
            "event": "finalize",
            "status": status,
            "ts": now_iso(),
            "started": started,
            "finished_at": now_iso(),
            "valid": valid,
            "exclusion_reason": reason,
            "grader_status": grader.get("status"),
            "attacker_started": attacker_started,
            "actor_started": attacker_started,
            "graded": grader.get("status") is not None,
            "completed": completed,
            "metrics_path": str(episode_dir / "metrics.json") if metrics else None,
            "error": None,
        })
        if not (episode_dir / "attempt.json").exists():
            write_json(episode_dir / "attempt.json", {**base, "status": "backfilled"})
        added.append(attempt_id)
        existing.add(attempt_id)
    return added


def reconcile_backfilled(runs_dir: Path) -> int:
    """Correct derived ledger rows for prepared/ungraded backfilled attempts."""
    from .util import read_json

    fixed = 0
    for row in summarize_ledger()["attempts"]:
        if not row.get("backfilled"):
            continue
        episode = Path(row.get("artifact_dir") or "")
        if not episode.is_dir() or (episode / "metrics.json").exists():
            continue
        if (
            row.get("status") == "ungraded"
            and row.get("started")
            and row.get("exclusion_reason") == "never_started"
        ):
            continue
        grader = read_json(episode / "grader.json", default={}) or {}
        base = {
            "schema_version": LEDGER_SCHEMA_VERSION,
            "backfilled": True,
            "backfill_source": "reconcile",
            "attempt_id": row["attempt_id"],
            "episode_id": row["attempt_id"],
            "pair_id": row.get("pair_id"),
            "cve": row.get("cve"),
            "arm": row.get("arm"),
            "repetition": row.get("repetition"),
            "config_id": row.get("config_id"),
            "artifact_dir": str(episode),
            "started_at": row.get("started_at"),
        }
        _append({
            **base,
            "event": "finalize",
            "status": "ungraded",
            "ts": now_iso(),
            "started": bool(grader),
            "valid": False,
            "exclusion_reason": "never_started",
            "grader_status": grader.get("status"),
            "attacker_started": False,
            "actor_started": False,
            "graded": grader.get("status") is not None,
            "completed": False,
            "metrics_path": None,
            "error": None,
            "note": "backfill_consistency_fix",
        })
        fixed += 1
    return fixed


def classify_validity(
    *,
    started: bool,
    attacker_started: bool,
    completed: bool,
    metrics_written: bool,
    interrupted: bool = False,
    grader_status: Optional[bool] = None,
    config_mismatch: bool = False,
    attacker_actions: Optional[int] = None,
) -> Dict[str, Any]:
    """Apply the frozen validity policy to observed attempt facts."""
    reason = None
    if interrupted:
        reason = "interrupted"
    elif not started:
        reason = "never_started"
    elif not attacker_started:
        reason = "never_started"
    elif attacker_actions is not None and attacker_actions <= 0:
        reason = "no_attacker_actions"
    elif config_mismatch:
        reason = "config_mismatch"
    elif not completed or not metrics_written:
        reason = "infra_failure"
    valid = reason is None
    return {
        "valid": valid,
        "exclusion_reason": reason,
        "validity_policy": POLICY_VERSION,
        "grader_status": grader_status,
    }


def load_ledger(path: Optional[Path] = None) -> List[Dict[str, Any]]:
    from .util import read_jsonl

    return read_jsonl(Path(path) if path else ledger_path())


def summarize_ledger(path: Optional[Path] = None) -> Dict[str, Any]:
    """Fold append-only transitions into one row per attempt plus counts."""
    attempts: Dict[str, Dict[str, Any]] = {}
    for record in load_ledger(path):
        attempt_id = record.get("attempt_id")
        if not attempt_id:
            continue
        row = attempts.setdefault(
            attempt_id,
            {
                "attempt_id": attempt_id,
                "episode_id": attempt_id,
                "status": "attempted",
                "started": False,
                "attacker_started": False,
                "completed": False,
                "graded": False,
                "valid": None,
                "exclusion_reason": None,
                "events": [],
            },
        )
        row["events"].append(record.get("event"))
        for key in (
            "status",
            "pair_id",
            "cve",
            "arm",
            "repetition",
            "config_id",
            "started_at",
            "finished_at",
            "artifact_dir",
            "parent_attempt_id",
            "backfilled",
            "grader_status",
            "stop_reason",
            "error",
            "valid",
            "exclusion_reason",
            "metrics_path",
        ):
            if key in record and record[key] is not None:
                row[key] = record[key]
        if record.get("status") in ("started", "prepared") or record.get("started"):
            row["started"] = True
        if (
            record.get("status") == "attacker_started"
            or record.get("actor_started")
            or record.get("attacker_started")
        ):
            row["attacker_started"] = True
        if record.get("graded") or record.get("status") == "graded":
            row["graded"] = True
        if record.get("status") == "completed":
            row["completed"] = True

    counts = {
        "attempted": len(attempts),
        "started": sum(1 for r in attempts.values() if r["started"]),
        "attacker_started": sum(1 for r in attempts.values() if r["attacker_started"]),
        "graded": sum(1 for r in attempts.values() if r["graded"]),
        "completed": sum(1 for r in attempts.values() if r["completed"]),
        "valid": sum(1 for r in attempts.values() if r["valid"] is True),
        "failed": sum(1 for r in attempts.values() if r["status"] == "failed"),
        "interrupted": sum(1 for r in attempts.values() if r["status"] == "interrupted"),
        "ungraded": sum(1 for r in attempts.values() if r["status"] == "ungraded"),
    }
    return {
        "policy": VALIDITY_POLICY,
        "policy_hash": policy_hash(),
        "counts": counts,
        "attempts": [attempts[key] for key in sorted(attempts)],
    }


def write_ledger_summary(out_dir: Optional[Path] = None) -> Dict[str, Any]:
    out_dir = Path(out_dir) if out_dir else RUNS_DIR / "summary"
    summary = summarize_ledger()
    write_json(out_dir / "ledger_summary.json", summary)

    import csv

    fields = [
        "attempt_id",
        "pair_id",
        "cve",
        "arm",
        "repetition",
        "status",
        "started",
        "attacker_started",
        "graded",
        "completed",
        "valid",
        "exclusion_reason",
        "grader_status",
        "stop_reason",
        "parent_attempt_id",
        "config_id",
        "started_at",
        "finished_at",
        "artifact_dir",
    ]
    out_dir.mkdir(parents=True, exist_ok=True)
    with open(out_dir / "all_attempts.csv", "w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields)
        writer.writeheader()
        for row in summary["attempts"]:
            writer.writerow({key: _csv_value(row.get(key)) for key in fields})
    return summary


def _csv_value(value: Any) -> Any:
    if value is None:
        return ""
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, (list, dict)):
        return json.dumps(value, sort_keys=True)
    return value


def seed_inventory(root: Path) -> List[Dict[str, Any]]:
    """Deterministic hash inventory for the fixed decoy seed tree."""
    from .util import sha256_bytes

    root = Path(root)
    rows: List[Dict[str, Any]] = []
    if not root.is_dir():
        return rows
    for path in sorted(p for p in root.rglob("*") if p.is_file()):
        data = path.read_bytes()
        rows.append(
            {
                "relpath": str(path.relative_to(root)),
                "sha256": sha256_bytes(data),
                "bytes": len(data),
            }
        )
    return rows


def seed_inventory_hash(rows: Iterable[Dict[str, Any]]) -> str:
    return hashlib.sha256(
        json.dumps(list(rows), sort_keys=True).encode("utf-8")
    ).hexdigest()
