"""Cross-episode isolation manifests and marker checks.

The episode controller gives every attempt a new directory tree, new compose
project, new volumes, and new containers. This module makes that explicit,
records the persistence locations, and provides a repeatable marker test:
write a unique string into episode X's attacker state, then search episode Y's
host-side state and live containers for it.
"""

from __future__ import annotations

import hashlib
import os
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional

from .util import now_iso, sha256_bytes

MAX_SCAN_BYTES = 25 * 1024 * 1024


def persistence_inventory(paths: Any) -> Dict[str, str]:
    """Every writable location an attempt can use, and its reset mechanism."""
    return {
        "episode_root": f"{paths.root} (new directory per attempt; never reused)",
        "attacker_artemis_session": (
            f"{paths.attacker}/artemis_session (supervisor iterations, workspaces, "
            "realtime_context, final_result, reports; new directory per attempt)"
        ),
        "attacker_runtime": (
            f"{paths.attacker}/*.json (budget, summary, input, container log); new per attempt"
        ),
        "cowrie_state": f"{paths.cowrie_state} (host keys, tty, downloads; new per attempt)",
        "cowrie_log": f"{paths.cowrie_log} (JSON/text session log; new per attempt)",
        "decoy_home": f"{paths.decoy_home} (reset from the fixed seed image every attempt)",
        "decoy_log": f"{paths.decoy_log} (command audit; new per attempt)",
        "board": f"{paths.root}/board.sqlite (namespaced by episode id; new per attempt)",
        "target_and_db_volumes": (
            "Docker named volumes scoped to the episode compose project; removed with "
            "`docker compose down --volumes --remove-orphans` before every attempt"
        ),
        "container_local_ephemeral": (
            "Attacker /root/.codex sessions, /tmp, and worker homes live only inside the "
            "attempt container and are destroyed with it"
        ),
        "shared_read_only": (
            "vendor/ checkouts, built images, and runs/openrouter_pricing.json contain no "
            "episode-specific content and are read-only to agents"
        ),
        "external_provider_caches": (
            "The model provider may cache transport/session data outside this machine; the "
            "harness does not control provider-side caches and does not store prompts there "
            "beyond normal API requests"
        ),
    }


def write_reset_manifest(
    episode_dir: Path,
    *,
    episode_id: str,
    compose_project: str,
    paths: Any,
    previous_attempt_id: Optional[str],
    seed_rows: Iterable[Dict[str, Any]],
    lure_enabled: bool,
    decoy_enabled: bool,
    reset_command: str,
) -> Dict[str, Any]:
    from .ledger import seed_inventory_hash

    payload = {
        "schema_version": 1,
        "episode_id": episode_id,
        "compose_project": compose_project,
        "created_at": now_iso(),
        "previous_attempt_id": previous_attempt_id,
        "fresh_namespace": True,
        "reset_method": reset_command,
        "volumes_removed": True,
        "decoy_enabled": decoy_enabled,
        "decoy_seed_reset": decoy_enabled,
        "lure_enabled": lure_enabled,
        "breadcrumb_state": "fresh per-episode sidecar/breadcrumb_profile.json; regenerated before attacker startup",
        "seed_inventory_sha256": seed_inventory_hash(list(seed_rows)),
        "persistence": persistence_inventory(paths),
        "shared_writable_state_between_attempts": [],
    }
    from .util import write_json

    write_json(Path(episode_dir) / "reset.json", payload)
    return payload


def scan_paths(roots: Iterable[Path], marker: str, max_bytes: int = MAX_SCAN_BYTES) -> Dict[str, Any]:
    """Search host directories for a marker, without loading large files whole."""
    needle = marker.encode("utf-8")
    hits: List[Dict[str, Any]] = []
    scanned = 0
    skipped: List[Dict[str, Any]] = []
    for root in roots:
        root = Path(root)
        if not root.exists():
            continue
        candidates = [root] if root.is_file() else [p for p in root.rglob("*") if p.is_file()]
        for path in candidates:
            try:
                size = path.stat().st_size
            except OSError:
                continue
            if size > max_bytes:
                skipped.append({"path": str(path), "bytes": size, "reason": "larger_than_scan_limit"})
                continue
            scanned += 1
            try:
                data = path.read_bytes()
            except OSError as exc:
                skipped.append({"path": str(path), "reason": f"unreadable: {exc}"})
                continue
            offset = data.find(needle)
            if offset >= 0:
                hits.append({"path": str(path), "offset": offset})
    return {
        "marker": marker,
        "roots": [str(r) for r in roots],
        "files_scanned": scanned,
        "skipped": skipped,
        "hits": hits,
        "found": bool(hits),
    }


def write_isolation_check(
    episode_dir: Path,
    *,
    source_episode: Path,
    marker: str,
    source_scan: Dict[str, Any],
    target_scan: Dict[str, Any],
    container_scan: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    from .util import write_json

    report = {
        "schema_version": 1,
        "checked_at": now_iso(),
        "source_episode": str(source_episode),
        "target_episode": str(episode_dir),
        "marker_sha256": hashlib.sha256(marker.encode("utf-8")).hexdigest(),
        "source_marker_present": source_scan.get("found", False),
        "target_marker_present": target_scan.get("found", False),
        "source_scan": source_scan,
        "target_scan": target_scan,
        "container_scan": container_scan,
        "pass": bool(source_scan.get("found")) and not target_scan.get("found") and not (container_scan or {}).get("found"),
    }
    write_json(Path(episode_dir) / "isolation_check.json", report)
    return report


def file_sha256(path: Path) -> Optional[str]:
    try:
        return sha256_bytes(Path(path).read_bytes())
    except OSError:
        return None
