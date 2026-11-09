#!/usr/bin/env python3
"""Cross-episode state-isolation check (handoff v0.2, item 1).

Writes a unique synthetic marker into episode X's attacker/decoy/Cowrie state,
then searches episode Y's host state and (if live) containers for it. The
marker is never passed to either team; this is evaluator-private instrumentation.

Usage:
    python scripts/isolation_check.py --source runs/<X> --episode runs/<Y>

Exit code 0 only when the marker is present in X and absent in Y.
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
import uuid
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from swarmpot.config import load_config
from swarmpot.cve_adapter import CveBench
from swarmpot.isolation import scan_paths, write_isolation_check
from swarmpot.util import RUNS_DIR, read_json, write_json


def write_marker(source: Path, marker: str) -> list[str]:
    targets = [
        source / "attacker" / "artemis_session" / "MARKER.txt",
        source / "attacker" / "artemis_session" / "workspaces" / "marker" / "MARKER.txt",
        source / "decoy_home" / "MARKER.txt",
        source / "cowrie_state" / "MARKER.txt",
    ]
    written = []
    for path in targets:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(f"isolation marker: {marker}\n", encoding="utf-8")
        written.append(str(path))
    # Also exercise the ARTEMIS history and findings-shaped stores.
    todo = source / "attacker" / "artemis_session" / "supervisor_todo.json"
    todo.parent.mkdir(parents=True, exist_ok=True)
    todo.write_text(json.dumps({"marker": marker, "items": []}) + "\n", encoding="utf-8")
    written.append(str(todo))
    findings = source / "attacker" / "artemis_session" / "session_vulnerabilities.jsonl"
    with open(findings, "a", encoding="utf-8") as handle:
        handle.write(json.dumps({"marker": marker, "kind": "synthetic"}) + "\n")
    written.append(str(findings))
    return written


def container_scan(episode: Path, marker: str) -> dict:
    manifest = read_json(episode / "manifest.json", default={}) or {}
    project = manifest.get("compose_project")
    if not project:
        return {"checked": False, "reason": "no manifest", "found": False, "hits": []}
    cfg = load_config()
    bench = CveBench(cfg.cvebench)
    override = episode / "compose.override.yml"
    targets = {
        "attacker": ["/logs", "/opt/artemis", "/root/.codex"],
        "decoy": ["/home/admin", "/var/log/gateway"],
        "cowrie": ["/var/lib/cowrie", "/var/log/cowrie"],
    }
    hits = []
    checked = []
    for service, paths in targets.items():
        cmd = bench.compose_cmd(manifest["cve"], project, override, manifest["seed"]) + [
            "ps", "-q", service,
        ]
        proc = subprocess.run(cmd, env=bench.env(manifest["seed"]), text=True, capture_output=True)
        cids = [line.strip() for line in proc.stdout.splitlines() if line.strip()]
        grep = f"grep -rl -- {marker} {' '.join(paths)} 2>/dev/null || true"
        if cids:
            checked.append(service)
            exec_proc = subprocess.run(
                ["docker", "exec", cids[-1], "sh", "-lc", grep], text=True, capture_output=True
            )
            out = exec_proc.stdout
        else:
            # The service may be declared but not started (e.g. the attacker
            # profile, or a prepared control stack). Run the same image with the
            # same per-episode mounts in a throwaway container.
            run_cmd = bench.compose_cmd(manifest["cve"], project, override, manifest["seed"]) + [
                "run", "--rm", "--no-deps", "--entrypoint", "sh", service, "-lc", grep,
            ]
            run_proc = subprocess.run(run_cmd, env=bench.env(manifest["seed"]), text=True, capture_output=True)
            if "no such service" in (run_proc.stderr or "").lower():
                continue
            checked.append(f"{service}:one-off")
            out = run_proc.stdout
        for line in out.splitlines():
            if line.strip():
                hits.append({"service": service, "path": line.strip()})
    return {
        "checked": bool(checked),
        "services": checked,
        "found": bool(hits),
        "hits": hits,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--source", required=True, help="episode that receives the marker")
    parser.add_argument("--episode", required=True, help="fresh episode that must not contain it")
    parser.add_argument("--marker", default=None)
    args = parser.parse_args()

    source = Path(args.source)
    episode = Path(args.episode)
    if not (source / "manifest.json").exists():
        print(f"source is not an episode: {source}", file=sys.stderr)
        return 2
    if not (episode / "manifest.json").exists():
        print(f"episode is not an episode: {episode}", file=sys.stderr)
        return 2

    marker = args.marker or f"SWARMPOT_MARKER_{uuid.uuid4().hex}"
    written = write_marker(source, marker)

    source_scan = scan_paths([source], marker)
    target_scan = scan_paths([episode], marker)
    containers = container_scan(episode, marker)
    report = write_isolation_check(
        episode,
        source_episode=source,
        marker=marker,
        source_scan=source_scan,
        target_scan=target_scan,
        container_scan=containers,
    )
    report["marker_written_to"] = written
    write_json(episode / "isolation_check.json", report)

    print(json.dumps({
        "pass": report["pass"],
        "marker_sha256": report["marker_sha256"],
        "source_hits": len(source_scan["hits"]),
        "target_hits": len(target_scan["hits"]),
        "container_scan": containers,
        "report": str(episode / "isolation_check.json"),
    }, indent=2))
    return 0 if report["pass"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
