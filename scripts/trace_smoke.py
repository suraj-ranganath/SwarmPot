#!/usr/bin/env python3
"""Deterministic correlated-logging smoke test (handoff v0.2, item 4).

Runs against a live prepared E episode. A scripted (non-LLM) defender exercises
observation, a committed edit, a denied edit, and a board post/read while real
SSH traffic crosses Cowrie. The script then verifies the correlation chain in
events.jsonl and writes trace_smoke.json.

This is instrumentation evidence, not a scientific result.

Usage:
    python scripts/trace_smoke.py --episode runs/<E episode>
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from swarmpot.board import Board
from swarmpot.config import load_config
from swarmpot.cowrie_events import CowrieIndex
from swarmpot.defenders import DecoyFiles, DecoyManifest, DefenderAgent, DefenderBudget
from swarmpot.events import EventLog
from swarmpot.overrides import EpisodePaths
from swarmpot.pricing import Pricing
from swarmpot.util import read_json, sha256_text, write_json


def ssh_traffic(manifest: dict, password: str) -> dict:
    network = f"{manifest['compose_project']}_exposure_net"
    script = (
        f"printf '#!/bin/sh\\necho {password}\\n' > /tmp/askpass; chmod +x /tmp/askpass; "
        "export SSH_ASKPASS=/tmp/askpass SSH_ASKPASS_REQUIRE=force; "
        "setsid -w ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null "
        "-p 2222 admin@fileserver-01 "
        "\"cat /home/admin/README.txt; echo smoke > /home/admin/attacker-note.txt; "
        "ls -la /home/admin\""
    )
    proc = subprocess.run(
        ["docker", "run", "--rm", "--network", network, "--entrypoint", "bash",
         "swarmpot/attacker:dev", "-lc", script],
        text=True, capture_output=True, timeout=180,
    )
    return {"returncode": proc.returncode, "stdout": proc.stdout[-4000:], "stderr": proc.stderr[-1000:]}


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--episode", required=True)
    args = parser.parse_args()
    episode = Path(args.episode)
    manifest = read_json(episode / "manifest.json")
    if not manifest:
        print("not an episode", file=sys.stderr)
        return 2
    cfg = load_config()
    paths = EpisodePaths.under(episode)
    events = EventLog(episode, manifest["episode_id"], manifest["arm"], attempt_id=manifest.get("attempt_id"))
    index = CowrieIndex(
        paths.cowrie_log / "cowrie.json",
        ["defender-1", "defender-2"],
        events=events,
    )
    decoy_manifest = DecoyManifest(episode / "decoy_manifest.jsonl")
    board = Board(
        path=episode / "board.sqlite",
        episode_id=manifest["episode_id"],
        team="defenders",
        max_messages=cfg.defender.board_messages,
    )
    budget = DefenderBudget(cfg.defender.combined_decisions, 2, cfg.defender.max_cost_usd)
    agent = DefenderAgent(
        agent_id="defender-1",
        model=cfg.defender.model,
        session_dir=episode / "agents" / "defender-1-smoke",
        events=events,
        index=index,
        decoy=DecoyFiles(paths.decoy_home, decoy_manifest, cfg.decoy.max_file_bytes, "defender-1", events),
        budget=budget,
        pricing=Pricing(cache_path=None),
        board=board,
        poll_seconds=1.0,
        max_output_tokens=256,
        temperature=0.0,
        reasoning_effort=None,
    )

    decision = events.emit(
        "defender",
        "llm_decision",
        agent_id="defender-1",
        tool="scripted",
        status="scripted",
        payload={"scripted": True, "trigger": "trace_smoke"},
    )

    traffic = ssh_traffic(manifest, cfg.decoy.password)
    time.sleep(2)
    index.poll()

    read_session = agent._execute_tool(
        "read_session", {"since_seq": 0, "limit": 50}, decision_event_id=decision["event_id"]
    )
    read_file = agent._execute_tool(
        "read_decoy_files", {"path": "/home/admin/README.txt"}, decision_event_id=decision["event_id"]
    )
    edit = agent._execute_tool(
        "write_decoy_file",
        {
            "path": "/home/admin/deploy/runbook.txt",
            "content": "Migration runbook\nReplica host: replica-02.internal\nToken: rb_7c1e9a4d2f80\n",
        },
        decision_event_id=decision["event_id"],
    )
    denied = agent._execute_tool(
        "write_decoy_file",
        {"path": "/home/admin/../../escape.txt", "content": "escape"},
        decision_event_id=decision["event_id"],
    )
    post = agent._execute_tool(
        "board_post",
        {"body": "Planted /home/admin/deploy/runbook.txt for the migration story."},
        decision_event_id=decision["event_id"],
    )
    board_read = agent._execute_tool(
        "board_read", {"since_seq": 0}, decision_event_id=decision["event_id"]
    )
    decision2 = events.emit(
        "defender",
        "llm_decision",
        agent_id="defender-1",
        tool="scripted",
        status="scripted",
        refs=[str(post.get("seq"))],
        payload={
            "scripted": True,
            "trigger": "board_followup",
            "board_context_message_seqs": list(agent._board_context_seqs),
        },
    )
    followup = agent._execute_tool(
        "write_decoy_file",
        {
            "path": "/home/admin/deploy/board-followup.txt",
            "content": "Follow-up recorded after reading the teammate board.\n",
        },
        decision_event_id=decision2["event_id"],
    )
    board.close()

    rows = [json.loads(line) for line in (episode / "events.jsonl").read_text().splitlines() if line.strip()]
    ssh_rows = [r for r in rows if r.get("kind") == "ssh_event"]
    tool_rows = [r for r in rows if r.get("kind") == "tool_call" and r.get("agent_id") == "defender-1"]
    edit_rows = [r for r in rows if r.get("kind") == "decoy_edit"]
    board_rows = [r for r in rows if r.get("kind") == "board_post"]

    checks = []

    def check(name: str, ok: bool, detail: object) -> None:
        checks.append({"name": name, "ok": bool(ok), "detail": detail})

    ssh_commands = [r for r in ssh_rows if r.get("tool") == "cowrie.command.input"]
    check("ssh_command_events_present", bool(ssh_commands), [r["payload"].get("input") for r in ssh_commands])
    check("ssh_events_have_observation_ids", all(r["payload"].get("observation_id") for r in ssh_rows), len(ssh_rows))
    check("session_owner_assigned", any(r.get("kind") == "session_owner" for r in rows), None)
    rs = [r for r in tool_rows if r.get("tool") == "read_session"]
    observed_ids = (rs[-1]["payload"].get("observed_trace_event_ids") if rs else []) or []
    check("read_session_returns_trace_ids", bool(observed_ids), len(observed_ids))
    rf = [r for r in tool_rows if r.get("tool") == "read_decoy_files"]
    seed_readme = (Path("docker/decoy/seed/home/admin/README.txt")).read_text(encoding="utf-8")
    check(
        "file_observation_matches_seed_hash",
        bool(rf) and rf[-1]["payload"].get("sha256") == __import__("hashlib").sha256(seed_readme.encode()).hexdigest(),
        rf[-1]["payload"].get("sha256") if rf else None,
    )
    check("committed_edit_logged", bool(edit_rows) and edit_rows[-1]["payload"].get("commit_status") == "committed", edit_rows[-1]["payload"] if edit_rows else None)
    check("denied_edit_logged", denied.get("error") is not None, denied)
    denied_rows = [r for r in tool_rows if r.get("tool") == "write_decoy_file" and r.get("status") == "denied"]
    check("denied_edit_not_counted_as_commit", bool(denied_rows) and not (episode.parent / "escape.txt").exists(), len(denied_rows))
    check("board_post_logged", bool(board_rows) and board_rows[-1]["payload"].get("message_id") == post.get("seq"), post)
    br = [r for r in tool_rows if r.get("tool") == "board_read"]
    check("board_read_returns_message_id", bool(br) and post.get("seq") in (br[-1]["payload"].get("message_seqs") or []), br[-1]["payload"] if br else None)
    smoke_tool_rows = [
        r for r in tool_rows if decision["seq"] < r.get("seq", 0) < decision2["seq"]
    ]
    check(
        "tool_calls_link_to_decision",
        bool(smoke_tool_rows) and all(r.get("parent_event_id") == decision["event_id"] for r in smoke_tool_rows),
        [r.get("parent_event_id") for r in smoke_tool_rows],
    )
    smoke_edit_rows = [
        r for r in edit_rows if decision["seq"] < r.get("seq", 0) < decision2["seq"]
    ]
    check(
        "edit_links_to_decision",
        bool(smoke_edit_rows)
        and all(r.get("payload", {}).get("source_decision_event_id") == decision["event_id"] for r in smoke_edit_rows),
        [r.get("payload", {}).get("source_decision_event_id") for r in smoke_edit_rows],
    )
    check("event_schema_v2", all(r.get("schema_version") == 2 for r in rows), rows[-1].get("schema_version"))
    br_rows = [r for r in board_rows if r.get("seq", 0) > decision["seq"]]
    check(
        "board_context_in_next_decision",
        post.get("seq") in (decision2.get("payload", {}).get("board_context_message_seqs") or []),
        decision2.get("payload", {}).get("board_context_message_seqs"),
    )
    follow_rows = [r for r in tool_rows if r.get("seq", 0) > decision2["seq"] and r.get("tool") == "write_decoy_file"]
    check(
        "followup_action_after_board_read",
        bool(follow_rows)
        and follow_rows[-1].get("status") == "committed"
        and bool(br) and follow_rows[-1]["seq"] > br[-1]["seq"],
        {"followup_status": follow_rows[-1].get("status") if follow_rows else None},
    )

    report = {
        "schema_version": 1,
        "kind": "deterministic_instrumentation_smoke",
        "episode_id": manifest["episode_id"],
        "traffic": traffic,
        "results": {
            "read_session": read_session,
            "read_file": read_file,
            "edit": edit,
            "denied": denied,
            "board_post": post,
            "board_read": board_read,
        },
        "checks": checks,
        "pass": all(c["ok"] for c in checks),
    }
    write_json(episode / "trace_smoke.json", report)
    print(json.dumps({"pass": report["pass"], "checks": checks}, indent=2))
    return 0 if report["pass"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
