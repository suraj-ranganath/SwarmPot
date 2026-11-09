"""G5/G6 driver: run the defender team against a live prepared episode.

Usage: python scripts/verify_defenders.py <episode_dir> <seconds> <sessions>

Starts the same DefenderTeam construction used by run_episode, generates a few
concurrent proxied SSH sessions through Cowrie, then dumps the budget, board and
event counts to <episode_dir>/g5_defender_state.json.
"""

from __future__ import annotations

import json
import subprocess
import sys
import threading
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from swarmpot.board import Board
from swarmpot.config import load_config
from swarmpot.cowrie_events import CowrieIndex
from swarmpot.defenders import (
    DecoyFiles,
    DecoyManifest,
    DefenderAgent,
    DefenderBudget,
    DefenderTeam,
)
from swarmpot.events import EventLog
from swarmpot.overrides import EpisodePaths
from swarmpot.pricing import Pricing
from swarmpot.util import RUNS_DIR, read_json

SSH = (
    "printf '#!/bin/sh\\necho swarmpot\\n' > /tmp/askpass; chmod +x /tmp/askpass; "
    "export SSH_ASKPASS=/tmp/askpass SSH_ASKPASS_REQUIRE=force; "
    "setsid -w ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null "
    "-p 2222 admin@fileserver-01 "
)


def traffic(project: str, sessions: int) -> str:
    network = f"{project}_exposure_net"
    cmds = [
        "id; uname -a; ls -la /home/admin; cat /home/admin/secrets.env",
        "find /home/admin -maxdepth 2 -type f -print; cat /home/admin/deploy/config.yml",
        "echo probe > /home/admin/nothing-to-see.txt; ls -la /home/admin",
    ]
    script = "".join(
        f"({SSH}{json.dumps(cmds[i % len(cmds)])!r} > /tmp/s{i}.out 2>&1) & "
        for i in range(sessions)
    )
    script += "wait; for f in /tmp/s*.out; do echo \"--- $f\"; tail -3 \"$f\"; done"
    proc = subprocess.run(
        [
            "docker", "run", "--rm", "--network", network,
            "--entrypoint", "bash", "swarmpot/attacker:dev", "-lc", script,
        ],
        text=True, capture_output=True, timeout=180,
    )
    return proc.stdout[-3000:] + proc.stderr[-1000:]


def main() -> int:
    episode_dir = Path(sys.argv[1])
    seconds = int(sys.argv[2]) if len(sys.argv) > 2 else 45
    sessions = int(sys.argv[3]) if len(sys.argv) > 3 else 2
    manifest = read_json(episode_dir / "manifest.json")
    cfg = load_config()
    arm_name = manifest["arm"]
    arm = cfg.arm(arm_name)
    paths = EpisodePaths.under(episode_dir)
    events = EventLog(episode_dir, manifest["episode_id"], arm_name)
    index = CowrieIndex(paths.cowrie_log / "cowrie.json", [f"defender-{i + 1}" for i in range(arm.defenders)])
    manifest_files = DecoyManifest(episode_dir / "decoy_manifest.jsonl")
    budget = DefenderBudget(cfg.defender.combined_decisions, max(1, arm.defenders), cfg.defender.max_cost_usd)
    board = Board(
        path=episode_dir / "board.sqlite",
        episode_id=manifest["episode_id"],
        team="defenders",
        max_messages=cfg.defender.board_messages,
    ) if arm.board else None
    pricing = Pricing(cache_path=RUNS_DIR / "openrouter_pricing.json")

    agents = []
    for i in range(arm.defenders):
        agent_id = f"defender-{i + 1}"
        agents.append(
            DefenderAgent(
                agent_id=agent_id,
                model=cfg.defender.model,
                session_dir=episode_dir / "agents" / agent_id,
                events=events,
                index=index,
                decoy=DecoyFiles(paths.decoy_home, manifest_files, cfg.decoy.max_file_bytes, agent_id, events),
                budget=budget,
                pricing=pricing,
                board=board,
                poll_seconds=cfg.defender.poll_seconds,
                max_output_tokens=cfg.defender.max_output_tokens,
                temperature=cfg.defender.temperature,
                reasoning_effort=cfg.defender.reasoning_effort,
            )
        )

    team = DefenderTeam(agents, index, budget, cfg.defender.poll_seconds)
    stop = threading.Event()
    thread = threading.Thread(target=team.run, args=(stop,), daemon=True)
    thread.start()
    time.sleep(2)
    out = traffic(manifest["compose_project"], sessions)
    deadline = time.time() + seconds
    while time.time() < deadline:
        time.sleep(2)
    stop.set()
    thread.join(timeout=60)

    state = {
        "episode_id": manifest["episode_id"],
        "arm": arm_name,
        "defenders": arm.defenders,
        "board_enabled": arm.board,
        "budget": budget.snapshot(),
        "board_messages": board.count() if board else 0,
        "board_rows": board.read_since(0) if board else [],
        "sessions": index.sessions(),
        "commands": index.command_count(),
        "sessions_owned": index.session_owner,
        "traffic_tail": out,
        "decisions_by_agent": {a.agent_id: a.decisions for a in agents},
        "tool_schemas": {
            a.agent_id: [t["function"]["name"] for t in __import__("swarmpot.defenders", fromlist=["_tool_schemas"])._tool_schemas(a.board is not None)]
            for a in agents
        },
    }
    (episode_dir / "g5_defender_state.json").write_text(json.dumps(state, indent=2, sort_keys=True) + "\n")
    print(json.dumps({k: state[k] for k in ("arm", "budget", "board_messages", "sessions", "commands", "decisions_by_agent", "tool_schemas")}, indent=2))
    if board:
        board.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
