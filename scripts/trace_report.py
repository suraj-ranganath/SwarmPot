#!/usr/bin/env python3
"""Reconstruct causal traces from an episode's append-only logs.

Produces episode/trace/trace_report.json and trace_report.md, plus a small
summary of whether the episode contains:
  * a real committed defender edit,
  * a board post -> delivery/read -> later decision sequence,
  * a subsequent attacker command referencing the edited artifact,
  * genuine 2-attacker / 2-defender activity.

Exposure is labelled `version_known=false` when the attacker log does not prove
which file version was read. Observation and influence are kept separate.

Usage:
    python scripts/trace_report.py --episode runs/<episode>
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Any, Dict, List

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from swarmpot.util import read_json, read_jsonl, write_json


def _load_events(episode: Path) -> List[Dict[str, Any]]:
    return read_jsonl(episode / "events.jsonl")


def _attacker_actions(episode: Path) -> List[Dict[str, Any]]:
    rows = read_jsonl(episode / "attacker" / "attacker_events.jsonl")
    return [row for row in rows if row.get("kind") == "tool_call"]


def build(episode: Path) -> Dict[str, Any]:
    events = _load_events(episode)
    actions = _attacker_actions(episode)
    ssh = {row["event_id"]: row for row in events if row.get("kind") == "ssh_event"}
    owners = {
        row.get("payload", {}).get("session"): row.get("payload", {}).get("owner")
        for row in events
        if row.get("kind") == "session_owner"
    }
    decisions = [row for row in events if row.get("kind") == "llm_decision"]
    tool_calls = [row for row in events if row.get("kind") == "tool_call"]
    edits = [row for row in events if row.get("kind") == "decoy_edit"]
    board_posts = [row for row in events if row.get("kind") == "board_post"]
    board_reads = [row for row in events if row.get("kind") == "board_read"]
    board_deliveries = [row for row in events if row.get("kind") == "board_delivery"]

    edit_chains = []
    for edit in edits:
        payload = edit.get("payload") or {}
        decision = next((d for d in decisions if d.get("event_id") == edit.get("parent_event_id")), None)
        observation = None
        if decision:
            for call in tool_calls:
                if call.get("parent_event_id") == decision.get("event_id"):
                    ids = (call.get("payload") or {}).get("observed_trace_event_ids") or []
                    if ids:
                        observation = call
                        break
        observed_ssh = []
        if observation:
            for event_id in (observation.get("payload") or {}).get("observed_trace_event_ids") or []:
                if event_id in ssh:
                    observed_ssh.append(ssh[event_id].get("payload") or {})
        path = str(payload.get("path") or "")
        after = edit.get("ts", "")
        needle = path.rsplit("/", 1)[-1] if path else ""
        exposure = [
            action
            for action in actions
            if after and str(action.get("ts", "")) > after and needle and needle in str((action.get("payload") or {}).get("command", ""))
        ]
        edit_chains.append(
            {
                "edit_id": payload.get("edit_id"),
                "path": path,
                "before_sha256": payload.get("before_sha256"),
                "after_sha256": payload.get("after_sha256"),
                "committed_at": edit.get("ts"),
                "decision_event_id": decision.get("event_id") if decision else None,
                "request_id": (decision.get("payload") or {}).get("request_id") if decision else None,
                "observed_ssh": observed_ssh[:5],
                "session_owners": owners,
                "subsequent_attacker_actions": exposure,
                "exposure": "observed_command_reference" if exposure else "no_subsequent_reference",
                "version_known": False,
            }
        )

    board_chains = []
    for post in board_posts:
        seq = (post.get("payload") or {}).get("message_id")
        delivered = [
            row for row in board_deliveries
            if seq in ((row.get("payload") or {}).get("message_seqs") or [])
        ]
        read = [
            row for row in board_reads
            if seq in ((row.get("payload") or {}).get("message_seqs") or [])
        ]
        context_decisions = [
            d for d in decisions
            if seq in ((d.get("payload") or {}).get("board_context_message_seqs") or [])
        ]
        followups = []
        if context_decisions:
            decision_ids = {d.get("event_id") for d in context_decisions}
            followups = [
                call for call in tool_calls
                if call.get("parent_event_id") in decision_ids and call.get("status") == "committed"
            ]
        board_chains.append(
            {
                "message_id": seq,
                "sender": (post.get("payload") or {}).get("sender") or post.get("agent_id"),
                "posted_at": post.get("ts"),
                "delivered_to": sorted({row.get("agent_id") for row in delivered}),
                "read_by": sorted({row.get("agent_id") for row in read}),
                "context_in_decisions": [d.get("event_id") for d in context_decisions],
                "committed_followups": [c.get("event_id") for c in followups],
            }
        )

    attacker_agents = sorted({row.get("agent_id") for row in actions if row.get("agent_id")})
    defender_agents = sorted({row.get("agent_id") for row in decisions if row.get("agent_id")})
    summary = {
        "ssh_events": len(ssh),
        "attacker_actions": len(actions),
        "attacker_agents": attacker_agents,
        "defender_agents": defender_agents,
        "decisions": len(decisions),
        "committed_edits": len(edits),
        "board_messages": len(board_posts),
        "board_reads": len(board_reads),
        "board_deliveries": len(board_deliveries),
        "has_two_attackers": len(attacker_agents) >= 2,
        "has_two_defenders": len(defender_agents) >= 2,
        "has_real_edit": bool(edits),
        "has_board_chain": bool(board_chains),
        "has_edit_exposure": any(chain["subsequent_attacker_actions"] for chain in edit_chains),
        "version_known": False,
    }
    return {
        "episode": str(episode),
        "summary": summary,
        "edit_chains": edit_chains,
        "board_chains": board_chains,
        "decisions": [
            {
                "event_id": d.get("event_id"),
                "agent_id": d.get("agent_id"),
                "ts": d.get("ts"),
                "request_id": (d.get("payload") or {}).get("request_id"),
                "payload_ref": (d.get("payload") or {}).get("payload_ref"),
                "tool_names": (d.get("payload") or {}).get("tool_names"),
                "observation_ids": (d.get("payload") or {}).get("observation_ids"),
                "board_context": (d.get("payload") or {}).get("board_context_message_seqs"),
            }
            for d in decisions
        ],
    }


def render_markdown(report: Dict[str, Any]) -> str:
    s = report["summary"]
    lines = [
        "# Episode trace report",
        "",
        f"- episode: `{report['episode']}`",
        f"- attacker agents: {', '.join(s['attacker_agents']) or 'none'}",
        f"- defender agents: {', '.join(s['defender_agents']) or 'none'}",
        f"- decisions: {s['decisions']}",
        f"- committed edits: {s['committed_edits']}",
        f"- board messages/reads: {s['board_messages']}/{s['board_reads']}",
        f"- 2v2 present: attackers={s['has_two_attackers']} defenders={s['has_two_defenders']}",
        f"- edit followed by attacker reference: {s['has_edit_exposure']}",
        "",
        "## Edit chains",
        "",
    ]
    for chain in report["edit_chains"]:
        lines += [
            f"### `{chain['edit_id']}` {chain['path']}",
            "",
            f"- committed: {chain['committed_at']}",
            f"- decision: `{chain['decision_event_id']}` request `{chain['request_id']}`",
            f"- SSH observations: {len(chain['observed_ssh'])}",
            f"- subsequent attacker references: {len(chain['subsequent_attacker_actions'])}",
            f"- exposure: {chain['exposure']} (version known: {chain['version_known']})",
            "",
        ]
        for action in chain["subsequent_attacker_actions"][:5]:
            lines.append(
                f"  - {action.get('ts')} {action.get('agent_id')}: "
                f"`{str((action.get('payload') or {}).get('command'))[:200]}`"
            )
        lines.append("")
    lines += ["## Board chains", ""]
    for chain in report["board_chains"]:
        lines += [
            f"### message {chain['message_id']} by {chain['sender']}",
            "",
            f"- delivered to: {chain['delivered_to']}",
            f"- read by: {chain['read_by']}",
            f"- in decision context: {chain['context_in_decisions']}",
            f"- committed follow-ups: {chain['committed_followups']}",
            "",
        ]
    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--episode", required=True)
    args = parser.parse_args()
    episode = Path(args.episode)
    if not (episode / "events.jsonl").exists():
        print("no events.jsonl", file=sys.stderr)
        return 2
    report = build(episode)
    out = episode / "trace"
    out.mkdir(exist_ok=True)
    write_json(out / "trace_report.json", report)
    (out / "trace_report.md").write_text(render_markdown(report), encoding="utf-8")
    print(json.dumps(report["summary"], indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
