from __future__ import annotations

import tempfile
from pathlib import Path

import pytest

from swarmpot.board import Board
from swarmpot.cowrie_events import CowrieIndex
from swarmpot.defenders import (
    DecoyFiles,
    DecoyManifest,
    DefenderAgent,
    DefenderBudget,
    _tool_schemas,
)
from swarmpot.events import EventLog
from swarmpot.pricing import Pricing


def make_agent(with_board: bool) -> tuple[DefenderAgent, Path]:
    root = Path(tempfile.mkdtemp(prefix="swarmpot-defender-"))
    (root / "decoy_home").mkdir()
    (root / "cowrie").mkdir()
    (root / "decoy_home" / "notes.txt").write_text("seed note\n", encoding="utf-8")
    events = EventLog(root, "ep-test", "E")
    index = CowrieIndex(root / "cowrie" / "cowrie.json", ["defender-1", "defender-2"])
    manifest = DecoyManifest(root / "manifest.jsonl")
    board = Board(path=root / "board.sqlite", episode_id="ep-test", team="defenders", max_messages=4) if with_board else None
    agent = DefenderAgent(
        agent_id="defender-1",
        model="openai/gpt-5-nano",
        session_dir=root / "agents" / "defender-1",
        events=events,
        index=index,
        decoy=DecoyFiles(root / "decoy_home", manifest, 8192, "defender-1", events),
        budget=DefenderBudget(40, 2, 1.5),
        pricing=Pricing(cache_path=None),
        board=board,
        poll_seconds=1.0,
        max_output_tokens=256,
        temperature=0.0,
        reasoning_effort=None,
    )
    return agent, root


def test_board_tools_only_exist_when_board_is_enabled() -> None:
    without = {tool["function"]["name"] for tool in _tool_schemas(False)}
    with_board = {tool["function"]["name"] for tool in _tool_schemas(True)}
    assert without == {"read_session", "read_decoy_files", "write_decoy_file"}
    assert with_board == without | {"board_read", "board_post"}


def test_board_tool_round_trip_and_disabled_denial() -> None:
    agent, _ = make_agent(with_board=True)
    posted = agent._execute_tool("board_post", {"body": "backup manifest planted"})
    assert posted["sender"] == "defender-1"
    assert agent._execute_tool("board_read", {})["messages"][0]["body"] == "backup manifest planted"

    solo, _ = make_agent(with_board=False)
    denied = solo._execute_tool("board_post", {"body": "should not persist"})
    assert "unknown or unavailable tool" in denied["error"]


def test_decoy_writes_stay_inside_allowlist() -> None:
    agent, root = make_agent(with_board=False)
    result = agent._execute_tool(
        "write_decoy_file", {"path": "/home/admin/deploy/notes.txt", "content": "db host: replica-02\n"}
    )
    assert result["ok"] is True
    assert (root / "decoy_home" / "deploy" / "notes.txt").read_text(encoding="utf-8") == "db host: replica-02\n"
    for bad in ("/home/admin/../escape.txt", "/etc/passwd", "/home/admin/../../tmp/x"):
        denied = agent._execute_tool("write_decoy_file", {"path": bad, "content": "x"})
        assert "outside the decoy allowlist" in denied["error"]


def test_combined_budget_is_team_wide_and_split_evenly() -> None:
    one = DefenderBudget(40, 1, 1.5)
    two = DefenderBudget(40, 2, 1.5)
    assert one.combined_decisions == two.combined_decisions == 40
    assert one.per_agent_quota == 40
    assert two.per_agent_quota == 20
    for _ in range(20):
        assert two.acquire("defender-1")
    assert not two.acquire("defender-1")
    assert two.acquire("defender-2")
    assert two.snapshot()["decisions_used"] == 21
