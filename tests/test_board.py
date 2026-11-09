from __future__ import annotations

import tempfile
from pathlib import Path

import pytest

from swarmpot.board import Board, BoardBudgetExceeded


def make_board(max_messages: int = 3) -> Board:
    tmp = Path(tempfile.mkdtemp(prefix="swarmpot-board-"))
    return Board(path=tmp / "board.sqlite", episode_id="ep-test", team="defenders", max_messages=max_messages)


def test_post_and_read_since_are_ordered() -> None:
    board = make_board()
    try:
        first = board.post("defender-1", "I planted a fake backup manifest.")
        second = board.post("defender-2", "I will not touch /home/admin/backup.")
        rows = board.read_since(0)
        assert [row["seq"] for row in rows] == [first["seq"], second["seq"]]
        assert rows[0]["sender"] == "defender-1"
        assert rows[1]["body"].startswith("I will not")
        assert board.read_since(first["seq"])[0]["seq"] == second["seq"]
        assert board.read_since(first["seq"])[0]["body"] == "I will not touch /home/admin/backup."
        assert board.count() == 2
    finally:
        board.close()


def test_message_limit_is_enforced() -> None:
    board = make_board(max_messages=2)
    try:
        board.post("defender-1", "one")
        board.post("defender-2", "two")
        with pytest.raises(BoardBudgetExceeded):
            board.post("defender-1", "three")
        assert board.count() == 2
    finally:
        board.close()


def test_board_is_isolated_by_episode() -> None:
    tmp = Path(tempfile.mkdtemp(prefix="swarmpot-board-"))
    path = tmp / "board.sqlite"
    one = Board(path=path, episode_id="ep-one", team="defenders", max_messages=4)
    one.post("defender-1", "from one")
    one.close()
    two = Board(path=path, episode_id="ep-two", team="defenders", max_messages=4)
    try:
        assert two.read_since(0) == []
        two.post("defender-1", "from two")
        assert [row["body"] for row in two.read_since(0)] == ["from two"]
    finally:
        two.close()
