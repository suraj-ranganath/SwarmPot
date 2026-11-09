from __future__ import annotations

import json

from swarmpot.events import SCHEMA_VERSION, EventLog


def test_event_schema_v2_has_ids_links_and_clock(tmp_path):
    log = EventLog(tmp_path, "ep-1", "E", attempt_id="attempt-1")
    first = log.emit("defender", "tool_call", agent_id="defender-1", tool="read_session", status="observed")
    second = log.emit(
        "defender",
        "decoy_edit",
        agent_id="defender-1",
        tool="write_decoy_file",
        parent_event_id=first["event_id"],
        refs=[first["event_id"]],
        status="committed",
        payload={"edit_id": "edit-1"},
    )
    rows = [json.loads(line) for line in (tmp_path / "events.jsonl").read_text().splitlines()]
    assert len(rows) == 2
    assert rows[0]["schema_version"] == SCHEMA_VERSION
    assert rows[0]["event_id"] == "evt-ep-1-000001"
    assert rows[0]["attempt_id"] == "attempt-1"
    assert rows[0]["team"] == "defender"
    assert rows[1]["parent_event_id"] == first["event_id"]
    assert rows[1]["refs"] == [first["event_id"]]
    assert rows[1]["status"] == "committed"
    assert rows[1]["monotonic_ns"] >= rows[0]["monotonic_ns"]
    assert rows[1]["clock_scope"] == rows[0]["clock_scope"]
    assert second["payload"]["schema_version"] == SCHEMA_VERSION


def test_lifecycle_and_missing_artifact_status(tmp_path):
    log = EventLog(tmp_path, "ep-2", "A")
    log.lifecycle("reset_start")
    missing = log.artifact("solution", tmp_path / "does-not-exist")
    assert missing["status"] == "missing"
    assert missing["payload"]["sha256"] is None
