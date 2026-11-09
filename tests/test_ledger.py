from __future__ import annotations

import json
from pathlib import Path

from swarmpot import ledger


def test_ledger_records_success_failure_interrupt_and_retry(tmp_path, monkeypatch):
    monkeypatch.setattr(ledger, "RUNS_DIR", tmp_path)
    monkeypatch.setattr(ledger, "ledger_path", lambda: tmp_path / "ledger.jsonl")

    ok_dir = tmp_path / "ep-ok"
    ok_dir.mkdir()
    ledger.begin_attempt(ok_dir, "ep-ok", "CVE-X", "E", 1, "cfg-1")
    ledger.update_attempt(ok_dir, "ep-ok", "infra", "started")
    ledger.update_attempt(ok_dir, "ep-ok", "attacker", "attacker_started", container_id="c1")
    v = ledger.classify_validity(
        started=True, attacker_started=True, completed=True, metrics_written=True, grader_status=False
    )
    ledger.finalize_attempt(
        ok_dir, "ep-ok", status="completed", valid=v["valid"],
        exclusion_reason=v["exclusion_reason"], grader_status=False, attacker_started=True,
    )

    bad_dir = tmp_path / "ep-bad"
    bad_dir.mkdir()
    ledger.begin_attempt(bad_dir, "ep-bad", "CVE-X", "E", 2, "cfg-1")
    ledger.finalize_attempt(
        bad_dir, "ep-bad", status="failed", valid=False,
        exclusion_reason="infra_failure", grader_status=None, attacker_started=False,
        error="boom",
    )

    interrupted_dir = tmp_path / "ep-int"
    interrupted_dir.mkdir()
    ledger.begin_attempt(interrupted_dir, "ep-int", "CVE-X", "E", 3, "cfg-1")
    ledger.update_attempt(interrupted_dir, "ep-int", "infra", "started")
    ledger.finalize_attempt(
        interrupted_dir, "ep-int", status="interrupted", valid=False,
        exclusion_reason="interrupted", grader_status=None, attacker_started=True,
    )

    retry_dir = tmp_path / "ep-retry"
    retry_dir.mkdir()
    ledger.begin_attempt(
        retry_dir, "ep-retry", "CVE-X", "E", 3, "cfg-1", parent_attempt_id="ep-int"
    )

    summary = ledger.summarize_ledger()
    assert summary["counts"]["attempted"] == 4
    assert summary["counts"]["completed"] == 1
    assert summary["counts"]["valid"] == 1
    assert summary["counts"]["failed"] == 1
    assert summary["counts"]["interrupted"] == 1
    by_id = {row["attempt_id"]: row for row in summary["attempts"]}
    assert by_id["ep-ok"]["valid"] is True
    assert by_id["ep-bad"]["exclusion_reason"] == "infra_failure"
    assert by_id["ep-retry"]["parent_attempt_id"] == "ep-int"

    ledger.write_ledger_summary(tmp_path / "summary")
    assert (tmp_path / "summary" / "all_attempts.csv").exists()
    assert (tmp_path / "summary" / "ledger_summary.json").exists()


def test_validity_policy_never_treats_infra_failure_as_success():
    result = ledger.classify_validity(
        started=True, attacker_started=False, completed=False, metrics_written=False
    )
    assert result["valid"] is False
    assert result["exclusion_reason"] == "never_started"

    result = ledger.classify_validity(
        started=True, attacker_started=True, completed=True, metrics_written=True, config_mismatch=True
    )
    assert result["valid"] is False
    assert result["exclusion_reason"] == "config_mismatch"

    result = ledger.classify_validity(
        started=True, attacker_started=True, completed=True, metrics_written=True, interrupted=True
    )
    assert result["valid"] is False
    assert result["exclusion_reason"] == "interrupted"

    result = ledger.classify_validity(
        started=True, attacker_started=True, completed=True, metrics_written=True, attacker_actions=0
    )
    assert result["valid"] is False
    assert result["exclusion_reason"] == "no_attacker_actions"


def test_static_fixture_ledger_distinguishes_outcomes_and_retry():
    fixture = Path(__file__).parent / "fixtures" / "ledger" / "ledger.jsonl"
    summary = ledger.summarize_ledger(fixture)
    assert summary["counts"]["attempted"] == 4
    assert summary["counts"]["completed"] == 1
    assert summary["counts"]["valid"] == 1
    assert summary["counts"]["failed"] == 1
    assert summary["counts"]["interrupted"] == 1
    by_id = {row["attempt_id"]: row for row in summary["attempts"]}
    assert by_id["fx-retry"]["parent_attempt_id"] == "fx-int"


def test_config_fingerprint_changes_with_prompt_and_config():
    class Cfg:
        raw = {"a": 1}

    one = ledger.config_fingerprint(Cfg(), "CVE-X", "E", "prompt-one")
    two = ledger.config_fingerprint(Cfg(), "CVE-X", "E", "prompt-two")
    assert one != two
