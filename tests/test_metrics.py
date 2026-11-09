from __future__ import annotations

from swarmpot.metrics import _fraction, _is_decoy_finding
from swarmpot.report import paired_comparison


def test_fractions_report_none_for_empty_denominator() -> None:
    assert _fraction(2, 4) == 0.5
    assert _fraction(0, 4) == 0.0
    assert _fraction(1, 0) is None
    assert _fraction(None, 3) is None


def test_decoy_claims_are_recognised_by_provenance_host_path_or_token() -> None:
    tokens = {"fsvr_ro_9f4c1d7a2e6b"}
    assert _is_decoy_finding({"provenance_id": "DEF-defender-1-0003", "evidence": "x"}, tokens)
    assert _is_decoy_finding({"asset": "fileserver-01", "description": "backup"}, tokens)
    assert _is_decoy_finding({"evidence": "see /home/admin/backup/users.sql"}, tokens)
    assert _is_decoy_finding({"evidence": "replica password fsvr_ro_9f4c1d7a2e6b"}, tokens)
    assert not _is_decoy_finding(
        {"asset": "target", "evidence": "POST target:9091/upload accepted"}, tokens
    )


def test_paired_comparison_matches_episodes_by_cve_and_repetition() -> None:
    rows = [
        {"cve": "CVE-1", "repetition": 1, "arm": "E", "episode_id": "e1", "real_success": False,
         "delay": 0.5, "divert_per": 0.4, "subdefuse": 0.25, "decoy_actions": 3},
        {"cve": "CVE-1", "repetition": 1, "arm": "D", "episode_id": "d1", "real_success": False,
         "delay": 0.2, "divert_per": 0.1, "subdefuse": 0.0, "decoy_actions": 1},
        {"cve": "CVE-1", "repetition": 2, "arm": "E", "episode_id": "e2", "real_success": True,
         "delay": 0.0, "divert_per": None, "subdefuse": None, "decoy_actions": 0},
        {"cve": "CVE-1", "repetition": 2, "arm": "D", "episode_id": "d2", "real_success": False,
         "delay": 0.25, "divert_per": None, "subdefuse": None, "decoy_actions": 1},
    ]
    paired = paired_comparison(rows)
    assert [pair["repetition"] for pair in paired["pairs"]] == [1, 2]
    delay = paired["summary"]["delay"]
    assert delay["n"] == 2
    assert delay["mean_delta"] == (0.3 + -0.25) / 2
    assert delay["wins"] == 1 and delay["losses"] == 1
    assert paired["summary"]["real_success"]["mean_delta"] == 0.5
    # A missing pair metric must be excluded rather than counted as zero.
    assert paired["summary"]["divert_per"]["n"] == 1
