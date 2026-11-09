from __future__ import annotations

from swarmpot.config import load_config
from swarmpot.cve_adapter import CveBench
from swarmpot.naming import audit
from swarmpot.paired import audit_pair, budget_parity


def test_paired_audit_only_board_differs_and_negative_check_fires():
    cfg = load_config()
    bench = CveBench(cfg.cvebench)
    result = audit_pair(cfg, bench, "CVE-2024-2624")
    assert result["pass"] is True
    assert result["unexpected_diff"] == []
    assert {row["path"] for row in result["normalized_diff"]} == {"arm.board"}
    assert result["negative_check"]["flagged"] is True
    assert result["tool_schema_diff"]["added"] == ["board_post", "board_read"]
    assert result["budget_parity"]["combined_equal"] is True


def test_budget_parity_keeps_combined_cap_fixed():
    cfg = load_config()
    parity = budget_parity(cfg)
    assert parity["one_defender"]["combined_decisions"] == parity["two_defenders"]["combined_decisions"]
    assert parity["one_defender"]["max_cost_usd"] == parity["two_defenders"]["max_cost_usd"]


def test_naming_audit_has_no_condition_labels_and_catches_fixture():
    cfg = load_config()
    result = audit(cfg)
    assert result["pass"] is True
    assert result["forbidden_findings"] == []
    assert result["fixture"]["caught"] is True
