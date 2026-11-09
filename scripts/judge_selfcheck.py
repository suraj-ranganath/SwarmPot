#!/usr/bin/env python3
"""Run the live evidence judge on the fixed fixture set.

This spends a small amount of model credit (default cap $0.02) and records the
actual outputs under runs/audit/judge_fixture_<utc>/. Fixture expectations are
reported, not forced: a mismatch is evidence about the judge, not a reason to
rewrite the fixture.

Usage:
    python scripts/judge_selfcheck.py
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from swarmpot import judge
from swarmpot.util import RUNS_DIR, utc_stamp, write_json


def main() -> int:
    cases = json.loads(
        (Path(__file__).parent.parent / "tests" / "fixtures" / "judge" / "cases.json").read_text()
    )
    out = RUNS_DIR / "audit" / f"judge_fixture_{utc_stamp()}"
    (out / "attacker" / "reports").mkdir(parents=True, exist_ok=True)
    (out / "cowrie").mkdir()
    (out / "manifest.json").write_text(json.dumps({"episode_id": "judge-fixture", "cve": "FIXTURE", "arm": "eval"}))
    rows = []
    for case in cases:
        pid = case["finding"].get("provenance_id")
        if pid and not any(row.get("provenance_id") == pid for row in rows):
            rows.append(
                {
                    "origin": "seed",
                    "provenance_id": pid,
                    "path": "/home/admin/secrets.env",
                    "sha256": "fixturehash",
                    "tokens": ["fsvr_ro_9f4c1d7a2e6b"],
                }
            )
    (out / "decoy_manifest.jsonl").write_text("\n".join(json.dumps(r) for r in rows) + "\n")
    report = {
        "handler": "swarmpot",
        "submission": {
            "summary": "judge fixture report",
            "findings": [case["finding"] for case in cases],
            "real_target_verified": False,
        },
    }
    (out / "attacker" / "reports" / "report_001.json").write_text(json.dumps(report))

    policy = judge.JudgePolicy(max_cost_usd=0.02, max_claims=10)
    result = judge.score_episode(out, policy=policy, fresh=True)
    claims = {c["claim_id"]: c for c in result["claims"]}
    rows_out = []
    for index, case in enumerate(cases, start=1):
        row = claims.get(f"r01c{index:02d}", {})
        expected = case["responses"][-1]
        rows_out.append(
            {
                "case": case["name"],
                "expected_origin": expected["origin"],
                "expected_stance": expected["stance"],
                "observed_origin": row.get("origin"),
                "observed_stance": row.get("stance"),
                "resolved": row.get("resolved"),
                "origin_match": row.get("origin") == expected["origin"],
                "stance_match": row.get("stance") == expected["stance"],
            }
        )
    summary = {
        "generated_at": result["generated_at"],
        "out": str(out),
        "judging": result["judging"],
        "claim_level": result["claim_level"],
        "report_level": result["report_level"],
        "coverage": result["coverage"],
        "cases": rows_out,
        "matches": sum(1 for row in rows_out if row["origin_match"] and row["stance_match"]),
        "cases_total": len(rows_out),
    }
    write_json(out / "selfcheck.json", summary)
    write_json(RUNS_DIR / "audit" / "judge_selfcheck_latest.json", summary)
    print(json.dumps(summary, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
