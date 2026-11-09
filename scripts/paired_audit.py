#!/usr/bin/env python3
"""Machine-readable D/E (and C) paired-configuration audit.

Usage:
    python scripts/paired_audit.py

Writes runs/paired/<CVE>_D_E.json for each configured task and a summary.
Exit code 0 only when every pair differs solely on board access and the
negative mismatch check fires.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from swarmpot.config import load_config
from swarmpot.cve_adapter import CveBench
from swarmpot.defenders import DefenderBudget
from swarmpot.paired import audit_pair
from swarmpot.util import RUNS_DIR, read_json, write_json


def latest_episode(cve: str, arm: str):
    rows = sorted(RUNS_DIR.glob(f"*-{cve.lower()}-{arm.lower()}-r*"), reverse=True)
    for row in rows:
        manifest = read_json(row / "manifest.json", default={}) or {}
        try:
            repetition = int(manifest.get("repetition") or 0)
        except (TypeError, ValueError):
            repetition = 0
        if repetition < 900:
            return row
    return None


def paired_seed_check(cve: str) -> dict:
    d = latest_episode(cve, "D")
    e = latest_episode(cve, "E")
    if not d or not e:
        return {"status": "pending", "reason": "no D and E episode pair on disk"}
    dm = read_json(d / "manifest.json", default={}) or {}
    em = read_json(e / "manifest.json", default={}) or {}
    dh, eh = dm.get("seed_inventory_sha256"), em.get("seed_inventory_sha256")
    if not dh or not eh:
        return {
            "status": "pending",
            "reason": "paired episodes predate the seed-inventory manifest field",
            "d_episode": str(d),
            "e_episode": str(e),
        }
    return {
        "status": "verified" if dh == eh else "mismatch",
        "d_episode": str(d),
        "e_episode": str(e),
        "d_seed_inventory_sha256": dh,
        "e_seed_inventory_sha256": eh,
        "match": dh == eh,
    }


def budget_enforcement() -> dict:
    two = DefenderBudget(40, 2, 1.5)
    one = DefenderBudget(40, 1, 1.5)
    for _ in range(20):
        assert two.acquire("defender-1")
    denied = not two.acquire("defender-1")
    allowed_second = two.acquire("defender-2")
    for _ in range(40):
        assert one.acquire("solo")
    solo_denied = not one.acquire("solo")
    return {
        "two_agent_quota": 20,
        "two_agent_first_denied_after_quota": denied,
        "two_agent_second_agent_allowed": allowed_second,
        "one_agent_quota": 40,
        "one_agent_denied_after_quota": solo_denied,
        "combined_cap": 40,
    }


def main() -> int:
    cfg = load_config()
    out = RUNS_DIR / "paired"
    out.mkdir(parents=True, exist_ok=True)
    rows = {}
    bench = CveBench(cfg.cvebench)
    for task in cfg.tasks:
        audit = audit_pair(cfg, bench, task.cve)
        audit["paired_seed_check"] = paired_seed_check(task.cve)
        audit["budget_enforcement"] = budget_enforcement()
        audit["pass"] = (
            audit["pass"]
            and audit["negative_check"]["pass"]
            and audit["budget_enforcement"]["two_agent_first_denied_after_quota"]
            and audit["budget_enforcement"]["one_agent_denied_after_quota"]
        )
        write_json(out / f"{task.cve}_D_E.json", audit)
        rows[task.cve] = {
            "pass": audit["pass"],
            "unexpected_diff": audit["unexpected_diff"],
            "negative_check": audit["negative_check"],
            "seed": audit["paired_seed_check"],
        }
    summary = {"pass": all(row["pass"] for row in rows.values()), "pairs": rows}
    write_json(out / "summary.json", summary)
    print(json.dumps(summary, indent=2))
    return 0 if summary["pass"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
