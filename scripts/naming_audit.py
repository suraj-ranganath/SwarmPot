#!/usr/bin/env python3
"""Attacker-visible naming audit and fictional reference validation.

Usage:
    python scripts/naming_audit.py

Writes runs/audit/naming_<utc>.json and exits nonzero on a failed check.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from swarmpot.config import load_config
from swarmpot.naming import audit
from swarmpot.util import RUNS_DIR, utc_stamp, write_json


def main() -> int:
    cfg = load_config()
    report = audit(cfg)
    out = RUNS_DIR / "audit"
    out.mkdir(parents=True, exist_ok=True)
    path = out / f"naming_{utc_stamp()}.json"
    write_json(path, report)
    write_json(out / "naming_latest.json", report)
    print(json.dumps({
        "pass": report["pass"],
        "surfaces": report["surfaces"],
        "forbidden": len(report["forbidden_findings"]),
        "informational": len(report["informational_findings"]),
        "failed_references": [row["name"] for row in report["references"]["failed"]],
        "fixture_caught": report["fixture"]["caught"],
        "report": str(path),
    }, indent=2))
    return 0 if report["pass"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
