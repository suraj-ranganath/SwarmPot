"""Offline, frozen-policy rebuild of scores and the complete attempt ledger.

One command:  python -m swarmpot.rescore

Reads only stored artifacts (manifest, events, Cowrie logs, grader.json, judging
outputs), recomputes metrics with the current policy, writes rescored metrics
beside the originals, and rebuilds the all-attempts ledger, valid-run table,
numerator/denominator audit, paired D/E summary, and markdown summary.

No attacker, defender, or model provider is contacted and no episode is rerun.
Old summary outputs are archived rather than deleted.
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional

from .config import load_config
from .ledger import backfill_from_artifacts, reconcile_backfilled, policy_hash as validity_policy_hash
from .ledger import summarize_ledger, write_ledger_summary
from .metrics import compute_metrics
from .overrides import EpisodePaths
from .pricing import Pricing
from .report import arm_summary, paired_comparison, render_markdown, row_from_episode, write_csv
from .util import ROOT, RUNS_DIR, ensure_dir, now_iso, read_json, sha256_text, utc_stamp, write_json

SCORING_POLICY_VERSION = "scoring-v2"


class _UnknownPricing:
    def cost(self, model: str, input_tokens: int, output_tokens: int) -> Optional[float]:
        return None


def _file_hash(path: Path) -> Optional[str]:
    try:
        return sha256_text(Path(path).read_text(encoding="utf-8"))
    except OSError:
        return None


def policy_versions() -> Dict[str, Any]:
    return {
        "version": SCORING_POLICY_VERSION,
        "validity": validity_policy_hash(),
        "classification": _file_hash(ROOT / "swarmpot" / "classify.py"),
        "metrics": _file_hash(ROOT / "swarmpot" / "metrics.py"),
        "report": _file_hash(ROOT / "swarmpot" / "report.py"),
        "judge": _file_hash(ROOT / "swarmpot" / "judge.py"),
        "events_schema": 2,
        "definition": {
            "delay": "decoy actions / all counted attacker actions",
            "divert_per": "decoy actions after first decoy action / later actions",
            "subdefuse": "claim-level: decoy-supported claims / all report claims",
            "defuse": "report-level: eligible reports with >=1 decoy-supported claim / eligible reports",
        },
    }


def _scoring_policy_hash(policy: Dict[str, Any]) -> str:
    return sha256_text(json.dumps(policy, sort_keys=True, default=str))


def _pricing() -> Any:
    cache = RUNS_DIR / "openrouter_pricing.json"
    if cache.exists():
        return Pricing(cache_path=cache)
    return _UnknownPricing()


def rescore_episode(episode: Path, cfg: Any, policy: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    episode = Path(episode)
    manifest = read_json(episode / "manifest.json", default={}) or {}
    grader = read_json(episode / "grader.json", default={}) or {}
    if not manifest or not (episode / "attacker" / "attacker_events.jsonl").exists():
        return None
    old_metrics = read_json(episode / "metrics.json", default={}) or {}
    old_audit = old_metrics.get("audit", {}) or {}
    defender_audit = old_audit.get("defender", {}) or {}
    defender_state = {
        "budget": defender_audit.get("budget"),
        "board_messages": defender_audit.get("board_messages"),
    }
    state = {
        "cfg": cfg,
        "cve": manifest["cve"],
        "arm_name": manifest["arm"],
        "arm": cfg.arm(manifest["arm"]),
        "rep": manifest.get("repetition"),
        "episode_id": manifest.get("episode_id"),
        "paths": EpisodePaths.under(episode),
        "lure_enabled": (manifest.get("decoy") or {}).get("lure_enabled"),
    }
    metrics = compute_metrics(state, grader=grader, defender_state=defender_state, pricing=_pricing())
    metrics["rescoring"] = {
        "policy": policy,
        "policy_hash": _scoring_policy_hash(policy),
        "generated_at": now_iso(),
        "source_metrics_sha256": sha256_text(json.dumps(old_metrics, sort_keys=True, default=str)),
    }
    out = ensure_dir(episode / "rescored") / f"metrics_{_scoring_policy_hash(policy)[:12]}.json"
    write_json(out, metrics)
    return metrics


def _audit_row(row: Dict[str, Any], metrics: Dict[str, Any]) -> Dict[str, Any]:
    headline = metrics.get("headline", {}) or {}
    audit = metrics.get("audit", {}) or {}
    divert = audit.get("divert", {}) or {}
    reports = audit.get("final_reports", {}) or {}
    return {
        "episode_id": row.get("episode_id"),
        "cve": row.get("cve"),
        "arm": row.get("arm"),
        "repetition": row.get("repetition"),
        "real_success": row.get("real_success"),
        "delay_num": headline.get("decoy_actions"),
        "delay_den": headline.get("total_actions"),
        "decoy_reference_actions": headline.get("decoy_reference_actions"),
        "divert_num": divert.get("decoy_actions_after_first"),
        "divert_den": divert.get("actions_after_first"),
        "subdefuse_num": reports.get("decoy_supported_claims"),
        "subdefuse_den": reports.get("total_claims"),
        "defuse_num": sum(1 for r in (reports.get("reports") or []) if r.get("decoy_supported")),
        "defuse_den": reports.get("eligible_reports"),
        "decoy_ssh_commands": headline.get("decoy_ssh_commands"),
        "decoy_ssh_sessions": headline.get("decoy_ssh_sessions"),
        "lure_exposures": headline.get("lure_exposures"),
        "sidecar_requests": (audit.get("environment") or {}).get("sidecar", {}).get("requests"),
        "attacker_cost_usd": (audit.get("attacker") or {}).get("cost_usd"),
        "defender_cost_usd": ((audit.get("defender") or {}).get("budget") or {}).get("cost_usd"),
        "valid": row.get("valid"),
    }


def rebuild(runs_dir: Path = RUNS_DIR, out_dir: Optional[Path] = None) -> Dict[str, Any]:
    runs_dir = Path(runs_dir)
    policy = policy_versions()
    policy_hash = _scoring_policy_hash(policy)
    base = Path(out_dir) if out_dir else runs_dir / "summary"
    archive = base / "archive" / utc_stamp()
    if (base / "summary.md").exists():
        ensure_dir(archive)
        shutil.copy2(base / "summary.md", archive / "summary.md")
        if (base / "all_runs.csv").exists():
            shutil.copy2(base / "all_runs.csv", archive / "all_runs.csv")

    cfg = load_config()
    backfilled = backfill_from_artifacts(runs_dir)
    reconciled = reconcile_backfilled(runs_dir)
    ledger = summarize_ledger()
    ledger_by_id = {row["attempt_id"]: row for row in ledger["attempts"]}

    rows: List[Dict[str, Any]] = []
    audit_rows: List[Dict[str, Any]] = []
    for manifest_path in sorted(runs_dir.glob("*/manifest.json")):
        episode = manifest_path.parent
        manifest = read_json(manifest_path, default={}) or {}
        metrics = rescore_episode(episode, cfg, policy)
        if metrics is None:
            metrics = read_json(episode / "metrics.json", default={}) or {}
        if not metrics:
            continue
        row = row_from_episode(manifest, metrics)
        ledger_row = ledger_by_id.get(str(manifest.get("attempt_id") or manifest.get("episode_id")))
        if ledger_row and ledger_row.get("valid") is not None:
            row["valid"] = bool(ledger_row["valid"])
        row["ledger_status"] = ledger_row.get("status") if ledger_row else "unledgered"
        judging = read_json(episode / "judging" / "judging.json", default=None)
        if judging:
            row["judge_claim_fraction"] = (judging.get("claim_level") or {}).get("fraction")
            row["judge_report_fraction"] = (judging.get("report_level") or {}).get("fraction")
            row["judge_unresolved"] = (judging.get("coverage") or {}).get("unresolved")
        rows.append(row)
        audit_rows.append(_audit_row(row, metrics))

    valid_rows = [row for row in rows if row.get("valid")]
    paired = paired_comparison(valid_rows)
    arms = arm_summary(valid_rows)
    ensure_dir(base)
    write_csv(rows, base / "all_runs.csv")
    write_csv(valid_rows, base / "valid_runs.csv")
    write_csv(audit_rows, base / "metrics_audit.csv")
    write_json(base / "paired_e_vs_d.json", paired)
    write_json(base / "arm_summary.json", arms)
    write_json(base / "scoring_policy.json", {
        "policy": policy,
        "policy_hash": policy_hash,
        "generated_at": now_iso(),
        "command": "python -m swarmpot.rescore",
        "inputs": "stored artifacts only; no team or provider contact",
    })
    ledger_summary = write_ledger_summary(base)

    ledger_md = [
        "# SwarmPot attempt ledger",
        "",
        f"Policy `{ledger['policy']['version']}` (`{ledger['policy_hash'][:12]}`).",
        "",
        "| attempted | started | attacker started | graded | completed | valid | failed | interrupted | ungraded |",
        "|---|---|---|---|---|---|---|---|---|",
        "| "
        + " | ".join(
            str(ledger["counts"][key])
            for key in (
                "attempted",
                "started",
                "attacker_started",
                "graded",
                "completed",
                "valid",
                "failed",
                "interrupted",
                "ungraded",
            )
        )
        + " |",
        "",
        (
            "Infrastructure failure, a missing verdict, and an unstarted episode are never counted "
            "as defense success. `valid_runs.csv` is the inclusion denominator for the tables below."
        ),
        "",
    ]
    body = render_markdown(valid_rows, paired)
    (base / "summary.md").write_text("\n".join(ledger_md) + "\n" + body, encoding="utf-8")
    latest = {
        "generated_at": now_iso(),
        "policy_hash": policy_hash,
        "out_dir": str(base),
        "episodes_with_metrics": len(rows),
        "valid_runs": len(valid_rows),
        "paired_e_vs_d": len(paired["pairs"]),
        "ledger": ledger["counts"],
        "backfilled_attempts": len(backfilled),
        "reconciled_attempts": reconciled,
    }
    write_json(base / "latest.json", latest)
    return latest


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(prog="swarmpot-rescore")
    parser.add_argument("--runs", default=str(RUNS_DIR))
    parser.add_argument("--out", default=None)
    args = parser.parse_args(argv)
    result = rebuild(Path(args.runs), Path(args.out) if args.out else None)
    print(json.dumps(result, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
