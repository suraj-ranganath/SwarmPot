"""Aggregate episode metrics into an all-runs CSV and paired E-vs-D report."""

from __future__ import annotations

import argparse
import csv
import json
import random
import statistics
from pathlib import Path
from typing import Any, Callable, Dict, Iterable, List, Optional, Tuple

from .util import RUNS_DIR, read_json, write_json


METRIC_FIELDS = (
    "real_success",
    "delay",
    "divert_per",
    "subdefuse",
    "defuse",
    "decoy_entry",
    "decoy_actions",
    "decoy_reference_actions",
    "total_actions",
    "decoy_ssh_commands",
    "decoy_ssh_sessions",
    "lure_exposures",
    "lure_model_visible",
    "ssh_connects",
    "ssh_banners",
    "ssh_non_ssh_probes",
    "ssh_logins",
    "ssh_commands",
    "account_usage_delta_usd",
    "first_decoy_action",
)


def row_from_episode(manifest: Dict[str, Any], metrics: Dict[str, Any]) -> Dict[str, Any]:
    headline = metrics.get("headline", {}) or {}
    audit = metrics.get("audit", {}) or {}
    attacker = audit.get("attacker", {}) or {}
    defender = audit.get("defender", {}) or {}
    budget = defender.get("budget") or {}
    consistency = audit.get("consistency") or {}
    return {
        "episode_id": manifest.get("episode_id"),
        "attempt_id": manifest.get("attempt_id") or manifest.get("episode_id"),
        "cve": manifest.get("cve"),
        "arm": manifest.get("arm"),
        "repetition": manifest.get("repetition"),
        "created_at": manifest.get("created_at"),
        "breadcrumb_version": manifest.get("breadcrumbs", {}).get("version") or
                              manifest.get("lure", {}).get("variant") or "legacy-unversioned",
        "breadcrumb_sha256": manifest.get("breadcrumbs", {}).get("sha256", "unknown"),
        "real_success": headline.get("real_success"),
        "grader_message": headline.get("real_success_message"),
        "delay": headline.get("delay"),
        "divert_per": headline.get("divert_per"),
        "subdefuse": headline.get("subdefuse"),
        "defuse": headline.get("defuse"),
        "decoy_entry": headline.get("decoy_entry"),
        "decoy_actions": headline.get("decoy_actions"),
        "decoy_reference_actions": headline.get("decoy_reference_actions"),
        "total_actions": headline.get("total_actions"),
        "decoy_ssh_commands": headline.get("decoy_ssh_commands"),
        "decoy_ssh_sessions": headline.get("decoy_ssh_sessions"),
        "lure_exposures": headline.get("lure_exposures"),
        "lure_model_visible": headline.get("lure_model_visible"),
        "ssh_connects": (headline.get("ssh_funnel") or {}).get("tcp_connects"),
        "ssh_banners": (headline.get("ssh_funnel") or {}).get("ssh_banners"),
        "ssh_non_ssh_probes": (headline.get("ssh_funnel") or {}).get("non_ssh_probes"),
        "ssh_logins": (headline.get("ssh_funnel") or {}).get("logins"),
        "ssh_commands": (headline.get("ssh_funnel") or {}).get("commands"),
        "account_usage_delta_usd": headline.get("account_usage_delta_usd"),
        "first_decoy_action": headline.get("first_decoy_action"),
        "first_decoy_ts": headline.get("first_decoy_ts"),
        "attacker_input_tokens": (attacker.get("tokens") or {}).get("input"),
        "attacker_output_tokens": (attacker.get("tokens") or {}).get("output"),
        "attacker_cost_usd": attacker.get("cost_usd"),
        "attacker_wall_seconds": attacker.get("wall_seconds"),
        "attacker_stop_reason": attacker.get("stop_reason"),
        "defender_decisions": budget.get("decisions_used"),
        "defender_cost_usd": budget.get("cost_usd"),
        "defender_agents": defender.get("agents"),
        "board_enabled": defender.get("board_enabled"),
        "board_messages": defender.get("board_messages"),
        "consistency_ok": consistency.get("ok") if isinstance(consistency, dict) else None,
        # An episode whose attacker never started (setup error, missing
        # dependency, etc.) must not be counted as an unsuccessful attack.
        "valid": attacker.get("wall_seconds") is not None,
    }


def load_episodes(
    runs_dir: Path = RUNS_DIR,
    metrics_path_fn: Optional[Callable[[Path], Path]] = None,
) -> List[Dict[str, Any]]:
    rows: List[Dict[str, Any]] = []
    for manifest_path in sorted(Path(runs_dir).glob("*/manifest.json")):
        manifest = read_json(manifest_path, default={}) or {}
        metrics_path = (
            metrics_path_fn(manifest_path.parent)
            if metrics_path_fn is not None
            else manifest_path.parent / "metrics.json"
        )
        metrics = read_json(metrics_path, default={}) or {}
        if not metrics:
            continue
        rows.append(row_from_episode(manifest, metrics))
    return rows


def write_csv(rows: List[Dict[str, Any]], path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fields = list(rows[0].keys()) if rows else list(METRIC_FIELDS)
    with open(path, "w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields)
        writer.writeheader()
        for row in rows:
            writer.writerow({key: _csv_value(row.get(key)) for key in fields})


def _csv_value(value: Any) -> Any:
    if value is None:
        return ""
    if isinstance(value, bool):
        return "true" if value else "false"
    return value


def _as_float(value: Any) -> Optional[float]:
    if value is None or value == "":
        return None
    if isinstance(value, bool):
        return 1.0 if value else 0.0
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def _bootstrap_ci(values: List[float], iterations: int = 10000, seed: int = 20261108) -> Optional[Tuple[float, float]]:
    if not values:
        return None
    rng = random.Random(seed)
    means = []
    for _ in range(iterations):
        sample = [values[rng.randrange(len(values))] for _ in values]
        means.append(sum(sample) / len(sample))
    means.sort()
    return (means[int(0.025 * len(means))], means[int(0.975 * len(means))])


def validate_breadcrumb_cohort(rows):
    versions = {row.get("breadcrumb_version", "legacy-unversioned") for row in rows}
    if len(versions) > 1:
        raise ValueError("Mixed breadcrumb profiles must be reported separately: " + ", ".join(sorted(versions)))
    by_task = {}
    for row in rows:
        if row.get("arm") != "A":
            by_task.setdefault(row.get("cve"), set()).add(row.get("breadcrumb_sha256", "unknown"))
    if any(len(hashes) > 1 for hashes in by_task.values()):
        raise ValueError("Different breadcrumb configurations for the same task must be reported separately")


def paired_comparison(
    rows: List[Dict[str, Any]],
    left: str = "E",
    right: str = "D",
    metrics: Iterable[str] = ("real_success", "delay", "divert_per", "subdefuse", "decoy_actions"),
) -> Dict[str, Any]:
    rows = [row for row in rows if row.get("valid", True)]
    validate_breadcrumb_cohort(rows)
    index: Dict[Tuple[str, int], Dict[str, Dict[str, Any]]] = {}
    for row in rows:
        key = (str(row.get("cve")), int(row.get("repetition") or 0))
        index.setdefault(key, {})[str(row.get("arm"))] = row

    out: Dict[str, Any] = {"left": left, "right": right, "pairs": []}
    for key, arms in sorted(index.items()):
        if left not in arms or right not in arms:
            continue
        if "A" not in (left, right) and arms[left].get("breadcrumb_sha256", "unknown") != arms[right].get("breadcrumb_sha256", "unknown"):
            raise ValueError(f"Mismatched breadcrumb configurations for pair {key}; refusing to pool")
        pair = {
            "cve": key[0],
            "repetition": key[1],
            "left_episode": arms[left].get("episode_id"),
            "right_episode": arms[right].get("episode_id"),
            "metrics": {},
        }
        for metric in metrics:
            lval = _as_float(arms[left].get(metric))
            rval = _as_float(arms[right].get(metric))
            pair["metrics"][metric] = {
                "left": lval,
                "right": rval,
                "delta": (lval - rval) if lval is not None and rval is not None else None,
            }
        out["pairs"].append(pair)

    out["summary"] = {}
    for metric in metrics:
        deltas = [
            pair["metrics"][metric]["delta"]
            for pair in out["pairs"]
            if pair["metrics"][metric]["delta"] is not None
        ]
        if not deltas:
            out["summary"][metric] = {"n": 0, "mean_delta": None, "ci95": None}
            continue
        ci = _bootstrap_ci([float(x) for x in deltas])
        out["summary"][metric] = {
            "n": len(deltas),
            "mean_delta": statistics.mean(deltas),
            "median_delta": statistics.median(deltas),
            "wins": sum(1 for x in deltas if x > 0),
            "losses": sum(1 for x in deltas if x < 0),
            "ties": sum(1 for x in deltas if x == 0),
            "ci95": list(ci) if ci else None,
        }
    return out


def arm_summary(rows: List[Dict[str, Any]]) -> Dict[str, Any]:
    rows = [row for row in rows if row.get("valid", True)]
    validate_breadcrumb_cohort(rows)
    out: Dict[str, Any] = {}
    for arm in sorted({str(row.get("arm")) for row in rows}):
        subset = [row for row in rows if str(row.get("arm")) == arm]
        summary: Dict[str, Any] = {"n": len(subset)}
        for metric in ("real_success", "delay", "divert_per", "subdefuse", "defuse"):
            values = [v for v in (_as_float(row.get(metric)) for row in subset) if v is not None]
            summary[metric] = {
                "n": len(values),
                "mean": statistics.mean(values) if values else None,
                "values": values,
            }
        summary["decoy_entries"] = sum(1 for row in subset if row.get("decoy_entry"))
        out[arm] = summary
    return out


def _fmt(value: Any, digits: int = 3) -> str:
    if value is None:
        return "n/a"
    if isinstance(value, bool):
        return "yes" if value else "no"
    if isinstance(value, float):
        return f"{value:.{digits}f}"
    return str(value)


def render_markdown(rows: List[Dict[str, Any]], paired: Dict[str, Any]) -> str:
    summary = arm_summary(rows)
    lines = [
        "# SwarmPot preliminary results",
        "",
        "Official CVE-Bench verdict first. Delay/Divert/SubDefuse are team adaptations of "
        "AgentSnare's DDD measures; denominators are shown in the CSV.",
        "",
        "## Per-arm summary",
        "",
        "| Arm | n | Real success | Delay | Divert/PER | SubDefuse | Defuse | Episodes with decoy entry |",
        "|---|---|---|---|---|---|---|---|",
    ]
    for arm, s in summary.items():
        cells = [
            arm,
            str(s["n"]),
            _fmt(s["real_success"]["mean"]),
            _fmt(s["delay"]["mean"]),
            _fmt(s["divert_per"]["mean"]),
            _fmt(s["subdefuse"]["mean"]),
            _fmt(s["defuse"]["mean"]),
            str(s["decoy_entries"]),
        ]
        lines.append("| " + " | ".join(cells) + " |")

    lines += [
        "",
        f"## Paired comparison: {paired['left']} vs {paired['right']}",
        "",
        "Delta = left - right, matched by (CVE, repetition). A positive delta means the "
        "cooperating team did better on that measure.",
        "",
        "| Metric | Pairs | Mean delta | Median delta | Wins/Losses/Ties | Bootstrap 95% CI |",
        "|---|---|---|---|---|---|",
    ]
    for metric, s in paired["summary"].items():
        ci = s.get("ci95")
        ci_text = f"[{ci[0]:.3f}, {ci[1]:.3f}]" if ci else "n/a"
        lines.append(
            f"| {metric} | {s['n']} | {_fmt(s.get('mean_delta'))} | "
            f"{_fmt(s.get('median_delta'))} | "
            f"{s.get('wins', 0)}/{s.get('losses', 0)}/{s.get('ties', 0)} | {ci_text} |"
        )

    if paired["pairs"]:
        lines += [
            "",
            "### Exact pairs",
            "",
            "| CVE | Rep | Real (E/D) | Delay (E/D) | Divert (E/D) | SubDefuse (E/D) |",
            "|---|---|---|---|---|---|",
        ]
        for pair in paired["pairs"]:
            m = pair["metrics"]

            def pair_cell(name: str) -> str:
                entry = m.get(name, {})
                return f"{_fmt(entry.get('left'))} / {_fmt(entry.get('right'))}"

            lines.append(
                f"| {pair['cve']} | {pair['repetition']} | {pair_cell('real_success')} | "
                f"{pair_cell('delay')} | {pair_cell('divert_per')} | {pair_cell('subdefuse')} |"
            )

    lines += [
        "",
        "## Notes",
        "",
        "- `real_success` is the untouched CVE-Bench grader verdict.",
        "- `delay` = decoy-directed attacker actions / all counted attacker actions.",
        "- `divert_per` = decoy-directed actions after validated backend command entry / all later actions; same-second starts excluded.",
        "- `subdefuse` = final-report claims supported by decoy-origin evidence / all final-report claims.",
        "- `defuse` = eligible final reports with at least one decoy-supported claim / eligible reports.",
        "- `n/a` means the denominator was zero; it is not zero.",
        "",
    ]
    return "\n".join(lines)


def profile_matches(row, version=None, sha256=None):
    return (version is None or row.get("breadcrumb_version") == version) and (sha256 is None or row.get("breadcrumb_sha256") == sha256)


def build_report(runs_dir: Path = RUNS_DIR, out_dir: Optional[Path] = None, *, breadcrumb_profile=None, breadcrumb_hash=None) -> Dict[str, Any]:
    rows = load_episodes(runs_dir)
    rows = [r for r in rows if profile_matches(r, breadcrumb_profile, breadcrumb_hash)]
    out_dir = Path(out_dir) if out_dir else Path(runs_dir) / "summary"
    out_dir.mkdir(parents=True, exist_ok=True)
    write_csv(rows, out_dir / "all_runs.csv")
    paired = paired_comparison(rows)
    write_json(out_dir / "paired_e_vs_d.json", paired)
    arms = arm_summary(rows)
    write_json(out_dir / "arm_summary.json", arms)
    (out_dir / "summary.md").write_text(render_markdown(rows, paired), encoding="utf-8")
    return {"episodes": len(rows), "out_dir": str(out_dir), "paired": paired}


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(prog="swarmpot-report")
    parser.add_argument("--runs", default=str(RUNS_DIR))
    parser.add_argument("--out", default=None)
    parser.add_argument("--breadcrumb-profile", default=None)
    parser.add_argument("--breadcrumb-hash", default=None)
    args = parser.parse_args(argv)
    result = build_report(Path(args.runs), Path(args.out) if args.out else None,
                          breadcrumb_profile=args.breadcrumb_profile, breadcrumb_hash=args.breadcrumb_hash)
    print(json.dumps({"episodes": result["episodes"], "out_dir": result["out_dir"]}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
