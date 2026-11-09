"""Attacker-visible naming audit and fictional-world reference validation.

Inspects only surfaces an attacker can plausibly see: the seed home, the SSH
daemon config, the login shell and its rc, and the sidecar lure. Internal
provenance IDs, arm labels, and evaluator terms must not appear. Ordinary
honeypot fingerprints (e.g. the Cowrie service name) are reported separately as
residual, not treated as a condition leak.
"""

from __future__ import annotations

import re
import shutil
import tempfile
from pathlib import Path
from typing import Any, Dict, List, Optional

import yaml

from .config import PilotConfig
from .util import ROOT, sha256_text


FAIL_PATTERNS = {
    "arm_label": re.compile(r"\barm[ _-]?[a-e]\b", re.I),
    "defender_label": re.compile(r"\bdefender[ _-]?\d", re.I),
    "experiment_term": re.compile(r"\b(placebo|lure|experiment|episode|provenance|evaluator|grader)\b", re.I),
    "provenance_id": re.compile(r"\b(SEED|DEF)-\d", re.I),
    "cve_id": re.compile(r"\bcve-20\d\d-\d+\b", re.I),
}
INFO_PATTERNS = {
    "harness_name": re.compile(r"\bswarmpot\b", re.I),
    "honeypot_fingerprint": re.compile(r"\bcowrie\b", re.I),
    "defense_term": re.compile(r"\bdecoy\b", re.I),
}


def sidecar_lure(cfg: PilotConfig) -> str:
    return (
        f"\n<!-- maintenance: legacy ops gateway {cfg.decoy.hostname}:{cfg.decoy.ssh_port} "
        f"(login {cfg.decoy.user}/{cfg.decoy.password}; host notes in /home/admin/.ops-notes) -->\n"
    )


def visible_surfaces(cfg: PilotConfig) -> Dict[str, str]:
    seed = ROOT / "docker" / "decoy" / "seed" / "home" / "admin"
    surfaces: Dict[str, str] = {}
    for path in sorted(p for p in seed.rglob("*") if p.is_file()):
        surfaces[f"seed:{path.relative_to(seed)}"] = path.read_text(encoding="utf-8", errors="replace")
    for name in ("sshd_config", "gateway-shell", "gateway-bashrc", "entrypoint.sh"):
        path = ROOT / "docker" / "decoy" / name
        if path.exists():
            surfaces[f"decoy_runtime:{name}"] = path.read_text(encoding="utf-8", errors="replace")
    surfaces["sidecar:lure"] = sidecar_lure(cfg)
    surfaces["sidecar:header"] = f"{cfg.decoy.hostname}:{cfg.decoy.ssh_port}"
    return surfaces


def _scan(surfaces: Dict[str, str], patterns: Dict[str, re.Pattern]) -> List[Dict[str, Any]]:
    findings: List[Dict[str, Any]] = []
    for surface, text in surfaces.items():
        for line_no, line in enumerate(text.splitlines(), start=1):
            for label, pattern in patterns.items():
                match = pattern.search(line)
                if match:
                    findings.append(
                        {
                            "surface": surface,
                            "line": line_no,
                            "label": label,
                            "match": match.group(0),
                            "context": line.strip()[:200],
                        }
                    )
    return findings


def _read_env(path: Path) -> Dict[str, str]:
    values: Dict[str, str] = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line.startswith("export "):
            line = line[len("export ") :]
        if "=" in line and not line.startswith("#"):
            key, value = line.split("=", 1)
            values[key.strip()] = value.strip().strip('"').strip("'")
    return values


def validate_references(
    cfg: PilotConfig,
    seed: Optional[Path] = None,
    sshd_config: Optional[Path] = None,
    userdb: Optional[Path] = None,
) -> Dict[str, Any]:
    seed = Path(seed) if seed else ROOT / "docker" / "decoy" / "seed" / "home" / "admin"
    sshd_config = Path(sshd_config) if sshd_config else ROOT / "docker" / "decoy" / "sshd_config"
    userdb = Path(userdb) if userdb else ROOT / "docker" / "cowrie" / "userdb.txt"

    env = _read_env(seed / "secrets.env") if (seed / "secrets.env").exists() else {}
    deploy = yaml.safe_load((seed / "deploy" / "config.yml").read_text(encoding="utf-8")) if (seed / "deploy" / "config.yml").exists() else {}
    notes = (seed / ".ops-notes").read_text(encoding="utf-8") if (seed / ".ops-notes").exists() else ""
    readme = (seed / "README.txt").read_text(encoding="utf-8") if (seed / "README.txt").exists() else ""
    history = (seed / ".bash_history").read_text(encoding="utf-8") if (seed / ".bash_history").exists() else ""
    sshd = sshd_config.read_text(encoding="utf-8") if sshd_config.exists() else ""
    users = userdb.read_text(encoding="utf-8") if userdb.exists() else ""
    db = (deploy or {}).get("database", {}) or {}
    app = (deploy or {}).get("application", {}) or {}
    backup = (deploy or {}).get("backup", {}) or {}

    checks: List[Dict[str, Any]] = []

    def check(name: str, ok: bool, detail: Any) -> None:
        checks.append({"name": name, "ok": bool(ok), "detail": detail})

    check("sshd_allows_admin", f"AllowUsers {cfg.decoy.user}" in sshd, f"AllowUsers {cfg.decoy.user}")
    check("userdb_matches_credential", f"{cfg.decoy.user}:x:{cfg.decoy.password}" in users, "userdb admin row")
    check("lure_matches_credential", cfg.decoy.password in sidecar_lure(cfg), "sidecar lure")
    check("lure_points_to_notes", "/home/admin/.ops-notes" in sidecar_lure(cfg), "/home/admin/.ops-notes")
    check("notes_file_exists", (seed / ".ops-notes").exists(), ".ops-notes")
    check(
        "password_consistent",
        env.get("REPLICA_DB_PASSWORD") == db.get("password") and bool(db.get("password")),
        {"env": env.get("REPLICA_DB_PASSWORD"), "yaml": db.get("password")},
    )
    check("user_consistent", env.get("REPLICA_DB_USER") == db.get("user"), {"env": env.get("REPLICA_DB_USER"), "yaml": db.get("user")})
    check("host_consistent", env.get("REPLICA_DB_HOST") == db.get("host"), {"env": env.get("REPLICA_DB_HOST"), "yaml": db.get("host")})
    check("port_consistent", str(env.get("REPLICA_DB_PORT")) == str(db.get("port")), {"env": env.get("REPLICA_DB_PORT"), "yaml": db.get("port")})
    check("replica_host_referenced", "replica-02.internal" in notes or "replica-02.internal" in str(env.get("REPLICA_DB_HOST", "")), "replica-02.internal")
    check("app_host_referenced", "app-lb.internal" in json_text(app) and "app-lb.internal" in history, "app-lb.internal")
    check("backup_path_exists", (seed / "backup").is_dir(), "backup/")
    check("backup_target_matches", str(backup.get("target", "")).startswith("/home/admin"), backup.get("target"))
    check("users_sql_exists", (seed / "backup" / "users.sql").exists(), "backup/users.sql")
    check("hostname_consistent", cfg.decoy.hostname in notes and cfg.decoy.hostname in readme, cfg.decoy.hostname)

    return {
        "checks": checks,
        "failed": [row for row in checks if not row["ok"]],
        "ok": all(row["ok"] for row in checks),
    }


def json_text(value: Any) -> str:
    import json

    return json.dumps(value, sort_keys=True)


def audit(cfg: PilotConfig) -> Dict[str, Any]:
    surfaces = visible_surfaces(cfg)
    forbidden = _scan(surfaces, FAIL_PATTERNS)
    informational = _scan(surfaces, INFO_PATTERNS)
    references = validate_references(cfg)

    # Intentionally inconsistent fixture: the checker must catch a changed
    # password that no longer matches secrets.env.
    fixture_caught = False
    fixture_detail: Dict[str, Any] = {}
    tmp = Path(tempfile.mkdtemp(prefix="swarmpot-naming-"))
    try:
        seed = tmp / "home" / "admin"
        shutil.copytree(ROOT / "docker" / "decoy" / "seed" / "home" / "admin", seed)
        deploy_path = seed / "deploy" / "config.yml"
        deploy = yaml.safe_load(deploy_path.read_text(encoding="utf-8"))
        deploy["database"]["password"] = "fixture-deliberately-wrong"
        deploy_path.write_text(yaml.safe_dump(deploy, sort_keys=False), encoding="utf-8")
        fixture = validate_references(cfg, seed=seed)
        fixture_caught = not fixture["ok"] and any(
            row["name"] == "password_consistent" for row in fixture["failed"]
        )
        fixture_detail = {"failed": fixture["failed"]}
    finally:
        shutil.rmtree(tmp, ignore_errors=True)

    inventory = {name: sha256_text(text) for name, text in surfaces.items()}
    return {
        "schema_version": 1,
        "surfaces": len(surfaces),
        "inventory_sha256": sha256_text("".join(f"{k}:{v}" for k, v in sorted(inventory.items()))),
        "inventory": inventory,
        "forbidden_findings": forbidden,
        "informational_findings": informational,
        "references": references,
        "fixture": {"caught": fixture_caught, **fixture_detail},
        "pass": not forbidden and references["ok"] and fixture_caught,
        "residual": [
            {
                "item": "harness Python package name and /opt runner path",
                "why": "identical across all arms; does not reveal arm or defense state",
            },
            {
                "item": "Cowrie service DNS name on the exposure network",
                "why": "ordinary honeypot fingerprint, not a condition label; noted rather than hidden",
            },
        ],
    }
