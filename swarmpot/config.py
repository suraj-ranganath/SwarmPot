from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional

import yaml

from .util import CONFIGS_DIR, ROOT


@dataclass
class AttackerConfig:
    supervisor_model: str = "openai/o4-mini"
    subagent_model: str = "anthropic/claude-sonnet-4"
    max_tool_actions: int = 200
    wall_clock_minutes: int = 30
    max_subagents: int = 2
    ensure_subagents: int = 2
    ensure_after_seconds: int = 90
    codex_binary: str = "/usr/local/bin/codex"


@dataclass
class DefenderConfig:
    model: str = "anthropic/claude-sonnet-4"
    combined_decisions: int = 40
    max_cost_usd: float = 1.50
    board_messages: int = 24
    poll_seconds: float = 2.0
    max_output_tokens: int = 700
    temperature: float = 0.2


@dataclass
class DecoyConfig:
    hostname: str = "fileserver-01"
    ssh_port: int = 2222
    user: str = "admin"
    password: str = "swarmpot"
    allowlist_root: str = "/home/admin"
    max_file_bytes: int = 8192


@dataclass
class CveBenchConfig:
    dir: str = "vendor/cve-bench"
    variant: str = "zero_day"
    version: str = "critical"


@dataclass
class TaskConfig:
    cve: str
    family: str = ""
    notes: str = ""


@dataclass
class ArmConfig:
    name: str
    decoy: bool
    defenders: int
    board: bool
    description: str = ""


@dataclass
class PilotConfig:
    name: str
    attacker: AttackerConfig
    defender: DefenderConfig
    decoy: DecoyConfig
    cvebench: CveBenchConfig
    tasks: List[TaskConfig]
    arms: Dict[str, ArmConfig]
    source_path: Optional[Path] = None
    raw: Dict = field(default_factory=dict)

    def arm(self, name: str) -> ArmConfig:
        try:
            return self.arms[name.upper()]
        except KeyError:
            raise KeyError(f"unknown arm {name!r}; choose from {sorted(self.arms)}")


DEFAULT_ARMS = {
    "A": ArmConfig("A", decoy=False, defenders=0, board=False, description="no deception; placebo sidecar"),
    "B": ArmConfig("B", decoy=True, defenders=0, board=False, description="static Cocwrie/OpenSSH decoy"),
    "C": ArmConfig("C", decoy=True, defenders=1, board=False, description="one reactive defender"),
    "D": ArmConfig("D", decoy=True, defenders=2, board=False, description="two defenders, board disabled"),
    "E": ArmConfig("E", decoy=True, defenders=2, board=True, description="two defenders, board enabled"),
}


def _resolve_cvebench_dir(value: str) -> str:
    path = Path(value)
    if not path.is_absolute():
        path = ROOT / path
    return str(path)


def load_config(path: Optional[Path] = None) -> PilotConfig:
    path = Path(path) if path else CONFIGS_DIR / "pilot.yml"
    with open(path, "r", encoding="utf-8") as handle:
        raw = yaml.safe_load(handle) or {}

    attacker = AttackerConfig(**raw.get("attacker", {}))
    defender = DefenderConfig(**raw.get("defender", {}))
    decoy = DecoyConfig(**raw.get("decoy", {}))
    cvebench_raw = raw.get("cvebench", {})
    cvebench = CveBenchConfig(
        dir=_resolve_cvebench_dir(os.environ.get("SWARMPOT_CVEBENCH_DIR", cvebench_raw.get("dir", "vendor/cve-bench"))),
        variant=cvebench_raw.get("variant", "zero_day"),
        version=cvebench_raw.get("version", "critical"),
    )

    tasks = [TaskConfig(**item) for item in raw.get("tasks", [])]
    arms_raw = raw.get("arms")
    if arms_raw:
        arms = {name.upper(): ArmConfig(name=name.upper(), **cfg) for name, cfg in arms_raw.items()}
    else:
        arms = dict(DEFAULT_ARMS)

    return PilotConfig(
        name=raw.get("name", "swarmpot-pilot"),
        attacker=attacker,
        defender=defender,
        decoy=decoy,
        cvebench=cvebench,
        tasks=tasks,
        arms=arms,
        source_path=path,
        raw=raw,
    )
