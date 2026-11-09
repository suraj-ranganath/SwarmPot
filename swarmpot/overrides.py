from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional

import yaml

from .config import ArmConfig, PilotConfig
from .cve_adapter import CveBench


SIDECAR_IP = "172.31.250.10"
EXPOSURE_SUBNET = "172.31.250.0/24"
IMAGE_TAG = os.environ.get("SWARMPOT_IMAGE_TAG", "dev")
COWRIE_ALIAS = "fileserver-01"


@dataclass
class EpisodePaths:
    root: Path
    attacker: Path
    sidecar: Path
    egress: Path
    cowrie_log: Path
    cowrie_state: Path
    decoy_home: Path
    decoy_log: Path

    @classmethod
    def under(cls, root: Path) -> "EpisodePaths":
        root = Path(root)
        return cls(
            root=root,
            attacker=root / "attacker",
            sidecar=root / "sidecar",
            egress=root / "egress",
            cowrie_log=root / "cowrie",
            cowrie_state=root / "cowrie_state",
            decoy_home=root / "decoy_home",
            decoy_log=root / "decoy_log",
        )

    def create(self) -> "EpisodePaths":
        for path in (
            self.root,
            self.attacker,
            self.sidecar,
            self.egress,
            self.cowrie_log,
            self.cowrie_state,
            self.decoy_home,
            self.decoy_log,
        ):
            path.mkdir(parents=True, exist_ok=True)
        # Cowrie writes tty transcripts and downloads below its state directory.
        # The bind mount hides the image's copy, so the subdirectories must exist
        # on the host before Cowrie opens them.
        for name in ("tty", "downloads", "snapshots"):
            (self.cowrie_state / name).mkdir(parents=True, exist_ok=True)
        # The decoy and Cowrie containers run as unprivileged uids and write
        # through bind mounts.
        for path in (
            self.decoy_home,
            self.decoy_log,
            self.cowrie_log,
            self.cowrie_state,
            self.cowrie_state / "tty",
            self.cowrie_state / "downloads",
            self.cowrie_state / "snapshots",
        ):
            try:
                os.chmod(path, 0o777)
            except OSError:
                pass
        return self


def _volume(host: Path, container: str, mode: Optional[str] = None) -> Dict[str, Any]:
    entry: Dict[str, Any] = {"type": "bind", "source": str(host.resolve()), "target": container}
    if mode:
        entry["read_only"] = mode == "ro"
    return entry


def build_override(
    cfg: PilotConfig,
    bench: CveBench,
    cve: str,
    arm: ArmConfig,
    paths: EpisodePaths,
    lure_enabled: bool,
    egress_allow: str,
) -> Dict[str, Any]:
    """Compose overlay for one episode.

    The upstream compose file is never edited. This overlay only adds SwarmPot
    services and pins the amd64 target/db services. It deliberately publishes no
    host ports.
    """
    base_services = set(bench.service_names(cve))
    sidecar_env = {
        "UPSTREAM_HOST": "target",
        "UPSTREAM_PORT": "9090",
        "UPSTREAM_GRADER_PORT": "9091",
        "SWARMPOT_LURE_ENABLED": "1" if lure_enabled else "0",
        "SWARMPOT_DECOY_HOST": cfg.decoy.hostname,
        "SWARMPOT_DECOY_PORT": str(cfg.decoy.ssh_port),
        "SWARMPOT_DECOY_USER": cfg.decoy.user,
        "SWARMPOT_DECOY_PASSWORD": cfg.decoy.password,
        "SIDECAR_LOG": "/logs/sidecar.jsonl",
    }
    attacker_env = {
        "OPENROUTER_API_KEY": "${OPENROUTER_API_KEY:-}",
        "OPENAI_API_KEY": "${OPENAI_API_KEY:-}",
        "ROUTER_MODEL": cfg.attacker.supervisor_model,
        "SUBAGENT_MODEL": cfg.attacker.subagent_model,
        "HTTPS_PROXY": "http://egress-proxy:3128",
        "HTTP_PROXY": "http://egress-proxy:3128",
        "ALL_PROXY": "http://egress-proxy:3128",
        "NO_PROXY": "localhost,127.0.0.1,target,fileserver-01,cowrie,decoy,sidecar,egress-proxy",
        "no_proxy": "localhost,127.0.0.1,target,fileserver-01,cowrie,decoy,sidecar,egress-proxy",
        "SWARMPOT_ATTACKER_INPUT": "/logs/attacker_input.json",
        "PYTHONPATH": "/opt/swarmpot",
    }

    services: Dict[str, Any] = {
        "sidecar": {
            "image": f"swarmpot/sidecar:{IMAGE_TAG}",
            "environment": sidecar_env,
            "volumes": [_volume(paths.sidecar, "/logs")],
            "networks": {
                "target_network": {},
                "exposure_net": {"ipv4_address": SIDECAR_IP},
            },
            "depends_on": {"target": {"condition": "service_healthy"}},
            "healthcheck": {
                "test": [
                    "CMD",
                    "python",
                    "-c",
                    "import socket;[socket.create_connection(('127.0.0.1',p),2).close() for p in (9090,9091)]",
                ],
                "interval": "2s",
                "timeout": "5s",
                "retries": 60,
            },
            "restart": "no",
        },
        "decoy": {
            "image": f"swarmpot/decoy:{IMAGE_TAG}",
            "volumes": [
                _volume(paths.decoy_home, "/home/admin"),
                _volume(paths.decoy_log, "/var/log/gateway"),
            ],
            "networks": {"decoy_net": {}},
            "healthcheck": {
                # A TCP probe every two seconds would create (and abandon) an
                # sshd child each time, inflating MaxStartups and crowding out
                # real sessions. Check the daemon process instead.
                "test": ["CMD-SHELL", "pgrep -x sshd >/dev/null"],
                "interval": "2s",
                "timeout": "5s",
                "retries": 60,
            },
            "restart": "no",
        },
        "cowrie": {
            "image": f"swarmpot/cowrie:{IMAGE_TAG}",
            "volumes": [
                _volume(paths.cowrie_log, "/var/log/cowrie"),
                _volume(paths.cowrie_state, "/var/lib/cowrie"),
            ],
            "networks": {
                "exposure_net": {"aliases": [COWRIE_ALIAS]},
                "decoy_net": {},
            },
            "depends_on": {"decoy": {"condition": "service_started"}},
            "healthcheck": {
                # Probing the listener would make Cowrie dial the decoy backend
                # every two seconds. Supervise the process instead.
                "test": ["CMD-SHELL", "pgrep -f 'twistd.*cowrie' >/dev/null"],
                "interval": "2s",
                "timeout": "5s",
                "retries": 60,
            },
            "restart": "no",
        },
        "egress-proxy": {
            "image": f"swarmpot/egress:{IMAGE_TAG}",
            "environment": {
                "SWARMPOT_EGRESS_ALLOW": egress_allow,
                "SWARMPOT_EGRESS_LOG": "/logs/egress.jsonl",
            },
            "volumes": [_volume(paths.egress, "/logs")],
            "networks": {"exposure_net": {}, "swarmpot_egress": {}},
            "healthcheck": {
                "test": [
                    "CMD",
                    "python",
                    "-c",
                    "import socket;socket.create_connection(('127.0.0.1',3128),2).close()",
                ],
                "interval": "2s",
                "timeout": "5s",
                "retries": 60,
            },
            "restart": "no",
        },
        "attacker": {
            "image": f"swarmpot/attacker:{IMAGE_TAG}",
            "command": ["python", "-m", "swarmpot.artemis_adapter"],
            "environment": attacker_env,
            "extra_hosts": [f"target:{SIDECAR_IP}"],
            "volumes": [
                _volume(paths.attacker, "/logs"),
                _volume(Path(__file__).resolve().parent, "/opt/swarmpot/swarmpot", "ro"),
            ],
            "networks": {"exposure_net": {}},
            "profiles": ["attacker"],
            "depends_on": {
                "sidecar": {"condition": "service_healthy"},
                "cowrie": {"condition": "service_healthy"},
                "egress-proxy": {"condition": "service_healthy"},
            },
            "restart": "no",
        },
    }

    # Pin the upstream target/db images to amd64 without changing the upstream
    # compose files. Services absent from this task are not created.
    for name in base_services:
        services.setdefault(name, {})["platform"] = "linux/amd64"

    return {
        "services": services,
        "networks": {
            "exposure_net": {
                "internal": True,
                "ipam": {"config": [{"subnet": EXPOSURE_SUBNET}]},
            },
            "decoy_net": {"internal": True},
            "swarmpot_egress": {},
        },
    }


def write_override(path: Path, override: Dict[str, Any]) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(yaml.safe_dump(override, sort_keys=False), encoding="utf-8")
    return path


def infra_services(bench: CveBench, cve: str) -> List[str]:
    """Services to bring up before the attacker starts."""
    names = ["target"]
    for name in bench.service_names(cve):
        if name != "target":
            names.append(name)
    return names + ["sidecar", "decoy", "cowrie", "egress-proxy"]
