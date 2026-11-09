from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import time
from pathlib import Path
from typing import Any, Dict, List, Optional

import yaml

from .config import CveBenchConfig
from .util import read_json, write_json


class CveBenchError(RuntimeError):
    pass


def _read_version(repo: Path) -> str:
    init = repo / "src" / "cvebench" / "__init__.py"
    text = init.read_text(encoding="utf-8")
    match = re.search(r'__version__\s*=\s*"([^"]+)"', text)
    if not match:
        raise CveBenchError(f"cannot read CVE-Bench version from {init}")
    return match.group(1)


class CveBench:
    """Thin adapter over a pinned CVE-Bench checkout.

    It deliberately reuses the upstream compose files, the upstream zero-day
    prompt (`eval.yml`), and the upstream grader entrypoint
    (`/evaluator/done.sh` inside the target container). No vulnerability logic,
    task text, secret generation, or grading is reimplemented here.
    """

    def __init__(self, cfg: CveBenchConfig):
        self.repo = Path(cfg.dir).resolve()
        self.version = cfg.version
        self.variant = cfg.variant
        self.tag = _read_version(self.repo)
        self.version_dir = self.repo / "src" / self.version
        self.challenge_dir = self.version_dir / "challenges"
        self.metadata_dir = self.version_dir / "metadata"
        self.docker_dir = self.repo / "src" / "common" / "docker"
        self.evaluations_dir = self.repo / "src" / "common" / "evaluations"
        self.sandboxes_dir = self.repo / "src" / "common" / "sandboxes"

    # ---------------------------------------------------------------- tasks
    def task_dir(self, cve: str) -> Path:
        path = self.challenge_dir / cve
        if not path.is_dir():
            raise CveBenchError(f"unknown CVE-Bench task: {cve}")
        return path

    def compose_file(self, cve: str) -> Path:
        return self.task_dir(cve) / "compose.yml"

    def eval_config(self, cve: str) -> Dict[str, Any]:
        with open(self.task_dir(cve) / "eval.yml", "r", encoding="utf-8") as handle:
            return yaml.safe_load(handle)

    def prompt(self, cve: str, variant: Optional[str] = None) -> str:
        variant = variant or self.variant
        data = self.eval_config(cve)
        try:
            return data["variants"][variant]["prompt"].strip()
        except KeyError:
            raise CveBenchError(f"{cve} has no variant {variant!r}")

    def metadata(self, cve: str) -> Dict[str, Any]:
        path = self.metadata_dir / f"{cve}.yml"
        if path.exists():
            with open(path, "r", encoding="utf-8") as handle:
                return yaml.safe_load(handle) or {}
        return self.eval_config(cve).get("metadata", {})

    def service_names(self, cve: str) -> List[str]:
        """Service names declared directly in the upstream compose file."""
        with open(self.compose_file(cve), "r", encoding="utf-8") as handle:
            data = yaml.safe_load(handle) or {}
        return sorted((data.get("services") or {}).keys())

    def reference_solution(self, cve: str) -> Optional[Path]:
        path = self.task_dir(cve) / "solution" / "solution.sh"
        return path if path.exists() else None

    # ---------------------------------------------------------- compose env
    def env(self, secret_seed: str = "42") -> Dict[str, str]:
        env = os.environ.copy()
        # The harness runs target containers under explicit amd64 pinning (in the
        # generated override), while SwarmPot's own images are native arm64.
        # A global platform would force the latter through emulation.
        env.pop("DOCKER_DEFAULT_PLATFORM", None)
        env["COMPOSE_ANSI"] = "never"
        env["COMPOSE_PROGRESS"] = "plain"
        env.update(
            {
                "CVEBENCH_TAG": self.tag,
                "CVEBENCH_VERSION": self.version,
                "CVEBENCH_VERSION_DIR": str(self.version_dir),
                "CVEBENCH_METADATA_DIR": str(self.metadata_dir),
                "CVEBENCH_CHALLENGE_DIR": str(self.challenge_dir),
                "CVEBENCH_NVD_DIR": str(self.version_dir / "nvd"),
                "CVEBENCH_VERSION_DOCKER_DIR": str(self.version_dir / "docker"),
                "CVEBENCH_DOCKER_DIR": str(self.docker_dir),
                "CVEBENCH_EVALUATIONS_DIR": str(self.evaluations_dir),
                "CVEBENCH_VERSION_EVALUATIONS_DIR": str(self.version_dir / "evaluations"),
                "CVEBENCH_SANDBOXES_DIR": str(self.sandboxes_dir),
                # The upstream Kali agent is not part of a SwarmPot episode. The
                # empty sandbox include keeps the target/db/secrets services and
                # leaves the attacker role to our own container.
                "CVEBENCH_SANDBOX_COMPOSE_FILE": str(self.docker_dir / "compose-empty.yml"),
                "CVEBENCH_ORGANIZATION": "cvebench",
                "CVEBENCH_SECRET_SEED": secret_seed,
                "CVEBENCH_AGENT_INTERNET": "false",
                "CVEBENCH_AGENT_INTERNET_INTERNAL": "true",
                "CVEBENCH_KALI_SIZE": "core",
            }
        )
        return env

    def compose_cmd(
        self,
        cve: str,
        project: str,
        override: Optional[Path] = None,
        secret_seed: str = "42",
    ) -> List[str]:
        cmd = [
            "docker",
            "compose",
            "--project-name",
            project,
            "--project-directory",
            str(self.task_dir(cve)),
        ]
        cmd += ["-f", str(self.compose_file(cve))]
        if override is not None:
            cmd += ["-f", str(override)]
        return cmd

    # ------------------------------------------------------------- lifecycle
    def up(
        self,
        cve: str,
        project: str,
        override: Path,
        services: List[str],
        secret_seed: str = "42",
        timeout_seconds: int = 900,
    ) -> None:
        cmd = self.compose_cmd(cve, project, override, secret_seed) + [
            "up",
            "-d",
            "--wait",
            "--wait-timeout",
            str(timeout_seconds),
        ] + services
        self._run(cmd, env=self.env(secret_seed), timeout=timeout_seconds + 120)

    def down(self, cve: str, project: str, override: Optional[Path] = None, secret_seed: str = "42") -> None:
        cmd = self.compose_cmd(cve, project, override, secret_seed) + [
            "down",
            "--volumes",
            "--remove-orphans",
            "--timeout",
            "0",
        ]
        self._run(cmd, env=self.env(secret_seed), timeout=300, check=False)

    def compose_exec(
        self,
        cve: str,
        project: str,
        service: str,
        command: List[str],
        override: Optional[Path] = None,
        secret_seed: str = "42",
        timeout: int = 120,
    ) -> subprocess.CompletedProcess:
        cmd = self.compose_cmd(cve, project, override, secret_seed) + ["exec", "-T", service] + command
        return self._run(cmd, env=self.env(secret_seed), timeout=timeout, check=False)

    def images(self, cve: str, project: str, override: Path, seed: str = "42") -> List[Dict[str, Any]]:
        proc = self._run(
            self.compose_cmd(cve, project, override, seed) + ["images", "--format", "json"],
            env=self.env(seed),
            timeout=60,
            check=False,
        )
        rows: List[Dict[str, Any]] = []
        if proc.returncode != 0:
            return rows
        text = proc.stdout.strip()
        if not text:
            return rows
        for line in text.splitlines():
            try:
                rows.append(json.loads(line))
            except json.JSONDecodeError:
                continue
        return rows

    # --------------------------------------------------------------- grading
    def health(self, cve: str, project: str, override: Optional[Path] = None, seed: str = "42") -> Dict[str, Any]:
        proc = self.compose_exec(
            cve, project, "target", ["sh", "/evaluator/health.sh"], override=override, secret_seed=seed, timeout=30
        )
        return {"ok": proc.returncode == 0, "stdout": proc.stdout[-4000:], "stderr": proc.stderr[-4000:]}

    def grade(self, cve: str, project: str, override: Optional[Path] = None, seed: str = "42") -> Dict[str, Any]:
        """Invoke the untouched upstream grader.

        This is the same entrypoint Inspect's CVE-Bench scorer executes inside
        the target sandbox: ``sh /evaluator/done.sh`` -> ``done.py`` -> GET
        ``http://localhost:9091/done`` -> ``grader.check_attack_success()``.
        """
        started = time.time()
        proc = self.compose_exec(
            cve,
            project,
            "target",
            ["sh", "/evaluator/done.sh"],
            override=override,
            secret_seed=seed,
            timeout=600,
        )
        elapsed = time.time() - started
        status: Optional[bool] = None
        message = ""
        raw = proc.stdout
        index = raw.find("{")
        if index >= 0:
            try:
                data = json.loads(raw[index:])
                status = bool(data.get("status")) if "status" in data else None
                message = str(data.get("message", ""))
            except json.JSONDecodeError:
                pass
        return {
            "status": status,
            "message": message,
            "returncode": proc.returncode,
            "elapsed_seconds": round(elapsed, 3),
            "stdout": proc.stdout[-8000:],
            "stderr": proc.stderr[-8000:],
            "grader_error": "CVE_GRADER_ERROR" in proc.stderr,
            "entrypoint": "docker compose exec -T target sh /evaluator/done.sh",
        }

    # ----------------------------------------------------------------- misc
    def host_pin(self) -> Dict[str, Any]:
        def git_output(*args: str) -> str:
            try:
                return subprocess.check_output(
                    ["git", "-C", str(self.repo)] + list(args), text=True, stderr=subprocess.DEVNULL
                ).strip()
            except (subprocess.CalledProcessError, FileNotFoundError):
                return ""

        return {
            "repo": "https://github.com/uiuc-kang-lab/cve-bench",
            "commit": git_output("rev-parse", "HEAD"),
            "tag": self.tag,
            "version": self.version,
        }

    @staticmethod
    def _run(
        cmd: List[str], env: Dict[str, str], timeout: int = 120, check: bool = True
    ) -> subprocess.CompletedProcess:
        proc = subprocess.run(
            cmd,
            env=env,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=timeout,
        )
        if check and proc.returncode != 0:
            raise CveBenchError(
                f"command failed ({proc.returncode}): {' '.join(cmd)}\nSTDOUT:\n{proc.stdout[-4000:]}\nSTDERR:\n{proc.stderr[-4000:]}"
            )
        return proc


def reset_decoy_home(decoy_home: Path, seed_dir: Path) -> None:
    if decoy_home.exists():
        shutil.rmtree(decoy_home)
    decoy_home.mkdir(parents=True, exist_ok=True)
    if seed_dir.exists():
        for item in seed_dir.iterdir():
            target = decoy_home / item.name
            if item.is_dir():
                shutil.copytree(item, target)
            else:
                shutil.copy2(item, target)


def dump_task_snapshot(cve: str, bench: CveBench, out_dir: Path) -> Dict[str, Any]:
    snapshot = {
        "cve": cve,
        "prompt": bench.prompt(cve),
        "metadata": bench.metadata(cve),
        "compose_file": str(bench.compose_file(cve)),
        "solution_available": bench.reference_solution(cve) is not None,
    }
    write_json(out_dir / "task.json", snapshot)
    return snapshot
