# SwarmPot

**SwarmPot is a reproducible research harness for evaluating SSH honeypots against cooperating AI pentesting agents.** Its central question is:

> Under fixed attacker and defender budgets, does explicit cooperation between defenders improve their ability to delay, divert, and defuse an attacker swarm?

The project is an environment and preliminary evaluation study. It uses existing attacker, benchmark, and honeypot systems; it does not propose a new exploit agent or a new honeypot engine. The [builder handoff](SwarmPot_Builder_Handoff.md) is the source of truth for the study design. **Implementation and validation are in progress; no comparative result is claimed here.**

## Approach

![SwarmPot architecture: the attacker team can continue to the real CVE-Bench application or voluntarily follow an SSH clue into a shared Cowrie-backed decoy; defenders observe assigned SSH sessions and may coordinate through a private board; the official grader checks only the real application.](docs/architecture.svg)

*Planned architecture from the handoff. [Editable TikZ source](docs/architecture.tex) · [vector PDF](docs/architecture.pdf). Solid arrows show traffic, observations, or permitted changes; dashed arrows show episode control.*

Each episode combines one CVE-Bench task, one ARTEMIS attacker team, an optional SSH decoy and defender team, fixed budgets, and an independent exploit verdict. The attacker sees the real application through an HTTP sidecar. In decoy-enabled arms, the sidecar adds the same small SSH clue to eligible HTML responses; the attacker chooses whether to follow it. Ordinary requests continue to the real application.

The SSH path leads through Cowrie proxy mode to **one disposable OpenSSH container**. All SSH sessions in that episode share its filesystem. Defenders receive only their assigned Cowrie session events, the permitted fictional files, and, in the cooperative arm, a private team board. They can edit allowlisted decoy files; they cannot access the hidden CVE solution, attacker reasoning, or official grader state. The official CVE-Bench grader checks the **real vulnerable application**, never the decoy.

| Role | Planned system | Responsibility |
| --- | --- | --- |
| Benchmark and oracle | [CVE-Bench v2.2.0](https://github.com/uiuc-kang-lab/cve-bench) | Vulnerable applications, zero-day prompts, reset, and original exploit grading |
| Attacker team | [ARTEMIS](https://github.com/Stanford-Trinity/ARTEMIS) | Supervisor and concurrent attacker workers |
| SSH honeypot | [Cowrie](https://github.com/cowrie/cowrie) | SSH proxy and structured session logs for a single shared decoy backend |
| SwarmPot layer | This repository | Episode control, fixed HTTP lure, restricted defenders, private board, event accounting, and metrics |

The three upstream repositories are pinned in [`vendor.lock.json`](vendor.lock.json). The local `vendor/` checkouts and `runs/` outputs are intentionally untracked.

## Experiment design

The primary comparison is **E versus D**: two defenders with a private board versus two defenders without one. Both arms use the same attacker swarm, lure, initial decoy, and **combined** defender budget. Arms A through C establish the baseline and the effects of a static decoy and one reactive defender.

| Arm | SSH decoy | Defenders | Private board | Purpose |
| :---: | --- | :---: | :---: | --- |
| A | None; placebo HTTP sidecar | 0 | Off | Real-target exploitability baseline |
| B | Fixed Cowrie/OpenSSH decoy | 0 | Off | Value of a static honeypot |
| C | Same initial decoy | 1 | Off | Effect of reactive adaptation |
| D | Same initial decoy | 2 | Off | Parallel defenders without messaging |
| E | Same initial decoy | 2 | On | Effect of explicit defender cooperation |

The pilot configuration proposes **two active attacker workers**, a team-wide ceiling of **200 counted tool actions** and **30 minutes**, and a defender-team ceiling of **40 LLM decisions** plus a fixed cost limit. These are pilot choices, not benchmark requirements. Every arm should use paired task instances and seeds, matched models, and the same accounting rules. A solo-attacker control is an optional diagnostic.

The planned exploratory run is three eligible CVE-Bench tasks, five arms, and three independent repetitions per arm: **45 episodes**. The [pilot task list](configs/pilot.yml) is provisional. Tasks must first launch on the available machine, retain their official grader behavior through the placebo sidecar, show at least some undefended attacker success, and span more than one application or weakness family. Selection must be fixed before examining defender results.

### What gets measured

1. **Real-target attack success (primary):** whether any attacker satisfies the original CVE-Bench objective, as determined by its official grader.
2. **Delay:** decoy-directed attacker-team tool actions divided by all attacker-team tool actions, alongside SSH command count and time spent at the decoy.
3. **Divert / team-level PER:** the fraction of team actions directed to the decoy after the first SSH decoy entry, with per-agent retention reported separately.
4. **Defuse / SubDefuse:** the share of eligible final reports or claims supported by decoy-origin evidence. This is separate from the official exploit verdict; when no eligible report or claim exists, the fraction is `N/A`.

Every fraction should retain its numerator, denominator, and aggregation rule. Supporting records include entry and abandonment times, cross-session consistency, model usage and cost, defender response latency, and paired outcomes by task and seed. These are SwarmPot team adaptations of the Delay/Divert/Defuse ideas in [AgentSnare](https://arxiv.org/abs/2607.26998); they are not automatically comparable to its single-agent numbers.

## Progress and next gates

As of **8 November 2026**, the research question, architecture, five-arm protocol, metrics, isolation rules, and stop/go gates are written in the [handoff](SwarmPot_Builder_Handoff.md). The repository has pinned upstream revisions, Docker definitions for the sidecar, attacker, Cowrie, and decoy, and initial Python modules for orchestration, grading, defenders, event logs, and reporting. These modules are active work in progress.

Untracked local smoke artifacts show a CVE-2024-2624 stack reaching application health and attacker-path reachability checks, with Cowrie session logs and a limited two-defender exercise. They **do not** constitute a completed attacker episode or a cooperation result: the inspected local runs contain no final `grader.json` or `metrics.json`, and the recorded defender exercise did not demonstrate board messages. The next work is to complete and document the gates in order:

1. Verify laptop compatibility and the untouched upstream CVE-Bench health, solution, and grading path.
2. Run ARTEMIS end to end against one isolated task; verify tool-action accounting, supervisor/worker logs, grading, and reset.
3. Verify the sidecar leaves placebo health and grading unchanged, and prove two SSH sessions see the same decoy filesystem while containment holds.
4. Verify solo and two-defender behavior, then the board-off versus board-on ablation under a matched team budget.
5. Run the paired pilot and publish raw episode records, official verdicts, metric audits, uncertainty, and failure analysis.

## Local workflow (under active integration)

You need Python 3.9+, Docker with Compose, enough resources for the selected CVE-Bench target, and an OpenAI-compatible model route. CVE-Bench recommends `amd64`; its `arm64` support is experimental. The episode overlay pins upstream target and database containers to `linux/amd64` while SwarmPot services can run natively. On Apple Silicon, verify one task under emulation before attempting the pilot.

```bash
python3 -m pip install -e .
scripts/bootstrap_upstream.sh
scripts/build_images.sh

# Supply your model-provider key through the environment.
export OPENROUTER_API_KEY='<your-key>'

# Intended one-episode entry point; arm A is the no-decoy baseline.
python3 -m swarmpot.episodes run --cve CVE-2024-2624 --arm A --rep 1

# Once complete episodes exist, generate the paired summary.
python3 -m swarmpot.report
```

The intended episode output is `runs/<episode-id>/`, including an episode manifest, timestamped events, the official `grader.json`, and recomputable `metrics.json`. The summary command writes `runs/summary/`. The CLI also exposes `prepare`, `grade`, `probe`, `down`, and `list` for integration checks; inspect `python3 -m swarmpot.episodes --help` for current arguments.

The diagram is editable TikZ. Rebuild its vector assets from the repository root with:

```bash
pdflatex -interaction=nonstopmode -halt-on-error -output-directory docs docs/architecture.tex
pdftocairo -svg docs/architecture.pdf docs/architecture.svg
```

## Scope and containment

Episodes must use isolated, authorized CVE-Bench targets. The decoy is disposable and must have no model keys, Docker socket, sensitive host mounts, unrestricted internet/LAN access, or route to the real vulnerable application. Model-provider egress is restricted through a broker. SwarmPot should keep the upstream vulnerability and grader untouched, reset the decoy between episodes, and record versions, prompts, budgets, and image digests in each run manifest.

The v0.1 scope excludes new exploits, RL, adaptive decoy placement, a dashboard, distributed execution, and recreation of AgentSnare's ShadowOS. The acceptance goal is one reproducible, isolated episode per selected arm whose real grader verdict and summary metrics can be inspected from raw records.
