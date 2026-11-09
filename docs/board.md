# Defender board observer and wake-ups

Launch from a checkout with the normal Python dependencies installed:

```sh
python -m swarmpot.board_view --runs-dir runs --port 8765
# equivalent after pip install -e .:
swarmpot-board --runs-dir runs --port 8765
```

Open <http://127.0.0.1:8765>. An isolated worktree has its own default `runs/`;
pass the original checkout's absolute runs path to inspect its older episodes.
The observer serves only on IPv4 loopback. It belongs on the controller host,
outside container networks. It exposes no human wake or agent-control endpoint.
It needs neither Docker nor a running defender to inspect completed episodes.

The workspace shows **real benchmark episodes only**. A run must have a CVE,
arm, and recorded attacker startup (an attempt record or a legacy lifecycle
event). Standalone fixtures, directed hosted smoke checks, scripted verification
runs and prepared-only environments are excluded from both episode discovery
and direct snapshot URLs. A fixture cannot be enabled through a browser query.
This is an observer filter, not a change to experiment eligibility or scoring;
started episodes remain visible even when their boards are empty or they failed.

From the separate development worktree, inspect the primary checkout's real data:

```sh
python -m swarmpot.board_view --runs-dir ../SwarmPot/runs --port 8765
```

The interface uses a Slack-style workspace: experiments and channels in the
left sidebar, a chronological channel in the center, and team status or selected
event details on the right. `#defender-board` contains only actual board messages.
`#activity` shows recorded model decisions, tool calls, file commits and episode
lifecycle events, explicitly labeled as activity. Search filters the current
channel, including tool names; press `/` to focus search. Only defenders can
send messages. The observer has no message composer or wake control.

[Actual experiment activity](board-evidence/real-view/activity.png),
[event details](board-evidence/real-view/event-details.png), and the
[empty real E board](board-evidence/real-view/empty-real-board.png) show the
updated viewer. The primary checkout had eight started episodes when this
update was verified; both actual E boards contained zero messages. The GUI
preserves that empty state rather than substituting smoke messages. Earlier
fixture screenshots below remain archived verification evidence and are never
loaded by the normal observer.

Choose an arm and episode, optionally filter messages by sender, then select a
message for linked audit records. Live follow polls every 1.5 seconds. Turning
it off stops display polling. Pause scrolling keeps polling and updating the
record but holds the scroll position. Neither control changes execution.

Status cards show **recorded** state and its timestamp, pending message content
without successful automatic receipts, queued wakes, decisions remaining, team
cost remaining when known, and the last recorded decision/action. A crashed
producer can leave an old running record; its timestamp is evidence, not a
process liveness guarantee. Older logs with no status/receipt evidence show
unknown values, not invented activity or delivery. A stopped run can retain
unread content; that does not authorize another decision.

The browser displays at most 500 messages, reads messages in pages of 100, and
shows a recent audit window (at most 2 MiB / 2,000 relevant records). Use the next
page control for longer boards. Older event links outside the window are marked
unavailable. Episode discovery reads at most 100 manifests per page. SQLite and
raw audit records remain authoritative; the GUI is a redacted projection.
It does not serve arbitrary files, raw SSH transcripts, agent payload files, or
other board teams. HTML in messages is rendered as text. Credential-shaped
values and configured provider secrets are redacted. No external fonts, scripts,
services, models, or telemetry are loaded by the observer.

## Agent policy: teammate-wake-v1

Only arm E constructs the private board and offers its tools. `board_post(body,
notify=false)` is passive. `notify=true` persists one message and a durable
recipient notification in the same SQLite transaction, then records the queue
event. Both modes spend one shared message-cap slot. Invalid, failed, over-cap,
and unavailable posts cannot queue a wake. The two defenders' ordinary SSH
schedule, heartbeat, model, decision allowance and cost ceiling stay matched
with D. Board instructions explicitly discourage acknowledgement loops.

The team checks pending IDs at the existing scheduler interval (normally two
seconds), independently of SSH and heartbeat triggers. One request at a time is
admitted per defender. Busy recipients keep their wake IDs in SQLite; the next
dispatch coalesces the pending batch. Session observations are selected from
the owned Cowrie index after the busy request finishes. The SSH cursor advances
only for the batch actually supplied in a successful decision, so busy or failed
dispatches do not discard new SSH observations. This cursor follows the existing
process-local Cowrie index; board receipt state is durable across reopenings.

Each permitted decision includes up to eight unread messages / 6,500 serialized
message characters, prioritizing wake-causing IDs. Bodies are whole, and IDs
retain their original values. Only the recipient's own authorized SSH rows and
the private board enter that request. A sparse SQLite receipt table acknowledges
exactly the supplied message IDs after a successful provider response. Omitted
IDs remain unread. A passive message never starts a decision by itself, including
a passive remainder after a wake batch completes.

`llm_request` records the locally unique request ID, message IDs and observation
IDs. `board_delivery` distinguishes success from a failed request with unknown
exposure; an SDK retry is disabled. A scheduler retry uses another decision and
has a `retry_of` link. Failed request usage/cost is explicitly unknown. It does
not replenish a decision or cost allowance. Explicit `board_read` and its later
`board_read_context` receipt are separate from automatic delivery. Deliberate
reads are bounded so their returned content fits the existing tool-result limit.

`board_notification` records queued or denied disposition. `defender_status`
records waiting, running, pending, exhausted and stopped states. Request IDs
link delivered context, decisions, tool results and successful file commits.
These links show temporal/request membership; **context delivery is not proof of
understanding, influence, or causation**. There are no automatic replies,
self-wakes, or requeues of an already acknowledged ID. Stopped/exhausted agents
cannot be revived by pending content. An admitted final-budget request may
finish; a response arriving after an explicit episode stop cannot apply tools.

Every new episode manifest includes `board_notification_policy` and the narrow
`board_notification_audit`, preserving D/E tool schemas, scheduler interval and
allowances. [The recorded communication audit](board-evidence/notification-config-audit.json)
is supplementary to the other builder's full paired world/seed audit. Earlier
passive-board runs without this policy version are a separate E condition.

## Verification and evidence

```sh
python -m pytest
SWARMPOT_BROWSER_CHECK=1 SWARMPOT_BROWSER_ARTIFACTS=docs/board-evidence \
  python -m pytest tests/test_board_browser.py
python scripts/verify_board.py --out runs/board-fixture-new
python scripts/verify_board.py --out runs/board-hosted-new --hosted
```

The optional browser check opts into fixture access on its own isolated temporary
server; this option is not exposed by the normal CLI or browser API. It requires
the `agent-browser` CLI with its Chromium
runtime. It creates its own temporary data, server, browser session and model
stubs; it never touches an existing experiment. The smoke command refuses an
existing output directory. `--hosted` uses the configured environment's
OpenRouter key and a small capped allowance. It deliberately selects the named
post/write tools and supplies explicit communication instructions. These are
controlled instrumentation checks, not spontaneous cooperation or research
outcomes. Natural E episodes with no messages remain valid research attempts.

Saved evidence:

- [Browser check](board-evidence/browser-check.json), [live paused view](board-evidence/live-paused.png),
  [completed message details](board-evidence/completed.png), [mobile](board-evidence/mobile.png),
  [empty](board-evidence/empty.png), [missing evidence](board-evidence/missing-evidence.png),
  and [disconnected](board-evidence/disconnected.png).
- [Hosted smoke](board-evidence/hosted-smoke.json) and [audit sequence](board-evidence/hosted-events.jsonl):
  one actual agent-origin notifying post, a successful teammate context receipt,
  and a permitted committed edit. Two model decisions; 1,550 prompt tokens and
  105 output tokens; estimated cost $0.000119. Hosted request/response snapshots
  are saved alongside this evidence. The measured controller process peak RSS
  was 88,047,616 bytes, SQLite 28,672 bytes and audit log 13,128 bytes.
- [Earlier unconstrained attempt](board-evidence/unconstrained-hosted-smoke.json):
  one decision, no post, delivery or edit. It is preserved as a negative result;
  the directed success does not establish natural communication frequency.
- Browser `performance.memory.usedJSHeapSize` reported approximately 10,000,000
  bytes during the fixture (Chromium may coarsen this value). This is JS heap,
  not whole-browser RSS or incremental overhead. No zero-overhead claim is made.

Deterministic tests cover passive/failed/over-cap posts, idle wake without SSH,
busy bursts without overlapping calls, SSH retention, durable partial batches,
failed request/retry accounting, explicit reads, self-wake suppression, disabled
board, exhausted quota, final admitted work, stopped-agent denial, cross-team
privacy, credential redaction, and read-only HTTP refreshes. The browser check
also verifies filters, scroll pause with live updates, linked delivery/commit
records, completed runs, missing evidence, disconnection/recovery and mobile
layout. Hosted smoke raw data remains under the worktree's ignored `runs/`;
the committed copies above are redacted evidence, not replacement authorities.
