"use strict";
const $ = (id) => document.getElementById(id);
let runs = [],
  nextRuns = null,
  episode = "",
  data = null,
  messages = [],
  selected = null;
let channel = "summary",
  follow = true,
  paused = false,
  busy = false,
  feedSignature = "",
  runSignature = "",
  browsingOlder = false;
let traceItems = [],
  traceCursor = 0,
  traceNext = null,
  traceBusy = false,
  traceKey = "";
const activityKinds = new Set([
  "llm_decision",
  "llm_request",
  "llm_error",
  "llm_retry",
  "tool_call",
  "decoy_edit",
  "decoy_write",
  "board_post",
  "board_read",
  "board_notification",
  "board_delivery",
  "decision_denied",
  "defender_error",
]);
const lifecycleStages = new Set([
  "attacker_started",
  "attacker_exit",
  "grading_start",
  "grading_done",
  "teardown_done",
  "attempt_finalized",
  "infra_failed",
  "metrics_written",
  "teardown_start",
  "grading_skipped",
]);
function node(tag, text, cls) {
  const e = document.createElement(tag);
  if (text !== undefined) e.textContent = text;
  if (cls) e.className = cls;
  return e;
}
function badge(text) {
  return node("span", text, "badge " + String(text).replace(/\s+/g, "-"));
}
function avatar(id) {
  return node(
    "span",
    id === "defender-1" ? "D1" : id === "defender-2" ? "D2" : "◇",
    "avatar" + (id === "defender-2" ? " second" : !id ? " system" : ""),
  );
}
function empty(title, body) {
  const e = node("div", undefined, "empty");
  e.append(
    node("div", channel === "board" ? "#" : "↳", "empty-symbol"),
    node("strong", title),
    node("span", body),
  );
  return e;
}
function time(ts) {
  return ts
    ? new Date(ts).toLocaleTimeString([], {
        hour: "2-digit",
        minute: "2-digit",
      })
    : "Time unavailable";
}
function day(ts) {
  return ts
    ? new Date(ts).toLocaleDateString([], {
        month: "long",
        day: "numeric",
        year: "numeric",
      })
    : "Date unavailable";
}
function shortDate(ts) {
  return ts
    ? new Date(ts).toLocaleDateString([], { month: "short", day: "numeric" }) +
        " · " +
        time(ts)
    : "Date unavailable";
}
async function get(url) {
  const r = await fetch(url, { cache: "no-store" });
  if (!r.ok) throw new Error("Evidence unavailable");
  return r.json();
}
function connection(ok) {
  $("connection").textContent = ok
    ? "Connected"
    : "Disconnected · last records";
  $("connection").className = ok ? "" : "offline";
}
async function loadRuns(offset = 0) {
  try {
    const result = await get("/api/episodes?offset=" + offset);
    if (offset) browsingOlder = true;
    runs = offset ? runs.concat(result.episodes) : result.episodes;
    nextRuns = result.next_offset;
    $("more-runs").hidden = nextRuns === null;
    renderRuns();
    connection(true);
  } catch (e) {
    connection(false);
    if (!runs.length)
      $("feed").replaceChildren(
        empty(
          "Experiment logs unavailable",
          "Check the local observer connection. No sample data is substituted.",
        ),
      );
  }
}
function renderRuns() {
  const arm = $("arm").value,
    items = runs.filter((r) => !arm || r.arm === arm);
  const signature = JSON.stringify([items, arm]);
  if (signature !== runSignature) {
    runSignature = signature;
    const prior = episode;
    $("episode").replaceChildren();
    if (!items.length)
      $("episode").append(new Option("No started experiments", ""));
    for (const r of items)
      $("episode").append(
        new Option(
          `${r.cve || r.episode_id} · ${shortDate(r.created_at)} · ${r.arm || "?"}`,
          r.id,
        ),
      );
    $("episode").value = items.some((r) => r.id === prior)
      ? prior
      : items[0]?.id || "";
    if (episode !== $("episode").value || !items.length) chooseEpisode();
  }
  $("runs").replaceChildren();
  for (const r of items) {
    const b = node(
      "button",
      undefined,
      "run-button" + (r.id === episode ? " selected" : ""),
    );
    b.setAttribute("aria-label", `Open episode ${r.episode_id || r.id}`);
    const text = node("div", undefined, "run-button-text");
    text.append(
      node("strong", r.cve || r.episode_id),
      node(
        "small",
        `${shortDate(r.created_at)}${r.repetition != null ? " · Run " + r.repetition : ""}`,
      ),
    );
    b.append(node("span", r.arm || "?", "arm-pill"), text);
    if (r.board_message_count > 0)
      b.append(node("span", String(r.board_message_count), "run-count"));
    b.onclick = () => {
      $("episode").value = r.id;
      chooseEpisode();
      renderRuns();
    };
    $("runs").append(b);
  }
}
function showOverview() {
  selected = null;
  $("details").hidden = true;
  $("overview").hidden = false;
  $("inspector-title").textContent = "Episode overview";
  feedSignature = "";
  if (data) renderFeed();
}
function chooseEpisode() {
  episode = $("episode").value;
  messages = [];
  traceItems = [];
  traceCursor = 0;
  traceNext = null;
  traceKey = "";
  selected = null;
  data = null;
  feedSignature = "";
  showOverview();
  $("workspace").classList.remove("nav-open");
  $("sidebar-toggle").setAttribute("aria-expanded", "false");
  if (episode) {
    $("feed").replaceChildren(
      empty("Loading experiment", "Reading recorded events…"),
    );
    refresh();
  } else {
    $("run-meta").textContent = "Only started benchmark episodes are shown.";
    $("policy").textContent = "Notification policy not recorded";
    $("cards").replaceChildren();
    $("members").replaceChildren();
    $("header-members").replaceChildren();
    $("recent").replaceChildren();
    $("count").textContent = "0 records";
    $("board-count").textContent = "—";
    $("activity-count").textContent = "—";
    $("member-count").textContent = "";
    $("evidence-note").hidden = true;
    $("about-cve").textContent = "No episode selected";
    $("about-episode").textContent = "";
    $("about-tags").replaceChildren();
    $("feed").replaceChildren(
      empty(
        "No recorded runs",
        "No started benchmark episodes match this arm. Fixtures, smoke runs and prepared-only environments are excluded.",
      ),
    );
  }
}
function activity() {
  return data
    ? data.events.filter(
        (e) =>
          activityKinds.has(e.kind) ||
          (e.kind === "lifecycle" && lifecycleStages.has(e.payload.stage)),
      )
    : [];
}
function eventTitle(e) {
  if (e.explanation?.title) return e.explanation.title;
  const p = e.payload;
  if (e.kind === "llm_decision") return "Model decision";
  if (e.kind === "llm_request") return "Model request started";
  if (e.kind === "llm_error") return "Model request failed";
  if (e.kind === "llm_retry") return "Model request retried";
  if (e.kind === "decoy_write" || e.kind === "decoy_edit")
    return "File edit committed";
  if (e.kind === "tool_call")
    return (
      {
        read_session: "Read assigned session events",
        read_decoy_files: "Read decoy files",
        write_decoy_file: "Requested file edit",
        board_read: "Read the defender board",
        board_post: "Posted to the defender board",
      }[e.tool] ||
      e.tool ||
      "Tool call"
    );
  if (e.kind === "board_notification")
    return "Teammate wake-up " + (p.status || e.status || "recorded");
  if (e.kind === "board_delivery")
    return "Board context " + (p.status || "recorded");
  if (e.kind === "board_post") return "Board message posted";
  if (e.kind === "board_read") return "Board read recorded";
  if (e.kind === "lifecycle")
    return (
      {
        attacker_started: "Attacker team started",
        attacker_exit: "Attacker team finished",
        grading_start: "Official grading started",
        grading_done: "Official grading finished",
        teardown_done: "Episode environment stopped",
        attempt_finalized: "Attempt finalized",
        infra_failed: "Infrastructure failed",
      }[p.stage] ||
      p.stage ||
      "Episode event"
    );
  return e.kind.replace(/_/g, " ");
}
function eventBody(e) {
  if (e.explanation?.description) return e.explanation.description;
  const p = e.payload;
  if (p.content) return p.content;
  const parts = [eventTitle(e)];
  if (p.tool_names?.length) parts.push(p.tool_names.join(", "));
  if (p.path) parts.push(p.path);
  if (p.recipient) parts.push("Recipient: " + p.recipient);
  if (p.reason || e.reason) parts.push(p.reason || e.reason);
  return parts.join(" · ");
}
function eventState(e) {
  if (e.payload.status || e.status) return e.payload.status || e.status;
  if (e.payload.ok === false) return "failed";
  if (e.kind === "decoy_write") return "committed";
  return null;
}
function renderCards() {
  const budget = data.budget;
  $("cards").replaceChildren();
  $("members").replaceChildren();
  $("header-members").replaceChildren();
  $("member-count").textContent = data.cards.length || "";
  for (const c of data.cards) {
    const headerAvatar = node(
      "span",
      c.id === "defender-1" ? "D1" : c.id === "defender-2" ? "D2" : c.id,
      "mini-avatar" + (c.id === "defender-2" ? " second" : ""),
    );
    $("header-members").append(headerAvatar);
    const member = node("button", undefined, "member");
    member.append(
      avatar(c.id),
      node("span", c.id),
      node("i", undefined, "member-status " + c.state),
    );
    member.title = "Recorded status: " + c.state;
    member.onclick = () => {
      $("defender").value = c.id;
      renderFeed();
    };
    $("members").append(member);
    const card = node("article", undefined, "card"),
      top = node("div", undefined, "card-top");
    top.append(avatar(c.id), node("span", c.id, "agent-label"), badge(c.state));
    const used = budget?.decisions?.[c.id] ?? 0,
      remaining = budget
        ? Math.max(
            0,
            Math.min(
              budget.per_agent_quota - used,
              budget.combined_decisions - budget.decisions_used,
            ),
          )
        : null;
    const cost = budget?.cost_known
      ? Math.max(0, budget.max_cost_usd - budget.cost_usd)
      : null;
    const stats = node("div", undefined, "stats");
    for (const [value, label] of [
      [c.unread_count ?? "—", "PENDING MESSAGES"],
      [remaining ?? "—", "DECISIONS LEFT"],
      [cost === null ? "—" : "$" + cost.toFixed(3), "TEAM COST LEFT"],
    ]) {
      const s = node("div", undefined, "stat");
      s.append(node("strong", String(value)), node("span", label));
      stats.append(s);
    }
    const last = c.last,
      description = last
        ? `${time(last.ts)} · ${last.payload.path || last.tool || eventTitle(last)}`
        : "No decision or action recorded";
    const lastNode = node("button", description, "last");
    lastNode.title = description;
    lastNode.disabled = !last;
    if (last) lastNode.onclick = () => selectEvent(last);
    card.append(
      top,
      stats,
      node(
        "p",
        c.pending_known
          ? `${c.pending.length} queued wake-up(s)`
          : "Wake-up evidence unavailable",
        "wake-note",
      ),
      lastNode,
    );
    if (c.state_at)
      card.append(
        node("p", "Status recorded " + time(c.state_at), "status-time"),
      );
    $("cards").append(card);
  }
  if (!data.cards.length)
    $("cards").append(
      node(
        "p",
        "No defender activity recorded for this episode.",
        "recent-empty",
      ),
    );
  $("recent").replaceChildren();
  const recent = activity()
    .filter((e) =>
      [
        "llm_decision",
        "decoy_edit",
        "decoy_write",
        "board_notification",
        "board_delivery",
        "llm_error",
      ].includes(e.kind),
    )
    .slice(-4)
    .reverse();
  for (const e of recent) {
    const b = node("button", undefined, "recent-item"),
      text = node("div");
    text.append(
      node("strong", eventTitle(e)),
      node("span", `${e.agent_id || "System"} · ${time(e.ts)}`),
    );
    b.append(node("i", undefined, "recent-dot"), text);
    b.onclick = () => selectEvent(e);
    $("recent").append(b);
  }
  if (!recent.length)
    $("recent").append(
      node(
        "p",
        "No defender decisions or file edits are recorded in this episode.",
        "recent-empty",
      ),
    );
}
function related(m) {
  const direct = data.events.filter(
    (e) =>
      e.payload.message_id === m.seq ||
      [
        ...(e.payload.message_seqs || []),
        ...(e.payload.board_message_seqs || []),
        ...(e.payload.board_context_message_seqs || []),
      ].includes(m.seq),
  );
  const requests = new Set(
      direct
        .flatMap((e) => [e.payload.request_id, e.payload.provider_request_id])
        .filter(Boolean),
    ),
    ids = new Set(direct.map((e) => e.event_id).filter(Boolean));
  return data.events.filter(
    (e) =>
      direct.includes(e) ||
      (e.payload.request_id && requests.has(e.payload.request_id)) ||
      (e.parent_event_id && ids.has(e.parent_event_id)),
  );
}
function chooseChannel(next) {
  channel = next;
  selected = null;
  feedSignature = "";
  showOverview();
  $("workspace").classList.remove("inspector-open");
  const names = {
    summary: "run-summary",
    traces: "traces",
    board: "defender-board",
    activity: "activity",
  };
  const tabs = {
    summary: "Run summary",
    traces: "Trace records",
    board: "Messages",
    activity: "Activity",
  };
  $("channel-title").textContent = names[channel];
  $("tab-label").textContent = tabs[channel];
  for (const name of Object.keys(names)) {
    $("channel-" + name).classList.toggle("active", name === channel);
    $("channel-" + name).setAttribute("aria-pressed", String(name === channel));
  }
  $("phase").hidden = !["activity", "traces"].includes(channel);
  $("trace-toolbar").hidden = channel !== "traces";
  $("defender").hidden = channel === "summary";
  $("pause").hidden = channel === "summary";
  $("trace-more").hidden = channel !== "traces" || traceNext === null;
  if (data) {
    if (channel === "traces") loadTrace(true);
    renderFeed();
  }
}
function sourceOptions() {
  const prior = $("trace-source").value,
    options = data.inspection?.sources || [];
  $("trace-source").replaceChildren();
  for (const source of options)
    $("trace-source").append(new Option(source.title, source.id));
  if (options.some((s) => s.id === prior)) $("trace-source").value = prior;
}
function openTrace(phase = "all", source = "controller") {
  $("phase").value = phase;
  if ([...$("trace-source").options].some((o) => o.value === source))
    $("trace-source").value = source;
  chooseChannel("traces");
}
function traceButton(label, phase, source) {
  const b = node("button", label, "trace-link");
  b.onclick = () => openTrace(phase, source);
  return b;
}
function renderSummary() {
  const info = data.inspection;
  if (!info) return;
  const signature = JSON.stringify(info);
  if (feedSignature === signature) return;
  feedSignature = signature;
  const scroll = $("feed").scrollTop;
  $("feed").replaceChildren();
  $("older").hidden = true;
  $("trace-more").hidden = true;
  $("count").textContent = "Recorded evidence";
  const page = node("article", undefined, "run-summary");
  page.append(
    node("p", "RUN RECAP", "section-kicker"),
    node(
      "h2",
      info.outcome.official_success === true
        ? "Official attack succeeded"
        : info.outcome.official_success === false
          ? info.attacker.actions_used > 0
            ? "Attack attempted; official objective was not achieved"
            : info.attacker.actions_used === 0
              ? "No counted attacker action was recorded"
              : "Official grader reported the attack unsuccessful"
          : "Attack outcome is not yet established",
    ),
    node(
      "p",
      "From recorded controller events, attacker logs and official grading records.",
      "summary-intro",
    ),
  );
  const cards = node("div", undefined, "summary-metrics");
  for (const [label, value, detail] of [
    [
      "ATTACKER EXECUTION",
      info.attacker.actions_used ?? "Unknown",
      "counted tool actions",
    ],
    [
      "TIME ALLOWANCE",
      fmtDuration(info.termination.wall_clock_limit_seconds),
      "resolved per-run setting",
    ],
    [
      "ACTUAL DURATION",
      fmtDuration(info.termination.elapsed_seconds),
      info.termination.ended_before_time_allowance === true
        ? "ended before the allowance"
        : info.termination.ended_before_time_allowance === false
          ? "did not end early"
          : "timing comparison unknown",
    ],
    ["DECOY SSH", info.decoy.commands ?? "Unknown", "recorded SSH commands"],
  ]) {
    const c = node("div", undefined, "summary-metric");
    c.append(
      node("span", label),
      node("strong", String(value)),
      node("small", detail),
    );
    cards.append(c);
  }
  page.append(cards);
  const sections = [
    ["What the attackers did", info.attacker.description, "attack", "attacker"],
    [
      "Why execution stopped",
      info.termination.description,
      "attack",
      "supervisor",
    ],
    [
      "Official exploit result",
      info.outcome.description,
      "grading",
      "controller",
    ],
    [
      "Did the decoy draw them in?",
      info.decoy.description +
        " Causal steering is not established by a single run.",
      "attack",
      "ssh",
    ],
    [
      "What the defenders did",
      info.defender.description,
      "attack",
      "controller",
    ],
  ];
  if (info.finalization)
    sections.push([
      "What “finalized” means",
      info.finalization.description,
      "finalization",
      "controller",
    ]);
  for (const [title, text, phase, source] of sections) {
    const section = node("section", undefined, "summary-section");
    section.append(
      node("h3", title),
      node("p", text),
      traceButton("Inspect this phase ↗", phase, source),
    );
    page.append(section);
  }
  if (info.decoy.lure_responses != null) {
    const note = node(
      "p",
      `${info.decoy.lure_responses} lure-bearing HTTP responses are reported in the saved metrics. Serving a lure does not establish that an agent read or followed it.`,
      "summary-note",
    );
    page.append(note);
  }
  const phases = node("section", undefined, "summary-phases");
  phases.append(node("h3", "Explore the run by phase"));
  for (const p of info.phases) {
    const b = node("button", undefined, "phase-card");
    const text = node("span");
    text.append(
      node("strong", p.title),
      node(
        "small",
        p.start
          ? `${time(p.start)} → ${p.end ? time(p.end) : "end not recorded"}`
          : "Phase timing not recorded",
      ),
    );
    b.append(
      text,
      node("span", fmtDuration(p.elapsed_seconds)),
      node("span", "↗"),
    );
    b.onclick = () => openTrace(p.id, "controller");
    phases.append(b);
  }
  page.append(phases);
  $("feed").append(page);
  $("feed").scrollTop = scroll;
}
function fmtDuration(value) {
  if (value == null) return "Unknown";
  const n = Math.round(value);
  return n >= 60
    ? Math.floor(n / 60) + "m " + String(n % 60).padStart(2, "0") + "s"
    : n + "s";
}
async function loadTrace(reset = false) {
  if (!data || !episode) return;
  const source = $("trace-source").value,
    phase = $("phase").value,
    key = episode + "|" + source + "|" + phase;
  if (reset || key !== traceKey) {
    traceKey = key;
    traceItems = [];
    traceCursor = 0;
    traceNext = null;
    feedSignature = "";
  }
  if (traceBusy) return;
  if (!source) {
    $("trace-status").textContent = "No trace artifacts recorded";
    renderTrace();
    return;
  }
  traceBusy = true;
  $("trace-status").textContent = "Reading recorded trace…";
  try {
    const result = await get(
      "/api/trace?episode=" +
        encodeURIComponent(episode) +
        "&source=" +
        encodeURIComponent(source) +
        "&phase=" +
        phase +
        "&cursor=" +
        traceCursor,
    );
    if (key !== traceKey) return;
    const known = new Set(traceItems.map((r) => r.id));
    traceItems.push(...result.records.filter((r) => !known.has(r.id)));
    if (traceItems.length > 500) traceItems = traceItems.slice(-500);
    traceCursor = result.end_cursor ?? result.next_cursor ?? traceCursor;
    traceNext = result.next_cursor;
    $("trace-status").textContent = result.missing?.length
      ? result.missing.join(" · ")
      : result.scan_limited
        ? "Bounded scan · continue for more records"
        : "Recorded source · " + (result.ordering || "source file order");
    $("trace-more").hidden = traceNext === null;
    feedSignature = "";
    renderTrace();
  } catch (e) {
    $("trace-status").textContent =
      "Trace unavailable. No sample data substituted.";
  } finally {
    traceBusy = false;
    if (key !== traceKey && channel === "traces") loadTrace();
  }
}
function renderTrace() {
  const signature = JSON.stringify([
    traceItems,
    $("search").value,
    $("defender").value,
  ]);
  if (feedSignature === signature) return;
  feedSignature = signature;
  const scroll = $("feed").scrollTop,
    query = $("search").value.toLowerCase(),
    agent = $("defender").value;
  $("feed").replaceChildren();
  $("older").hidden = true;
  const visible = traceItems.filter(
    (r) =>
      (!agent || r.record.agent_id === agent) &&
      (!query || JSON.stringify(r.record).toLowerCase().includes(query)),
  );
  $("count").textContent = visible.length + " loaded records";
  $("trace-more").hidden = traceNext === null;
  if (!visible.length)
    $("feed").append(
      empty(
        "No trace records in this selection",
        "Choose another source or phase. Missing, filtered and partial evidence is never replaced with invented events.",
      ),
    );
  for (const item of visible) {
    const row = item.record,
      p = row.payload || {},
      b = node("button", undefined, "message trace-message");
    b.setAttribute("aria-label", "Inspect trace " + item.id);
    const body = node("div", undefined, "message-main"),
      top = node("div", undefined, "message-top");
    top.append(
      node("span", row.agent_id || row.actor || "Recorded source", "sender"),
      node(
        "span",
        item.ts
          ? /^\d\d:/.test(item.ts)
            ? item.ts
            : time(item.ts)
          : "Timestamp unavailable",
        "time",
      ),
    );
    body.append(
      top,
      node("div", row.kind || row.eventid || "trace", "event-kind"),
    );
    const text =
      row.kind === "http"
        ? `${row.method || "HTTP"} ${row.host || ""}${row.path || ""} → ${row.status ?? "status unknown"}${row.lure ? " · lure included" : ""}`
        : p.output_excerpt
          ? `${p.text || p.event || "Tool result"}\n${p.output_excerpt}`
          : p.command ||
            p.text ||
            p.message ||
            row.message ||
            row.input ||
            p.stage ||
            JSON.stringify(p);
    body.append(
      node("pre", String(text).slice(0, 1800), "trace-preview"),
      node(
        "span",
        `${item.source} · byte ${item.offset} · ${item.phase}${item.excerpt ? " · excerpt truncated" : ""}`,
        "trace-origin",
      ),
    );
    b.append(avatar(row.agent_id), body);
    b.onclick = () => {
      selected = { kind: "trace", id: item.id };
      renderDetails();
    };
    $("feed").append(b);
  }
  if (!paused && follow) $("feed").scrollTop = $("feed").scrollHeight;
  else $("feed").scrollTop = scroll;
}

function renderFeed() {
  if (!data) return;
  if (channel === "summary") {
    renderSummary();
    return;
  }
  if (channel === "traces") {
    renderTrace();
    return;
  }
  const query = $("search").value.toLowerCase().trim(),
    filter = $("defender").value;
  const records =
    channel === "board"
      ? messages
      : activity().filter(
          (e) => $("phase").value === "all" || e.phase === $("phase").value,
        );
  const visible = records.filter(
    (r) =>
      (!filter || (r.sender || r.agent_id) === filter) &&
      (!query ||
        [
          r.sender,
          r.agent_id,
          r.body,
          r.ts,
          r.tool,
          ...(r.payload?.tool_names || []),
          channel === "activity" ? eventBody(r) : "",
        ]
          .filter(Boolean)
          .join(" ")
          .toLowerCase()
          .includes(query)),
  );
  const signature = JSON.stringify([
    channel,
    records,
    data.notifications,
    data.receipts,
    filter,
    query,
    selected,
    $("phase").value,
  ]);
  if (signature === feedSignature) return;
  feedSignature = signature;
  const scroll = $("feed").scrollTop;
  $("feed").replaceChildren();
  $("count").textContent =
    filter || query
      ? `${visible.length} results`
      : `${records.length} ${channel === "board" ? "messages" : "records"}`;
  $("board-count").textContent = String(data.message_count ?? messages.length);
  $("activity-count").textContent = String(activity().length);
  if (!visible.length) {
    let title = filter
      ? "No messages from this defender"
      : query
        ? "No matching records"
        : channel === "board"
          ? "No defender messages yet"
          : "No activity recorded";
    let body =
      filter || query
        ? "Try another defender or clear your search."
        : channel === "board"
          ? data.board_enabled === false
            ? `The private board is disabled in arm ${data.episode.arm}. Recorded decisions are available in #activity.`
            : "This experiment has no recorded board messages. New agent messages will appear here when they are posted."
          : "No defender decisions or episode activity are available in this record.";
    $("feed").append(empty(title, body));
  }
  let lastDay = null;
  for (const r of visible) {
    const date = day(r.ts);
    if (date !== lastDay) {
      const d = node("div", undefined, "date-divider");
      d.append(node("span", date));
      $("feed").append(d);
      lastDay = date;
    }
    const isBoard = channel === "board",
      sender = isBoard ? r.sender : r.agent_id;
    const key = isBoard ? r.seq : r.event_id || r.seq,
      isSelected =
        selected?.kind === (isBoard ? "message" : "event") &&
        selected.id === key;
    const b = node(
      "button",
      undefined,
      "message" +
        (isSelected ? " selected" : "") +
        (isBoard ? "" : " event-message"),
    );
    b.setAttribute(
      "aria-label",
      isBoard
        ? `Message ${r.seq} from ${r.sender}`
        : `Event ${r.seq}: ${eventTitle(r)}`,
    );
    const content = node("div", undefined, "message-main"),
      top = node("div", undefined, "message-top");
    top.append(
      node("span", sender || "System", "sender"),
      node("span", sender ? "AGENT" : "EPISODE", "agent-tag"),
      node("span", time(r.ts), "time"),
      node("span", "#" + String(r.seq).padStart(3, "0"), "seq"),
    );
    content.append(top);
    if (!isBoard) content.append(node("div", eventTitle(r), "event-kind"));
    content.append(node("div", isBoard ? r.body : eventBody(r), "body"));
    const wake = node("div", undefined, "wake");
    if (isBoard) {
      const ns = data.notifications.filter((n) => n.message_seq === r.seq),
        rs = data.receipts.filter((n) => n.message_seq === r.seq);
      for (const n of ns)
        wake.append(
          node("span", `${r.sender} → ${n.recipient}`),
          badge(n.status),
        );
      if (!ns.length && !data.notification_evidence_complete)
        wake.append(node("span", "Wake-up evidence unavailable"));
      if (rs.length)
        wake.append(
          node(
            "span",
            `Context receipt · ${rs.map((n) => n.recipient).join(", ")}`,
          ),
        );
      wake.append(node("span", "View record ↗", "evidence-link"));
      b.onclick = () => {
        selected = { kind: "message", id: r.seq };
        renderDetails();
        feedSignature = "";
        renderFeed();
      };
    } else {
      const state = eventState(r);
      if (state) wake.append(badge(state));
      wake.append(node("span", "View event ↗", "evidence-link"));
      b.onclick = () => selectEvent(r);
    }
    content.append(wake);
    b.append(avatar(sender), content);
    $("feed").append(b);
  }
  if (!paused && follow) $("feed").scrollTop = $("feed").scrollHeight;
  else $("feed").scrollTop = scroll;
  $("older").hidden = channel !== "board" || !data.has_more;
}
function selectEvent(e) {
  selected = { kind: "event", id: e.event_id || e.seq };
  renderDetails();
  feedSignature = "";
  renderFeed();
}
function renderDetails() {
  if (!selected || !data) return;
  const panel = $("details"),
    opened = new Set(
      [...panel.querySelectorAll("details[open]")].map((e) => e.dataset.event),
    );
  let records, title, meta;
  if (selected.kind === "trace") {
    const item = traceItems.find((r) => r.id === selected.id);
    if (!item) return;
    records = [item.record];
    title = "Trace record";
    meta = `${item.source} · byte ${item.offset} · ${item.phase}`;
  } else if (selected.kind === "message") {
    const m = messages.find((r) => r.seq === selected.id);
    if (!m) return;
    records = related(m);
    title = "Message #" + String(m.seq).padStart(3, "0");
    meta = `${m.sender} · ${m.ts}`;
  } else {
    const e = data.events.find((r) => (r.event_id || r.seq) === selected.id);
    if (!e) return;
    records = [e];
    title = eventTitle(e);
    meta = `${e.agent_id || "System"} · ${e.ts}`;
  }
  $("overview").hidden = true;
  panel.hidden = false;
  $("inspector-title").textContent =
    selected.kind === "message" ? "Message details" : "Event details";
  $("workspace").classList.add("inspector-open");
  panel.replaceChildren(
    node("p", "RECORDED EVIDENCE", "eyebrow"),
    node("h3", title),
    node("p", meta),
    node(
      "p",
      selected.kind === "message"
        ? `${records.length} linked audit records. Links use recorded message, request and parent IDs.`
        : "Original recorded event. No message-to-action link is implied.",
    ),
  );
  if (selected.kind === "event") {
    const record = records[0];
    if (record.explanation) {
      panel.append(
        node("p", record.explanation.description, "detail-explanation"),
      );
      if (record.explanation.facts) {
        const facts = node("dl", undefined, "event-facts");
        for (const [key, value] of Object.entries(record.explanation.facts)) {
          if (
            [
              "reason",
              "reason_source",
              "elapsed_seconds",
              "wall_clock_limit_seconds",
              "ended_before_time_allowance",
              "exit_code",
              "actions_used",
              "action_limit",
              "valid",
              "official_attack_success",
              "exclusion_reason",
            ].includes(key)
          ) {
            facts.append(
              node("dt", key.replace(/_/g, " ")),
              node(
                "dd",
                value == null
                  ? "Not recorded"
                  : typeof value === "boolean"
                    ? value
                      ? "Yes"
                      : "No"
                    : String(value),
              ),
            );
          }
        }
        panel.append(facts);
      }
      for (const source of record.explanation.sources || [])
        panel.append(
          traceButton(
            "View " + source + " trace ↗",
            record.explanation.phase,
            source,
          ),
        );
    }
  }
  for (const e of records) {
    const d = node("details", undefined, "event");
    d.dataset.event = String(e.event_id || e.seq);
    d.open = opened.has(d.dataset.event) || selected.kind === "trace";
    d.append(
      node(
        "summary",
        `${e.ts ? time(e.ts) : "Recorded"} · ${e.kind || e.eventid || "raw trace"}${e.payload && eventState(e) ? " · " + eventState(e) : ""} · raw record`,
      ),
      node("pre", JSON.stringify(e, null, 2)),
    );
    panel.append(d);
  }
  if (!records.length)
    panel.append(
      node(
        "p",
        "No linked events in the available audit window. Message persistence alone proves no context delivery or action.",
      ),
    );
  panel.append(
    node(
      "p",
      "A context receipt confirms content was supplied to a successful request. Understanding, influence and causation remain unknown.",
      "caution",
    ),
  );
}
async function refresh() {
  if (busy || !episode) return;
  busy = true;
  const requested = episode;
  try {
    const result = await get(
      "/api/snapshot?episode=" +
        encodeURIComponent(episode) +
        "&after=" +
        (messages.at(-1)?.seq || 0),
    );
    if (episode !== requested) {
      busy = false;
      refresh();
      return;
    }
    data = result;
    const known = new Set(messages.map((m) => m.seq));
    messages.push(...data.messages.filter((m) => !known.has(m.seq)));
    if (messages.length > 500) messages = messages.slice(-500);
    connection(true);
    $("run-meta").textContent = [
      data.episode.cve,
      "Arm " + data.episode.arm,
      data.episode.created_at ? shortDate(data.episode.created_at) : null,
    ]
      .filter(Boolean)
      .join(" · ");
    $("run-state").textContent = data.attempt_status
      ? "Recorded status: " + data.attempt_status
      : data.stage
        ? "Last stage: " + data.stage
        : "Recorded experiment";
    $("about-cve").textContent = data.episode.cve || "Episode";
    $("about-episode").textContent = data.episode.episode_id;
    $("about-tags").replaceChildren(
      badge("Arm " + data.episode.arm),
      badge(data.attempt_status || "recorded"),
    );
    $("policy").textContent =
      "Notification policy: " +
      (data.policy?.version || "not recorded in this older run");
    $("evidence-note").hidden = !data.missing.length && !data.audit_windowed;
    $("notice").textContent = [
      ...data.missing,
      data.audit_windowed
        ? "Recent audit window only; older links may be unavailable."
        : "",
    ]
      .filter(Boolean)
      .join(" · ");
    const prior = $("defender").value;
    $("defender").replaceChildren(new Option("All defenders", ""));
    for (const id of new Set([
      ...data.cards.map((c) => c.id),
      ...messages.map((m) => m.sender),
    ]))
      $("defender").append(new Option(id, id));
    $("defender").value = prior;
    const last = data.events.at(-1);
    $("updated").textContent = last
      ? "Last record " + time(last.ts)
      : "No audit events recorded";
    sourceOptions();
    $("board-count").textContent =
      data.board_enabled === false
        ? "off"
        : String(data.message_count ?? messages.length);
    $("activity-count").textContent = String(activity().length);
    renderCards();
    renderFeed();
    if (channel === "traces") loadTrace();
    renderDetails();
  } catch (e) {
    connection(false);
  } finally {
    busy = false;
  }
}
$("episode").onchange = () => {
  chooseEpisode();
  renderRuns();
};
$("arm").onchange = renderRuns;
$("defender").onchange = () => {
  feedSignature = "";
  renderFeed();
};
$("search").oninput = () => {
  feedSignature = "";
  renderFeed();
};
$("more-runs").onclick = () => loadRuns(nextRuns);
$("older").onclick = refresh;
$("channel-summary").onclick = () => chooseChannel("summary");
$("channel-traces").onclick = () => chooseChannel("traces");
$("trace-source").onchange = () => loadTrace(true);
$("phase").onchange = () => {
  feedSignature = "";
  if (channel === "traces") loadTrace(true);
  else renderFeed();
};
$("trace-more").onclick = () => loadTrace();
$("channel-board").onclick = () => chooseChannel("board");
$("channel-activity").onclick = () => chooseChannel("activity");
$("follow").onclick = () => {
  follow = !follow;
  $("follow").replaceChildren(
    node("span", undefined, "follow-dot"),
    document.createTextNode(follow ? "Live follow on" : "Live follow off"),
  );
  $("follow").setAttribute("aria-pressed", String(follow));
  if (follow) refresh();
};
$("pause").onclick = () => {
  paused = !paused;
  $("pause").textContent = paused ? "Resume scrolling" : "Pause scrolling";
  $("pause").setAttribute("aria-pressed", String(paused));
  if (!paused && data) {
    feedSignature = "";
    renderFeed();
  }
};
$("team-toggle").onclick = () => {
  showOverview();
  $("workspace").classList.toggle("inspector-open");
};
$("close-details").onclick = () => {
  showOverview();
  $("workspace").classList.remove("inspector-open");
};
$("sidebar-toggle").onclick = () => {
  const open = $("workspace").classList.toggle("nav-open");
  $("sidebar-toggle").setAttribute("aria-expanded", String(open));
};
document.addEventListener("keydown", (e) => {
  if (
    e.key === "/" &&
    !["INPUT", "SELECT", "TEXTAREA"].includes(document.activeElement.tagName)
  ) {
    e.preventDefault();
    $("search").focus();
  }
  if (e.key === "Escape") {
    $("workspace").classList.remove("nav-open", "inspector-open");
  }
});
chooseChannel("summary");
loadRuns();
setInterval(() => {
  if (follow) refresh();
}, 1500);
setInterval(() => {
  if (follow && !browsingOlder) loadRuns();
}, 15000);
