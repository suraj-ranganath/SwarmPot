"use strict";
const $ = (id) => document.getElementById(id);
let runs = [],
  nextRuns = null,
  episode = "",
  data = null,
  messages = [],
  selected = null,
  follow = true,
  paused = false,
  busy = false,
  connected = false,
  feedSignature = "";
function node(tag, text, cls) {
  const e = document.createElement(tag);
  if (text !== undefined) e.textContent = text;
  if (cls) e.className = cls;
  return e;
}
function badge(text) {
  return node("span", text, "badge " + text);
}
function empty(title, body) {
  const e = node("div", undefined, "empty");
  e.append(node("strong", title), node("span", body));
  return e;
}
function time(ts) {
  return ts
    ? new Date(ts).toLocaleTimeString([], {
        hour: "2-digit",
        minute: "2-digit",
        second: "2-digit",
      })
    : "Time unavailable";
}
async function get(url) {
  const r = await fetch(url, { cache: "no-store" });
  if (!r.ok) throw new Error("Evidence unavailable");
  return r.json();
}
function connection(ok) {
  connected = ok;
  $("connection").textContent = ok
    ? "● Connected · local evidence"
    : "○ Disconnected · showing last evidence";
  $("connection").className = ok ? "" : "offline";
}
async function loadRuns(offset = 0) {
  try {
    const result = await get("/api/episodes?offset=" + offset);
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
          "Evidence disconnected",
          "Start the local viewer, then reconnect.",
        ),
      );
  }
}
function renderRuns() {
  const arm = $("arm").value,
    items = runs.filter((r) => !arm || r.arm === arm),
    prior = episode;
  $("episode").replaceChildren();
  if (!items.length)
    $("episode").append(new Option("No recorded episodes", ""));
  items.forEach((r) =>
    $("episode").append(
      new Option(`${r.episode_id || r.id} · arm ${r.arm || "?"}`, r.id),
    ),
  );
  $("episode").value = items.some((r) => r.id === prior)
    ? prior
    : items[0]?.id || "";
  if (episode !== $("episode").value || !items.length) chooseEpisode();
}
function chooseEpisode() {
  episode = $("episode").value;
  messages = [];
  selected = null;
  data = null;
  $("details").replaceChildren(
    node("p", "EVIDENCE INSPECTOR", "eyebrow"),
    node("h3", "The record, in context."),
    node(
      "p",
      "Select a message to inspect recorded delivery and subsequent actions.",
    ),
  );
  if (episode) refresh();
  else {
    $("run-meta").textContent = "";
    $("policy").textContent = "Notification policy: evidence unavailable";
    $("cards").replaceChildren();
    $("count").textContent = "0";
    $("notice").hidden = true;
    $("feed").replaceChildren(
      empty(
        "No recorded runs",
        "Select another arm or point the viewer at your runs directory.",
      ),
    );
  }
}
function renderCards() {
  const budget = data.budget;
  $("cards").replaceChildren();
  for (const c of data.cards) {
    const card = node("article", undefined, "card"),
      top = node("div", undefined, "card-top");
    top.append(node("span", c.id, "agent-label"), badge(c.state));
    const stats = node("div", undefined, "stats");
    const used = budget?.decisions?.[c.id] ?? 0;
    const remaining = budget
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
    for (const [value, label] of [
      [c.unread_count ?? "?", "PENDING MESSAGES"],
      [remaining ?? "?", "DECISIONS LEFT"],
      [cost === null ? "?" : "$" + cost.toFixed(3), "TEAM COST LEFT"],
    ]) {
      const stat = node("div", undefined, "stat");
      stat.append(node("strong", String(value)), node("span", label));
      stats.append(stat);
    }
    const wakeNote = node(
      "p",
      c.pending_known
        ? `${c.pending.length} queued wake-up(s)`
        : "Wake-up evidence unavailable",
      "eyebrow",
    );
    wakeNote.style.marginBottom = "10px";
    const last = c.last;
    let description = "Last decision / action: evidence unavailable";
    if (last)
      description = `${time(last.ts)} · ${last.tool || last.kind}${last.payload.path ? " · " + last.payload.path : ""}${last.payload.content ? " · " + last.payload.content : ""}`;
    const lastNode = node("div", description, "last");
    lastNode.title = description;
    card.append(top, stats, wakeNote, lastNode);
    if (c.state_at) {
      const p = node("p", "Status recorded " + time(c.state_at), "eyebrow");
      p.style.marginTop = "12px";
      card.append(p);
    }
    $("cards").append(card);
  }
}
function related(m) {
  const direct = data.events.filter((e) => {
    const p = e.payload;
    return (
      p.message_id === m.seq ||
      [
        ...(p.message_seqs || []),
        ...(p.board_message_seqs || []),
        ...(p.board_context_message_seqs || []),
      ].includes(m.seq)
    );
  });
  const requests = new Set(
    direct.map((e) => e.payload.request_id).filter(Boolean),
  );
  const ids = new Set(direct.map((e) => e.event_id).filter(Boolean));
  return data.events.filter(
    (e) =>
      direct.includes(e) ||
      (e.payload.request_id && requests.has(e.payload.request_id)) ||
      (e.parent_event_id && ids.has(e.parent_event_id)),
  );
}
function renderFeed() {
  const signature = JSON.stringify([
    messages,
    data.notifications,
    data.receipts,
    $("defender").value,
    selected,
  ]);
  if (signature === feedSignature) return;
  feedSignature = signature;
  const scroll = $("feed").scrollTop,
    filter = $("defender").value,
    visible = messages.filter((m) => !filter || m.sender === filter);
  $("count").textContent = messages.length + " recorded";
  $("feed").replaceChildren();
  if (!visible.length)
    $("feed").append(
      empty(
        filter ? "No messages from this defender" : "The board is quiet",
        filter
          ? "Choose all defenders to see the full exchange."
          : "No communication is recorded. Tool availability alone is not communication evidence.",
      ),
    );
  for (const m of visible) {
    const b = node(
      "button",
      undefined,
      "message" + (selected === m.seq ? " selected" : ""),
    );
    b.setAttribute("aria-label", `Message ${m.seq} from ${m.sender}`);
    const top = node("div", undefined, "message-top");
    top.append(
      node("span", "#" + String(m.seq).padStart(3, "0"), "seq"),
      node("span", m.sender, "sender"),
      node("span", time(m.ts), "time"),
    );
    b.append(top, node("div", m.body, "body"));
    const ns = data.notifications.filter((n) => n.message_seq === m.seq),
      rs = data.receipts.filter((r) => r.message_seq === m.seq),
      wake = node("div", undefined, "wake");
    if (ns.length) {
      for (const n of ns) {
        wake.append(
          node("span", `${m.sender} → ${n.recipient}`),
          badge(n.status),
        );
        if (n.reason) wake.append(node("span", n.reason));
      }
    } else {
      const hasPolicy = data.notification_evidence_complete;
      wake.append(
        node(
          "span",
          hasPolicy ? "No wake-up recorded" : "Wake-up evidence unavailable",
        ),
      );
    }
    if (rs.length)
      wake.append(
        node(
          "span",
          `Context receipt · ${rs.map((r) => r.recipient).join(", ")}`,
        ),
      );
    wake.append(node("span", "Inspect evidence ↗"));
    b.append(wake);
    b.onclick = () => {
      selected = m.seq;
      renderDetails();
      renderFeed();
    };
    $("feed").append(b);
  }
  if (!paused && follow) $("feed").scrollTop = $("feed").scrollHeight;
  else $("feed").scrollTop = scroll;
  $("older").hidden = !data.has_more;
}
function renderDetails() {
  const m = messages.find((x) => x.seq === selected);
  if (!m) return;
  const panel = $("details"),
    opened = new Set(
      [...panel.querySelectorAll("details[open]")].map((e) => e.dataset.event),
    );
  panel.replaceChildren(
    node("p", "MESSAGE #" + String(m.seq).padStart(3, "0"), "eyebrow"),
    node("h3", "Recorded chain"),
    node("p", `${m.sender} · ${m.ts}`),
  );
  const events = related(m);
  panel.append(
    node(
      "p",
      `${events.length} linked audit records. Links use recorded message, request and parent IDs.`,
    ),
  );
  for (const e of events) {
    const d = node("details", undefined, "event");
    d.dataset.event = String(e.event_id || e.seq);
    d.open = opened.has(d.dataset.event);
    const s = node(
      "summary",
      `${time(e.ts)} · ${e.kind} · ${e.payload.status || e.status || e.agent_id || "record"}`,
    );
    d.append(s, node("pre", JSON.stringify(e, null, 2)));
    panel.append(d);
  }
  if (!events.length)
    panel.append(
      node(
        "p",
        "No linked events in the available audit window. Message persistence alone proves no context delivery or action.",
      ),
    );
  panel.append(
    node(
      "p",
      "Delivery means included in a request with a successful response. Understanding, influence and causation are unknown. A subsequent edit is linked by request ID, not proof that the message caused it.",
      "caution",
    ),
  );
}
async function refresh() {
  if (busy || !episode) return;
  busy = true;
  const requestedEpisode = episode;
  try {
    const result = await get(
      "/api/snapshot?episode=" +
        encodeURIComponent(episode) +
        "&after=" +
        (messages.at(-1)?.seq || 0),
    );
    if (episode !== requestedEpisode) {
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
      data.stage ? `Last stage: ${data.stage}` : "Stage unknown",
      data.episode.evidence_kind,
    ]
      .filter(Boolean)
      .join(" · ");
    $("notice").hidden = !data.missing.length && !data.audit_windowed;
    $("notice").textContent = [
      ...data.missing,
      data.audit_windowed
        ? "Details show a bounded recent audit window; older links may be unavailable."
        : "",
    ]
      .filter(Boolean)
      .join(" · ");
    $("policy").textContent =
      "Notification policy: " +
      (data.policy?.version || "not recorded (legacy condition)");
    const previous = $("defender").value;
    $("defender").replaceChildren(new Option("All defenders", ""));
    for (const id of new Set([
      ...data.cards.map((c) => c.id),
      ...messages.map((m) => m.sender),
    ]))
      $("defender").append(new Option(id, id));
    $("defender").value = previous;
    renderCards();
    renderFeed();
    renderDetails();
  } catch (e) {
    connection(false);
  } finally {
    busy = false;
  }
}
$("episode").onchange = chooseEpisode;
$("arm").onchange = renderRuns;
$("defender").onchange = renderFeed;
$("more-runs").onclick = () => loadRuns(nextRuns);
$("older").onclick = refresh;
$("follow").onclick = () => {
  follow = !follow;
  $("follow").textContent = follow ? "Live follow on" : "Live follow off";
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
loadRuns();
setInterval(() => {
  if (follow) refresh();
}, 1500);
