/* Automatic Log Anomaly Detector — dashboard logic (plain JavaScript). */
"use strict";

const $ = (id) => document.getElementById(id);

const SEVERITY_ORDER = { NONE: 0, MEDIUM: 1, HIGH: 2, CRITICAL: 3 };
const ANOMALY_TYPE_LABELS = {
  INVALID_TRANSITION: "Invalid transition",
  INVALID_WORKFLOW: "Invalid workflow",
  BRUTE_FORCE: "Brute-force login",
  PRIVILEGE_ESCALATION: "Privilege escalation",
  SUSPICIOUS_DATABASE_ACCESS: "Suspicious database access",
  UNRECOGNIZED_EVENT: "Unknown symbol (∉ Σ)",
  INCOMPLETE_SESSION: "Incomplete session",
};

const SAMPLES = [
  ["normal_login", "Normal Log", "Login → auth success → file access → logout"],
  ["normal_file_access", "Normal File Activity", "Everyday activity, clean logout"],
  ["brute_force", "Brute Force", "3× auth failure, then ADMIN_ACCESS"],
  ["privilege_escalation", "Privilege Escalation", "PRIVILEGE_CHANGE → ADMIN_ACCESS"],
  ["database_attack", "Database Attack", "Admin + DB without elevation"],
  ["invalid_workflow", "Invalid Workflow", "File access after LOGOUT"],
];

/* ------------------------------------------------------------------ state */

let state = {
  logText: "",
  filename: "",
  result: null,
  selected: null, // index into result.results
  lastSource: "paste",
};

/* -------------------------------------------------------------- helpers */

function esc(s) {
  return String(s).replace(/[&<>"']/g, (c) => ({
    "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;",
  }[c]));
}

function toast(msg, kind = "info") {
  const bar = document.createElement("div");
  bar.className = `toast toast-${kind}`;
  bar.textContent = msg;
  document.body.appendChild(bar);
  setTimeout(() => bar.classList.add("show"), 10);
  setTimeout(() => bar.remove(), 3200);
}

async function api(path, options) {
  const res = await fetch(path, options);
  if (!res.ok) {
    let detail = res.statusText;
    try { detail = (await res.json()).detail || detail; } catch (_) {}
    throw new Error(detail);
  }
  return res.json();
}

/* ---------------------------------------------------------------- input */

const dropzone = $("dropzone");
const fileInput = $("file-input");
const logText = $("log-text");

dropzone.addEventListener("click", () => fileInput.click());
dropzone.addEventListener("keydown", (e) => e.key === "Enter" && fileInput.click());
dropzone.addEventListener("dragover", (e) => { e.preventDefault(); dropzone.classList.add("drag"); });
dropzone.addEventListener("dragleave", () => dropzone.classList.remove("drag"));
dropzone.addEventListener("drop", (e) => {
  e.preventDefault();
  dropzone.classList.remove("drag");
  if (e.dataTransfer.files[0]) loadFile(e.dataTransfer.files[0]);
});

fileInput.addEventListener("change", () => {
  if (fileInput.files[0]) loadFile(fileInput.files[0]);
  fileInput.value = "";
});

function loadFile(file) {
  if (!/\.(txt|log|out)$/i.test(file.name)) {
    toast("Only .txt, .log or .out files are accepted.", "error");
    return;
  }
  if (file.size > 512 * 1024) {
    toast("File too large — the limit is 512 KB.", "error");
    return;
  }
  const reader = new FileReader();
  reader.onload = () => {
    state.logText = String(reader.result || "");
    state.filename = file.name.replace(/[^\w.-]/g, "_").slice(0, 80) || "log.txt";
    logText.value = state.logText;
    $("filename-chip").textContent = state.filename;
    $("filename-chip").hidden = false;
    $("analyze-btn").disabled = !state.logText.trim();
    toast(`Loaded ${state.filename}`, "ok");
  };
  reader.onerror = () => toast("Could not read that file.", "error");
  reader.readAsText(file);
}

logText.addEventListener("input", () => {
  state.logText = logText.value;
  $("analyze-btn").disabled = !state.logText.trim();
});

/* --------------------------------------------------------------- samples */

const sampleGrid = $("sample-grid");
for (const [id, name, desc] of SAMPLES) {
  const btn = document.createElement("button");
  btn.className = "sample-btn";
  btn.innerHTML = `<div class="t">${esc(name)}</div><div class="d">${esc(desc)}</div>`;
  btn.addEventListener("click", async () => {
    try {
      const data = await api(`/api/sample/${id}`);
      state.logText = data.content;
      state.filename = data.filename;
      logText.value = data.content;
      $("filename-chip").textContent = data.filename;
      $("filename-chip").hidden = false;
      $("analyze-btn").disabled = false;
      toast(`Loaded ${data.filename}`, "ok");
    } catch (err) { toast(err.message, "error"); }
  });
  sampleGrid.appendChild(btn);
}

/* --------------------------------------------------------------- analyze */

$("analyze-btn").addEventListener("click", async () => {
  if (!state.logText.trim()) return;
  const btn = $("analyze-btn");
  btn.disabled = true;
  btn.textContent = "Analyzing…";
  try {
    const data = await api("/api/analyze-text", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        text: state.logText,
        filename: state.filename || "pasted-log.txt",
      }),
    });
    state.result = data;
    state.selected = null;
    renderAll();
    loadHistory();
    toast(`Analysis complete — ${data.summary.verdict} (${data.summary.anomalies} anomalies)`, "ok");
  } catch (err) {
    toast(err.message, "error");
  } finally {
    btn.disabled = !state.logText.trim();
    btn.textContent = "Analyze Log";
  }
});

/* ---------------------------------------------------------------- render */

function renderAll() { renderStats(); renderSequence(); renderResults(); renderDetails(); renderGraph(); }

function renderStats() {
  const s = state.result && state.result.summary;
  $("stat-total").textContent = s ? s.total_events : "—";
  $("stat-normal").textContent = s ? s.normal_events : "—";
  $("stat-anomalies").textContent = s ? s.anomalies : "—";
  $("stat-critical").textContent = s ? s.critical_anomalies : "—";
}

function renderSequence() {
  const el = $("sequence");
  el.innerHTML = "";
  if (!state.result) {
    el.innerHTML = '<span class="muted">Analyze a log to see its event sequence w = e₁·e₂·…·eₙ.</span>';
    return;
  }
  state.result.results.forEach((row, i) => {
    if (i > 0) {
      const arrow = document.createElement("span");
      arrow.className = "seq-arrow";
      arrow.textContent = "→";
      el.appendChild(arrow);
    }
    const chip = document.createElement("span");
    const isAnom = row.status === "ANOMALY";
    chip.className = `seq-chip${isAnom ? " anom" : ""}${state.selected === i ? " sel" : ""}`;
    chip.textContent = row.event;
    chip.title = row.reason;
    chip.addEventListener("click", () => { state.selected = state.selected === i ? null : i; renderAll(); });
    el.appendChild(chip);
  });
}

function renderResults() {
  const body = $("results-body");
  body.innerHTML = "";
  if (!state.result) return;
  state.result.results.forEach((row, i) => {
    const tr = document.createElement("tr");
    if (row.severity !== "NONE") tr.classList.add(`tint-${row.severity}`);
    if (state.selected === i) tr.classList.add("sel");
    const pos = row.event === "END_OF_LOG" ? "⟂" : row.position;
    const badge = row.severity === "NONE" ? "—" : `<span class="badge ${row.severity}">${row.severity}</span>`;
    tr.innerHTML = `
      <td class="mono">${esc(pos)}</td>
      <td class="mono"><strong>${esc(row.event)}</strong></td>
      <td class="mono">${esc(row.previous_state)}</td>
      <td class="mono">${esc(row.current_state)}</td>
      <td class="status-${esc(row.status)}">${esc(row.status)}</td>
      <td>${badge}</td>
      <td class="muted reason-cell">${esc(row.reason)}</td>`;
    tr.addEventListener("click", () => { state.selected = state.selected === i ? null : i; renderAll(); });
    body.appendChild(tr);
  });
}

function renderDetails() {
  const el = $("details");
  if (!state.result || state.selected === null) {
    el.className = "details muted";
    el.innerHTML = "Click a row in the results table (or a chip in the sequence) to inspect it.";
    return;
  }
  const row = state.result.results[state.selected];
  el.className = "details";
  const exp = row.expected_events.length
    ? row.expected_events.map((e) => `<span class="chip">${esc(e)}</span>`).join(" ")
    : "—";
  const typeLabel = row.anomaly_type
    ? (ANOMALY_TYPE_LABELS[row.anomaly_type] || row.anomaly_type) : "";
  el.innerHTML = `
    <h3>${esc(row.event)}
      ${row.severity !== "NONE" ? `<span class="badge ${row.severity}">${row.severity}</span>` : '<span class="badge NONE">NORMAL</span>'}
      ${typeLabel ? `<span class="chip">${esc(typeLabel)}</span>` : ""}
    </h3>
    <div class="grid">
      <div><div class="k">Position</div><div class="mono">${row.event === "END_OF_LOG" ? "⟂ end of log" : esc(row.position)}</div></div>
      <div><div class="k">Previous state</div><div class="mono">${esc(row.previous_state)}</div></div>
      <div><div class="k">Current state</div><div class="mono">${esc(row.current_state)}</div></div>
      <div><div class="k">Expected events</div><div>${exp}</div></div>
    </div>
    <div class="reason"><span class="k">Reason</span><br/>${esc(row.reason)}</div>`;
}

/* ----------------------------------------------------------------- graph */

/* Node layout (matches the transition table in backend/automaton.py). */
const NODES = {
  q0:   { x: 90,  y: 285, label: "START" },
  q1:   { x: 250, y: 285, label: "LOGIN_ATTEMPT" },
  q1f1: { x: 345, y: 465, label: "AUTH_FAIL_1" },
  q1f2: { x: 480, y: 465, label: "AUTH_FAIL_2" },
  q1f3: { x: 615, y: 465, label: "AUTH_FAIL_3+" },
  q2:   { x: 470, y: 205, label: "AUTHENTICATED" },
  q3:   { x: 735, y: 515, label: "LOGGED_OUT" },
  q4:   { x: 695, y: 285, label: "PRIVILEGE_CHANGE" },
  q5:   { x: 900, y: 285, label: "ADMIN_ACCESS" },
};
NODES.q1f2.label = "AUTH_FAIL_2";

const EDGES = [
  { from: "q0", to: "q1", events: ["LOGIN"] },
  { from: "q1", to: "q2", events: ["AUTH_SUCCESS"], bend: -18 },
  { from: "q1", to: "q1f1", events: ["AUTH_FAILURE"] },
  { from: "q1f1", to: "q1f2", events: ["AUTH_FAILURE"] },
  { from: "q1f2", to: "q1f3", events: ["AUTH_FAILURE"] },
  { from: "q1f1", to: "q2", events: ["AUTH_SUCCESS"], bend: 30, labelT: 0.35 },
  { from: "q1f2", to: "q2", events: ["AUTH_SUCCESS"] },
  { from: "q1f3", to: "q2", events: ["AUTH_SUCCESS"], bend: -30, labelT: 0.35 },
  { from: "q1", to: "q3", events: ["LOGOUT", "SESSION_TIMEOUT"], bend: -34 },
  { from: "q1f1", to: "q3", events: ["LOGOUT", "SESSION_TIMEOUT"], bend: 26 },
  { from: "q1f2", to: "q3", events: ["LOGOUT", "SESSION_TIMEOUT"], bend: 14 },
  { from: "q1f3", to: "q3", events: ["LOGOUT", "SESSION_TIMEOUT"], bend: 6 },
  { from: "q2", to: "q2", loop: "up", events: ["FILE_ACCESS", "FILE_DELETE", "PASSWORD_CHANGE", "USER_ACCESS", "API_ACCESS"] },
  { from: "q2", to: "q3", events: ["LOGOUT", "SESSION_TIMEOUT"], bend: 18 },
  { from: "q2", to: "q4", events: ["PRIVILEGE_CHANGE"], bend: -14 },
  { from: "q3", to: "q1", events: ["LOGIN"], c1: [640, 600], c2: [230, 560] },
  { from: "q4", to: "q5", events: ["ADMIN_ACCESS"], bend: 12 },
  { from: "q4", to: "q4", loop: "down", events: ["FILE_ACCESS", "FILE_DELETE", "CONFIG_CHANGE", "PASSWORD_CHANGE", "USER_ACCESS"] },
  { from: "q4", to: "q3", events: ["LOGOUT", "SESSION_TIMEOUT"], bend: -22 },
  { from: "q5", to: "q5", loop: "up", events: ["DATABASE_ACCESS", "FILE_ACCESS", "FILE_DELETE", "CONFIG_CHANGE", "API_ACCESS", "PASSWORD_CHANGE", "USER_ACCESS"] },
  { from: "q5", to: "q3", events: ["LOGOUT", "SESSION_TIMEOUT"], bend: 24 },
];

const SVG_NS = "http://www.w3.org/2000/svg";
const R = 27;

function svgEl(tag, attrs) {
  const el = document.createElementNS(SVG_NS, tag);
  for (const [k, v] of Object.entries(attrs || {})) el.setAttribute(k, v);
  return el;
}

const sub = (a, b) => ({ x: a.x - b.x, y: a.y - b.y });
const add = (a, b) => ({ x: a.x + b.x, y: a.y + b.y });
const mul = (a, k) => ({ x: a.x * k, y: a.y * k });
const unit = (a) => mul(a, 1 / Math.hypot(a.x, a.y));
const norm = (a) => ({ x: -a.y, y: a.x });

function borderPt(p, dir, pad = 0) {
  const u = unit(dir);
  return { x: p.x + u.x * (R + 2 + pad), y: p.y + u.y * (R + 2 + pad) };
}

function edgePath(edge) {
  const p1 = NODES[edge.from], p2 = NODES[edge.to];
  if (edge.loop) {
    const a = edge.loop === "up" ? -Math.PI / 2 : Math.PI / 2;
    const u = (t) => ({ x: Math.cos(t), y: Math.sin(t) });
    const s = add(p1, mul(u(a - 0.55), R + 2));
    const e = add(p1, mul(u(a + 0.55), R + 2));
    const c1 = add(p1, mul(u(a - 1.0), R + 34));
    const c2 = add(p1, mul(u(a + 1.0), R + 34));
    const label = add(p1, mul(u(a), R + 52));
    return { d: `M ${s.x} ${s.y} C ${c1.x} ${c1.y}, ${c2.x} ${c2.y}, ${e.x} ${e.y}`, label };
  }
  const s = borderPt(p1, sub(p2, p1), 4);
  const e = borderPt(p2, sub(p1, p2), 8);
  let c, c2 = e, cubic = false;
  if (edge.c1 && edge.c2) {
    c = { x: edge.c1[0], y: edge.c1[1] };
    c2 = { x: edge.c2[0], y: edge.c2[1] };
    cubic = true;
  } else {
    const m = mul(add(s, e), 0.5);
    c = add(m, mul(norm(unit(sub(e, s))), edge.bend || 0));
  }
  const t = edge.labelT || 0.5;
  const bez = (p0, p1c, p2c, p3, t) => ({
    x: (1-t)**3*p0.x + 3*(1-t)**2*t*p1c.x + 3*(1-t)*t**2*p2c.x + t**3*p3.x,
    y: (1-t)**3*p0.y + 3*(1-t)**2*t*p1c.y + 3*(1-t)*t**2*p2c.y + t**3*p3.y,
  });
  const bez2 = (p0, p1c, p2, t) => ({
    x: (1-t)**2*p0.x + 2*(1-t)*t*p1c.x + t**2*p2.x,
    y: (1-t)**2*p0.y + 2*(1-t)*t*p1c.y + t**2*p2.y,
  });
  const pt = cubic ? bez(s, c, c2, e, t) : bez2(s, c, e, t);
  const n = cubic ? { x: 0, y: 0 } : norm(unit(sub(e, s)));
  const label = cubic ? { x: pt.x, y: pt.y + 10 } : add(pt, mul(n, (edge.bend || 0) < 0 ? -11 : 11));
  const d = cubic
    ? `M ${s.x} ${s.y} C ${c.x} ${c.y}, ${c2.x} ${c2.y}, ${e.x} ${e.y}`
    : `M ${s.x} ${s.y} Q ${c.x} ${c.y}, ${e.x} ${e.y}`;
  return { d, label };
}

function labelLines(events) {
  const lines = [];
  for (let i = 0; i < events.length; i += 2) lines.push(events.slice(i, i + 2).join(" · "));
  return lines;
}

function renderGraph() {
  const svg = $("dfa-svg");
  svg.innerHTML = "";

  const selRow = state.result && state.selected !== null
    ? state.result.results[state.selected] : null;
  const highlight = selRow && selRow.status === "ANOMALY" && selRow.event !== "END_OF_LOG"
    ? selRow : null;

  // defs + arrowheads
  const defs = svgEl("defs", {});
  for (const [id, color, size] of [["arrow", "#5b6e93", 7], ["arrow-red", "#f87171", 8]]) {
    const marker = svgEl("marker", {
      id, viewBox: "0 0 10 10", refX: 9, refY: 5,
      markerWidth: size, markerHeight: size, orient: "auto-start-reverse",
    });
    marker.appendChild(svgEl("path", { d: "M 0 0 L 10 5 L 0 10 z", fill: color }));
    defs.appendChild(marker);
  }
  svg.appendChild(defs);

  // start arrow
  const q0 = NODES.q0;
  svg.appendChild(svgEl("line", {
    x1: q0.x - R - 34, y1: q0.y, x2: q0.x - R - 6, y2: q0.y,
    stroke: "#5b6e93", "stroke-width": 1.6, "marker-end": "url(#arrow)",
  }));
  const startText = svgEl("text", {
    x: q0.x - R - 40, y: q0.y + 4, "text-anchor": "end",
    "font-size": 10, fill: "#93a4c3",
  });
  startText.textContent = "start";
  svg.appendChild(startText);

  // edges
  EDGES.forEach((edge) => {
    const { d, label } = edgePath(edge);
    const isHighlighted = highlight &&
      edge.from === highlight.previous_state && edge.to === highlight.current_state &&
      edge.events.includes(highlight.event);
    const g = svgEl("g", isHighlighted ? {} : { opacity: highlight ? 0.35 : 1 });
    svg.appendChild(g);

    g.appendChild(svgEl("path", {
      d, fill: "none",
      stroke: isHighlighted ? "#f87171" : "rgba(91,110,147,.75)",
      "stroke-width": isHighlighted ? 2.6 : 1.4,
      "marker-end": `url(#${isHighlighted ? "arrow-red" : "arrow"})`,
    }));

    const lines = labelLines(edge.events);
    const text = svgEl("text", {
      x: label.x, y: label.y, "text-anchor": "middle", "font-size": 9.5,
      fill: isHighlighted ? "#f87171" : "#8ea2c7",
      "font-family": "ui-monospace, Consolas, monospace",
      stroke: "#0e1528", "stroke-width": 4, "paint-order": "stroke",
    });
    lines.forEach((line, li) => {
      const tspan = svgEl("tspan", { x: label.x, dy: li === 0 ? 0 : 11 });
      tspan.textContent = line;
      text.appendChild(tspan);
    });
    g.appendChild(text);
  });

  // invalid-transition ring + ✗ label
  if (highlight && highlight.previous_state === highlight.current_state) {
    const p = NODES[highlight.previous_state];
    svg.appendChild(svgEl("circle", {
      cx: p.x, cy: p.y, r: R + 7, fill: "none", stroke: "#f87171",
      "stroke-width": 2.5, "stroke-dasharray": "5 4",
    }));
    const cross = svgEl("text", {
      x: p.x, y: p.y - R - 14, "text-anchor": "middle", "font-size": 10.5,
      fill: "#f87171", "font-family": "ui-monospace, Consolas, monospace",
      stroke: "#0e1528", "stroke-width": 4, "paint-order": "stroke",
    });
    cross.textContent = `✗ ${highlight.event}`;
    svg.appendChild(cross);
  }

  // nodes
  const accepting = new Set(["q2", "q3"]);
  const current = selRow ? selRow.current_state
    : state.result ? state.result.summary.final_state : null;
  for (const [name, p] of Object.entries(NODES)) {
    const g = svgEl("g", {});
    const isCurrent = current === name;
  const isRejected = highlight && highlight.previous_state === name &&
    highlight.previous_state === highlight.current_state;

    if (isCurrent) {
      g.appendChild(svgEl("circle", {
        cx: p.x, cy: p.y, r: R + 9, fill: "#22d3ee", opacity: 0.18,
      }));
    }
    if (accepting.has(name)) {
      g.appendChild(svgEl("circle", {
        cx: p.x, cy: p.y, r: R + 5, fill: "none", stroke: "#4a5b7d", "stroke-width": 1.3,
      }));
    }
    g.appendChild(svgEl("circle", {
      cx: p.x, cy: p.y, r: R,
      fill: isRejected ? "#3a1620" : isCurrent ? "#16324a" : "#1a2742",
      stroke: isRejected ? "#f87171" : isCurrent ? "#22d3ee" : "#4a5b7d",
      "stroke-width": isCurrent || isRejected ? 2.4 : 1.5,
    }));
    const nameText = svgEl("text", {
      x: p.x, y: p.y + 4, "text-anchor": "middle", "font-size": 13,
      "font-weight": 700, fill: "#e7eefc",
      "font-family": "ui-monospace, Consolas, monospace",
    });
    nameText.textContent = name;
    g.appendChild(nameText);
    const labelText = svgEl("text", {
      x: p.x, y: p.y + R + 16, "text-anchor": "middle", "font-size": 9.5,
      fill: "#8ea2c7", "font-family": "ui-monospace, Consolas, monospace",
      stroke: "#0e1528", "stroke-width": 4, "paint-order": "stroke",
    });
    labelText.textContent = p.label;
    g.appendChild(labelText);
    svg.appendChild(g);
  }
}

/* --------------------------------------------------------------- history */

async function loadHistory() {
  try {
    const scans = await api("/api/history");
    const body = $("history-body");
    body.innerHTML = "";
    if (!scans.length) {
      body.innerHTML = '<tr><td colspan="8" class="muted">No analyses yet — every log you analyze is recorded here.</td></tr>';
      return;
    }
    for (const s of scans) {
      const tr = document.createElement("tr");
      tr.style.cursor = "default";
      tr.innerHTML = `
        <td class="mono">${s.id}</td>
        <td class="muted">${esc(s.created_at.replace("T", " ").slice(0, 19))}</td>
        <td class="mono">${esc(s.filename)}</td>
        <td><span class="badge ${s.verdict === "NORMAL" ? "NONE" : s.verdict === "CRITICAL" ? "CRITICAL" : "HIGH"}">${esc(s.verdict)}</span></td>
        <td class="mono">${s.total_events}</td>
        <td class="mono">${s.anomalies}</td>
        <td class="mono ${s.critical_anomalies > 0 ? "red" : ""}">${s.critical_anomalies}</td>
        <td><button class="btn ghost small" data-del="${s.id}">Delete</button></td>`;
      tr.querySelector("[data-del]").addEventListener("click", async () => {
        await api(`/api/history/${s.id}`, { method: "DELETE" });
        loadHistory();
      });
      body.appendChild(tr);
    }
  } catch (_) { /* history is best-effort */ }
}

$("clear-history").addEventListener("click", async () => {
  if (!window.confirm("Delete the entire analysis history?")) return;
  await api("/api/history", { method: "DELETE" });
  loadHistory();
  toast("History cleared", "ok");
});

/* ------------------------------------------------------------- evaluation */

async function loadEvaluation() {
  try {
    const report = await api("/api/evaluation");
    const pct = (x) => (x * 100).toFixed(1) + "%";
    $("metrics-grid").innerHTML = [
      ["Accuracy", pct(report.accuracy)],
      ["Precision", pct(report.precision)],
      ["Recall", pct(report.recall)],
      ["F1-score", pct(report.f1)],
    ].map(([k, v]) => `<div class="metric"><div class="v">${v}</div><div class="k">${k}</div></div>`).join("");
    $("eval-body").innerHTML = report.samples.map((s) => `
      <tr style="cursor:default">
        <td class="mono">${esc(s.filename)}</td>
        <td class="muted">${esc(s.label)}</td>
        <td class="mono">${esc(s.predicted)}</td>
        <td class="mono">${s.events}</td>
        <td class="mono">${s.anomalies}</td>
        <td class="mono ${s.critical > 0 ? "red" : ""}">${s.critical}</td>
        <td class="mono">${s.detection_ms}</td>
        <td class="${s.correct ? "status-NORMAL" : "status-ANOMALY"}">${s.correct ? "✓ correct" : "✗ wrong"}</td>
      </tr>`).join("");
    $("eval-disclaimer").textContent = report.disclaimer;
  } catch (_) { /* evaluation is best-effort */ }
}

/* ------------------------------------------------------------------ init */

$("analyze-btn").disabled = true;
loadHistory();
loadEvaluation();
