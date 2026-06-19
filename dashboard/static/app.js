/* Cerberus dashboard — SSE client, live provenance DAG, panels, controls.
   The capability core is frozen; the trifecta legs here are DERIVED from the
   existing event stream (value/tool_call/trifecta/verdict). */

const EGRESS = new Set(["docsearch", "status_page", "exfil", "exfil_server"]);
const SENS = { 0: "PUBLIC", 1: "PRIVATE", 2: "SECRET" };
let seq = 0, lastNode = "user", lastEgressNode = null, currentRunId = null, scrubbing = false;

/* ---------- Cytoscape DAG ---------- */
const cy = cytoscape({
  container: document.getElementById("cy"),
  style: [
    { selector: "node", style: {
      "label": "data(label)", "color": "#e9eef6",
      "font-family": "Space Grotesk, system-ui, sans-serif", "font-size": 10, "font-weight": 500,
      "text-wrap": "wrap", "text-max-width": 102, "text-valign": "center", "text-halign": "center",
      "background-color": "#141a25", "background-opacity": 0.96, "border-width": 1.5, "border-color": "#2b3543",
      "width": 110, "height": 50, "shape": "round-rectangle", "padding": 8 } },
    { selector: "node.user", style: { "background-color": "#14223f", "border-color": "#4f86f7" } },
    { selector: "node.trusted", style: { "border-color": "#2fd486" } },
    { selector: "node.private", style: { "background-color": "#26210e", "border-color": "#f0a83a" } },
    { selector: "node.untrusted", style: { "background-color": "#2a1d0c", "border-color": "#f0a83a" } },
    { selector: "node.secret", style: { "background-color": "#2c1411", "border-color": "#ff5d54" } },
    { selector: "node.egress", style: { "shape": "hexagon", "width": 118, "height": 60, "border-color": "#ff7a45" } },
    { selector: "node.blocked", style: { "border-color": "#ff5d54", "border-width": 3, "color": "#ffd9d5",
      "background-color": "#3a1411", "shadow-blur": 30, "shadow-color": "#ff5d54", "shadow-opacity": 0.85 } },
    { selector: "edge", style: { "width": 1.6, "line-color": "#2b3543",
      "target-arrow-shape": "triangle", "target-arrow-color": "#2b3543", "curve-style": "bezier", "arrow-scale": 0.9 } },
    { selector: "edge.blocked", style: { "line-color": "#ff5d54", "width": 4,
      "target-arrow-color": "#ff5d54", "source-arrow-shape": "tee", "source-arrow-color": "#ff5d54" } },
  ],
  layout: { name: "breadthfirst", directed: true, spacingFactor: 1.1 },
});

function relayout() { cy.layout({ name: "breadthfirst", directed: true, spacingFactor: 1.1 }).run(); }

function resetDag() {
  cy.elements().remove();
  cy.add({ data: { id: "user", label: "USER\n(task)" }, classes: "user" });
  seq = 0; lastNode = "user"; lastEgressNode = null;
}

function addNode(id, label, cls) {
  if (cy.getElementById(id).length) return id;
  cy.add({ data: { id, label }, classes: cls });
  cy.add({ data: { id: "e_" + id, source: lastNode, target: id } });
  lastNode = id;
  relayout();
  return id;
}

function markBlocked() {
  const target = lastEgressNode || lastNode;
  cy.getElementById(target).addClass("blocked");
  cy.getElementById("e_" + target).addClass("blocked");
  const n = cy.getElementById(target);
  if (n.length) n.data("label", "🔒 " + (n.data("label") || ""));
}

/* ---------- panels ---------- */
function setLeg(id, on) { document.getElementById(id).classList.toggle("on", !!on); }
function setLegsFrom(v) { setLeg("L1", v.L1_private_access); setLeg("L2", v.L2_untrusted_influence); setLeg("L3", v.L3_egress); }

function setVerdict(decision, reason, mode) {
  const el = document.getElementById("verdict");
  el.className = "verdict " + (decision || "").toLowerCase();
  document.getElementById("verdict-big").textContent = decision || "—";
  document.getElementById("verdict-reason").textContent = reason || "";
  if (mode) document.getElementById("mode-chip").textContent = "policy: " + mode;
}

function setLeak(bits) {
  const g = document.getElementById("gauge");
  g.style.setProperty("--v", Math.min(100, bits));
  document.getElementById("gauge-val").textContent = bits ? "~" + bits : "0";
  document.getElementById("leak-meta").textContent = bits ? "bits of a known secret in the payload" : "no secret bits detected";
}
function setHoney(text) { document.getElementById("honey").textContent = text ? "🍯 " + text : ""; }

function setSink(received) {
  const el = document.getElementById("sink");
  if (received && received.length) {
    el.className = "sink hit";
    el.innerHTML = "⚠ EXFIL SINK RECEIVED<code>" + escapeHtml(received[0].slice(0, 120)) + "</code>";
  } else {
    el.className = "sink empty";
    el.textContent = "sink secure · nothing received ✓";
  }
}

function setStatus(text, cls) {
  const p = document.getElementById("status-pill");
  if (!p) return;
  p.className = "status-pill" + (cls ? " " + cls : "");
  p.innerHTML = '<span class="ping"></span> ' + text;
}

function addReceipt(d) {
  const wrap = document.getElementById("receipts");
  const div = document.createElement("div");
  div.className = "receipt";
  const hash = (d.this_hash || "").slice(0, 10);
  div.innerHTML = `<span class="pill ${d.decision}">${d.decision}</span>
    <span>${escapeHtml(d.tool || "")}</span>
    <span class="hash">#${hash}…</span>`;
  wrap.appendChild(div);
  wrap.scrollTop = wrap.scrollHeight;
}

async function refreshVerify() {
  const r = await fetch("/api/verify").then(x => x.json()).catch(() => null);
  if (!r) return;
  const el = document.getElementById("verify-badge");
  el.className = "verify-badge " + (r.intact ? "ok" : "bad");
  el.textContent = r.intact ? `✓ chain intact (${r.receipts} receipts)` : `✗ chain TAMPERED (${r.receipts} receipts)`;
}

function toast(code, detail, severity) {
  const wrap = document.getElementById("toasts");
  const t = document.createElement("div");
  t.className = "toast " + (severity || "INFO");
  t.innerHTML = `<span class="code">SENTINEL ${severity}: ${escapeHtml(code)}</span><br>${escapeHtml(detail || "")}`;
  wrap.appendChild(t);
  setTimeout(() => t.remove(), 7000);
}

function escapeHtml(s) { return String(s).replace(/[&<>"]/g, c => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c])); }

/* ---------- event router (shared by SSE + replay) ---------- */
function handleEvent(e) {
  const d = e.data || {};
  switch (e.kind) {
    case "tool_call": {
      const cls = EGRESS.has(d.server) ? "egress" : "trusted";
      const id = addNode("n" + (++seq), `${d.server}\n${d.tool}`, cls);
      if (EGRESS.has(d.server)) { lastEgressNode = id; setLeg("L3", true); }
      break;
    }
    case "value": {
      let cls = "trusted";
      if (d.value_kind === "untrusted") { cls = "untrusted"; setLeg("L2", true); }
      if (d.sensitivity >= 2) cls = "secret";
      else if (d.sensitivity >= 1) cls = (cls === "untrusted" ? "untrusted" : "private");
      if (d.sensitivity >= 1) setLeg("L1", true);
      const label = (d.value_kind === "untrusted" ? "UNTRUSTED" : "tool") + "\n" + (SENS[d.sensitivity] || "PUBLIC");
      addNode("v_" + (d.ref || ("x" + (++seq))), label, cls);
      break;
    }
    case "sentinel":
      toast(d.code, d.detail, d.severity);
      break;
    case "trifecta":
      setLegsFrom(d);
      if (d.evidence) {
        const m = /([\d.]+)\s*bits/.exec(d.evidence.leak_meter || "");
        if (m) setLeak(parseFloat(m[1]));
        if (d.evidence.honeytoken) setHoney(d.evidence.honeytoken);
      }
      break;
    case "verdict":
      setVerdict(d.decision, d.reason, null);
      if (d.head_verdicts) setLegsFrom(d.head_verdicts);
      if (d.decision === "BLOCK" || d.decision === "QUARANTINE") { markBlocked(); setStatus("threat blocked", "threat"); }
      addReceipt(d);
      refreshSinkAndVerify();
      break;
    case "sink_state": {
      const leaked = (d.received || []).length;
      setSink(d.received || []);
      setStatus(leaked ? "breach · key exfiltrated" : "secure · sink empty", leaked ? "breach" : "live");
      refreshVerify();
      break;
    }
    case "confirm_request":
      showConfirm(d);
      break;
  }
}

async function refreshSinkAndVerify() {
  if (scrubbing) return;
  const s = await fetch("/api/sink").then(x => x.json()).catch(() => null);
  if (s) setSink(s.received);
  refreshVerify();
}

/* ---------- CONFIRM modal ---------- */
function showConfirm(d) {
  currentRunId = d.run_id;
  document.getElementById("confirm-body").textContent = d.prompt || "Approve this action?";
  document.getElementById("modal").classList.remove("hidden");
}
async function answerConfirm(approve) {
  document.getElementById("modal").classList.add("hidden");
  await fetch("/api/confirm", { method: "POST", headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ run_id: currentRunId, approve }) });
}

/* ---------- controls ---------- */
function fullReset() {
  resetDag();
  ["L1", "L2", "L3"].forEach(l => setLeg(l, false));
  setVerdict("—", "awaiting run…", document.getElementById("mode").value);
  setLeak(0); setHoney(""); setSink([]);
  document.getElementById("receipts").innerHTML = "";
  document.getElementById("verify-badge").textContent = "";
  setStatus("awaiting run", "");
}

async function runScenario() {
  await fetch("/api/reset", { method: "POST" });
  fullReset();
  const enabled = document.getElementById("toggle").checked;
  const mode = enabled ? document.getElementById("mode").value : null;
  const r = await fetch("/api/run", { method: "POST", headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ enabled, mode }) }).then(x => x.json());
  currentRunId = r.run_id;
  document.getElementById("mode-chip").textContent = enabled ? "policy: " + mode : "CERBERUS OFF";
  setStatus(enabled ? "live · monitoring" : "unprotected · cerberus off", enabled ? "live" : "threat");
  // The backend emits a deterministic `sink_state` event when the run completes,
  // which refreshes the sink card (covers OFF mode, which emits no verdict event).
}

async function tamper() {
  await fetch("/api/tamper", { method: "POST" });
  setTimeout(refreshVerify, 100);
}

/* ---------- replay scrubber ---------- */
let sessionEvents = [];
async function loadSession() {
  const r = await fetch("/api/session").then(x => x.json()).catch(() => ({ events: [] }));
  sessionEvents = r.events || [];
  const sl = document.getElementById("scrub");
  sl.max = Math.max(0, sessionEvents.length);
  sl.value = sl.max;
}
function scrubTo(i) {
  scrubbing = true;
  fullReset();
  for (let k = 0; k < i && k < sessionEvents.length; k++) handleEvent(sessionEvents[k]);
  scrubbing = false;
}

/* ---------- wire up ---------- */
window.addEventListener("DOMContentLoaded", () => {
  fullReset();
  document.getElementById("run").onclick = runScenario;
  document.getElementById("reset").onclick = async () => { await fetch("/api/reset", { method: "POST" }); fullReset(); };
  document.getElementById("tamper").onclick = tamper;
  document.getElementById("loadsession").onclick = loadSession;
  document.getElementById("scrub").oninput = (ev) => scrubTo(parseInt(ev.target.value, 10));
  document.getElementById("approve").onclick = () => answerConfirm(true);
  document.getElementById("deny").onclick = () => answerConfirm(false);
  document.getElementById("toggle").onchange = (ev) => {
    document.getElementById("mode").disabled = !ev.target.checked;
    document.getElementById("onoff").textContent = ev.target.checked ? "CERBERUS ON" : "CERBERUS OFF";
  };

  const es = new EventSource("/events");
  es.onmessage = (m) => { if (scrubbing) return; try { handleEvent(JSON.parse(m.data)); } catch (_) {} };
  es.addEventListener("reset", () => { if (!scrubbing) fullReset(); });
});
