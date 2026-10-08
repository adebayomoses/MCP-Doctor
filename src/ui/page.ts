/**
 * The single-page web app served by `mcp-detector ui`.
 *
 * Security notes:
 *  - The only script is one inline block protected by a per-response CSP nonce; there are no remote resources.
 *  - Everything that came from a scanned server is shown either through textContent or inside a
 *    sandboxed iframe (srcdoc, no allow-* flags) that holds an already-escaped, script-free report.
 *  - The page contains no secrets. The access key arrives in the URL fragment (never sent to a server,
 *    never in a Referer) and is removed from the address bar immediately.
 */
export function uiCsp(nonce: string): string {
  return [
    "default-src 'none'",
    `script-src 'nonce-${nonce}'`,
    "style-src 'unsafe-inline'", // inherited by the report iframe, whose own CSP forbids scripts
    "connect-src 'self'",
    "img-src data:",
    "frame-src about:",
    "base-uri 'none'",
    "form-action 'none'",
    "frame-ancestors 'none'",
  ].join("; ");
}

const CSS = `
:root{--bg:#fff;--fg:#1a1a1a;--muted:#5f6670;--card:#f6f7f9;--line:#dfe3e8;--accent:#2457d6;--accent-fg:#fff;--ok:#1a7f37;--bad:#c62828;--warn:#9a6700}
@media (prefers-color-scheme:dark){:root{--bg:#14161a;--fg:#e8eaed;--muted:#9aa3ad;--card:#1d2026;--line:#2f343c;--accent:#7aa2ff;--accent-fg:#0b1020;--ok:#3fb950;--bad:#ff7b72;--warn:#d29922}}
*{box-sizing:border-box}html{-webkit-text-size-adjust:100%}
body{margin:0;background:var(--bg);color:var(--fg);font:16px/1.5 system-ui,-apple-system,Segoe UI,Roboto,sans-serif}
main{max-width:960px;margin:0 auto;padding:24px 16px 64px}
h1{font-size:24px;margin:0}h2{font-size:18px;margin:0 0 12px}.sub{color:var(--muted);margin:2px 0 20px}
.card{background:var(--card);border:1px solid var(--line);border-radius:12px;padding:20px;margin-bottom:16px}
.muted{color:var(--muted)}.small{font-size:14px}.mono{font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace}
.steps{display:grid;grid-template-columns:repeat(3,1fr);gap:12px;margin:0;padding:0;list-style:none}
.steps li{background:var(--bg);border:1px solid var(--line);border-radius:10px;padding:12px 14px}
.steps b{display:block;margin-bottom:2px}
@media(max-width:640px){.steps{grid-template-columns:1fr}}
[role=tablist]{display:flex;gap:6px;flex-wrap:wrap;margin-bottom:16px}
[role=tab]{font:inherit;border:1px solid var(--line);background:var(--bg);color:var(--fg);border-radius:999px;padding:7px 14px;cursor:pointer}
[role=tab][aria-selected=true]{background:var(--accent);border-color:var(--accent);color:var(--accent-fg);font-weight:600}
label{display:block;font-weight:600;margin:12px 0 4px}
input[type=text],input[type=url],input[type=password]{width:100%;font:inherit;padding:10px 12px;border:1px solid var(--line);border-radius:8px;background:var(--bg);color:var(--fg)}
input:focus-visible,button:focus-visible,[role=tab]:focus-visible,summary:focus-visible{outline:3px solid var(--accent);outline-offset:2px}
.check{display:flex;gap:10px;align-items:flex-start;font-weight:400;margin:14px 0 0}.check input{margin-top:5px;flex:none}
.hdr{display:grid;grid-template-columns:1fr 1.4fr;gap:8px}
button.primary{font:inherit;font-weight:600;background:var(--accent);color:var(--accent-fg);border:0;border-radius:8px;padding:11px 20px;margin-top:18px;cursor:pointer}
button.primary:disabled{opacity:.5;cursor:not-allowed}
button.link{font:inherit;background:none;border:0;color:var(--accent);padding:0;cursor:pointer;text-decoration:underline}
.warn{border-left:4px solid var(--warn);background:var(--bg);padding:10px 12px;border-radius:6px;margin-top:12px}
.err{border-left:4px solid var(--bad);background:var(--bg);padding:10px 12px;border-radius:6px;margin:0 0 12px}
.clients{list-style:none;margin:0;padding:0;border:1px solid var(--line);border-radius:10px;overflow:hidden}
.clients li{display:flex;gap:10px;padding:10px 12px;background:var(--bg);border-bottom:1px solid var(--line)}.clients li:last-child{border-bottom:0}
.clients .t{overflow-wrap:anywhere}
.runs{list-style:none;margin:0;padding:0}.runs li{display:flex;gap:12px;align-items:center;justify-content:space-between;padding:10px 0;border-bottom:1px solid var(--line)}.runs li:last-child{border-bottom:0}
.pill{display:inline-block;min-width:44px;text-align:center;padding:1px 10px;border-radius:999px;font-weight:700;color:#fff}
.spin{display:inline-block;width:14px;height:14px;border:2px solid var(--line);border-top-color:var(--accent);border-radius:50%;animation:s .8s linear infinite;vertical-align:-2px;margin-right:8px}
@keyframes s{to{transform:rotate(360deg)}}@media(prefers-reduced-motion:reduce){.spin{animation:none}}
iframe{width:100%;height:70vh;min-height:420px;border:1px solid var(--line);border-radius:10px;background:#fff}
.actions{display:flex;gap:16px;flex-wrap:wrap;margin:12px 0 0}
.visually-hidden{position:absolute;width:1px;height:1px;overflow:hidden;clip:rect(0 0 0 0);white-space:nowrap}
[hidden]{display:none!important}
`;

const JS = `
"use strict";
const $ = (id) => document.getElementById(id);
const el = (tag, props, ...kids) => {
  const n = document.createElement(tag);
  for (const [k, v] of Object.entries(props || {})) { if (k === "class") n.className = v; else if (k === "text") n.textContent = v; else n.setAttribute(k, v); }
  for (const c of kids) n.append(c);
  return n;
};
const colorFor = (s) => s >= 90 ? "#44cc11" : s >= 80 ? "#6fa300" : s >= 70 ? "#b88a00" : s >= 50 ? "#e8590c" : "#d6402c";

let token = null;
try { token = sessionStorage.getItem("mcpd"); } catch {}
const m = /token=([a-f0-9]+)/.exec(location.hash);
if (m) { token = m[1]; try { sessionStorage.setItem("mcpd", token); } catch {} }
if (location.hash) history.replaceState(null, "", location.pathname);

async function api(path, body) {
  const res = await fetch(path, {
    method: body ? "POST" : "GET",
    headers: { "x-mcpd-token": token || "", ...(body ? { "content-type": "application/json" } : {}) },
    body: body ? JSON.stringify(body) : undefined,
  });
  let data = null;
  try { data = await res.json(); } catch {}
  if (!res.ok) { const e = new Error((data && data.error) || ("Request failed (" + res.status + ")")); e.status = res.status; throw e; }
  return data;
}

if (!token) {
  $("noToken").hidden = false;
  $("app").hidden = true;
}

// ---- tabs
const tabs = [...document.querySelectorAll("[role=tab]")];
function selectTab(name) {
  for (const t of tabs) {
    const on = t.dataset.tab === name;
    t.setAttribute("aria-selected", String(on));
    t.tabIndex = on ? 0 : -1;
    $("panel-" + t.dataset.tab).hidden = !on;
  }
}
tabs.forEach((t, i) => {
  t.addEventListener("click", () => selectTab(t.dataset.tab));
  t.addEventListener("keydown", (e) => {
    if (e.key !== "ArrowRight" && e.key !== "ArrowLeft") return;
    const next = tabs[(i + (e.key === "ArrowRight" ? 1 : tabs.length - 1)) % tabs.length];
    next.focus(); selectTab(next.dataset.tab);
  });
});

// ---- runs
const runs = new Map(); // id -> {label, view}
let selected = null;
let lastStarted = null; // the scan the person asked for most recently: its result is what they want to see

function renderRuns() {
  const list = $("runlist");
  list.replaceChildren();
  for (const [id, r] of runs) {
    const v = r.view;
    const right = el("span");
    if (!v || v.status === "running") right.append(el("span", { class: "spin", "aria-hidden": "true" }), el("span", { text: "Scanning…", class: "muted" }));
    else if (v.status === "error" || (v.result && v.result.status === "failed")) right.append(el("span", { text: "Could not scan", class: "muted" }));
    else right.append(el("span", { class: "pill", text: String(v.result.score), style: "background:" + colorFor(v.result.score) }));
    const open = el("button", { class: "link", type: "button", text: "View" });
    if (v && v.status !== "running") open.addEventListener("click", () => show(id)); else open.disabled = true;
    list.append(el("li", {}, el("span", { text: r.label }), el("span", {}, right, document.createTextNode("  "), open)));
  }
  $("runs").hidden = runs.size === 0;
}

function show(id) {
  selected = id;
  const r = runs.get(id), v = r && r.view;
  if (!v) return;
  const box = $("summary");
  box.replaceChildren();
  if (v.problem) {
    box.append(el("div", { class: "err", role: "alert" }, el("strong", { text: v.problem.title }), el("br"), el("span", { text: v.problem.hint })));
  }
  if (v.result && v.result.status === "connected") {
    const res = v.result;
    const s = res.summary;
    box.append(
      el("h2", { text: (res.server && res.server.name) ? res.server.name + (res.server.version ? " v" + res.server.version : "") : r.label }),
      el("p", {}, el("span", { class: "pill", text: String(res.score), style: "background:" + colorFor(res.score) }), document.createTextNode("  " + res.grade + " · " + res.counts.tools + " tools · " +
        s.critical + " critical, " + s.high + " high, " + s.medium + " medium, " + s.low + " low findings")),
    );
  }
  const frame = $("frame");
  frame.srcdoc = v.html || "";
  frame.hidden = !v.html;
  $("viewer").hidden = false;
  $("dlHtml").hidden = !v.html;
  $("dlJson").hidden = !v.result;
  $("viewer").scrollIntoView({ behavior: "smooth", block: "start" });
}

function download(name, type, text) {
  const a = el("a", { download: name, href: URL.createObjectURL(new Blob([text], { type })) });
  document.body.append(a); a.click(); a.remove();
}
$("dlHtml").addEventListener("click", () => { const r = runs.get(selected); if (r && r.view && r.view.html) download("mcp-detector-report.html", "text/html", r.view.html); });
$("dlJson").addEventListener("click", () => { const r = runs.get(selected); if (r && r.view && r.view.result) download("mcp-detector-report.json", "application/json", JSON.stringify(r.view.result, null, 2)); });

async function poll(id) {
  for (;;) {
    await new Promise((ok) => setTimeout(ok, 700));
    let v;
    try { v = await api("/api/scan/" + id); } catch (e) { v = { id, status: "error", error: e.message, problem: { title: "Lost contact with the scanner.", hint: e.message } }; }
    const r = runs.get(id); r.view = v; renderRuns();
    if (v.status !== "running") { if (lastStarted === id || !selected) show(id); loadRecent(); return; }
  }
}

async function startScan(label, body) {
  setBusy(true); clearFormError();
  try {
    const { id } = await api("/api/scan", body);
    runs.set(id, { label, view: { id, status: "running" } });
    lastStarted = id;
    renderRuns();
    poll(id);
  } catch (e) { formError(e.message); }
  finally { setBusy(false); }
}
function setBusy(b) { document.querySelectorAll("button.primary").forEach((x) => { x.dataset.busy = b ? "1" : ""; refreshButtons(); }); }
function formError(msg) { const n = $("formError"); n.textContent = msg; n.hidden = false; }
function clearFormError() { $("formError").hidden = true; }

// ---- command tab
$("panel-command").addEventListener("submit", (e) => {
  e.preventDefault();
  const command = $("cmd").value.trim();
  if (!command) return formError("Enter the command that starts your MCP server.");
  startScan(command, { kind: "command", command, active: $("cmdActive").checked, confirm: $("cmdConfirm").checked });
});
// ---- url tab
function addHeaderRow() {
  const row = el("div", { class: "hdr" },
    el("input", { type: "text", placeholder: "Header name (e.g. Authorization)", "aria-label": "Header name", autocomplete: "off" }),
    el("input", { type: "password", placeholder: "Value (e.g. Bearer abc123)", "aria-label": "Header value", autocomplete: "off" }));
  $("hdrs").append(row);
}
addHeaderRow();
$("addHdr").addEventListener("click", addHeaderRow);
$("panel-url").addEventListener("submit", (e) => {
  e.preventDefault();
  const url = $("url").value.trim();
  if (!url) return formError("Enter the address of the MCP server.");
  const headers = {};
  for (const row of $("hdrs").children) { const [n, v] = row.querySelectorAll("input"); if (n.value.trim() && v.value) headers[n.value.trim()] = v.value; }
  startScan(url, { kind: "url", url, headers, active: false });
});
// ---- installed tab
let clients = [];
function renderClients() {
  const ul = $("clientList");
  ul.replaceChildren();
  $("noClients").hidden = clients.length > 0;
  $("clientBox").hidden = clients.length === 0;
  clients.forEach((c) => {
    const cb = el("input", { type: "checkbox", id: "c" + c.id, value: String(c.id) });
    cb.addEventListener("change", refreshButtons);
    ul.append(el("li", {}, cb, el("label", { for: "c" + c.id, class: "t", style: "margin:0;font-weight:400" },
      el("strong", { text: c.name }), document.createTextNode("  "), el("span", { class: "muted small", text: c.source }), el("br"), el("span", { class: "mono small muted", text: c.target }))));
  });
}
$("panel-installed").addEventListener("submit", async (e) => {
  e.preventDefault();
  const picked = clients.filter((c) => $("c" + c.id).checked);
  if (!picked.length) return formError("Tick at least one server.");
  for (const c of picked) await startScan(c.name, { kind: "client", id: c.id, active: false, confirm: $("clientConfirm").checked });
});
// ---- demo
$("demoVuln").addEventListener("click", () => startScan("Demo: unsafe example server", { kind: "demo", name: "vulnerable" }));
$("demoOk").addEventListener("click", () => startScan("Demo: well-built example server", { kind: "demo", name: "secure" }));

function refreshButtons() {
  const busy = [...document.querySelectorAll("button.primary")].some((b) => b.dataset.busy === "1");
  $("cmdGo").disabled = busy || !$("cmdConfirm").checked;
  $("urlGo").disabled = busy;
  $("clientGo").disabled = busy || !$("clientConfirm").checked || !clients.some((c) => $("c" + c.id) && $("c" + c.id).checked);
  $("demoVuln").disabled = busy; $("demoOk").disabled = busy;
}
for (const id of ["cmdConfirm", "clientConfirm"]) $(id).addEventListener("change", refreshButtons);

// ---- recent scans (history)
async function loadRecent() {
  try {
    const { items } = await api("/api/history");
    const ul = $("recentList"); ul.replaceChildren();
    $("recent").hidden = items.length === 0;
    for (const it of items.slice(0, 12)) {
      const b = el("button", { class: "link", type: "button", text: "View" });
      b.addEventListener("click", async () => {
        const v = await api("/api/history/" + it.key);
        runs.set("h" + it.key, { label: it.name || it.target, view: v }); renderRuns(); show("h" + it.key);
      });
      ul.append(el("li", {}, el("span", {}, el("span", { class: "pill", text: String(it.score), style: "background:" + colorFor(it.score) }), document.createTextNode("  " + (it.name || it.target) + "  "),
        el("span", { class: "muted small", text: it.at.slice(0, 16).replace("T", " ") })), b));
    }
  } catch {}
}

(async function init() {
  if (!token) return;
  try {
    const st = await api("/api/state");
    clients = st.clients; renderClients();
    $("ver").textContent = "v" + st.version;
  } catch (e) {
    if (e.status === 401) { $("noToken").hidden = false; $("app").hidden = true; return; }
    formError(e.message);
  }
  refreshButtons(); loadRecent();
})();
`;

export function renderUiPage(nonce: string): string {
  return `<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="referrer" content="no-referrer"><meta name="robots" content="noindex">
<title>MCP Detector</title><style>${CSS}</style></head>
<body><main>
<h1>MCP Detector <span class="muted small" id="ver"></span></h1>
<p class="sub">Check an MCP server for security, reliability and quality problems before you trust it.</p>

<section id="noToken" class="card" hidden>
  <h2>Open this page from your terminal</h2>
  <p>This page needs a private access key that <code class="mono">mcp-detector ui</code> prints in the link it shows you. Run the command again and open the full link, including the part after the <code class="mono">#</code>.</p>
</section>

<div id="app">
<section class="card" aria-labelledby="how">
  <h2 id="how">How it works</h2>
  <ol class="steps">
    <li><b>1. Pick a server</b><span class="muted small">Paste its start command or web address, choose one you already use, or try the demo.</span></li>
    <li><b>2. We look, we don't touch</b><span class="muted small">By default we only connect and read the list of tools. We never run your tools.</span></li>
    <li><b>3. Read the report</b><span class="muted small">You get a 0–100 score, what was found, and how to fix each problem.</span></li>
  </ol>
</section>

<section class="card" aria-labelledby="scanH">
  <h2 id="scanH">Scan a server</h2>
  <div role="tablist" aria-label="What to scan">
    <button role="tab" id="tab-demo" data-tab="demo" aria-selected="true" aria-controls="panel-demo" type="button">Try the demo</button>
    <button role="tab" id="tab-command" data-tab="command" aria-selected="false" tabindex="-1" aria-controls="panel-command" type="button">Paste a command</button>
    <button role="tab" id="tab-url" data-tab="url" aria-selected="false" tabindex="-1" aria-controls="panel-url" type="button">Web address</button>
    <button role="tab" id="tab-installed" data-tab="installed" aria-selected="false" tabindex="-1" aria-controls="panel-installed" type="button">Servers I already use</button>
  </div>
  <div id="formError" class="err" role="alert" hidden></div>

  <div id="panel-demo" role="tabpanel" aria-labelledby="tab-demo">
    <p>New here? Scan one of our built-in example servers to see what a report looks like. Nothing on your computer is touched.</p>
    <button class="primary" id="demoVuln" type="button">Scan the unsafe example</button>
    <button class="primary" id="demoOk" type="button" style="margin-left:8px">Scan the well-built example</button>
  </div>

  <form id="panel-command" role="tabpanel" aria-labelledby="tab-command" hidden>
    <label for="cmd">Command that starts the server</label>
    <input id="cmd" type="text" placeholder="npx -y @modelcontextprotocol/server-everything" autocomplete="off" spellcheck="false">
    <p class="muted small">Exactly what you would type in a terminal to start your MCP server.</p>
    <label class="check"><input id="cmdConfirm" type="checkbox"><span>I understand this will <strong>start this program on my computer</strong>, the same way an MCP app would.</span></label>
    <label class="check"><input id="cmdActive" type="checkbox"><span>Also time the server's read-only tools <span class="muted">(calls tools that look safe to read; leave off if unsure)</span></span></label>
    <button class="primary" id="cmdGo" type="submit" disabled>Scan</button>
  </form>

  <form id="panel-url" role="tabpanel" aria-labelledby="tab-url" hidden>
    <label for="url">Server address</label>
    <input id="url" type="url" placeholder="https://example.com/mcp" autocomplete="off" spellcheck="false">
    <label>Sign-in header <span class="muted">(only if the server needs one)</span></label>
    <div id="hdrs"></div>
    <p class="small"><button class="link" id="addHdr" type="button">+ add another header</button></p>
    <p class="muted small">Headers are used for this scan only and are never saved or shown in reports.</p>
    <button class="primary" id="urlGo" type="submit">Scan</button>
  </form>

  <form id="panel-installed" role="tabpanel" aria-labelledby="tab-installed" hidden>
    <p id="noClients" class="muted" hidden>No MCP apps with configured servers were found on this computer (looked for Claude Desktop, Cursor, VS Code, Windsurf and Claude Code).</p>
    <div id="clientBox" hidden>
      <p>These servers are set up in your MCP apps:</p>
      <ul class="clients" id="clientList"></ul>
      <label class="check"><input id="clientConfirm" type="checkbox"><span>I understand this will <strong>start the ticked programs on my computer</strong>, exactly as those apps start them.</span></label>
      <button class="primary" id="clientGo" type="submit" disabled>Scan ticked servers</button>
    </div>
  </form>
</section>

<section class="card" id="runs" aria-labelledby="runsH" hidden>
  <h2 id="runsH">This session</h2>
  <ul class="runs" id="runlist" aria-live="polite"></ul>
</section>

<section class="card" id="viewer" aria-labelledby="viewH" hidden>
  <h2 id="viewH" class="visually-hidden">Report</h2>
  <div id="summary"></div>
  <iframe id="frame" sandbox="" title="Scan report" referrerpolicy="no-referrer"></iframe>
  <div class="actions"><button class="link" id="dlHtml" type="button">Download report (HTML)</button><button class="link" id="dlJson" type="button">Download data (JSON)</button></div>
  <p class="muted small">The score is an engineering signal, not a security certification. Findings are heuristic indicators and can include false positives.</p>
</section>

<section class="card" id="recent" aria-labelledby="recentH" hidden>
  <h2 id="recentH">Earlier scans</h2>
  <ul class="runs" id="recentList"></ul>
</section>
</div>
</main>
<script nonce="${nonce}">${JS}</script>
</body></html>
`;
}
