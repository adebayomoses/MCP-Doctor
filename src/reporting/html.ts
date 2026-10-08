import { CATEGORIES, type Category, type Finding, type ScanResult, type Severity } from "../core/types.js";
import type { BatchEntry, BatchResult } from "../batch/types.js";
import { scoreColor } from "./badge.js";
import { uniqueRecommendations } from "./recommendations.js";

/**
 * Everything in these pages that came from a scanned server (names, descriptions, evidence,
 * error messages) is untrusted. All of it goes through esc(), the pages contain no scripts, and
 * a CSP forbids them anyway, so a hostile server cannot run code in the person viewing a report.
 */
export const esc = (s: unknown): string =>
  String(s ?? "")
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");

const SEV_COLOR: Record<Severity, string> = { critical: "#c62828", high: "#e65100", medium: "#b28900", low: "#1565c0", info: "#6b7280" };
const CAT_LABEL: Record<Category, string> = { protocol: "Protocol", security: "Security", tools: "Tools", schema: "Schema", performance: "Performance", quality: "Quality" };

const CSP = "default-src 'none'; style-src 'unsafe-inline'; img-src 'self' data:; base-uri 'none'; form-action 'none'";

const CSS = `
:root{--bg:#fff;--fg:#1a1a1a;--muted:#5f6670;--card:#f6f7f9;--line:#e1e4e8;--accent:#2457d6}
@media (prefers-color-scheme:dark){:root{--bg:#14161a;--fg:#e8eaed;--muted:#9aa3ad;--card:#1d2026;--line:#2f343c;--accent:#7aa2ff}}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--fg);font:15px/1.5 system-ui,-apple-system,Segoe UI,Roboto,sans-serif}
main{max-width:980px;margin:0 auto;padding:24px 16px 64px}h1{font-size:22px;margin:0 0 4px}h2{font-size:17px;margin:32px 0 12px}
a{color:var(--accent)}.muted{color:var(--muted)}.mono{font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;font-size:13px}
.card{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:16px}
.hero{display:flex;gap:24px;align-items:center;flex-wrap:wrap}.ring{flex:none}
.cats{flex:1;min-width:240px;display:grid;gap:8px}.cat{display:grid;grid-template-columns:96px 1fr 32px;align-items:center;gap:8px;font-size:14px}
.bar{height:8px;background:var(--line);border-radius:4px;overflow:hidden}.bar>i{display:block;height:100%}
.pill{display:inline-block;padding:1px 8px;border-radius:999px;font-size:12px;font-weight:600;color:#fff}
details.f{border:1px solid var(--line);border-left-width:4px;border-radius:8px;margin:8px 0;background:var(--card)}
details.f>summary{cursor:pointer;padding:10px 12px;list-style:none}details.f>summary::-webkit-details-marker{display:none}
details.f .body{padding:0 12px 12px}.ev{background:var(--bg);border:1px solid var(--line);border-radius:6px;padding:8px;margin:6px 0;white-space:pre-wrap;word-break:break-word}
table{width:100%;border-collapse:collapse;font-size:14px}th,td{text-align:left;padding:8px 10px;border-bottom:1px solid var(--line);vertical-align:top}th{color:var(--muted);font-weight:600;font-size:12px;text-transform:uppercase;letter-spacing:.04em}
td.n,th.n{text-align:right;font-variant-numeric:tabular-nums}.note{font-size:13px;color:var(--muted);margin-top:24px}
.stats{display:flex;gap:12px;flex-wrap:wrap}.stat{flex:1;min-width:120px}.stat b{display:block;font-size:24px}
@media (max-width:560px){.cat{grid-template-columns:80px 1fr 28px}th:nth-child(n+5),td:nth-child(n+5){display:none}}
`;

function page(title: string, body: string): string {
  return `<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="${CSP}"><meta name="robots" content="noindex">
<title>${esc(title)}</title><style>${CSS}</style></head><body><main>${body}</main></body></html>
`;
}

function ring(score: number, size = 120): string {
  const r = 50;
  const c = 2 * Math.PI * r;
  const col = scoreColor(score);
  return `<svg class="ring" width="${size}" height="${size}" viewBox="0 0 120 120" role="img" aria-label="Score ${score} out of 100"><circle cx="60" cy="60" r="${r}" fill="none" stroke="var(--line)" stroke-width="10"/><circle cx="60" cy="60" r="${r}" fill="none" stroke="${col}" stroke-width="10" stroke-linecap="round" stroke-dasharray="${((score / 100) * c).toFixed(1)} ${c.toFixed(1)}" transform="rotate(-90 60 60)"/><text x="60" y="66" text-anchor="middle" font-size="28" font-weight="700" fill="currentColor">${score}</text></svg>`;
}

const pill = (sev: Severity) => `<span class="pill" style="background:${SEV_COLOR[sev]}">${sev}</span>`;

function findingHtml(f: Finding): string {
  const details = (f.details ?? []).map((d) => `<div class="ev mono">${esc(d)}</div>`).join("");
  return `<details class="f" style="border-left-color:${SEV_COLOR[f.severity]}"><summary>${pill(f.severity)} <b>${esc(f.rule)}</b> ${esc(f.name)}${f.tool ? ` <span class="mono muted">· ${esc(f.tool)}</span>` : ""}<div class="muted">${esc(f.message)}</div></summary><div class="body">${f.evidence ? `<div class="ev mono">${esc(f.evidence)}</div>` : ""}${details}<p><b>Why it matters.</b> ${esc(f.why)}</p><p><b>How to fix.</b> ${esc(f.recommendation)}</p></div></details>`;
}

/** The body of a single-server report (also embedded on per-server pages of the site). */
export function reportBody(r: ScanResult, extra = ""): string {
  const name = r.server?.name ? `${r.server.name}${r.server.version ? ` v${r.server.version}` : ""}` : r.target;
  const bars = CATEGORIES.map(
    (c) => `<div class="cat"><span>${CAT_LABEL[c]}</span><div class="bar"><i style="width:${r.scores[c]}%;background:${scoreColor(r.scores[c])}"></i></div><b>${r.scores[c]}</b></div>`,
  ).join("");
  const t = r.timings;
  const perf = [
    `Connection + init: ${t.connectMs ?? "n/a"} ms`,
    `Discovery: ${t.discoveryMs ?? "n/a"} ms`,
    t.avgToolMs !== undefined ? `Average tool call: ${t.avgToolMs} ms` : "Tool calls not measured (passive scan)",
  ].join(" · ");
  const recs = uniqueRecommendations(r.findings);
  return `<h1>${esc(name)}</h1><div class="muted mono">${esc(r.target)}</div>
<div class="card hero" style="margin-top:16px">${ring(r.score)}<div><div style="font-size:22px;font-weight:700">${esc(r.grade)}</div><div class="muted">${r.status === "connected" ? `${r.counts.tools} tools · ${r.counts.resources} resources · ${r.counts.prompts} prompts` : "could not connect"}</div>${r.protocolVersion ? `<div class="muted">protocol ${esc(r.protocolVersion)}</div>` : ""}</div><div class="cats">${bars}</div></div>
<p class="muted">${esc(perf)}</p>${extra}
<h2>Findings (${r.findings.length})</h2>${r.findings.length ? r.findings.map(findingHtml).join("") : '<p class="muted">No findings.</p>'}
${recs.length ? `<h2>Recommendations</h2><ul>${recs.map((x) => `<li><b>${esc(x.rule)} ${esc(x.name)}</b> (${x.count}×): ${esc(x.recommendation)}</li>`).join("")}</ul>` : ""}
<p class="note">${esc(r.disclaimer)} Generated by mcp-detector ${esc(r.version)}.</p>`;
}

export function renderHtmlReport(r: ScanResult): string {
  return page(`MCP Detector – ${r.server?.name ?? r.target}`, reportBody(r));
}

// ---------------------------------------------------------------------------------------------
// Batch / site
// ---------------------------------------------------------------------------------------------

export function slugify(name: string, taken: Set<string>): string {
  const base = name.toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(/^-+|-+$/g, "").slice(0, 60) || "server";
  let s = base;
  for (let i = 2; taken.has(s); i++) s = `${base}-${i}`;
  taken.add(s);
  return s;
}

function sparkline(scores: number[]): string {
  if (scores.length < 2) return "";
  const w = 80;
  const h = 20;
  const pts = scores.map((s, i) => `${((i / (scores.length - 1)) * (w - 2) + 1).toFixed(1)},${(h - 1 - (s / 100) * (h - 2)).toFixed(1)}`).join(" ");
  return `<svg width="${w}" height="${h}" viewBox="0 0 ${w} ${h}" role="img" aria-label="score history"><polyline fill="none" stroke="var(--accent)" stroke-width="1.5" points="${pts}"/></svg>`;
}

export interface SiteEntry {
  entry: BatchEntry;
  slug: string;
  history: number[];
}

export function renderSiteIndex(batch: BatchResult, items: SiteEntry[], opts: { title?: string } = {}): string {
  const scored = items.filter((i) => i.entry.status === "scanned" && i.entry.result).sort((a, b) => b.entry.result!.score - a.entry.result!.score);
  const others = items.filter((i) => i.entry.status !== "scanned");
  const s = batch.summary;
  const rows = scored
    .map((i, n) => {
      const r = i.entry.result!;
      return `<tr><td class="n">${n + 1}</td><td><a href="servers/${esc(i.slug)}.html">${esc(i.entry.name)}</a>${i.entry.meta?.description ? `<div class="muted" style="font-size:13px">${esc(i.entry.meta.description.slice(0, 140))}</div>` : ""}</td><td class="n"><span class="pill" style="background:${scoreColor(r.score)}">${r.score}</span></td><td>${esc(r.grade)}</td><td class="n">${r.summary.critical}</td><td class="n">${r.summary.high}</td><td class="n">${r.summary.medium}</td><td class="n">${r.counts.tools}</td><td>${sparkline(i.history)}</td></tr>`;
    })
    .join("");
  const notScored = others.length
    ? `<h2>Not scored (${others.length})</h2><table><thead><tr><th>Server</th><th>Status</th><th>Reason</th></tr></thead><tbody>${others
        .map((i) => `<tr><td>${esc(i.entry.name)}</td><td>${esc(i.entry.status.replace("_", " "))}</td><td class="muted">${esc((i.entry.note ?? "").slice(0, 200))}</td></tr>`)
        .join("")}</tbody></table>`
    : "";
  const body = `<h1>${esc(opts.title ?? "MCP server scoreboard")}</h1>
<p class="muted">Passive scans by mcp-detector ${esc(batch.version)} · ${esc(batch.createdAt.slice(0, 10))} · source: ${esc(batch.origin)}</p>
<div class="card stats"><div class="stat"><b>${s.scanned}</b><span class="muted">scored</span></div><div class="stat"><b>${s.averageScore ?? "–"}</b><span class="muted">average score</span></div><div class="stat"><b>${s.bySeverity.critical}</b><span class="muted">critical findings</span></div><div class="stat"><b>${s.bySeverity.high}</b><span class="muted">high findings</span></div><div class="stat"><b>${s.authRequired + s.failed}</b><span class="muted">not scored</span></div></div>
<h2>Scores</h2>${scored.length ? `<table><thead><tr><th class="n">#</th><th>Server</th><th class="n">Score</th><th>Grade</th><th class="n">Crit</th><th class="n">High</th><th class="n">Med</th><th class="n">Tools</th><th>Trend</th></tr></thead><tbody>${rows}</tbody></table>` : '<p class="muted">No servers could be scored.</p>'}
${notScored}
<p class="note"><b>How to read this.</b> Scores summarise heuristic findings from a passive scan: the scanner connected, listed tools, resources and prompts, and never called a tool. A score is an engineering signal, not a security certification; findings are indicators that may include false positives, and a high score does not prove a server is safe. Open a server's page for the evidence behind each finding. Servers that require authentication are listed but not scored.</p>`;
  return page(opts.title ?? "MCP server scoreboard", body);
}

export function renderSiteServerPage(item: SiteEntry): string {
  const r = item.entry.result!;
  const back = `<p><a href="../index.html">← all servers</a></p>`;
  const meta = item.entry.meta?.description ? `<p class="muted">${esc(item.entry.meta.description)}</p>` : "";
  const badge = `<p><img src="../badges/${esc(item.slug)}.svg" alt="mcp-detector score ${r.score}/100"></p>`;
  return page(`MCP Detector – ${item.entry.name}`, back + reportBody(r, meta + badge));
}
