import pc from "picocolors";
import type { BatchEntry, BatchResult } from "../batch/types.js";
import { SEVERITY_ICON } from "./severity.js";

export type BatchFormat = "terminal" | "json" | "markdown";

const worst = (e: BatchEntry) => {
  const f = e.result?.findings[0];
  return f ? `${SEVERITY_ICON[f.severity]} ${f.rule}${f.tool ? ` ${f.tool}` : ""}` : "";
};
const scoreOf = (e: BatchEntry) => (e.status === "scanned" && e.result ? e.result.score : -1);
const sorted = (b: BatchResult) => [...b.entries].sort((x, y) => scoreOf(y) - scoreOf(x) || x.name.localeCompare(y.name));
const cell = (s: string) => s.replace(/\|/g, "\\|").replace(/\n/g, " ");

export function renderBatch(b: BatchResult, format: BatchFormat, opts: { color?: boolean } = {}): string {
  if (format === "json") return JSON.stringify(b, null, 2);
  if (format === "markdown") return renderBatchMarkdown(b);
  return renderBatchTerminal(b, opts.color ?? pc.isColorSupported);
}

function renderBatchTerminal(b: BatchResult, color: boolean): string {
  const c = pc.createColors(color);
  const L: string[] = [c.bold("MCP DETECTOR · batch scan"), "━".repeat(44), ""];
  const nameW = Math.min(40, Math.max(6, ...b.entries.map((e) => e.name.length)));
  L.push(c.dim(`${"Server".padEnd(nameW)}  ${"Score".padStart(5)}  ${"C".padStart(2)} ${"H".padStart(2)} ${"M".padStart(2)}  Tools  Status / top finding`));
  for (const e of sorted(b)) {
    const name = (e.name.length > nameW ? e.name.slice(0, nameW - 1) + "…" : e.name).padEnd(nameW);
    if (e.status === "scanned" && e.result) {
      const r = e.result;
      const col = r.score >= 80 ? c.green : r.score >= 60 ? c.yellow : c.red;
      L.push(`${name}  ${col(String(r.score).padStart(5))}  ${String(r.summary.critical).padStart(2)} ${String(r.summary.high).padStart(2)} ${String(r.summary.medium).padStart(2)}  ${String(r.counts.tools).padStart(5)}  ${worst(e)}`);
    } else {
      const label = e.status === "auth_required" ? "needs authentication" : e.status === "failed" ? "failed" : "skipped";
      L.push(`${name}  ${c.dim("    –")}  ${c.dim(" –  –  –")}  ${c.dim("    –")}  ${c.dim(label)}${e.note && e.status === "failed" ? c.dim(`: ${e.note.slice(0, 60)}`) : ""}`);
    }
  }
  const s = b.summary;
  L.push("", `${s.total} server(s): ${s.scanned} scored${s.averageScore !== undefined ? ` (average ${s.averageScore}/100)` : ""}, ${s.authRequired} need authentication, ${s.failed} failed${s.skipped ? `, ${s.skipped} skipped` : ""}`);
  L.push(`Findings: ${s.bySeverity.critical} critical, ${s.bySeverity.high} high, ${s.bySeverity.medium} medium, ${s.bySeverity.low} low`);
  L.push("", c.dim("Scores are engineering signals, not security certifications. See `mcp-detector scan` on a single server for evidence."));
  return L.join("\n");
}

function renderBatchMarkdown(b: BatchResult): string {
  const s = b.summary;
  const L = ["# MCP Detector batch report", "", `Scanned ${s.total} server(s) from \`${b.origin}\` on ${b.createdAt.slice(0, 10)}: ${s.scanned} scored${s.averageScore !== undefined ? `, average **${s.averageScore}/100**` : ""}.`, ""];
  L.push("| Server | Score | Grade | Crit | High | Med | Tools | Status / top finding |", "|---|---|---|---|---|---|---|---|");
  for (const e of sorted(b)) {
    if (e.status === "scanned" && e.result) {
      const r = e.result;
      L.push(`| ${cell(e.name)} | ${r.score} | ${r.grade} | ${r.summary.critical} | ${r.summary.high} | ${r.summary.medium} | ${r.counts.tools} | ${cell(worst(e))} |`);
    } else L.push(`| ${cell(e.name)} | – | – | – | – | – | – | ${e.status.replace("_", " ")}${e.note ? `: ${cell(e.note.slice(0, 80))}` : ""} |`);
  }
  L.push("", "_Scores are engineering signals, not security certifications; findings are heuristic indicators._");
  return L.join("\n");
}
