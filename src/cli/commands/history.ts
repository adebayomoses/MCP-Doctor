import pc from "picocolors";
import { Command } from "commander";
import { diffResults, listTargets, readTargetHistory, trend } from "../../store/history.js";
import { SEVERITY_ICON } from "../../reporting/severity.js";

const arrow = { up: "↑", down: "↓", flat: "→" } as const;

export function historyCommand(): Command {
  return new Command("history")
    .description("Show past scans: every target with its score trend, or one target's runs and what changed since the previous scan")
    .argument("[target]", "name, key or part of the command/URL of a scanned server")
    .option("--json", "machine-readable output")
    .option("--no-color", "disable colored output")
    .action((query: string | undefined, opts: { json?: boolean; color?: boolean }) => {
      const c = pc.createColors(opts.color !== false && pc.isColorSupported);
      const targets = listTargets();
      if (!targets.length) {
        process.stdout.write("No scan history yet. Run `mcp-detector scan` first (results are kept in .mcp-detector/history).\n");
        return;
      }
      if (!query) {
        if (opts.json) return void process.stdout.write(JSON.stringify(targets.map((t) => ({ key: t.key, name: t.name, target: t.target, runs: t.runs, score: t.latest.result.score, at: t.latest.at })), null, 2) + "\n");
        for (const t of targets) {
          const scores = readTargetHistory(t.target).map((h) => h.result.score);
          process.stdout.write(`${t.key}  ${String(t.latest.result.score).padStart(3)}/100 ${arrow[trend(scores)]}  ${String(t.runs).padStart(3)} run(s)  ${(t.name ?? "").padEnd(24)} ${c.dim(t.target.slice(0, 70))}\n`);
        }
        process.stdout.write(c.dim("\nShow one: mcp-detector history <key or name>\n"));
        return;
      }
      const q = query.toLowerCase();
      const matches = targets.filter((t) => t.key.startsWith(q) || (t.name ?? "").toLowerCase().includes(q) || t.target.toLowerCase().includes(q));
      if (!matches.length) throw new Error(`No scanned server matches "${query}". Run \`mcp-detector history\` to list them.`);
      if (matches.length > 1) throw new Error(`"${query}" matches ${matches.length} servers: ${matches.map((m) => m.key).join(", ")}. Use a key.`);
      const t = matches[0];
      const runs = readTargetHistory(t.target);
      const diff = runs.length > 1 ? diffResults(runs[runs.length - 2].result, runs[runs.length - 1].result) : undefined;
      if (opts.json) return void process.stdout.write(JSON.stringify({ target: t.target, runs: runs.map((r) => ({ at: r.at, score: r.result.score, findings: r.result.findings.length, summary: r.result.summary })), diff }, null, 2) + "\n");

      process.stdout.write(`${c.bold(t.name ?? t.target)}  ${c.dim(t.target)}\n\n`);
      for (const r of runs.slice(-15)) {
        const s = r.result.summary;
        process.stdout.write(`${r.at.replace("T", " ").slice(0, 19)}  ${String(r.result.score).padStart(3)}/100  ${String(r.result.findings.length).padStart(3)} finding(s)  (${s.critical} critical, ${s.high} high, ${s.medium} medium)\n`);
      }
      if (diff) {
        const sign = diff.scoreDelta > 0 ? "+" : "";
        process.stdout.write(`\nSince the previous scan: score ${sign}${diff.scoreDelta}\n`);
        for (const f of diff.newFindings) process.stdout.write(`  ${c.red("+")} ${SEVERITY_ICON[f.severity]} ${f.rule} ${f.name}${f.tool ? ` [${f.tool}]` : ""}\n`);
        for (const f of diff.resolvedFindings) process.stdout.write(`  ${c.green("−")} ${SEVERITY_ICON[f.severity]} ${f.rule} ${f.name}${f.tool ? ` [${f.tool}]` : ""}\n`);
        for (const x of diff.changedSeverity) process.stdout.write(`  ~ ${x.after.rule}${x.after.tool ? ` [${x.after.tool}]` : ""}: ${x.before.severity} → ${x.after.severity}\n`);
        if (!diff.newFindings.length && !diff.resolvedFindings.length && !diff.changedSeverity.length) process.stdout.write("  no change in findings\n");
      }
    });
}
