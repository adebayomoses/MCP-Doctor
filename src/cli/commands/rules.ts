import pc from "picocolors";
import { Command } from "commander";
import { allRules, getRule } from "../../rules/index.js";
import { SEVERITY_ICON } from "../../reporting/severity.js";

export function rulesCommand(): Command {
  return new Command("rules")
    .description("List all detection rules, or explain one (e.g. `mcp-detector rules MCP-005`)")
    .argument("[id]", "rule ID to explain")
    .option("--json", "machine-readable output")
    .action((id: string | undefined, opts: { json?: boolean }) => {
      if (id) {
        const r = getRule(id);
        if (!r) throw new Error(`Unknown rule "${id}". Run \`mcp-detector rules\` to list all rules.`);
        if (opts.json) return void process.stdout.write(JSON.stringify(r, (k, v) => (k === "check" ? undefined : v), 2) + "\n");
        process.stdout.write(
          [
            pc.bold(`${r.id} ${r.name}`),
            "",
            `Severity:  ${SEVERITY_ICON[r.severity]} ${r.severity}`,
            `Category:  ${r.category}`,
            r.group ? `Config:    rules.${r.group}` : "",
            "",
            pc.bold("What it detects"),
            r.description,
            "",
            pc.bold("Why it matters"),
            r.why,
            "",
            pc.bold("How to fix"),
            r.recommendation,
            "",
          ].join("\n"),
        );
        return;
      }
      const rules = allRules();
      if (opts.json)
        return void process.stdout.write(
          JSON.stringify(rules.map((r) => ({ id: r.id, name: r.name, category: r.category, severity: r.severity, group: r.group })), null, 2) + "\n",
        );
      for (const r of rules)
        process.stdout.write(`${r.id}  ${SEVERITY_ICON[r.severity]} ${r.severity.padEnd(8)} ${r.category.padEnd(12)} ${r.name}\n`);
    });
}
