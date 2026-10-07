import { resolve } from "node:path";
import pc from "picocolors";
import { Command } from "commander";
import { evaluate } from "../../core/detector.js";
import { BASELINE_FILENAME, buildBaseline, diffBaseline, saveBaseline } from "../../core/pinning.js";
import { collectSnapshot } from "../../core/scanner.js";
import { VERSION } from "../../version.js";
import { addTargetOptions, resolveConfig, type CommonOptions } from "../shared.js";

export function pinCommand(): Command {
  const cmd = new Command("pin")
    .description(
      "Record the server's current tool definitions as the trusted baseline (mcp-detector.lock.json). Later scans report any change as a possible rug pull (MCP-032).",
    )
    .argument("[server...]", "server command (after `--`) or an http(s) URL")
    .option("-o, --output <file>", "baseline file to write", BASELINE_FILENAME)
    .option("--no-color", "disable colored output");
  addTargetOptions(cmd);
  cmd.action(async (server: string[], opts: CommonOptions) => {
    const c = pc.createColors(opts.color !== false && pc.isColorSupported);
    const { config } = resolveConfig(server, { ...opts, baseline: opts.baseline });
    const previous = config.baseline;
    config.baseline = undefined; // judge the server on its own merits, not against the old pin

    const snapshot = await collectSnapshot(config);
    if (!snapshot.connected) throw new Error(`Could not connect, nothing was pinned: ${snapshot.connectError}`);
    const { result } = evaluate(snapshot, config);

    if (previous) {
      const d = diffBaseline(previous, snapshot);
      const lines = [
        ...d.changed.map((x) => `  ~ changed  ${x.tool} (${[x.description && "description", x.schema && "schema", x.annotations && "annotations"].filter(Boolean).join(", ")})`),
        ...d.added.map((n) => `  + added    ${n}`),
        ...d.removed.map((n) => `  - removed  ${n}`),
        ...(d.instructionsChanged ? ["  ~ changed  server instructions"] : []),
      ];
      process.stdout.write(lines.length ? `Changes since the previous pin:\n${lines.join("\n")}\n\n` : "No changes since the previous pin.\n\n");
    }

    const file = resolve(opts.output ?? BASELINE_FILENAME);
    saveBaseline(file, buildBaseline(snapshot, VERSION));
    process.stdout.write(`${c.green("✓")} Pinned ${snapshot.tools.length} tool(s) to ${file}\n`);

    const serious = result.findings.filter((f) => f.severity === "critical" || f.severity === "high").length;
    if (serious)
      process.stdout.write(
        c.yellow(`⚠ This server has ${serious} critical/high finding(s). Pinning records its current state as trusted, so review \`mcp-detector scan\` first.\n`),
      );
    process.stdout.write(c.dim("Commit the file so changes to tool definitions show up in review.\n"));
  });
  return cmd;
}
