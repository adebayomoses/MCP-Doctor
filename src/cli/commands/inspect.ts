import pc from "picocolors";
import { Command } from "commander";
import { evaluate } from "../../core/detector.js";
import { collectSnapshot } from "../../core/scanner.js";
import { classifyTool } from "../../detectors/tools/capabilities.js";
import { toolParams, paramType } from "../../detectors/tools/text.js";
import { SEVERITY_ICON } from "../../reporting/severity.js";
import { SEVERITY_ORDER, type Finding, type Severity } from "../../core/types.js";
import { addTargetOptions, loadExtraRules, resolveConfig, validateFormat, writeOutput, type CommonOptions } from "../shared.js";

function toolRisk(findings: Finding[]): Severity | "none" {
  let worst = -1;
  for (const f of findings) worst = Math.max(worst, SEVERITY_ORDER.indexOf(f.severity));
  return worst < 0 ? "none" : SEVERITY_ORDER[worst];
}

export function inspectCommand(): Command {
  const cmd = new Command("inspect")
    .description("Show every tool, resource and prompt a server exposes, with per-tool risk")
    .argument("[server...]", "server command (after `--`) or an http(s) URL")
    .option("-f, --format <format>", "terminal | json", "terminal")
    .option("-o, --output <file>", "write to a file")
    .option("--no-color", "disable colored output");
  addTargetOptions(cmd);
  cmd.action(async (server: string[], opts: CommonOptions) => {
    const format = validateFormat(opts.format);
    const { config } = resolveConfig(server, opts);
    await loadExtraRules(config, opts);
    const snapshot = await collectSnapshot(config);
    const { result } = evaluate(snapshot, config);
    const c = pc.createColors(opts.color !== false && !opts.output && pc.isColorSupported);

    const tools = snapshot.tools.map((t) => {
      const findings = result.findings.filter((f) => f.tool === t.name);
      return {
        name: t.name,
        description: t.description ?? null,
        risk: toolRisk(findings),
        capabilities: classifyTool(t).map((x) => x.capability),
        annotations: t.annotations ?? null,
        parameters: Object.entries<any>(toolParams(t)).map(([name, p]) => ({
          name,
          type: paramType(p) ?? "unspecified",
          required: Array.isArray(t.inputSchema?.required) && t.inputSchema!.required.includes(name),
          description: p?.description ?? null,
        })),
        findings: findings.map((f) => ({ rule: f.rule, severity: f.severity, message: f.message })),
      };
    });

    if (format === "json") {
      writeOutput(
        JSON.stringify(
          { target: snapshot.target, connected: snapshot.connected, server: snapshot.serverInfo, protocolVersion: snapshot.protocolVersion, capabilities: snapshot.capabilities, instructions: snapshot.instructions ?? null, tools, resources: snapshot.resources, prompts: snapshot.prompts },
          null,
          2,
        ),
        opts.output,
      );
      return;
    }

    const L: string[] = [];
    if (!snapshot.connected) {
      L.push(c.red(`Could not connect: ${snapshot.connectError}`));
      writeOutput(L.join("\n"), opts.output);
      process.exitCode = 1;
      return;
    }
    L.push(c.bold(`${snapshot.serverInfo?.name ?? snapshot.target} ${snapshot.serverInfo?.version ?? ""}`.trim()));
    L.push(c.dim(`protocol ${snapshot.protocolVersion ?? "?"} · capabilities: ${Object.keys(snapshot.capabilities ?? {}).join(", ") || "none"}`));
    if (snapshot.instructions) L.push("", c.dim(`instructions: ${snapshot.instructions.slice(0, 300)}`));
    L.push("", c.bold(`Tools (${tools.length})`));
    for (const t of tools) {
      const icon = t.risk === "none" ? "✓" : SEVERITY_ICON[t.risk];
      L.push("", `${icon} ${c.bold(t.name)}${t.risk !== "none" ? c.dim(`  risk: ${t.risk.toUpperCase()}`) : ""}`);
      if (t.description) L.push(`   ${t.description.replace(/\s+/g, " ").slice(0, 160)}`);
      if (t.capabilities.length) L.push(c.dim(`   capabilities: ${t.capabilities.join(", ")}`));
      if (t.parameters.length)
        L.push(c.dim(`   params: ${t.parameters.map((p) => `${p.name}${p.required ? "*" : ""}:${p.type}`).join(", ")}`));
      for (const f of t.findings) L.push(`   ${SEVERITY_ICON[f.severity]} ${f.rule} ${f.message}`);
    }
    if (snapshot.resources.length) {
      L.push("", c.bold(`Resources (${snapshot.resources.length})`));
      for (const r of snapshot.resources.slice(0, 50)) L.push(`  • ${r.uri}${r.name ? ` — ${r.name}` : ""}`);
    }
    if (snapshot.prompts.length) {
      L.push("", c.bold(`Prompts (${snapshot.prompts.length})`));
      for (const p of snapshot.prompts.slice(0, 50)) L.push(`  • ${p.name}${p.description ? ` — ${p.description.slice(0, 80)}` : ""}`);
    }
    L.push("", c.dim(`Health score ${result.score}/100 — run \`mcp-detector scan\` for the full report.`));
    writeOutput(L.join("\n"), opts.output);
  });
  return cmd;
}
