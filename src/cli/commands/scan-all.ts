import pc from "picocolors";
import { Command } from "commander";
import { runBatch, saveBatch } from "../../batch/runner.js";
import { discoverClientServers, DEFAULT_REGISTRY, listRegistry, parseServersFile } from "../../batch/sources.js";
import type { ServerSpec } from "../../batch/types.js";
import { loadConfig } from "../../config/config-loader.js";
import { describeTarget } from "../../transport/connect.js";
import { renderBatch, type BatchFormat } from "../../reporting/batch-report.js";
import { exceedsThreshold, parseSeverity } from "../../reporting/severity.js";
import { buildSite } from "../../reporting/site.js";
import { loadExtraRules, writeOutput } from "../shared.js";

interface Opts {
  config?: string;
  clients?: boolean;
  registry?: boolean;
  registryUrl?: string;
  limit?: string;
  search?: string;
  concurrency?: string;
  delay?: string;
  dryRun?: boolean;
  active?: boolean;
  failOn?: string;
  format?: string;
  output?: string;
  site?: string;
  history?: boolean;
  timeout?: string;
  color?: boolean;
  rules?: string[];
  allowPlugins?: boolean;
}

const int = (v: string | undefined, flag: string, dflt: number) => {
  if (v === undefined) return dflt;
  const n = Number(v);
  if (!Number.isInteger(n) || n < 0) throw new Error(`${flag} must be a non-negative integer (got "${v}").`);
  return n;
};

export function scanAllCommand(): Command {
  return new Command("scan-all")
    .description("Scan many servers at once: from a servers file, from your installed MCP clients' configs, or from the official registry")
    .argument("[file]", "servers file (JSON/YAML: an `mcpServers` map, a `servers` list, or a bare list)")
    .option("--clients", "scan every server configured in Claude Desktop, Cursor, VS Code, Windsurf and Claude Code")
    .option("--registry", "scan remote servers from the official MCP registry (passive only; package-based servers are never run)")
    .option("--registry-url <url>", "registry base URL", DEFAULT_REGISTRY)
    .option("--limit <n>", "maximum number of registry servers to scan", "25")
    .option("--search <text>", "filter registry servers by name")
    .option("--concurrency <n>", "scans to run in parallel (max 8)", "2")
    .option("--delay <ms>", "pause between starting scans (default: 500 for the registry, else 0)")
    .option("--dry-run", "list what would be scanned and exit")
    .option("--active", "call read-only tools to time them (own servers only; ignored for the registry)")
    .option("--fail-on <severity>", "exit 1 if any scanned server has a finding at or above this severity")
    .option("-c, --config <path>", "mcp-detector.yml supplying rule settings and thresholds")
    .option("--timeout <ms>", "per-request timeout in milliseconds")
    .option("-f, --format <format>", "terminal | json | markdown", "terminal")
    .option("-o, --output <file>", "write the report to a file")
    .option("--site <dir>", "also build a static scoreboard website in this directory")
    .option("--rules <path...>", "load community rule files or directories")
    .option("--allow-plugins", "also load JavaScript plugins listed in the config (they run code)")
    .option("--no-history", "do not record results in the scan history")
    .option("--no-color", "disable colored output")
    .action(async (file: string | undefined, opts: Opts) => {
      const sources = [file, opts.clients, opts.registry].filter(Boolean).length;
      if (sources !== 1) throw new Error("Choose exactly one source: a servers file, --clients, or --registry.");
      const format = (opts.format ?? "terminal") as BatchFormat;
      if (!["terminal", "json", "markdown"].includes(format)) throw new Error(`Invalid --format "${opts.format}". Use terminal, json or markdown.`);
      const { config } = loadConfig(opts.config);
      if (opts.timeout) config.thresholds.timeout_ms = int(opts.timeout, "--timeout", 10000);
      if (opts.failOn !== undefined) config.severity.fail_on = parseSeverity(opts.failOn);
      if (opts.active) config.active = true;
      await loadExtraRules(config, opts);
      const c = pc.createColors(opts.color !== false && pc.isColorSupported);
      const err = (s: string) => process.stderr.write(s + "\n");

      let specs: ServerSpec[];
      let origin: string;
      let isRegistry = false;
      if (file) {
        specs = parseServersFile(file);
        origin = file;
      } else if (opts.clients) {
        const found = discoverClientServers();
        for (const f of found.files) err(c.dim(`found ${f.servers} server(s) in ${f.client}: ${f.path}`));
        for (const e of found.errors) err(c.yellow(`warning: ${e}`));
        if (!found.specs.length) throw new Error("No MCP client configuration with servers was found on this machine.");
        specs = found.specs;
        origin = "installed MCP clients";
      } else {
        isRegistry = true;
        const listing = await listRegistry({ baseUrl: opts.registryUrl, limit: int(opts.limit, "--limit", 25), search: opts.search });
        err(c.dim(`registry: ${listing.fetched} entries fetched, ${listing.specs.length} remote server(s) selected, ${listing.skipped.length} skipped (package-only or not reachable without setup)`));
        specs = listing.specs;
        origin = opts.registryUrl ?? DEFAULT_REGISTRY;
      }
      if (!specs.length) throw new Error("Nothing to scan.");

      if (opts.dryRun) {
        for (const s of specs) process.stdout.write(`${s.name.padEnd(40)} ${s.source.padEnd(22)} ${describeTarget(s.server)}\n`);
        process.stdout.write(`\n${specs.length} server(s) would be scanned.\n`);
        return;
      }
      if (!isRegistry && !file) err(c.yellow(`Scanning ${specs.length} server(s) from your client configs. Local (stdio) servers will be started, exactly as your MCP clients start them.`));
      if (isRegistry && opts.active) err(c.yellow("--active is ignored for registry scans: third-party tools are never called."));

      const batch = await runBatch(specs, {
        base: config,
        concurrency: int(opts.concurrency, "--concurrency", 2),
        delayMs: opts.delay !== undefined ? int(opts.delay, "--delay", 0) : isRegistry ? 500 : 0,
        forcePassive: isRegistry,
        origin,
        saveToHistory: opts.history !== false,
        onProgress: (done, total, e) =>
          err(c.dim(`[${done}/${total}] ${e.name}: ${e.status === "scanned" ? `${e.result!.score}/100` : e.status.replace("_", " ")}`)),
      });
      const saved = saveBatch(batch);
      writeOutput(renderBatch(batch, format, { color: opts.color !== false && !opts.output && pc.isColorSupported }), opts.output);
      err(c.dim(`batch saved to ${saved}`));
      if (opts.site) {
        const built = buildSite(batch, opts.site);
        err(`${c.green("✓")} scoreboard with ${built.servers} server page(s) written to ${built.dir}`);
      }

      const threshold = config.severity.fail_on;
      const allFindings = batch.entries.flatMap((e) => (e.status === "scanned" ? e.result!.findings : []));
      if (exceedsThreshold(allFindings, threshold)) {
        err(`\nMCP Detector failed: findings at or above "${threshold}" in the batch.`);
        process.exitCode = 1;
      }
    });
}
