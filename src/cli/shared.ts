import { mkdirSync, writeFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { Command } from "commander";
import { loadConfig } from "../config/config-loader.js";
import { findBaseline, loadBaseline } from "../core/pinning.js";
import type { ResolvedConfig, ScanResult } from "../core/types.js";
import { parseSeverity } from "../reporting/severity.js";
import type { ReportFormat } from "../reporting/report-generator.js";

export const LAST_SCAN_PATH = ".mcp-detector/last-scan.json";

export interface CommonOptions {
  config?: string;
  url?: string;
  command?: string;
  arg?: string[];
  env?: string[];
  header?: string[];
  transport?: "stdio" | "http" | "sse";
  format?: ReportFormat;
  output?: string;
  failOn?: string;
  active?: boolean;
  timeout?: string;
  latency?: string;
  verbose?: boolean;
  color?: boolean;
  baseline?: string | false;
  rule?: string[];
  disable?: string[];
}

export function addTargetOptions(cmd: Command): Command {
  return cmd
    .option("-c, --config <path>", "path to mcp-detector.yml (auto-discovered by default)")
    .option("--url <url>", "connect to a remote server over HTTP/SSE")
    .option("--command <cmd>", "command that starts a stdio server")
    .option("--arg <value...>", "argument for --command (repeatable)")
    .option("--env <KEY=VALUE...>", "environment variable for the server process")
    .option("--header <Name:Value...>", "HTTP header for --url (e.g. 'Authorization: Bearer $TOKEN')")
    .option("--transport <type>", "force transport: stdio | http | sse")
    .option("--timeout <ms>", "per-request timeout in milliseconds")
    .option("--latency <ms>", "latency threshold in milliseconds")
    .option("--disable <rule...>", "disable rule IDs (e.g. MCP-024)");
}

export function addOutputOptions(cmd: Command): Command {
  return cmd
    .option("-f, --format <format>", "terminal | json | markdown", "terminal")
    .option("-o, --output <file>", "write the report to a file instead of stdout")
    .option("--verbose", "include explanations and remediation for each finding")
    .option("--no-color", "disable colored output");
}

/** Split a command line into argv, honouring single and double quotes. */
export function splitCommand(s: string): string[] {
  const out: string[] = [];
  let cur = "";
  let quote: string | null = null;
  let has = false;
  for (const ch of s) {
    if (quote) {
      if (ch === quote) quote = null;
      else cur += ch;
    } else if (ch === '"' || ch === "'") {
      quote = ch;
      has = true;
    } else if (/\s/.test(ch)) {
      if (cur || has) out.push(cur);
      cur = "";
      has = false;
    } else cur += ch;
  }
  if (cur || has) out.push(cur);
  return out;
}

function parseKv(items: string[] | undefined, sep: string, what: string): Record<string, string> | undefined {
  if (!items?.length) return undefined;
  const out: Record<string, string> = {};
  for (const it of items) {
    const i = it.indexOf(sep);
    if (i <= 0) throw new Error(`Invalid ${what} "${it}" (expected NAME${sep}VALUE).`);
    out[it.slice(0, i).trim()] = it.slice(i + 1).trim();
  }
  return out;
}

/**
 * Merge config file, positional target and CLI flags into one ResolvedConfig.
 * Precedence: CLI flags > positional target > config file.
 */
export function resolveConfig(targetArgs: string[], opts: CommonOptions, cwd = process.cwd()): { config: ResolvedConfig; file?: string } {
  const { config, file } = loadConfig(opts.config, cwd);

  let server = config.server ? { ...config.server } : undefined;
  const flagUrl = opts.url;
  const flagCmd = opts.command;

  if (flagUrl) server = { ...(server ?? {}), url: flagUrl, command: undefined, args: undefined };
  else if (flagCmd) server = { ...(server ?? {}), command: flagCmd, args: opts.arg ?? [], url: undefined };
  else if (targetArgs.length) {
    if (targetArgs.length === 1 && /^https?:\/\//i.test(targetArgs[0])) {
      server = { ...(server ?? {}), url: targetArgs[0], command: undefined, args: undefined };
    } else {
      const argv = targetArgs.length === 1 ? splitCommand(targetArgs[0]) : targetArgs;
      server = { ...(server ?? {}), command: argv[0], args: argv.slice(1), url: undefined };
    }
  }
  if (!server || (!server.url && !server.command)) {
    throw new Error(
      "No MCP server specified.\n  Pass a command:  mcp-detector scan -- npx -y @modelcontextprotocol/server-everything\n  or a URL:        mcp-detector scan https://example.com/mcp\n  or add a `server:` block to mcp-detector.yml.",
    );
  }
  const env = parseKv(opts.env, "=", "--env");
  if (env) server.env = { ...(server.env ?? {}), ...env };
  const headers = parseKv(opts.header, ":", "--header");
  if (headers) server.headers = { ...(server.headers ?? {}), ...headers };
  if (opts.transport) server.transport = opts.transport;
  config.server = server;

  // Baseline (rug-pull detection): --no-baseline > --baseline <file> > config `baseline:` > auto-discovered lockfile.
  if (opts.baseline !== false) {
    const path = typeof opts.baseline === "string" ? resolve(cwd, opts.baseline) : config.baselineFile ?? findBaseline(cwd);
    if (path) {
      config.baseline = loadBaseline(path);
      config.baselineFile = path;
    }
  }
  if (opts.failOn !== undefined) config.severity.fail_on = parseSeverity(opts.failOn);
  if (opts.active) config.active = true;
  if (opts.timeout) config.thresholds.timeout_ms = positiveInt(opts.timeout, "--timeout");
  if (opts.latency) config.thresholds.latency_ms = positiveInt(opts.latency, "--latency");
  for (const id of opts.disable ?? []) config.ruleOverrides[id.toUpperCase()] = { ...(config.ruleOverrides[id.toUpperCase()] ?? {}), enabled: false };
  return { config, file };
}

function positiveInt(v: string, flag: string): number {
  const n = Number(v);
  if (!Number.isFinite(n) || n <= 0) throw new Error(`${flag} must be a positive number (got "${v}").`);
  return Math.round(n);
}

export function writeOutput(text: string, file?: string): void {
  if (file) {
    mkdirSync(dirname(resolve(file)), { recursive: true });
    writeFileSync(file, text + "\n", "utf8");
    process.stderr.write(`Report written to ${file}\n`);
  } else process.stdout.write(text + "\n");
}

export function saveLastScan(result: ScanResult): void {
  try {
    mkdirSync(dirname(LAST_SCAN_PATH), { recursive: true });
    writeFileSync(LAST_SCAN_PATH, JSON.stringify(result, null, 2) + "\n", "utf8");
  } catch {
    /* best effort */
  }
}

export function validateFormat(f: string | undefined): ReportFormat {
  const v = (f ?? "terminal").toLowerCase();
  if (v === "md") return "markdown";
  if (v === "terminal" || v === "json" || v === "markdown") return v;
  throw new Error(`Invalid --format "${f}". Use terminal, json or markdown.`);
}
