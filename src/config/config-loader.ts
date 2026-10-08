import { existsSync, readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { parse } from "yaml";
import { defaultConfig } from "./default-config.js";
import { SEVERITY_ORDER, type ResolvedConfig, type Severity } from "../core/types.js";

export const CONFIG_FILENAMES = ["mcp-detector.yml", "mcp-detector.yaml", ".mcp-detector.yml"];

export function findConfigFile(cwd = process.cwd()): string | undefined {
  for (const f of CONFIG_FILENAMES) {
    const p = resolve(cwd, f);
    if (existsSync(p)) return p;
  }
  return undefined;
}

function asSeverity(v: unknown, where: string): Severity {
  if (typeof v === "string" && (SEVERITY_ORDER as string[]).includes(v)) return v as Severity;
  throw new Error(`Invalid severity "${String(v)}" in ${where}. Use one of: ${SEVERITY_ORDER.join(", ")}.`);
}

/** Load config from an explicit path, or auto-discover mcp-detector.yml. */
export function loadConfig(path?: string, cwd = process.cwd()): { config: ResolvedConfig; file?: string } {
  const cfg = defaultConfig();
  const file = path ? resolve(cwd, path) : findConfigFile(cwd);
  if (!file) return { config: cfg };
  if (!existsSync(file)) throw new Error(`Config file not found: ${file}`);

  let raw: any;
  try {
    raw = parse(readFileSync(file, "utf8")) ?? {};
  } catch (e) {
    throw new Error(`Could not parse ${file}: ${(e as Error).message}`);
  }
  if (typeof raw !== "object" || Array.isArray(raw)) throw new Error(`${file} must contain a YAML mapping.`);

  if (raw.server) {
    const s = raw.server;
    cfg.server = {
      command: s.command,
      args: Array.isArray(s.args) ? s.args.map(String) : undefined,
      env: s.env,
      cwd: s.cwd,
      url: s.url,
      headers: s.headers,
      transport: s.transport,
    };
  }
  if (raw.severity?.fail_on !== undefined) {
    cfg.severity.fail_on = raw.severity.fail_on === "none" ? "none" : asSeverity(raw.severity.fail_on, "severity.fail_on");
  }
  if (raw.rules && typeof raw.rules === "object") {
    for (const [k, v] of Object.entries(raw.rules)) {
      if (/^[A-Za-z][A-Za-z0-9]*-\d+$/.test(k)) {
        const id = k.toUpperCase();
        if (typeof v === "boolean") cfg.ruleOverrides[id] = { enabled: v };
        else if (typeof v === "string") cfg.ruleOverrides[id] = v === "off" ? { enabled: false } : { severity: asSeverity(v, `rules.${k}`) };
        else if (v && typeof v === "object") {
          const o: any = v;
          cfg.ruleOverrides[id] = {
            enabled: o.enabled,
            severity: o.severity ? asSeverity(o.severity, `rules.${k}.severity`) : undefined,
          };
        }
      } else {
        cfg.groups[k] = Boolean(v);
      }
    }
  }
  if (raw.thresholds) {
    const t = raw.thresholds;
    if (t.latency_ms !== undefined) cfg.thresholds.latency_ms = Number(t.latency_ms);
    if (t.timeout_ms !== undefined) cfg.thresholds.timeout_ms = Number(t.timeout_ms);
    if (t.connect_ms !== undefined) cfg.thresholds.connect_ms = Number(t.connect_ms);
    if (t.max_timeout_rate !== undefined) cfg.thresholds.max_timeout_rate = Number(t.max_timeout_rate);
  }
  if (raw.active) {
    if (typeof raw.active === "boolean") cfg.active = raw.active;
    else {
      cfg.active = raw.active.enabled !== false;
      cfg.activeAllow = raw.active.allow ?? [];
      cfg.activeDeny = raw.active.deny ?? [];
    }
  }
  const asList = (v: unknown) => (Array.isArray(v) ? v : v === undefined ? [] : [v]).map((p) => resolve(dirname(file), String(p)));
  cfg.communityRules = asList(raw.community_rules);
  cfg.plugins = asList(raw.plugins);
  if (typeof raw.baseline === "string") cfg.baselineFile = resolve(dirname(file), raw.baseline);
  if (raw.ignore) {
    cfg.ignore.rules = (raw.ignore.rules ?? []).map((r: string) => String(r).toUpperCase());
    cfg.ignore.tools = raw.ignore.tools ?? [];
  }
  return { config: cfg, file };
}
