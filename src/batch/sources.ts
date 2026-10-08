import { existsSync, readFileSync } from "node:fs";
import { homedir, platform } from "node:os";
import { join, resolve } from "node:path";
import { parse as parseYaml } from "yaml";
import type { ResolvedConfig } from "../core/types.js";
import type { ServerSpec } from "./types.js";

type Server = NonNullable<ResolvedConfig["server"]>;

/** Expand ${env:NAME} and ${NAME} from the environment; unknown variables are left as written. */
function expand(v: string, env: NodeJS.ProcessEnv = process.env): string {
  return v.replace(/\$\{(?:env:)?([A-Za-z_][A-Za-z0-9_]*)\}/g, (m, name) => env[name] ?? m);
}
const expandMap = (m?: Record<string, unknown>) =>
  m ? Object.fromEntries(Object.entries(m).map(([k, v]) => [k, expand(String(v))])) : undefined;

/** Convert one entry of any common MCP client config shape into a ServerSpec. */
export function toSpec(name: string, e: any, source: string): ServerSpec | undefined {
  if (!e || typeof e !== "object") return undefined;
  if (e.disabled === true) return undefined;
  const url = e.url ?? e.serverUrl;
  const server: Server = {};
  if (typeof url === "string") {
    server.url = expand(url);
    server.headers = expandMap(e.headers);
    const t = String(e.type ?? e.transport ?? "").toLowerCase();
    if (t === "sse") server.transport = "sse";
    else if (t === "http" || t === "streamable-http" || t === "streamablehttp") server.transport = "http";
  } else if (typeof e.command === "string") {
    server.command = expand(e.command);
    server.args = Array.isArray(e.args) ? e.args.map((a: unknown) => expand(String(a))) : [];
    server.env = expandMap(e.env);
    if (typeof e.cwd === "string") server.cwd = e.cwd;
  } else return undefined;
  return { name, source, server };
}

/** Parse a servers file: `{ mcpServers: {...} }`, `{ servers: {...} | [...] }`, or a bare list. */
export function parseServersFile(path: string): ServerSpec[] {
  const file = resolve(path);
  if (!existsSync(file)) throw new Error(`Servers file not found: ${file}`);
  let raw: any;
  try {
    const text = readFileSync(file, "utf8");
    raw = /\.ya?ml$/i.test(file) ? parseYaml(text) : JSON.parse(text);
  } catch (e) {
    throw new Error(`Could not parse ${file}: ${(e as Error).message}`);
  }
  return specsFromObject(raw, file, file);
}

export function specsFromObject(raw: any, source: string, label = source): ServerSpec[] {
  const out: ServerSpec[] = [];
  const container = raw?.mcpServers ?? raw?.servers ?? raw?.context_servers ?? raw;
  if (Array.isArray(container)) {
    container.forEach((e, i) => {
      const s = toSpec(String(e?.name ?? `server-${i + 1}`), e, label);
      if (s) out.push(s);
    });
  } else if (container && typeof container === "object") {
    for (const [name, e] of Object.entries(container)) {
      const s = toSpec(name, e, label);
      if (s) out.push(s);
    }
  }
  if (!out.length) throw new Error(`No servers found in ${source}. Expected an "mcpServers" map, a "servers" list, or a list of servers.`);
  return out;
}

export interface ClientConfigLocation {
  client: string;
  path: string;
  /** Property that holds the server map when it is not at the top level. */
  pick?: (json: any) => any;
}

export function clientConfigLocations(home = homedir(), os = platform(), env: NodeJS.ProcessEnv = process.env): ClientConfigLocation[] {
  const appData = env.APPDATA ?? join(home, "AppData", "Roaming");
  const mac = join(home, "Library", "Application Support");
  const xdg = env.XDG_CONFIG_HOME ?? join(home, ".config");
  const base = os === "win32" ? appData : os === "darwin" ? mac : xdg;
  return [
    { client: "Claude Desktop", path: join(base, "Claude", "claude_desktop_config.json") },
    { client: "Cursor", path: join(home, ".cursor", "mcp.json") },
    { client: "VS Code", path: join(base, "Code", "User", "mcp.json") },
    { client: "Windsurf", path: join(home, ".codeium", "windsurf", "mcp_config.json") },
    { client: "Claude Code", path: join(home, ".claude.json"), pick: (j) => ({ mcpServers: j?.mcpServers }) },
    { client: "Claude Code (project)", path: resolve(".mcp.json") },
    { client: "Cursor (project)", path: resolve(".cursor", "mcp.json") },
    { client: "VS Code (project)", path: resolve(".vscode", "mcp.json") },
  ];
}

export interface DiscoveredClients {
  specs: ServerSpec[];
  /** Config files that were found, for the user to see what was read. */
  files: { client: string; path: string; servers: number }[];
  errors: string[];
}

export function discoverClientServers(locations = clientConfigLocations()): DiscoveredClients {
  const res: DiscoveredClients = { specs: [], files: [], errors: [] };
  const seen = new Set<string>();
  for (const loc of locations) {
    if (!existsSync(loc.path)) continue;
    try {
      let json = JSON.parse(readFileSync(loc.path, "utf8"));
      if (loc.pick) json = loc.pick(json);
      const specs = specsFromObject(json, loc.path, loc.client);
      let n = 0;
      for (const s of specs) {
        const key = JSON.stringify([s.server.command, s.server.args, s.server.url]);
        if (seen.has(key)) continue; // same server configured in several clients: scan once
        seen.add(key);
        res.specs.push(s);
        n++;
      }
      res.files.push({ client: loc.client, path: loc.path, servers: n });
    } catch (e) {
      if (!/No servers found/.test((e as Error).message)) res.errors.push(`${loc.path}: ${(e as Error).message}`);
    }
  }
  return res;
}

// ---------------------------------------------------------------------------------------------
// Registry
// ---------------------------------------------------------------------------------------------

export const DEFAULT_REGISTRY = "https://registry.modelcontextprotocol.io";

interface RegistryEntry {
  server: {
    name: string;
    description?: string;
    version?: string;
    websiteUrl?: string;
    remotes?: { type: string; url: string; headers?: { name: string; isRequired?: boolean }[] }[];
    packages?: unknown[];
  };
  _meta?: Record<string, any>;
}

export interface RegistryListing {
  specs: ServerSpec[];
  /** Entries we deliberately did not turn into scans, with reasons (so nothing is silently dropped). */
  skipped: { name: string; reason: string }[];
  fetched: number;
}

const semverish = (v = "") => v.split(/[.+-]/).map((p) => (/^\d+$/.test(p) ? Number(p) : 0));
function newer(a: RegistryEntry, b: RegistryEntry): boolean {
  const ua = a._meta?.["io.modelcontextprotocol.registry/official"]?.updatedAt ?? "";
  const ub = b._meta?.["io.modelcontextprotocol.registry/official"]?.updatedAt ?? "";
  if (ua !== ub) return ua > ub;
  const va = semverish(a.server.version);
  const vb = semverish(b.server.version);
  for (let i = 0; i < Math.max(va.length, vb.length); i++) if ((va[i] ?? 0) !== (vb[i] ?? 0)) return (va[i] ?? 0) > (vb[i] ?? 0);
  return false;
}

/**
 * List servers from the official MCP registry that can be scanned safely: remote (HTTP/SSE) servers only.
 * Package-based servers (npm/pypi/docker) would require running third-party code locally, so they are
 * reported as skipped rather than executed.
 */
export async function listRegistry(
  opts: { baseUrl?: string; limit?: number; search?: string; fetchImpl?: typeof fetch } = {},
): Promise<RegistryListing> {
  const base = (opts.baseUrl ?? DEFAULT_REGISTRY).replace(/\/$/, "");
  const f = opts.fetchImpl ?? fetch;
  const limit = opts.limit ?? 50;
  const latest = new Map<string, RegistryEntry>();
  let cursor: string | undefined;
  let fetched = 0;
  for (let page = 0; page < 40 && latest.size < limit * 3; page++) {
    const u = new URL(`${base}/v0/servers`);
    u.searchParams.set("limit", "100");
    if (opts.search) u.searchParams.set("search", opts.search);
    if (cursor) u.searchParams.set("cursor", cursor);
    const res = await f(u, { headers: { accept: "application/json", "user-agent": "mcp-detector" }, signal: AbortSignal.timeout(20_000) });
    if (!res.ok) throw new Error(`Registry request failed: ${res.status} ${res.statusText} (${u.origin})`);
    const body: any = await res.json();
    for (const e of (body.servers ?? []) as RegistryEntry[]) {
      fetched++;
      if (!e?.server?.name) continue;
      const cur = latest.get(e.server.name);
      if (!cur || newer(e, cur)) latest.set(e.server.name, e);
    }
    cursor = body.metadata?.nextCursor;
    if (!cursor) break;
  }

  const specs: ServerSpec[] = [];
  const skipped: RegistryListing["skipped"] = [];
  for (const e of latest.values()) {
    const s = e.server;
    const status = e._meta?.["io.modelcontextprotocol.registry/official"]?.status;
    if (status && status !== "active") {
      skipped.push({ name: s.name, reason: `registry status is ${status}` });
      continue;
    }
    const remote = (s.remotes ?? []).find((r) => (r.type === "streamable-http" || r.type === "sse") && !/[{}]/.test(r.url));
    if (!remote) {
      skipped.push({
        name: s.name,
        reason: s.packages?.length ? "package-only server (scanning would run third-party code locally)" : (s.remotes?.length ? "remote URL needs template variables" : "no remote endpoint"),
      });
      continue;
    }
    if (specs.length >= limit) continue;
    specs.push({
      name: s.name,
      source: "registry",
      server: { url: remote.url, transport: remote.type === "sse" ? "sse" : "http" },
      meta: { description: s.description, version: s.version, homepage: s.websiteUrl },
    });
  }
  return { specs, skipped, fetched };
}
