import { z } from "zod";
import type { Connection } from "../transport/connect.js";
import { connect, describeTarget } from "../transport/connect.js";
import type { ResolvedConfig, ServerSnapshot, ToolCallResult, ToolDef } from "./types.js";
import { buildSampleArgs, classifyToolForActiveCall } from "./active.js";

const MAX_PAGES = 50;

/** Connection errors that mean "you need credentials", as opposed to "the server is broken". */
export const AUTH_ERROR =
  /\b(401|403)\b|unauthori[sz]ed|forbidden|not authenticated|authentication (?:is )?required|\b(?:invalid|missing|expired|bad)\b[^.]{0,25}\b(?:token|api[ _-]?key|credentials?|authorization)\b|\b(?:token|api[ _-]?key|credentials?) (?:is |are )?(?:required|missing|invalid)\b|oauth/i;

/**
 * Issue a request and return the raw result. The SDK's typed list helpers throw away the
 * whole response if any single entry is malformed, which would hide exactly the defects
 * (invalid schemas, missing fields) this tool exists to report.
 */
async function rawList(client: any, method: string, key: string, timeout: number, cursor?: string): Promise<{ items: any[]; next?: string }> {
  const res: any = await client.request({ method, params: cursor ? { cursor } : {} }, z.any(), { timeout });
  const items = res?.[key];
  if (!Array.isArray(items)) throw new Error(`${method} result has no "${key}" array`);
  return { items: items.filter((i) => i && typeof i === "object"), next: typeof res.nextCursor === "string" ? res.nextCursor : undefined };
}

const oneLine = (s: string) => s.replace(/\s+/g, " ").trim().slice(0, 300);

async function listAll<T>(fn: (cursor?: string) => Promise<{ items: T[]; next?: string }>): Promise<T[]> {
  const out: T[] = [];
  let cursor: string | undefined;
  for (let i = 0; i < MAX_PAGES; i++) {
    const page = await fn(cursor);
    out.push(...page.items);
    if (!page.next) break;
    cursor = page.next;
  }
  return out;
}

function emptySnapshot(target: string, active: boolean): ServerSnapshot {
  return {
    target,
    connected: false,
    tools: [],
    resources: [],
    prompts: [],
    listErrors: {},
    toolNames: [],
    timings: {},
    toolCalls: [],
    activeMode: active,
    skippedCalls: [],
  };
}

/**
 * Connect to the configured server and gather everything detectors need.
 * Passive by default: only handshake + list/ping calls. Tool calls are made
 * only when `config.active` is on, and only for tools judged safe to call.
 */
export async function collectSnapshot(config: ResolvedConfig): Promise<ServerSnapshot> {
  if (!config.server) throw new Error("No server configured.");
  const snap = emptySnapshot(describeTarget(config.server), config.active);
  let stderr = "";
  let conn: Connection;
  try {
    conn = await connect(config.server, config.thresholds.connect_ms, (c) => {
      if (stderr.length < 8000) stderr += c;
    });
  } catch (e) {
    snap.connectError = (e as Error).message;
    snap.authRequired = AUTH_ERROR.test(snap.connectError);
    snap.stderr = stderr || undefined;
    return snap;
  }

  try {
    const { client } = conn;
    snap.connected = true;
    snap.timings.connectMs = Math.round(conn.connectMs);
    snap.timings.initializeMs = Math.round(conn.connectMs);
    snap.protocolVersion = conn.protocolVersion;
    snap.serverInfo = client.getServerVersion() as any;
    snap.capabilities = (client.getServerCapabilities() as any) ?? {};
    snap.instructions = client.getInstructions();

    // Ping.
    {
      const t = performance.now();
      try {
        await client.ping({ timeout: config.thresholds.timeout_ms });
        snap.ping = { ok: true, ms: Math.round(performance.now() - t) };
      } catch (e) {
        snap.ping = { ok: false, ms: Math.round(performance.now() - t), error: (e as Error).message };
      }
    }

    // An unknown method must be rejected with a JSON-RPC error rather than hanging.
    {
      try {
        await client.request({ method: "mcp-detector/unknown-method" } as any, { parse: (x: unknown) => x } as any, {
          timeout: Math.min(config.thresholds.timeout_ms, 5000),
        });
        snap.unknownMethod = { rejected: false, timedOut: false };
      } catch (e: any) {
        const timedOut = /timed out/i.test(e?.message ?? "") || e?.code === -32001;
        snap.unknownMethod = {
          rejected: !timedOut,
          code: typeof e?.code === "number" ? e.code : undefined,
          timedOut,
        };
      }
    }

    // Discovery.
    const caps = snap.capabilities ?? {};
    const disc = performance.now();
    const guard = async <T>(name: string, supported: boolean, run: () => Promise<T[]>): Promise<T[]> => {
      if (!supported) return [];
      try {
        return await run();
      } catch (e) {
        snap.listErrors[name] = oneLine((e as Error).message);
        return [];
      }
    };
    const opts = { timeout: config.thresholds.timeout_ms };
    snap.tools = (await guard("tools", !!caps.tools, () =>
      listAll<ToolDef>((cursor) => rawList(client, "tools/list", "tools", opts.timeout, cursor)),
    )) as ToolDef[];
    snap.tools = snap.tools.filter((t) => typeof t.name === "string");
    snap.toolNames = snap.tools.map((t) => t.name);
    snap.resources = await guard("resources", !!caps.resources, () =>
      listAll<any>((cursor) => rawList(client, "resources/list", "resources", opts.timeout, cursor)),
    );
    snap.prompts = await guard("prompts", !!caps.prompts, () =>
      listAll<any>((cursor) => rawList(client, "prompts/list", "prompts", opts.timeout, cursor)),
    );
    snap.timings.discoveryMs = Math.round(performance.now() - disc);

    if (config.active) await runActiveCalls(conn, snap, config);
  } catch (e) {
    snap.connectError = snap.connectError ?? (e as Error).message;
  } finally {
    await conn.close();
    snap.stderr = stderr || undefined;
  }
  return snap;
}

async function runActiveCalls(conn: Connection, snap: ServerSnapshot, config: ResolvedConfig) {
  const seen = new Set<string>();
  for (const tool of snap.tools) {
    if (seen.has(tool.name)) continue;
    seen.add(tool.name);
    const decision = classifyToolForActiveCall(tool, config);
    if (!decision.safe) {
      snap.skippedCalls.push({ tool: tool.name, reason: decision.reason });
      continue;
    }
    const args = buildSampleArgs(tool);
    const t = performance.now();
    const result: ToolCallResult = { tool: tool.name, ok: false, timedOut: false, durationMs: 0 };
    try {
      const r: any = await conn.client.callTool({ name: tool.name, arguments: args }, undefined, {
        timeout: config.thresholds.timeout_ms,
      });
      result.ok = !r.isError;
      const text = Array.isArray(r.content)
        ? r.content.filter((c: any) => c.type === "text").map((c: any) => c.text).join("\n")
        : "";
      result.text = text.slice(0, 4000);
      if (r.isError) result.error = text.slice(0, 300) || "Tool returned isError";
    } catch (e: any) {
      result.timedOut = /timed out/i.test(e?.message ?? "") || e?.code === -32001;
      result.error = e?.message ?? String(e);
    }
    result.durationMs = Math.round(performance.now() - t);
    snap.toolCalls.push(result);
  }
}
