import { defaultConfig } from "../../src/config/default-config.js";
import type { ResolvedConfig, ServerSnapshot, ToolDef } from "../../src/core/types.js";

export function makeSnapshot(over: Partial<ServerSnapshot> & { tools?: ToolDef[] } = {}): ServerSnapshot {
  const tools = over.tools ?? [];
  return {
    target: "test",
    connected: true,
    serverInfo: { name: "test", version: "1.0.0" },
    protocolVersion: "2025-11-25",
    capabilities: { tools: {} },
    tools,
    resources: [],
    prompts: [],
    listErrors: {},
    toolNames: tools.map((t) => t.name),
    timings: { connectMs: 100, initializeMs: 100, discoveryMs: 5 },
    toolCalls: [],
    activeMode: false,
    skippedCalls: [],
    ping: { ok: true, ms: 1 },
    unknownMethod: { rejected: true, code: -32601, timedOut: false },
    ...over,
  };
}

export function tool(name: string, over: Partial<ToolDef> = {}): ToolDef {
  return {
    name,
    description: `Does the ${name} thing and returns a result.`,
    inputSchema: { type: "object", properties: {}, additionalProperties: false },
    ...over,
  };
}

export function cfg(over: Partial<ResolvedConfig> = {}): ResolvedConfig {
  return { ...defaultConfig(), ...over };
}
