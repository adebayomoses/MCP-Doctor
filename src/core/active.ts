import type { ResolvedConfig, ToolDef } from "./types.js";

const DESTRUCTIVE_NAME =
  /(delete|remove|drop|destroy|wipe|purge|erase|kill|truncate|write|create|update|insert|exec|run|shell|command|send|post|publish|deploy|commit|push|pay|transfer|charge|upload|install|set_|put|patch|reset|format|move|rename)/i;
const READISH_NAME =
  /^(get|list|read|search|find|fetch|query|show|describe|status|info|ping|echo|version|health|count|lookup|view|check)/i;

export function classifyToolForActiveCall(
  tool: ToolDef,
  config: ResolvedConfig,
): { safe: true } | { safe: false; reason: string } {
  if (config.activeDeny.includes(tool.name)) return { safe: false, reason: "listed in active.deny" };
  const a = tool.annotations ?? {};
  if (a.destructiveHint === true) return { safe: false, reason: "annotated destructiveHint=true" };
  if (config.activeAllow.includes(tool.name)) return { safe: true };
  if (a.readOnlyHint === true) return { safe: true };
  if (a.readOnlyHint === false) return { safe: false, reason: "annotated readOnlyHint=false" };
  if (DESTRUCTIVE_NAME.test(tool.name))
    return { safe: false, reason: "name suggests a side effect (add to active.allow to override)" };
  if (READISH_NAME.test(tool.name)) return { safe: true };
  return {
    safe: false,
    reason: "not annotated read-only and name not recognised as read-only (add to active.allow to override)",
  };
}

/** Generate minimal arguments satisfying a tool's required properties. */
export function buildSampleArgs(tool: ToolDef): Record<string, unknown> {
  const schema = tool.inputSchema ?? {};
  const props: Record<string, any> = schema.properties ?? {};
  const required: string[] = Array.isArray(schema.required) ? schema.required : [];
  const args: Record<string, unknown> = {};
  for (const key of required) args[key] = sample(props[key] ?? {});
  return args;
}

function sample(s: any): unknown {
  if (s.default !== undefined) return s.default;
  if (Array.isArray(s.enum) && s.enum.length) return s.enum[0];
  if (s.const !== undefined) return s.const;
  const type = Array.isArray(s.type) ? s.type[0] : s.type;
  switch (type) {
    case "string":
      return s.format === "uri" ? "https://example.com" : "test";
    case "integer":
    case "number":
      return s.minimum ?? 1;
    case "boolean":
      return false;
    case "array":
      return [];
    case "object":
      return {};
    default:
      return "test";
  }
}
