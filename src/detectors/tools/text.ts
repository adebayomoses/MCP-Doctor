import type { ToolDef } from "../../core/types.js";

export interface TextSurface {
  /** Where the text came from, e.g. `description` or `param "path" description`. */
  where: string;
  text: string;
}

/** Walk a JSON schema and yield every human-visible/model-visible string in it. */
function schemaSurfaces(schema: any, path: string, out: TextSurface[], depth = 0) {
  if (!schema || typeof schema !== "object" || depth > 8) return;
  for (const key of ["description", "title"]) {
    if (typeof schema[key] === "string" && schema[key]) out.push({ where: `${path} ${key}`, text: schema[key] });
  }
  if (typeof schema.default === "string") out.push({ where: `${path} default`, text: schema.default });
  if (Array.isArray(schema.examples))
    for (const e of schema.examples) if (typeof e === "string") out.push({ where: `${path} example`, text: e });
  if (Array.isArray(schema.enum))
    for (const e of schema.enum) if (typeof e === "string") out.push({ where: `${path} enum value`, text: e });
  if (schema.properties && typeof schema.properties === "object") {
    for (const [k, v] of Object.entries(schema.properties)) {
      out.push({ where: `param name "${k}"`, text: k });
      schemaSurfaces(v, `param "${k}"`, out, depth + 1);
    }
  }
  if (schema.items) schemaSurfaces(schema.items, `${path} items`, out, depth + 1);
  for (const k of ["anyOf", "oneOf", "allOf"]) {
    if (Array.isArray(schema[k])) for (const s of schema[k]) schemaSurfaces(s, path, out, depth + 1);
  }
}

/** All text a model could read from a tool definition. */
export function toolTextSurfaces(tool: ToolDef): TextSurface[] {
  const out: TextSurface[] = [];
  if (tool.name) out.push({ where: "name", text: tool.name });
  if (typeof tool.title === "string") out.push({ where: "title", text: tool.title });
  if (typeof tool.description === "string") out.push({ where: "description", text: tool.description });
  schemaSurfaces(tool.inputSchema, "input", out);
  schemaSurfaces(tool.outputSchema, "output", out);
  return out;
}

export function snippet(text: string, index: number, length: number, pad = 30): string {
  const start = Math.max(0, index - pad);
  const end = Math.min(text.length, index + length + pad);
  return (start > 0 ? "…" : "") + text.slice(start, end).replace(/\s+/g, " ") + (end < text.length ? "…" : "");
}

/** Properties of a tool's top-level input schema. */
export function toolParams(tool: ToolDef): Record<string, any> {
  const p = tool.inputSchema?.properties;
  return p && typeof p === "object" ? (p as Record<string, any>) : {};
}

export function paramType(schema: any): string | undefined {
  if (!schema || typeof schema !== "object") return undefined;
  if (Array.isArray(schema.type)) return schema.type.find((t: string) => t !== "null") ?? schema.type[0];
  return schema.type;
}

/** True if a string param has any meaningful constraint. */
export function isConstrained(schema: any): boolean {
  if (!schema || typeof schema !== "object") return false;
  return Boolean(
    schema.enum ||
      schema.const !== undefined ||
      schema.pattern ||
      schema.maxLength !== undefined ||
      schema.format ||
      schema.oneOf ||
      schema.anyOf,
  );
}
