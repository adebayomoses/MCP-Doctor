import { createHash } from "node:crypto";
import { existsSync, readFileSync, writeFileSync } from "node:fs";
import { resolve } from "node:path";
import type { Baseline, BaselineTool, ServerSnapshot, ToolDef } from "./types.js";

export const BASELINE_FILENAME = "mcp-detector.lock.json";

/** Deterministic JSON: object keys sorted, so equal definitions always hash equally. */
function canonical(v: unknown): string {
  if (Array.isArray(v)) return `[${v.map(canonical).join(",")}]`;
  if (v && typeof v === "object")
    return `{${Object.keys(v as object)
      .sort()
      .map((k) => `${JSON.stringify(k)}:${canonical((v as any)[k])}`)
      .join(",")}}`;
  return JSON.stringify(v) ?? "null";
}

export function sha256(s: string): string {
  return createHash("sha256").update(s).digest("hex");
}

/** The parts of a tool definition that a model can see or that affect how it is called. */
function pinnedParts(t: ToolDef) {
  return {
    title: t.title ?? null,
    description: t.description ?? null,
    inputSchema: t.inputSchema ?? null,
    outputSchema: t.outputSchema ?? null,
    annotations: t.annotations ?? null,
  };
}

export function pinTool(t: ToolDef): BaselineTool {
  const parts = pinnedParts(t);
  return {
    hash: sha256(canonical(parts)),
    descriptionHash: sha256(parts.description ?? ""),
    schemaHash: sha256(canonical([parts.inputSchema, parts.outputSchema])),
    annotationsHash: sha256(canonical(parts.annotations)),
    description: parts.description ?? undefined,
  };
}

export function buildBaseline(snapshot: ServerSnapshot, version: string): Baseline {
  const tools: Record<string, BaselineTool> = {};
  for (const t of snapshot.tools) tools[t.name] = pinTool(t);
  return {
    version: 1,
    createdBy: `mcp-detector ${version}`,
    createdAt: new Date().toISOString(),
    server: snapshot.serverInfo,
    instructionsHash: snapshot.instructions ? sha256(snapshot.instructions) : undefined,
    tools,
  };
}

export interface BaselineDiff {
  added: string[];
  removed: string[];
  changed: { tool: string; description: boolean; schema: boolean; annotations: boolean; before?: string; after?: string }[];
  instructionsChanged: boolean;
}

export function diffBaseline(base: Baseline, snapshot: ServerSnapshot): BaselineDiff {
  const current = new Map(snapshot.tools.map((t) => [t.name, t]));
  const diff: BaselineDiff = { added: [], removed: [], changed: [], instructionsChanged: false };
  for (const [name, t] of current) {
    const was = base.tools[name];
    if (!was) {
      diff.added.push(name);
      continue;
    }
    const now = pinTool(t);
    if (now.hash === was.hash) continue;
    diff.changed.push({
      tool: name,
      description: now.descriptionHash !== was.descriptionHash,
      schema: now.schemaHash !== was.schemaHash,
      annotations: now.annotationsHash !== was.annotationsHash,
      before: was.description,
      after: t.description,
    });
  }
  for (const name of Object.keys(base.tools)) if (!current.has(name)) diff.removed.push(name);
  const instr = snapshot.instructions ? sha256(snapshot.instructions) : undefined;
  diff.instructionsChanged = instr !== base.instructionsHash;
  return diff;
}

/** Show where two strings start to differ, with a little context, for evidence. */
export function describeChange(before = "", after = ""): string {
  if (before === after) return "(no text change)";
  let i = 0;
  while (i < before.length && i < after.length && before[i] === after[i]) i++;
  const clip = (s: string) => JSON.stringify((i > 20 ? "…" : "") + s.slice(Math.max(0, i - 20), i + 80) + (s.length > i + 80 ? "…" : ""));
  return `was ${clip(before)} → now ${clip(after)}`;
}

export function loadBaseline(path: string): Baseline {
  let raw: any;
  try {
    raw = JSON.parse(readFileSync(path, "utf8"));
  } catch (e) {
    throw new Error(`Could not read baseline ${path}: ${(e as Error).message}`);
  }
  if (raw?.version !== 1 || typeof raw.tools !== "object" || raw.tools === null)
    throw new Error(`${path} is not a valid MCP Detector baseline (expected version 1). Re-create it with \`mcp-detector pin\`.`);
  return raw as Baseline;
}

export function findBaseline(cwd = process.cwd()): string | undefined {
  const p = resolve(cwd, BASELINE_FILENAME);
  return existsSync(p) ? p : undefined;
}

export function saveBaseline(path: string, baseline: Baseline): void {
  writeFileSync(path, JSON.stringify(baseline, null, 2) + "\n", "utf8");
}
