import { existsSync, readFileSync } from "node:fs";
import { join, resolve } from "node:path";
import { listTargets } from "../store/history.js";
import { batchDir, summarize } from "./runner.js";
import type { BatchEntry, BatchResult } from "./types.js";

export function readBatch(file: string): BatchResult {
  const p = resolve(file);
  if (!existsSync(p)) throw new Error(`Batch result not found: ${p}`);
  let j: any;
  try {
    j = JSON.parse(readFileSync(p, "utf8"));
  } catch (e) {
    throw new Error(`Could not read ${p}: ${(e as Error).message}`);
  }
  if (j?.tool !== "mcp-detector" || j?.kind !== "batch" || !Array.isArray(j.entries))
    throw new Error(`${p} is not an MCP Detector batch result (create one with \`mcp-detector scan-all\`).`);
  return j as BatchResult;
}

/**
 * Pick the data to show: an explicit file, else the most recent batch scan, else the latest scan of
 * every target in the history (so single `scan` runs also appear on the dashboard).
 */
export function loadBatchOrHistory(file?: string, cwd = process.cwd()): BatchResult {
  if (file) return readBatch(file);
  const latest = join(batchDir(cwd), "latest.json");
  if (existsSync(latest)) return readBatch(latest);
  const targets = listTargets(cwd);
  if (!targets.length)
    throw new Error("No scan data found. Run `mcp-detector scan` or `mcp-detector scan-all` first (results are kept in .mcp-detector/).");
  const entries: BatchEntry[] = targets.map((t) => ({
    name: t.name ?? t.target,
    source: "history",
    target: t.target,
    status: "scanned",
    result: t.latest.result,
  }));
  return summarize(entries, "scan history");
}
