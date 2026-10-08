import { mkdirSync, writeFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { evaluate } from "../core/detector.js";
import { collectSnapshot } from "../core/scanner.js";
import type { ResolvedConfig } from "../core/types.js";
import { describeTarget } from "../transport/connect.js";
import { saveHistory, DATA_DIR } from "../store/history.js";
import { VERSION } from "../version.js";
import type { BatchEntry, BatchResult, ServerSpec } from "./types.js";

export interface RunOptions {
  /** Config providing rule settings and thresholds; its `server` is replaced per entry. */
  base: ResolvedConfig;
  concurrency?: number;
  /** Pause between starting scans, to be polite to remote servers. */
  delayMs?: number;
  /** Never call tools, whatever the config says (used for registry scans of third-party servers). */
  forcePassive?: boolean;
  origin: string;
  onProgress?: (done: number, total: number, entry: BatchEntry) => void;
  /** Persist each result to the per-target history. */
  saveToHistory?: boolean;
  cwd?: string;
}

const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

export async function scanOne(spec: ServerSpec, o: RunOptions): Promise<BatchEntry> {
  const config: ResolvedConfig = {
    ...o.base,
    server: spec.server,
    active: o.forcePassive ? false : o.base.active,
    // A baseline belongs to one server; it must not be applied to every entry of a batch.
    baseline: undefined,
  };
  const target = describeTarget(spec.server);
  const entry: BatchEntry = { name: spec.name, source: spec.source, target, status: "failed", meta: spec.meta };
  try {
    const snapshot = await collectSnapshot(config);
    const { result } = evaluate(snapshot, config);
    entry.result = result;
    if (!snapshot.connected && snapshot.authRequired) {
      entry.status = "auth_required";
      entry.note = "The server requires authentication; it was not scored. Scan it individually with --header to include it.";
    } else if (!snapshot.connected) {
      entry.status = "failed";
      entry.note = snapshot.connectError;
    } else entry.status = "scanned";
    if (o.saveToHistory && entry.status === "scanned") saveHistory(result, o.cwd);
  } catch (e) {
    entry.status = "failed";
    entry.note = (e as Error).message;
  }
  return entry;
}

export async function runBatch(specs: ServerSpec[], o: RunOptions): Promise<BatchResult> {
  const entries: BatchEntry[] = new Array(specs.length);
  const concurrency = Math.max(1, Math.min(o.concurrency ?? 2, 8));
  let next = 0;
  let done = 0;
  async function worker() {
    for (;;) {
      const i = next++;
      if (i >= specs.length) return;
      if (o.delayMs && i > 0) await sleep(o.delayMs);
      entries[i] = await scanOne(specs[i], o);
      o.onProgress?.(++done, specs.length, entries[i]);
    }
  }
  await Promise.all(Array.from({ length: Math.min(concurrency, specs.length) }, worker));
  return summarize(entries, o.origin);
}

export function summarize(entries: BatchEntry[], origin: string): BatchResult {
  const bySeverity = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  let scoreSum = 0;
  let scanned = 0;
  for (const e of entries) {
    if (e.status !== "scanned" || !e.result) continue;
    scanned++;
    scoreSum += e.result.score;
    for (const k of Object.keys(bySeverity) as (keyof typeof bySeverity)[]) bySeverity[k] += e.result.summary[k];
  }
  return {
    tool: "mcp-detector",
    kind: "batch",
    version: VERSION,
    createdAt: new Date().toISOString(),
    origin,
    entries,
    summary: {
      total: entries.length,
      scanned,
      failed: entries.filter((e) => e.status === "failed").length,
      authRequired: entries.filter((e) => e.status === "auth_required").length,
      skipped: entries.filter((e) => e.status === "skipped").length,
      averageScore: scanned ? Math.round(scoreSum / scanned) : undefined,
      bySeverity,
    },
  };
}

export function batchDir(cwd = process.cwd()): string {
  return resolve(cwd, DATA_DIR, "batch");
}

/** Save a batch result under .mcp-detector/batch/ and as latest.json. Returns the timestamped path. */
export function saveBatch(batch: BatchResult, cwd = process.cwd()): string {
  const dir = batchDir(cwd);
  mkdirSync(dir, { recursive: true });
  const file = join(dir, `${batch.createdAt.replace(/[:.]/g, "-")}.json`);
  writeFileSync(file, JSON.stringify(batch, null, 2) + "\n", "utf8");
  writeFileSync(join(dir, "latest.json"), JSON.stringify(batch, null, 2) + "\n", "utf8");
  mkdirSync(dirname(file), { recursive: true });
  return file;
}
