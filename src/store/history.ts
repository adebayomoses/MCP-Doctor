import { createHash } from "node:crypto";
import { existsSync, mkdirSync, readdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { join, resolve } from "node:path";
import type { Finding, ScanResult } from "../core/types.js";

export const DATA_DIR = ".mcp-detector";
const KEEP_PER_TARGET = 50;

export interface HistoryRecord {
  /** ISO timestamp of the scan. */
  at: string;
  result: ScanResult;
}

export interface TargetSummary {
  key: string;
  target: string;
  name?: string;
  runs: number;
  latest: HistoryRecord;
  previous?: HistoryRecord;
}

export function targetKey(target: string): string {
  return createHash("sha1").update(target).digest("hex").slice(0, 12);
}

export function historyDir(cwd = process.cwd()): string {
  return resolve(cwd, DATA_DIR, "history");
}

const fileSafe = (iso: string) => iso.replace(/[:.]/g, "-");

/** Append a result to the history of its target. Never throws: history is best effort. */
export function saveHistory(result: ScanResult, cwd = process.cwd(), at = new Date()): HistoryRecord | undefined {
  try {
    const dir = join(historyDir(cwd), targetKey(result.target));
    mkdirSync(dir, { recursive: true });
    const record: HistoryRecord = { at: at.toISOString(), result };
    writeFileSync(join(dir, `${fileSafe(record.at)}.json`), JSON.stringify(record) + "\n", "utf8");
    const files = readdirSync(dir).filter((f) => f.endsWith(".json")).sort();
    for (const old of files.slice(0, Math.max(0, files.length - KEEP_PER_TARGET))) rmSync(join(dir, old), { force: true });
    return record;
  } catch {
    return undefined;
  }
}

function readRecords(dir: string): HistoryRecord[] {
  const out: HistoryRecord[] = [];
  for (const f of readdirSync(dir).filter((f) => f.endsWith(".json")).sort()) {
    try {
      const r = JSON.parse(readFileSync(join(dir, f), "utf8"));
      if (r?.result?.tool === "mcp-detector" && typeof r.at === "string") out.push(r);
    } catch {
      /* skip corrupt file */
    }
  }
  return out;
}

/** All runs for one target, oldest first. */
export function readTargetHistory(target: string, cwd = process.cwd()): HistoryRecord[] {
  const dir = join(historyDir(cwd), targetKey(target));
  return existsSync(dir) ? readRecords(dir) : [];
}

/** One summary per target that has history, most recently scanned first. */
export function listTargets(cwd = process.cwd()): TargetSummary[] {
  const root = historyDir(cwd);
  if (!existsSync(root)) return [];
  const out: TargetSummary[] = [];
  for (const key of readdirSync(root)) {
    const dir = join(root, key);
    let recs: HistoryRecord[];
    try {
      recs = readRecords(dir);
    } catch {
      continue;
    }
    if (!recs.length) continue;
    const latest = recs[recs.length - 1];
    out.push({ key, target: latest.result.target, name: latest.result.server?.name, runs: recs.length, latest, previous: recs[recs.length - 2] });
  }
  return out.sort((a, b) => b.latest.at.localeCompare(a.latest.at));
}

const fkey = (f: Finding) => `${f.rule}|${f.tool ?? ""}`;

export interface HistoryDiff {
  scoreDelta: number;
  newFindings: Finding[];
  resolvedFindings: Finding[];
  /** Findings present in both runs whose severity changed. */
  changedSeverity: { before: Finding; after: Finding }[];
}

/** What changed between two scans of the same target. */
export function diffResults(before: ScanResult, after: ScanResult): HistoryDiff {
  const b = new Map(before.findings.map((f) => [fkey(f), f]));
  const a = new Map(after.findings.map((f) => [fkey(f), f]));
  return {
    scoreDelta: after.score - before.score,
    newFindings: [...a].filter(([k]) => !b.has(k)).map(([, f]) => f),
    resolvedFindings: [...b].filter(([k]) => !a.has(k)).map(([, f]) => f),
    changedSeverity: [...a].filter(([k, f]) => b.has(k) && b.get(k)!.severity !== f.severity).map(([k, f]) => ({ before: b.get(k)!, after: f })),
  };
}

export function trend(scores: number[]): "up" | "down" | "flat" {
  if (scores.length < 2) return "flat";
  const d = scores[scores.length - 1] - scores[scores.length - 2];
  return d > 0 ? "up" : d < 0 ? "down" : "flat";
}
