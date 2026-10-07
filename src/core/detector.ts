import { analyze } from "./analyzer.js";
import { categoryScores, gradeFor, overallScore } from "./health-score.js";
import { collectSnapshot } from "./scanner.js";
import { CATEGORIES, type ResolvedConfig, type ScanResult, type ServerSnapshot, type Severity } from "./types.js";
import { VERSION } from "../version.js";

export const DISCLAIMER =
  "The health score is an engineering signal, not a security certification. Findings are indicators produced by heuristics and may include false positives; a clean scan does not prove a server is safe.";

export interface DetectorOutput {
  result: ScanResult;
  snapshot: ServerSnapshot;
  ruleErrors: { rule: string; error: string }[];
}

/** Build a ScanResult from an already-collected snapshot (also used by tests). */
export function evaluate(snapshot: ServerSnapshot, config: ResolvedConfig): DetectorOutput {
  const { findings, ruleErrors } = analyze(snapshot, config);

  const scores = categoryScores(findings);
  let score = overallScore(scores);
  // If we could not even connect, nothing else can be verified.
  if (!snapshot.connected) score = 0;

  const summary: Record<Severity, number> = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  for (const f of findings) summary[f.severity]++;

  const calls = snapshot.toolCalls;
  const timings: ScanResult["timings"] = { ...snapshot.timings };
  if (calls.length) {
    timings.avgToolMs = Math.round(calls.reduce((a, c) => a + c.durationMs, 0) / calls.length);
    timings.timeoutRate = calls.filter((c) => c.timedOut).length / calls.length;
    timings.errorRate = calls.filter((c) => !c.ok && !c.timedOut).length / calls.length;
  }

  for (const c of CATEGORIES) if (scores[c] === undefined) scores[c] = 100;

  const result: ScanResult = {
    tool: "mcp-detector",
    version: VERSION,
    target: snapshot.target,
    server: snapshot.serverInfo,
    status: snapshot.connected ? "connected" : "failed",
    protocolVersion: snapshot.protocolVersion,
    counts: { tools: snapshot.tools.length, resources: snapshot.resources.length, prompts: snapshot.prompts.length },
    score,
    grade: gradeFor(score),
    scores,
    summary,
    timings,
    findings,
    disclaimer: DISCLAIMER,
  };
  return { result, snapshot, ruleErrors };
}

/** Connect to the configured server, run all detectors, and score the result. */
export async function runScan(config: ResolvedConfig): Promise<DetectorOutput> {
  const snapshot = await collectSnapshot(config);
  return evaluate(snapshot, config);
}
