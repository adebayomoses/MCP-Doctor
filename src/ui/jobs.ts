import { randomBytes } from "node:crypto";
import { defaultConfig } from "../config/default-config.js";
import { runScan } from "../core/detector.js";
import { explainConnectError, type ErrorExplanation } from "../core/explain.js";
import type { ResolvedConfig, ScanResult } from "../core/types.js";
import { renderHtmlReport } from "../reporting/html.js";
import { saveHistory } from "../store/history.js";

export type JobStatus = "running" | "done" | "error";

export interface JobView {
  id: string;
  status: JobStatus;
  /** What the person asked to scan (redacted: never contains headers or tokens). */
  label: string;
  startedAt: string;
  finishedAt?: string;
  /** Present when status is "done". */
  result?: ScanResult;
  /** Full, script-free, escaped HTML report for display in a sandboxed frame. */
  html?: string;
  /** Plain-language explanation when the server could not be scanned. */
  problem?: ErrorExplanation;
  /** Internal failure (not a finding about the scanned server). */
  error?: string;
}

export type Runner = (config: ResolvedConfig) => Promise<{ result: ScanResult; stderr?: string }>;

const defaultRunner: Runner = async (config) => {
  const { result, snapshot } = await runScan(config);
  return { result, stderr: snapshot.stderr };
};

export interface JobManagerOptions {
  /** Maximum scans running at once. */
  maxRunning?: number;
  /** Finished jobs are forgotten after this long. */
  ttlMs?: number;
  maxJobs?: number;
  runner?: Runner;
  /** Where scan history is written. */
  cwd?: string;
  now?: () => number;
}

export class TooManyJobsError extends Error {}

export class JobManager {
  private jobs = new Map<string, JobView>();
  private readonly maxRunning: number;
  private readonly ttlMs: number;
  private readonly maxJobs: number;
  private readonly runner: Runner;
  private readonly cwd?: string;
  private readonly now: () => number;

  constructor(o: JobManagerOptions = {}) {
    this.maxRunning = o.maxRunning ?? 2;
    this.ttlMs = o.ttlMs ?? 30 * 60_000;
    this.maxJobs = o.maxJobs ?? 50;
    this.runner = o.runner ?? defaultRunner;
    this.cwd = o.cwd;
    this.now = o.now ?? Date.now;
  }

  running(): number {
    return [...this.jobs.values()].filter((j) => j.status === "running").length;
  }

  /**
   * Start a scan in the background and return its id immediately.
   * `server` may contain headers/env with secrets: they are used for the scan only and never stored on the job.
   */
  start(label: string, server: NonNullable<ResolvedConfig["server"]>, opts: { active?: boolean } = {}): string {
    this.prune();
    if (this.running() >= this.maxRunning) throw new TooManyJobsError(`Already running ${this.maxRunning} scans; wait for one to finish.`);
    const id = randomBytes(8).toString("hex");
    const job: JobView = { id, status: "running", label, startedAt: new Date(this.now()).toISOString() };
    this.jobs.set(id, job);

    const config: ResolvedConfig = { ...defaultConfig(), server, active: opts.active === true };
    void this.runner(config)
      .then(({ result, stderr }) => {
        job.result = result;
        job.html = renderHtmlReport(result);
        if (result.status === "failed") {
          const finding = result.findings.find((f) => f.rule === "MCP-001" || f.rule === "MCP-002");
          job.problem = explainConnectError(finding?.message ?? "", { command: server.command, url: server.url, timeoutMs: config.thresholds.connect_ms, stderr });
        } else saveHistory(result, this.cwd);
        job.status = "done";
      })
      .catch((e: Error) => {
        job.status = "error";
        job.error = e.message;
        job.problem = explainConnectError(e.message, { command: server.command, url: server.url, timeoutMs: config.thresholds.connect_ms });
      })
      .finally(() => {
        job.finishedAt = new Date(this.now()).toISOString();
      });
    return id;
  }

  get(id: string): JobView | undefined {
    return this.jobs.get(id);
  }

  list(): JobView[] {
    return [...this.jobs.values()].sort((a, b) => b.startedAt.localeCompare(a.startedAt));
  }

  private prune() {
    const cutoff = this.now() - this.ttlMs;
    for (const [id, j] of this.jobs) if (j.status !== "running" && j.finishedAt && Date.parse(j.finishedAt) < cutoff) this.jobs.delete(id);
    while (this.jobs.size >= this.maxJobs) {
      const oldest = [...this.jobs.values()].filter((j) => j.status !== "running").sort((a, b) => a.startedAt.localeCompare(b.startedAt))[0];
      if (!oldest) break;
      this.jobs.delete(oldest.id);
    }
  }
}
