import type { ResolvedConfig, ScanResult } from "../core/types.js";

export interface ServerSpec {
  /** Human name (config key, registry name). */
  name: string;
  /** Where this spec came from, e.g. "Claude Desktop", "servers.json", "registry". */
  source: string;
  server: NonNullable<ResolvedConfig["server"]>;
  /** Extra info shown in reports (registry description, version). */
  meta?: { description?: string; version?: string; homepage?: string };
}

export type EntryStatus = "scanned" | "failed" | "auth_required" | "skipped";

export interface BatchEntry {
  name: string;
  source: string;
  /** Redacted command line or URL. */
  target: string;
  status: EntryStatus;
  result?: ScanResult;
  /** Why it was skipped or failed. */
  note?: string;
  meta?: ServerSpec["meta"];
}

export interface BatchResult {
  tool: "mcp-detector";
  kind: "batch";
  version: string;
  createdAt: string;
  /** What was scanned: file path, "clients", or "registry". */
  origin: string;
  entries: BatchEntry[];
  summary: {
    total: number;
    scanned: number;
    failed: number;
    authRequired: number;
    skipped: number;
    averageScore?: number;
    bySeverity: Record<"critical" | "high" | "medium" | "low" | "info", number>;
  };
}
