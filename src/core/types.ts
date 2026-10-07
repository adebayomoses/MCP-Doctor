export type Severity = "critical" | "high" | "medium" | "low" | "info";
export type Category =
  | "protocol"
  | "security"
  | "tools"
  | "schema"
  | "performance"
  | "quality";

export const SEVERITY_ORDER: Severity[] = ["info", "low", "medium", "high", "critical"];
export const CATEGORIES: Category[] = [
  "protocol",
  "security",
  "tools",
  "schema",
  "performance",
  "quality",
];

export interface ToolDef {
  name: string;
  description?: string;
  title?: string;
  inputSchema?: Record<string, any>;
  outputSchema?: Record<string, any>;
  annotations?: Record<string, any>;
  [k: string]: unknown;
}
export interface ResourceDef { uri: string; name?: string; description?: string; [k: string]: unknown }
export interface PromptDef { name: string; description?: string; arguments?: any[]; [k: string]: unknown }

export interface ToolCallResult {
  tool: string;
  ok: boolean;
  timedOut: boolean;
  durationMs: number;
  error?: string;
  /** Text content returned by the tool (truncated). */
  text?: string;
}

export interface Timings {
  connectMs?: number;
  initializeMs?: number;
  discoveryMs?: number;
}

/** Everything the detectors know about a server. Rules are pure functions of this. */
export interface ServerSnapshot {
  target: string;
  connected: boolean;
  connectError?: string;
  serverInfo?: { name?: string; version?: string };
  protocolVersion?: string;
  capabilities?: Record<string, any>;
  instructions?: string;
  tools: ToolDef[];
  resources: ResourceDef[];
  prompts: PromptDef[];
  /** Errors hit while listing tools/resources/prompts. */
  listErrors: Record<string, string>;
  /** Raw name list including duplicates, as returned by the server. */
  toolNames: string[];
  timings: Timings;
  toolCalls: ToolCallResult[];
  activeMode: boolean;
  /** Result of a `ping` request. */
  ping?: { ok: boolean; ms: number; error?: string };
  /** Whether an unknown JSON-RPC method was rejected with an error (as the spec requires). */
  unknownMethod?: { rejected: boolean; code?: number; timedOut: boolean };
  /** Tools skipped in active mode, with the reason. */
  skippedCalls: { tool: string; reason: string }[];
  /** Server stderr output captured during the scan (truncated). */
  stderr?: string;
}

export interface BaselineTool {
  /** sha256 of the canonical definition (title, description, schemas, annotations). */
  hash: string;
  descriptionHash: string;
  schemaHash: string;
  annotationsHash: string;
  /** Kept so a later change can show what the description used to say. */
  description?: string;
}

/** A trusted snapshot of a server's tool definitions (written by `mcp-detector pin`). */
export interface Baseline {
  version: 1;
  createdBy: string;
  createdAt: string;
  server?: { name?: string; version?: string };
  instructionsHash?: string;
  tools: Record<string, BaselineTool>;
}

export interface RuleHit {
  tool?: string;
  message: string;
  /** The text/pattern that triggered the rule, so false positives are easy to investigate. */
  evidence?: string;
  severity?: Severity;
}

export interface RuleContext {
  snapshot: ServerSnapshot;
  config: ResolvedConfig;
}

export interface Rule {
  id: string;
  name: string;
  category: Category;
  severity: Severity;
  /** What it detects. */
  description: string;
  /** Why it matters. */
  why: string;
  /** How to fix it. */
  recommendation: string;
  /** Config toggle group (e.g. "prompt_injection"). */
  group?: string;
  check(ctx: RuleContext): RuleHit[];
}

export interface Finding {
  rule: string;
  name: string;
  severity: Severity;
  category: Category;
  tool?: string;
  message: string;
  evidence?: string;
  /** When several indicators of the same rule hit the same tool, each one is listed here. */
  details?: string[];
  why: string;
  recommendation: string;
}

export interface CategoryScore { category: Category; score: number; findings: number }

export interface ScanResult {
  tool: "mcp-detector";
  version: string;
  target: string;
  server?: { name?: string; version?: string };
  status: "connected" | "failed";
  protocolVersion?: string;
  counts: { tools: number; resources: number; prompts: number };
  score: number;
  grade: "Excellent" | "Good" | "Fair" | "Poor" | "Critical";
  scores: Record<Category, number>;
  summary: Record<Severity, number>;
  timings: Timings & { avgToolMs?: number; timeoutRate?: number; errorRate?: number };
  findings: Finding[];
  disclaimer: string;
}

export interface ResolvedConfig {
  server?: {
    command?: string;
    args?: string[];
    env?: Record<string, string>;
    cwd?: string;
    url?: string;
    headers?: Record<string, string>;
    transport?: "stdio" | "http" | "sse";
  };
  severity: { fail_on: Severity | "none" };
  /** Toggle groups: prompt_injection, tool_poisoning, ... */
  groups: Record<string, boolean>;
  /** Per-rule overrides keyed by rule id. */
  ruleOverrides: Record<string, { enabled?: boolean; severity?: Severity }>;
  thresholds: { latency_ms: number; timeout_ms: number; connect_ms: number; max_timeout_rate: number };
  /** Allow calling tools to measure performance. Off by default (passive inspection). */
  active: boolean;
  /** Tool names that active mode may call even if they have required args. */
  activeAllow: string[];
  /** Tool names never called. */
  activeDeny: string[];
  ignore: { rules: string[]; tools: string[] };
  /** Trusted tool definitions to compare against (rug-pull detection). */
  baseline?: Baseline;
  baselineFile?: string;
}
