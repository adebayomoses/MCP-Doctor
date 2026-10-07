import type { Rule, RuleHit } from "../core/types.js";
import { classifyTool } from "../detectors/tools/capabilities.js";
import { toolParams } from "../detectors/tools/text.js";

const LIMIT_PARAM = /(timeout|deadline|limit|max_?(results|rows|time|duration|size|items|count|bytes)|page_?size|top_?k)/i;

export const performanceRules: Rule[] = [
  {
    id: "MCP-009",
    name: "Missing timeout",
    category: "performance",
    severity: "medium",
    group: "performance",
    description: "A tool hung past the timeout during an active scan, or (passively) a shell/database/network tool exposes no timeout, limit or row-cap parameter.",
    why: "Tools that can run unbounded block the agent, hold connections and are an easy denial-of-service vector.",
    recommendation: "Enforce a server-side timeout for every external call (database, HTTP, subprocess) and expose or document limits such as `timeout_ms`, `limit` or `max_results`.",
    check({ snapshot }) {
      const hits: RuleHit[] = [];
      for (const c of snapshot.toolCalls) {
        if (c.timedOut)
          hits.push({ tool: c.tool, message: `Call did not complete within the timeout (${c.durationMs} ms).`, evidence: "observed in active mode" });
      }
      for (const tool of snapshot.tools) {
        const caps = classifyTool(tool).map((c) => c.capability);
        if (!caps.some((c) => ["shell", "db_query", "network"].includes(c))) continue;
        const names = Object.keys(toolParams(tool));
        if (names.some((n) => LIMIT_PARAM.test(n))) continue;
        if (/\b(timeout|time[- ]?limit|limited to|max(imum)? \d+)\b/i.test(tool.description ?? "")) continue;
        hits.push({
          tool: tool.name,
          severity: "low",
          message: `Tool performs ${caps.filter((c) => ["shell", "db_query", "network"].includes(c)).join("/")} work but exposes no timeout or limit parameter.`,
          evidence: "static heuristic: confirm the server enforces its own timeout",
        });
      }
      return hits;
    },
  },
  {
    id: "MCP-015",
    name: "High tool latency",
    category: "performance",
    severity: "medium",
    group: "performance",
    description: "A tool call, or tool discovery, took longer than the configured latency threshold.",
    why: "Slow tools stall the agent loop and degrade the user's experience; very slow ones are often retried or abandoned by clients.",
    recommendation: "Profile the tool, cache or paginate expensive work, stream progress notifications for long operations, or raise `thresholds.latency_ms` if the latency is expected.",
    check({ snapshot, config }) {
      const hits: RuleHit[] = [];
      const limit = config.thresholds.latency_ms;
      for (const c of snapshot.toolCalls)
        if (!c.timedOut && c.durationMs > limit)
          hits.push({ tool: c.tool, message: `Call took ${c.durationMs} ms (threshold ${limit} ms).` });
      const d = snapshot.timings.discoveryMs;
      if (d !== undefined && d > limit)
        hits.push({ severity: "low", message: `Tool/resource discovery took ${d} ms (threshold ${limit} ms).` });
      return hits;
    },
  },
  {
    id: "MCP-019",
    name: "Slow connection or initialization",
    category: "performance",
    severity: "low",
    group: "performance",
    description: "Starting the server and completing initialize took longer than the latency threshold.",
    why: "Clients start servers frequently; slow start-up delays every session and may hit client start-up timeouts.",
    recommendation: "Defer heavy start-up work (index builds, downloads, auth) until the first call, or lazy-load dependencies. With `npx`, pin and pre-install packages.",
    check({ snapshot, config }) {
      const c = snapshot.timings.connectMs;
      if (!snapshot.connected || c === undefined || c <= config.thresholds.latency_ms) return [];
      return [{ message: `Connection and initialization took ${c} ms (threshold ${config.thresholds.latency_ms} ms).` }];
    },
  },
  {
    id: "MCP-023",
    name: "High timeout or error rate",
    category: "performance",
    severity: "high",
    group: "performance",
    description: "In active mode, too many tool calls timed out or returned errors.",
    why: "Frequent failures indicate an unreliable server; agents waste time on retries and may give up on the task.",
    recommendation: "Check the failing tools' logs, add timeouts and retries for upstream calls, and return clear error messages for invalid input.",
    check({ snapshot, config }) {
      const n = snapshot.toolCalls.length;
      if (!n) return [];
      const timeouts = snapshot.toolCalls.filter((c) => c.timedOut).length;
      const errors = snapshot.toolCalls.filter((c) => !c.ok && !c.timedOut).length;
      const hits: RuleHit[] = [];
      const tr = timeouts / n;
      if (tr > config.thresholds.max_timeout_rate)
        hits.push({ message: `${(tr * 100).toFixed(1)}% of calls timed out (${timeouts}/${n}).` });
      if (errors / n > 0.25)
        hits.push({
          severity: "medium",
          message: `${((errors / n) * 100).toFixed(1)}% of calls returned errors (${errors}/${n}).`,
          evidence: snapshot.toolCalls.filter((c) => !c.ok && !c.timedOut).slice(0, 3).map((c) => `${c.tool}: ${c.error?.slice(0, 80)}`).join(" · "),
        });
      return hits;
    },
  },
];
