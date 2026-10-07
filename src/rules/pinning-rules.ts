import { describeChange, diffBaseline } from "../core/pinning.js";
import type { Rule, RuleHit } from "../core/types.js";

export const pinningRules: Rule[] = [
  {
    id: "MCP-032",
    name: "Tool definition changed since baseline",
    category: "security",
    severity: "high",
    group: "rug_pull",
    description:
      "Compared with the trusted baseline (mcp-detector.lock.json), a tool's description, schema or annotations changed, a tool was added, or the server instructions changed.",
    why: "A server can behave well while you review it and later swap in malicious tool descriptions (a \"rug pull\"). Clients rarely tell you when a definition changes, so the only defence is to pin what you reviewed and alert on any difference.",
    recommendation:
      "Review the change. If it is expected and safe, accept it with `mcp-detector pin`; if not, stop using the server and treat it as compromised. Commit mcp-detector.lock.json so changes show up in code review.",
    check({ snapshot, config }) {
      const base = config.baseline;
      if (!base || !snapshot.connected) return [];
      const diff = diffBaseline(base, snapshot);
      const hits: RuleHit[] = [];
      for (const c of diff.changed) {
        const parts = [c.description && "description", c.schema && "input/output schema", c.annotations && "annotations"].filter(Boolean);
        hits.push({
          tool: c.tool,
          severity: c.description || c.schema ? "high" : "medium",
          message: `Tool definition changed since it was pinned (${parts.join(", ")}).`,
          evidence: c.description ? describeChange(c.before, c.after) : undefined,
        });
      }
      for (const name of diff.added)
        hits.push({ tool: name, severity: "medium", message: "Tool was added since the baseline was pinned (capability expansion)." });
      for (const name of diff.removed)
        hits.push({ severity: "low", message: `Tool "${name}" is in the baseline but the server no longer exposes it.` });
      if (diff.instructionsChanged)
        hits.push({ severity: "high", message: "Server instructions changed since the baseline was pinned." });
      return hits;
    },
  },
];
