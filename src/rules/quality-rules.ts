import type { Rule, RuleHit } from "../core/types.js";
import { toolParams } from "../detectors/tools/text.js";

const VALID_NAME = /^[A-Za-z0-9_.-]{1,128}$/;

function nameStyle(n: string): "snake" | "kebab" | "camel" | "pascal" | "dot" | "neutral" {
  if (/[a-z0-9]_[a-z0-9]/i.test(n) && n === n.toLowerCase()) return "snake";
  if (/[a-z0-9]-[a-z0-9]/i.test(n) && n === n.toLowerCase()) return "kebab";
  if (/^[a-z]+[A-Z]/.test(n)) return "camel";
  if (/^[A-Z][a-z]+[A-Z]/.test(n)) return "pascal";
  if (n.includes(".")) return "dot";
  return "neutral";
}

export const qualityRules: Rule[] = [
  {
    id: "MCP-013",
    name: "Missing tool description",
    category: "tools",
    severity: "low",
    group: "quality",
    description: "A tool has no description.",
    why: "Models choose tools by reading their descriptions. A tool with no description is rarely selected correctly.",
    recommendation: "Write one or two sentences saying what the tool does, when to use it, and what it returns.",
    check({ snapshot }) {
      return snapshot.tools
        .filter((t) => !t.description || !t.description.trim())
        .map((t) => ({ tool: t.name, message: "Tool has no description." }));
    },
  },
  {
    id: "MCP-025",
    name: "Unclear tool description",
    category: "quality",
    severity: "low",
    group: "quality",
    description: "A tool's description is very short or just repeats its name.",
    why: "Vague descriptions make it hard for a model to know when a tool applies and what it will do.",
    recommendation: "Explain what the tool does, its inputs, side effects and what it returns, in plain language.",
    check({ snapshot }) {
      const hits: RuleHit[] = [];
      for (const t of snapshot.tools) {
        const d = t.description?.trim();
        if (!d) continue;
        const norm = (s: string) => s.toLowerCase().replace(/[^a-z0-9]+/g, "");
        if (d.length < 20 || norm(d) === norm(t.name))
          hits.push({ tool: t.name, message: `Description is too short or unhelpful (${d.length} chars).`, evidence: `"${d}"` });
      }
      return hits;
    },
  },
  {
    id: "MCP-014",
    name: "Duplicate tool",
    category: "tools",
    severity: "medium",
    group: "quality",
    description: "Two or more tools (or resources/prompts) share the same name or URI.",
    why: "Duplicate names make calls ambiguous: clients may call the wrong implementation or reject the whole list.",
    recommendation: "Give every tool, prompt and resource a unique name or URI.",
    check({ snapshot }) {
      const hits: RuleHit[] = [];
      const dup = (items: string[]) => [...new Set(items.filter((n, i) => items.indexOf(n) !== i))];
      for (const n of dup(snapshot.toolNames)) {
        const count = snapshot.toolNames.filter((x) => x === n).length;
        hits.push({ tool: n, message: `Tool name "${n}" appears ${count} times.` });
      }
      for (const n of dup(snapshot.prompts.map((p) => p.name)))
        hits.push({ message: `Prompt name "${n}" is defined more than once.` });
      for (const n of dup(snapshot.resources.map((r) => r.uri)))
        hits.push({ message: `Resource URI "${n}" is listed more than once.` });
      return hits;
    },
  },
  {
    id: "MCP-020",
    name: "Poor parameter descriptions",
    category: "quality",
    severity: "low",
    group: "quality",
    description: "A tool has parameters with no description.",
    why: "Parameter descriptions tell the model what to put in each field; without them models guess formats and units.",
    recommendation: 'Add a `description` to each property that states its meaning, format, units and an example value.',
    check({ snapshot }) {
      const hits: RuleHit[] = [];
      for (const t of snapshot.tools) {
        const missing = Object.entries<any>(toolParams(t))
          .filter(([, p]) => !(p && typeof p.description === "string" && p.description.trim()))
          .map(([n]) => n);
        if (missing.length)
          hits.push({
            tool: t.name,
            message: `${missing.length} parameter${missing.length > 1 ? "s have" : " has"} no description.`,
            evidence: missing.slice(0, 8).join(", ") + (missing.length > 8 ? ", …" : ""),
          });
      }
      return hits;
    },
  },
  {
    id: "MCP-021",
    name: "Inconsistent or invalid naming",
    category: "tools",
    severity: "low",
    group: "quality",
    description: "Tool names use invalid characters, or mix naming conventions (snake_case, camelCase, kebab-case).",
    why: "Clients may reject names outside [A-Za-z0-9_.-], and inconsistent naming makes the tool set harder for models and people to navigate.",
    recommendation: "Use 1–128 characters from A–Z, a–z, 0–9, `_`, `-`, `.` and a single convention (snake_case is the most common).",
    check({ snapshot }) {
      const hits: RuleHit[] = [];
      for (const t of snapshot.tools)
        if (!VALID_NAME.test(t.name))
          hits.push({ tool: t.name, severity: "medium", message: "Tool name contains characters outside A–Z a–z 0–9 _ - . or is too long." });
      const styles = new Map<string, string[]>();
      for (const n of snapshot.toolNames) {
        const s = nameStyle(n);
        if (s !== "neutral") styles.set(s, [...(styles.get(s) ?? []), n]);
      }
      if (styles.size > 1)
        hits.push({
          message: `Tool names mix ${styles.size} conventions: ${[...styles.keys()].join(", ")}.`,
          evidence: [...styles.entries()].map(([s, n]) => `${s}: ${n[0]}`).join(" · "),
        });
      return hits;
    },
  },
  {
    id: "MCP-022",
    name: "Excessive description length",
    category: "quality",
    severity: "low",
    group: "quality",
    description: "A tool description is very long.",
    why: "Long descriptions burn context tokens on every request and are where hidden instructions tend to hide.",
    recommendation: "Keep descriptions under ~1,000 characters; move documentation elsewhere.",
    check({ snapshot }) {
      return snapshot.tools
        .filter((t) => (t.description?.length ?? 0) > 1500)
        .map((t) => ({ tool: t.name, message: `Description is ${t.description!.length} characters long.` }));
    },
  },
  {
    id: "MCP-024",
    name: "Missing tool annotations",
    category: "tools",
    severity: "info",
    group: "quality",
    description: "Tools do not declare behavioural annotations (readOnlyHint, destructiveHint, idempotentHint, openWorldHint).",
    why: "Annotations let clients decide which calls need user confirmation. Without them clients must assume the worst.",
    recommendation: "Set `annotations` on each tool, at minimum `readOnlyHint` and `destructiveHint`.",
    check({ snapshot }) {
      const missing = snapshot.tools.filter((t) => !t.annotations || Object.keys(t.annotations).length === 0);
      if (!missing.length) return [];
      return [
        {
          message: `${missing.length} of ${snapshot.tools.length} tools declare no annotations.`,
          evidence: missing.slice(0, 5).map((t) => t.name).join(", ") + (missing.length > 5 ? ", …" : ""),
        },
      ];
    },
  },
];
