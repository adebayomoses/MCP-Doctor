import type { Rule, RuleHit, Severity } from "../core/types.js";
import { checkJsonSchema, checkSchemaConsistency } from "../detectors/schema/validate.js";
import { isConstrained, paramType, toolParams } from "../detectors/tools/text.js";

const RISKY_PARAM = /^(path|file|filename|filepath|dir|directory|url|uri|command|cmd|sql|query|script|code|host|hostname|expression|regex|template)$/i;
const BOUNDED_NUMERIC = /^(limit|count|size|page|page_?size|max.*|timeout|depth|offset|top_?k|n)$/i;

export const schemaRules: Rule[] = [
  {
    id: "MCP-003",
    name: "Invalid tool schema",
    category: "schema",
    severity: "high",
    group: "schema",
    description: "A tool's inputSchema (or outputSchema) is missing, is not an object schema, is not valid JSON Schema, or contradicts itself.",
    why: "Clients and models rely on the schema to build valid calls. An invalid schema makes the tool unusable or lets malformed input through.",
    recommendation: 'Give every tool an inputSchema of `{ "type": "object", "properties": {...}, "required": [...] }` that validates as JSON Schema, and make sure every `required` entry is defined in `properties`.',
    check({ snapshot }) {
      const hits: RuleHit[] = [];
      for (const tool of snapshot.tools) {
        const s = tool.inputSchema;
        if (s === undefined || s === null) {
          hits.push({ tool: tool.name, message: "Tool has no inputSchema." });
          continue;
        }
        const problems = checkJsonSchema(s);
        if (problems.length) {
          hits.push({ tool: tool.name, message: "inputSchema is not valid JSON Schema.", evidence: problems.join("; ") });
          continue;
        }
        if ((s as any).type !== "object") {
          hits.push({
            tool: tool.name,
            message: `inputSchema.type must be "object" (found ${JSON.stringify((s as any).type)}).`,
          });
          continue;
        }
        const incon = checkSchemaConsistency(s);
        if (incon.length)
          hits.push({ tool: tool.name, severity: "medium", message: "inputSchema is internally inconsistent.", evidence: incon.join("; ") });
        if (tool.outputSchema !== undefined) {
          const op = checkJsonSchema(tool.outputSchema);
          if (op.length)
            hits.push({ tool: tool.name, severity: "medium", message: "outputSchema is not valid JSON Schema.", evidence: op.join("; ") });
        }
      }
      return hits;
    },
  },
  {
    id: "MCP-010",
    name: "Weak input validation",
    category: "schema",
    severity: "medium",
    group: "schema",
    description: "A tool's input schema leaves parameters untyped, unbounded or free-form (e.g. an unconstrained `path`, `url` or `command` string).",
    why: "Loose schemas let a model (or an attacker steering it) send unexpected values, which is the first step of most injection and path-traversal issues.",
    recommendation: "Type every parameter, add `enum`/`pattern`/`maxLength`/`format` to strings, `minimum`/`maximum` to numbers, `items` to arrays, list `required` fields, and validate again on the server.",
    check({ snapshot }) {
      const hits: RuleHit[] = [];
      for (const tool of snapshot.tools) {
        const schema = tool.inputSchema;
        if (!schema || typeof schema !== "object") continue; // reported by MCP-003
        const params = toolParams(tool);
        const issues: string[] = [];
        let sev: Severity = "low";
        for (const [name, p] of Object.entries<any>(params)) {
          if (!p || typeof p !== "object") continue;
          const t = paramType(p);
          const hasShape = p.enum || p.const !== undefined || p.oneOf || p.anyOf || p.allOf || p.$ref;
          if (!t && !hasShape) {
            issues.push(`"${name}" has no type`);
            sev = "medium";
            continue;
          }
          if (t === "string" && !isConstrained(p)) {
            if (RISKY_PARAM.test(name)) {
              issues.push(`"${name}" is an unconstrained string`);
              sev = "medium";
            }
          }
          if ((t === "integer" || t === "number") && BOUNDED_NUMERIC.test(name) && p.minimum === undefined && p.maximum === undefined && p.exclusiveMaximum === undefined)
            issues.push(`"${name}" is a number with no minimum/maximum`);
          if (t === "array" && !p.items) issues.push(`"${name}" is an array with no items schema`);
          if (t === "object" && !p.properties && p.additionalProperties !== false && !p.patternProperties)
            issues.push(`"${name}" is a free-form object`);
        }
        if (issues.length)
          hits.push({
            tool: tool.name,
            severity: sev,
            message: `Weak input validation (${issues.length} issue${issues.length > 1 ? "s" : ""}).`,
            evidence: issues.slice(0, 6).join("; ") + (issues.length > 6 ? `; +${issues.length - 6} more` : ""),
          });
      }
      return hits;
    },
  },
];
