import type { ToolDef } from "../../core/types.js";
import { toolParams } from "./text.js";

export type Capability =
  | "shell"
  | "fs_write"
  | "fs_delete"
  | "fs_read"
  | "db_write"
  | "db_query"
  | "network"
  | "credentials";

export interface CapabilityHit {
  capability: Capability;
  reason: string;
}

interface Signal {
  capability: Capability;
  /** Matched against the tool name, split into words ("runCommand" -> "run Command"). */
  name?: RegExp;
  /** Matched against the description. */
  desc?: RegExp;
  /** Matched against parameter names. */
  param?: RegExp;
}

const SIGNALS: Signal[] = [
  {
    capability: "shell",
    name: /\b(exec|execute|shell|bash|sh|cmd|command|terminal|eval|spawn|powershell|script)\b/i,
    desc: /\b(execute[sd]?|run[s]?|spawn[s]?|invoke[s]?)\b[^.]{0,40}\b(shell|bash|command[s]?|terminal|subprocess|script|arbitrary code|powershell)\b|\barbitrary (code|command)/i,
    param: /^(command|cmd|shell_?command|script|bash|powershell)$/i,
  },
  {
    capability: "fs_write",
    name: /\b(write|save|create|append|edit|overwrite|upload|mkdir|move|rename|copy)\b/i,
    desc: /\b(write[s]?|create[s]?|overwrite[s]?|modif(y|ies)|append[s]?|save[s]?)\b[^.]{0,40}\b(file|files|director(y|ies)|folder|disk)\b/i,
  },
  {
    capability: "fs_delete",
    name: /\b(delete|remove|rm|unlink|rmdir|purge|wipe|erase)\b/i,
    desc: /\b(delete[s]?|remove[s]?|unlink[s]?|erase[s]?)\b[^.]{0,40}\b(file|files|director(y|ies)|folder)\b/i,
  },
  {
    capability: "fs_read",
    name: /\b(read|cat|open|get|list|search|view)\b.*\b(file|files|dir|directory|folder|path)\b/i,
    desc: /\b(read[s]?|list[s]?|open[s]?)\b[^.]{0,40}\b(file|files|director(y|ies)|folder|filesystem)\b/i,
  },
  {
    capability: "db_write",
    name: /\b(insert|update|delete|drop|truncate|alter|migrate|write)\b.*\b(row|rows|record|records|table|db|database|document|data)\b/i,
    desc: /\b(insert[s]?|update[s]?|delete[s]?|drop[s]?|truncate[s]?|alter[s]?|modif(y|ies))\b[^.]{0,40}\b(row|rows|record|records|table|tables|database|collection|document)\b/i,
  },
  {
    capability: "db_query",
    name: /\b(sql|database|db)\b|\b(query|select)\b.*\b(table|tables|row|rows|record|records)\b/i,
    desc: /\b(sql|database)\b/i,
    param: /^(sql|sql_?query|statement|stmt)$/i,
  },
  {
    capability: "network",
    name: /\b(fetch|http|https|request|curl|download|scrape|browse|navigate|webhook|crawl|url)\b/i,
    desc: /\b(http[s]?|url|web ?page|webhook|download[s]?|fetch(es)?)\b/i,
    param: /^(url|uri|endpoint|host|hostname|address|webhook)$/i,
  },
  {
    capability: "credentials",
    name: /\b(secret|secrets|credential|credentials|password|token|apikey|keychain|vault|env|ssh)\b/i,
    desc: /\b(secret[s]?|credential[s]?|password[s]?|api[ _-]?key[s]?|access token[s]?|private key[s]?|keychain|environment variable[s]?)\b/i,
  },
];

/**
 * Heuristically classify what a tool can do. A capability is reported only when
 * the name or description clearly points to it, or when a parameter name strongly
 * implies it. Each hit carries its reason so false positives can be investigated.
 */
export function classifyTool(tool: ToolDef): CapabilityHit[] {
  const hits = new Map<Capability, string>();
  const params = Object.keys(toolParams(tool));
  const desc = tool.description ?? "";
  const spaced = tool.name.replace(/([a-z0-9])([A-Z])/g, "$1 $2").replace(/[_\-.]+/g, " ");
  for (const s of SIGNALS) {
    if (s.name?.test(spaced)) hits.set(s.capability, `tool name "${tool.name}"`);
    else if (s.desc?.test(desc)) hits.set(s.capability, "tool description");
    else if (s.param) {
      const p = params.find((k) => s.param!.test(k));
      if (p) hits.set(s.capability, `parameter "${p}"`);
    }
  }
  // A tool the server itself marks read-only is not a write/exec tool, even if its name matched loosely.
  if (tool.annotations?.readOnlyHint === true) {
    for (const c of ["shell", "fs_write", "fs_delete", "db_write"] as Capability[]) hits.delete(c);
  }
  return [...hits.entries()].map(([capability, reason]) => ({ capability, reason }));
}

export function hasCapability(hits: CapabilityHit[], c: Capability): CapabilityHit | undefined {
  return hits.find((h) => h.capability === c);
}
