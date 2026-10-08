import type { Rule } from "../core/types.js";
import { protocolRules } from "./protocol-rules.js";
import { schemaRules } from "./schema-rules.js";
import { securityRules } from "./security-rules.js";
import { qualityRules } from "./quality-rules.js";
import { performanceRules } from "./performance-rules.js";
import { hygieneRules } from "./hygiene-rules.js";
import { networkRules } from "./network-rules.js";
import { pinningRules } from "./pinning-rules.js";

const registry = new Map<string, Rule>();

/** Register a rule. Third-party rules can call this before running a scan. */
export function registerRule(rule: Rule): void {
  if (!/^[A-Z][A-Z0-9]{1,9}-\d{3,}$/.test(rule.id))
    throw new Error(`Invalid rule id "${rule.id}" (expected PREFIX-NNN, e.g. MCP-001 or ACME-001).`);
  if (registry.has(rule.id)) throw new Error(`Rule ${rule.id} is already registered.`);
  registry.set(rule.id, rule);
}

for (const r of [...protocolRules, ...schemaRules, ...securityRules, ...qualityRules, ...performanceRules, ...hygieneRules, ...networkRules, ...pinningRules]) registerRule(r);

export function unregisterRule(id: string): void {
  registry.delete(id);
}

export function allRules(): Rule[] {
  return [...registry.values()].sort((a, b) => a.id.localeCompare(b.id));
}

export function getRule(id: string): Rule | undefined {
  return registry.get(id.toUpperCase());
}
