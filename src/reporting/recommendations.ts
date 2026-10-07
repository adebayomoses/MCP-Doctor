import type { Finding } from "../core/types.js";

/** Unique, ordered list of recommendations for a set of findings (one per rule). */
export function uniqueRecommendations(findings: Finding[]): { rule: string; name: string; recommendation: string; count: number }[] {
  const map = new Map<string, { rule: string; name: string; recommendation: string; count: number }>();
  for (const f of findings) {
    const cur = map.get(f.rule);
    if (cur) cur.count++;
    else map.set(f.rule, { rule: f.rule, name: f.name, recommendation: f.recommendation, count: 1 });
  }
  return [...map.values()];
}
