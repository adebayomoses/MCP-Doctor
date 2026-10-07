import { allRules } from "../rules/index.js";
import { SEVERITY_ORDER, type Finding, type ResolvedConfig, type ServerSnapshot } from "./types.js";

export interface AnalysisOutput {
  findings: Finding[];
  /** Rules that threw while running (a bug in a rule should never crash a scan). */
  ruleErrors: { rule: string; error: string }[];
}

export function severityRank(s: string): number {
  return SEVERITY_ORDER.indexOf(s as any);
}

/** Run every enabled rule against the snapshot and collect findings. */
export function analyze(snapshot: ServerSnapshot, config: ResolvedConfig): AnalysisOutput {
  const findings: Finding[] = [];
  const ruleErrors: AnalysisOutput["ruleErrors"] = [];
  for (const rule of allRules()) {
    const override = config.ruleOverrides[rule.id];
    if (override?.enabled === false) continue;
    if (config.ignore.rules.includes(rule.id)) continue;
    if (rule.group && config.groups[rule.group] === false && override?.enabled !== true) continue;

    let hits;
    try {
      hits = rule.check({ snapshot, config });
    } catch (e) {
      ruleErrors.push({ rule: rule.id, error: (e as Error).message });
      continue;
    }
    // Merge hits of one rule on one tool into a single finding so output stays readable.
    const groups = new Map<string, typeof hits>();
    for (const h of hits) {
      if (h.tool && config.ignore.tools.includes(h.tool)) continue;
      const key = h.tool ?? "";
      groups.set(key, [...(groups.get(key) ?? []), h]);
    }
    for (const group of groups.values()) {
      const worst = group.reduce((a, b) =>
        severityRank(b.severity ?? rule.severity) > severityRank(a.severity ?? rule.severity) ? b : a,
      );
      const merged = group.length > 1;
      findings.push({
        rule: rule.id,
        name: rule.name,
        severity: override?.severity ?? worst.severity ?? rule.severity,
        category: rule.category,
        tool: group[0].tool,
        message: merged ? `${group.length} indicators found` : group[0].message,
        evidence: merged ? undefined : group[0].evidence,
        details: merged ? group.map((h) => (h.evidence ? `${h.message} ${h.evidence}` : h.message)) : undefined,
        why: rule.why,
        recommendation: rule.recommendation,
      });
    }
  }
  findings.sort(
    (a, b) => severityRank(b.severity) - severityRank(a.severity) || a.rule.localeCompare(b.rule) || (a.tool ?? "").localeCompare(b.tool ?? ""),
  );
  return { findings, ruleErrors };
}
