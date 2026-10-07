import { CATEGORIES, type Category, type Finding, type ScanResult, type Severity } from "./types.js";

/** Points deducted from a category for the first finding of a rule at each severity. */
export const PENALTY: Record<Severity, number> = { critical: 30, high: 15, medium: 7, low: 2.5, info: 0 };

/** How much each category contributes to the overall score. */
export const WEIGHTS: Record<Category, number> = {
  protocol: 20,
  security: 30,
  tools: 10,
  schema: 15,
  performance: 10,
  quality: 15,
};

/**
 * Repeats of the same rule add diminishing penalty so that one rule firing on
 * 40 tools cannot, on its own, zero a category: 1st = 100%, then +50% each, capped at 3x.
 */
function repeatMultiplier(n: number): number {
  return Math.min(1 + 0.5 * (n - 1), 3);
}

export function categoryScores(findings: Finding[]): Record<Category, number> {
  const scores = {} as Record<Category, number>;
  for (const cat of CATEGORIES) {
    const byRule = new Map<string, Finding[]>();
    for (const f of findings.filter((f) => f.category === cat)) {
      byRule.set(f.rule, [...(byRule.get(f.rule) ?? []), f]);
    }
    let penalty = 0;
    for (const group of byRule.values()) {
      // Use the worst severity seen for the rule as the base.
      const worst = group.reduce((a, b) => (PENALTY[b.severity] > PENALTY[a.severity] ? b : a));
      penalty += PENALTY[worst.severity] * repeatMultiplier(group.length);
    }
    scores[cat] = Math.max(0, Math.round(100 - penalty));
  }
  return scores;
}

export function overallScore(scores: Record<Category, number>): number {
  let total = 0;
  let weight = 0;
  for (const cat of CATEGORIES) {
    total += scores[cat] * WEIGHTS[cat];
    weight += WEIGHTS[cat];
  }
  return Math.round(total / weight);
}

export function gradeFor(score: number): ScanResult["grade"] {
  if (score >= 90) return "Excellent";
  if (score >= 80) return "Good";
  if (score >= 70) return "Fair";
  if (score >= 50) return "Poor";
  return "Critical";
}
