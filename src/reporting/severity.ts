import { SEVERITY_ORDER, type Finding, type Severity } from "../core/types.js";

export const SEVERITY_ICON: Record<Severity, string> = {
  critical: "🔴",
  high: "🟠",
  medium: "🟡",
  low: "🔵",
  info: "⚪",
};

export const SEVERITY_LABEL: Record<Severity, string> = {
  critical: "CRITICAL",
  high: "HIGH",
  medium: "MEDIUM",
  low: "LOW",
  info: "INFO",
};

/** True if any finding is at or above `threshold`. */
export function exceedsThreshold(findings: Finding[], threshold: Severity | "none"): boolean {
  if (threshold === "none") return false;
  const min = SEVERITY_ORDER.indexOf(threshold);
  return findings.some((f) => SEVERITY_ORDER.indexOf(f.severity) >= min);
}

export function countAtOrAbove(findings: Finding[], threshold: Severity): number {
  const min = SEVERITY_ORDER.indexOf(threshold);
  return findings.filter((f) => SEVERITY_ORDER.indexOf(f.severity) >= min).length;
}

export function parseSeverity(v: string): Severity | "none" {
  const s = v.toLowerCase();
  if (s === "none" || s === "off") return "none";
  if ((SEVERITY_ORDER as string[]).includes(s)) return s as Severity;
  throw new Error(`Invalid severity "${v}". Use one of: ${SEVERITY_ORDER.join(", ")}, none.`);
}
