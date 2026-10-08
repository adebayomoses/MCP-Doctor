import type { Category, ScanResult } from "../core/types.js";

const esc = (s: string) =>
  s.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;").replace(/'/g, "&#39;");

/** Same thresholds as the grade names so a badge and a report never disagree. */
export function scoreColor(score: number): string {
  if (score >= 90) return "#44cc11";
  if (score >= 80) return "#97ca00";
  if (score >= 70) return "#dfb317";
  if (score >= 50) return "#fe7d37";
  return "#e05d44";
}

/** Rough text width for Verdana 11px, good enough for a stable badge layout. */
function textWidth(s: string): number {
  let w = 0;
  for (const ch of s) w += /[ilI.,:;'|!]/.test(ch) ? 3.4 : /[mwMW@%]/.test(ch) ? 9.5 : /[A-Z0-9]/.test(ch) ? 7.3 : 6.4;
  return Math.round(w);
}

export interface BadgeOptions {
  label?: string;
  /** Show a single category's score instead of the overall score. */
  category?: Category;
}

export function badgeParts(r: ScanResult, o: BadgeOptions = {}): { label: string; message: string; color: string } {
  if (r.status === "failed") return { label: o.label ?? "mcp-detector", message: "unreachable", color: "#9f9f9f" };
  const score = o.category ? r.scores[o.category] : r.score;
  return { label: o.label ?? (o.category ? `mcp ${o.category}` : "mcp-detector"), message: `${score}/100`, color: scoreColor(score) };
}

/** A self-contained flat badge. Note the wording: a score, never a claim that a server is "safe". */
export function renderBadge(r: ScanResult, o: BadgeOptions = {}): string {
  const { label, message, color } = badgeParts(r, o);
  const lw = textWidth(label) + 12;
  const rw = textWidth(message) + 12;
  const w = lw + rw;
  const title = esc(`${label}: ${message}`);
  return `<svg xmlns="http://www.w3.org/2000/svg" width="${w}" height="20" role="img" aria-label="${title}"><title>${title}</title><linearGradient id="s" x2="0" y2="100%"><stop offset="0" stop-color="#bbb" stop-opacity=".1"/><stop offset="1" stop-opacity=".1"/></linearGradient><clipPath id="r"><rect width="${w}" height="20" rx="3" fill="#fff"/></clipPath><g clip-path="url(#r)"><rect width="${lw}" height="20" fill="#555"/><rect x="${lw}" width="${rw}" height="20" fill="${color}"/><rect width="${w}" height="20" fill="url(#s)"/></g><g fill="#fff" text-anchor="middle" font-family="Verdana,Geneva,DejaVu Sans,sans-serif" font-size="11"><text x="${lw / 2}" y="15" fill="#010101" fill-opacity=".3">${esc(label)}</text><text x="${lw / 2}" y="14">${esc(label)}</text><text x="${lw + rw / 2}" y="15" fill="#010101" fill-opacity=".3">${esc(message)}</text><text x="${lw + rw / 2}" y="14">${esc(message)}</text></g></svg>\n`;
}

/** Endpoint JSON understood by https://shields.io/badges/endpoint-badge */
export function shieldsEndpoint(r: ScanResult, o: BadgeOptions = {}) {
  const { label, message, color } = badgeParts(r, o);
  return { schemaVersion: 1, label, message, color: color.replace("#", "") };
}
