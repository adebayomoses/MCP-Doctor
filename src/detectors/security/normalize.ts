/**
 * Text normalisation so pattern matching still works when an attacker obfuscates a payload:
 * zero-width characters inside words, full-width or homoglyph letters, odd whitespace,
 * or the whole instruction wrapped in base64.
 */

const HIDDEN = /[​-‏‪-‮⁠-⁤⁦-⁩﻿­\u{E0000}-\u{E007F}]/gu;

/** Common Cyrillic/Greek look-alikes mapped to the Latin letter they imitate. */
const HOMOGLYPHS: Record<string, string> = {
  а: "a", в: "b", с: "c", е: "e", һ: "h", і: "i", ј: "j", к: "k", м: "m", н: "h", о: "o", р: "p", ѕ: "s", т: "t", у: "y", х: "x",
  ο: "o", α: "a", ε: "e", ν: "v", ι: "i", κ: "k", ρ: "p", τ: "t", υ: "u", χ: "x",
};

export function normalizeText(s: string): string {
  let out = s.normalize("NFKC").replace(HIDDEN, "");
  out = out.replace(/[Ͱ-ϿЀ-ӿ]/g, (c) => HOMOGLYPHS[c.toLowerCase()] ?? c);
  return out.replace(/[ \t  - 　]+/g, " ");
}

export interface DecodedBlob {
  /** The original encoded token (truncated, for evidence). */
  encoded: string;
  decoded: string;
}

const B64 = /(?<![A-Za-z0-9+/_-])[A-Za-z0-9+/_-]{32,}={0,2}(?![A-Za-z0-9+/_-])/g;
const HEX = /(?<![0-9a-fA-F])(?:[0-9a-fA-F]{2}){24,}(?![0-9a-fA-F])/g;

function printableRatio(s: string): number {
  if (!s.length) return 0;
  let ok = 0;
  for (const ch of s) {
    const c = ch.codePointAt(0)!;
    if ((c >= 32 && c < 127) || c === 10 || c === 13 || c === 9) ok++;
  }
  return ok / s.length;
}

/** Find base64 / hex blobs that decode to mostly-readable text. */
export function decodeBlobs(s: string): DecodedBlob[] {
  const out: DecodedBlob[] = [];
  for (const m of s.matchAll(B64)) {
    const token = m[0];
    // Skip things that are obviously not base64 (e.g. long identifiers, paths, hashes of only lowercase hex).
    if (/^[a-z0-9_-]+$/.test(token) && !/[0-9]/.test(token)) continue;
    try {
      const decoded = Buffer.from(token.replace(/-/g, "+").replace(/_/g, "/"), "base64").toString("utf8");
      if (decoded.length >= 16 && printableRatio(decoded) > 0.92 && /[a-z]{3}/i.test(decoded)) out.push({ encoded: token, decoded });
    } catch {
      /* not base64 */
    }
  }
  for (const m of s.matchAll(HEX)) {
    try {
      const decoded = Buffer.from(m[0], "hex").toString("utf8");
      if (decoded.length >= 16 && printableRatio(decoded) > 0.92 && /[a-z]{3}/i.test(decoded)) out.push({ encoded: m[0], decoded });
    } catch {
      /* not hex */
    }
  }
  return out.slice(0, 5);
}
