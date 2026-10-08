import { SECRET_PATTERNS } from "./patterns.js";

const SECRET_FLAG = /(--?[\w-]*(?:token|key|secret|password|passwd|auth|credential)[\w-]*)([= ]+)(\S+)/gi;
const SECRET_QUERY = /([?&][\w-]*(?:token|key|secret|password|auth|sig|signature)[\w-]*=)([^&\s]+)/gi;
const BEARER = /\b(Bearer|Basic)\s+[A-Za-z0-9._~+/=-]{8,}/gi;
const URL_CREDS = /(\b[a-z][a-z0-9+.-]*:\/\/)[^\s/@:]+:[^\s/@]+@/gi;

/**
 * Remove secrets from a command line or URL before it is stored in a report, history file or
 * public scoreboard. Targets come from users' own configs and often embed tokens.
 */
export function redactTarget(target: string): string {
  let out = target
    .replace(URL_CREDS, "$1***:***@")
    .replace(SECRET_QUERY, "$1***")
    .replace(BEARER, "$1 ***")
    .replace(SECRET_FLAG, "$1$2***");
  for (const p of SECRET_PATTERNS) {
    const re = new RegExp(p.re.source, p.re.flags.includes("g") ? p.re.flags : p.re.flags + "g");
    out = out.replace(re, "***");
  }
  return out;
}
