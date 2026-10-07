import type { Rule, RuleHit, Severity } from "../core/types.js";
import { normalizeText } from "../detectors/security/normalize.js";
import { snippet } from "../detectors/tools/text.js";
import { allSurfaces } from "./security-rules.js";

const URL_RE = /\b(?:https?|ftp|wss?):\/\/[^\s"'<>)\]}]+/gi;
/** Hosts that are routinely used to catch exfiltrated data or to test for blind SSRF. */
const CATCHER_HOSTS =
  /(^|\.)(webhook\.site|requestbin\.(com|net)|pipedream\.net|ngrok(-free)?\.(io|app|dev)|interact\.sh|oast\.(pro|live|site|online|fun|me)|burpcollaborator\.net|canarytokens\.(com|org)|requestcatcher\.com|beeceptor\.com|hookbin\.com|trycloudflare\.com|serveo\.net|localtunnel\.me|loca\.lt)$/i;
/** Hosts that are normal in documentation. */
const BENIGN_HOSTS = /(^|\.)(example\.(com|org|net)|localhost|json-schema\.org|modelcontextprotocol\.io|w3\.org|iana\.org|ietf\.org)$/i;
const INTERNAL_ADDR =
  /\b(169\.254\.169\.254|169\.254\.170\.2|100\.100\.100\.200|metadata\.google\.internal|fd00:ec2::254|(?:10|127)\.\d{1,3}\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3})\b/;
const DANGEROUS_SCHEME = /\b(file|gopher|dict|ldap|tftp|jar|netdoc):\/\/[^\s"']*/i;
/** Markdown/HTML images whose URL carries data: the classic zero-click exfiltration channel. */
const IMAGE_EXFIL = /(!\[[^\]]*\]\(\s*https?:\/\/[^)\s]*[?&=][^)\s]*\)|<img[^>]+src\s*=\s*["']?https?:\/\/[^"'>\s]*[?&=][^"'>\s]*)/i;
const PLACEHOLDER_IN_URL = /(\{[a-z_]+\}|\$\{[^}]+\}|<[a-z_ ]+>|%s|\[[a-z_ ]+\])/i;

function hostOf(u: string): string | undefined {
  try {
    return new URL(u).hostname.toLowerCase();
  } catch {
    return undefined;
  }
}

export const networkRules: Rule[] = [
  {
    id: "MCP-031",
    name: "Network risk indicator",
    category: "security",
    severity: "medium",
    group: "network_risk",
    description:
      "Server-provided text contains URLs or addresses that suggest data exfiltration or SSRF: known capture/tunnel hosts, URLs with templated data, image-embedded exfiltration, links to internal or cloud-metadata addresses, or non-HTTP schemes such as file:// and gopher://.",
    why: "Text that points the model at external hosts is the standard way to move stolen data out (render an image, call a webhook), and internal addresses or odd URL schemes are the standard way to reach cloud credentials through a fetch tool.",
    recommendation:
      "Remove external URLs from tool metadata unless they are documentation links users expect. Never let metadata or tool output instruct the model to call or render external URLs, and block internal/metadata addresses and non-HTTP schemes in any tool that fetches URLs.",
    check({ snapshot }) {
      const hits: RuleHit[] = [];
      const seen = new Set<string>();
      const add = (key: string, hit: RuleHit) => {
        if (seen.has(key)) return;
        seen.add(key);
        hits.push(hit);
      };
      for (const s of allSurfaces(snapshot, { includeNames: false })) {
        if (s.origin === "stderr") continue;
        const text = normalizeText(s.text);
        const subject = s.where;

        const img = IMAGE_EXFIL.exec(text);
        if (img)
          add(`${s.tool}|${s.where}|img`, {
            tool: s.tool,
            severity: "high",
            message: `${subject}: embeds an image/link whose URL carries query data (zero-click exfiltration channel).`,
            evidence: `"${snippet(text, img.index, img[0].length)}"`,
          });

        if (s.origin === "output") continue; // below this point: metadata only

        for (const m of text.matchAll(URL_RE)) {
          const url = m[0].replace(/[.,;:]+$/, "");
          const host = hostOf(url);
          if (!host || BENIGN_HOSTS.test(host)) continue;
          let sev: Severity = "low";
          let why = "contains an external URL (confirm it is an expected documentation link)";
          if (CATCHER_HOSTS.test(host)) {
            sev = "high";
            why = `points at ${host}, a host commonly used to capture exfiltrated data`;
          } else if (/^\d{1,3}(\.\d{1,3}){3}$/.test(host) && !INTERNAL_ADDR.test(host)) {
            sev = "medium";
            why = "points at a bare IP address";
          } else if (PLACEHOLDER_IN_URL.test(url) && /[?&=]/.test(url)) {
            sev = "medium";
            why = "contains a URL with a placeholder for data in its query string";
          }
          add(`${s.tool}|${s.where}|url|${host}`, {
            tool: s.tool,
            severity: sev,
            message: `${subject}: ${why}.`,
            evidence: `"${snippet(text, m.index!, m[0].length)}"`,
          });
        }

        const internal = INTERNAL_ADDR.exec(text);
        if (internal)
          add(`${s.tool}|${s.where}|internal`, {
            tool: s.tool,
            severity: /169\.254|metadata|100\.100\.100\.200|fd00:ec2/.test(internal[0]) ? "high" : "medium",
            message: `${subject}: references an internal or cloud-metadata address (${internal[0]}).`,
            evidence: `"${snippet(text, internal.index, internal[0].length)}"`,
          });

        const scheme = DANGEROUS_SCHEME.exec(text);
        if (scheme && !/resource/.test(s.origin))
          add(`${s.tool}|${s.where}|scheme`, {
            tool: s.tool,
            severity: "medium",
            message: `${subject}: mentions a non-HTTP URL scheme (${scheme[1]}://) often used to bypass SSRF filters.`,
            evidence: `"${snippet(text, scheme.index, scheme[0].length)}"`,
          });
      }
      return hits;
    },
  },
];
