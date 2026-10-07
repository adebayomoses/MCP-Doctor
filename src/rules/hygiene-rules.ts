import type { Rule, RuleHit } from "../core/types.js";

const LOCAL_HOST = /^(localhost|127\.\d+\.\d+\.\d+|\[?::1\]?|.*\.localhost)$/i;
const SENSITIVE_URI =
  /(\/etc\/(passwd|shadow|sudoers)|[\\/]\.ssh[\\/]|\bid_(rsa|ed25519|ecdsa)\b|[\\/]\.aws[\\/]|[\\/]\.gnupg[\\/]|\.env(\.|$|\b)|\.npmrc|\.netrc|\.pem$|\.key$|\.p12$|\.pfx$|keychain|wallet\.dat|credentials?\.(json|ya?ml|txt)|secrets?\.(json|ya?ml|txt))/i;

export const hygieneRules: Rule[] = [
  {
    id: "MCP-026",
    name: "Excessive number of tools",
    category: "quality",
    severity: "low",
    group: "quality",
    description: "The server exposes a very large number of tools.",
    why: "Every tool definition is sent to the model on each request. Large tool sets burn context, slow responses and make wrong-tool selection more likely.",
    recommendation: "Group rarely used tools behind a smaller set, split the server by domain, or let clients enable tools selectively.",
    check({ snapshot }) {
      const n = snapshot.tools.length;
      if (n <= 40) return [];
      const chars = snapshot.tools.reduce((a, t) => a + JSON.stringify(t).length, 0);
      return [{ message: `Server exposes ${n} tools (about ${Math.round(chars / 4).toLocaleString()} tokens of definitions).` }];
    },
  },
  {
    id: "MCP-027",
    name: "Declared capability is empty",
    category: "protocol",
    severity: "low",
    group: "protocol",
    description: "The server declares the tools, resources or prompts capability but lists none.",
    why: "Clients show and plan around declared capabilities; an empty declaration is usually a configuration or registration bug.",
    recommendation: "Register your handlers before connecting, or drop the capability from the initialize response if you do not use it.",
    check({ snapshot }) {
      if (!snapshot.connected) return [];
      const hits: RuleHit[] = [];
      for (const kind of ["tools", "resources", "prompts"] as const) {
        if (snapshot.capabilities?.[kind] && !snapshot.listErrors[kind] && snapshot[kind].length === 0)
          hits.push({ message: `Server declares the "${kind}" capability but ${kind}/list returned nothing.` });
      }
      return hits;
    },
  },
  {
    id: "MCP-028",
    name: "Insecure transport",
    category: "security",
    severity: "high",
    group: "dangerous_permissions",
    description: "A remote server is reached over plain HTTP instead of HTTPS.",
    why: "Tool calls, results and any credentials in headers can be read or modified by anyone on the network path.",
    recommendation: "Serve the MCP endpoint over HTTPS (TLS) and redirect or disable plain HTTP. Plain HTTP is acceptable only for localhost.",
    check({ snapshot, config }) {
      const url = config.server?.url;
      if (!snapshot.connected || !url) return [];
      let u: URL;
      try { u = new URL(url); } catch { return []; }
      if (u.protocol !== "http:" || LOCAL_HOST.test(u.hostname)) return [];
      const auth = Object.keys(config.server?.headers ?? {}).some((h) => /^(authorization|x-api-key|cookie)$/i.test(h));
      return [
        {
          severity: auth ? "critical" : "high",
          message: `Server is reached over unencrypted HTTP (${u.host})${auth ? " and credentials were sent with the request" : ""}.`,
        },
      ];
    },
  },
  {
    id: "MCP-029",
    name: "Missing server identity",
    category: "protocol",
    severity: "low",
    group: "protocol",
    description: "The initialize response has no server name or version.",
    why: "Clients and audit logs identify servers by name and version; without them, results and incidents cannot be attributed or pinned.",
    recommendation: "Return `serverInfo: { name, version }` from initialize (MCP SDKs do this from the constructor arguments).",
    check({ snapshot }) {
      if (!snapshot.connected) return [];
      const s = snapshot.serverInfo;
      const missing = [!s?.name && "name", !s?.version && "version"].filter(Boolean);
      return missing.length ? [{ message: `serverInfo is missing ${missing.join(" and ")}.` }] : [];
    },
  },
  {
    id: "MCP-030",
    name: "Sensitive resource exposure",
    category: "security",
    severity: "high",
    group: "dangerous_permissions",
    description: "A listed resource points at a sensitive location such as SSH keys, cloud credentials, .env files, or system password files.",
    why: "Resources are readable by the model and, through it, by anyone who can influence the conversation. Credential files should never be exposed.",
    recommendation: "Remove the resource, or serve a sanitised copy. Restrict file-backed resources to a dedicated, non-sensitive directory.",
    check({ snapshot }) {
      const hits: RuleHit[] = [];
      for (const r of snapshot.resources) {
        const subject = `${r.uri} ${r.name ?? ""}`;
        const m = SENSITIVE_URI.exec(subject);
        if (m) hits.push({ message: `Resource "${r.uri}" appears to expose sensitive data.`, evidence: `matched "${m[0]}"` });
      }
      return hits;
    },
  },
];
