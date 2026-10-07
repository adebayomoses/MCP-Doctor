import type { Rule, RuleHit, ServerSnapshot } from "../core/types.js";
import {
  HIDDEN_CHARS_RE,
  PROMPT_INJECTION_PATTERNS,
  SECRET_PATTERNS,
  TOOL_POISONING_PATTERNS,
  redact,
  type Pattern,
} from "../detectors/security/patterns.js";
import { decodeBlobs, normalizeText } from "../detectors/security/normalize.js";
import { classifyTool, hasCapability, type Capability } from "../detectors/tools/capabilities.js";
import { isConstrained, paramType, snippet, toolParams, toolTextSurfaces } from "../detectors/tools/text.js";

type Origin = "tool" | "instructions" | "resource" | "prompt" | "output" | "stderr";
export interface Surface {
  tool?: string;
  origin: Origin;
  where: string;
  text: string;
}

/** Every piece of server-provided text a model or user might read. */
export function allSurfaces(snap: ServerSnapshot, opts: { includeNames: boolean }): Surface[] {
  const out: Surface[] = [];
  for (const t of snap.tools) {
    for (const s of toolTextSurfaces(t)) {
      if (!opts.includeNames && (s.where === "name" || s.where.startsWith("param name"))) continue;
      out.push({ tool: t.name, origin: "tool", where: s.where, text: s.text });
    }
  }
  if (snap.instructions) out.push({ origin: "instructions", where: "server instructions", text: snap.instructions });
  for (const r of snap.resources) {
    for (const f of ["name", "description", "title"] as const) {
      const v = (r as any)[f];
      if (typeof v === "string") out.push({ origin: "resource", where: `resource ${r.uri} ${f}`, text: v });
    }
  }
  for (const p of snap.prompts) {
    if (typeof p.description === "string")
      out.push({ origin: "prompt", where: `prompt ${p.name} description`, text: p.description });
    for (const a of p.arguments ?? [])
      if (typeof a?.description === "string")
        out.push({ origin: "prompt", where: `prompt ${p.name} argument ${a.name}`, text: a.description });
  }
  for (const c of snap.toolCalls)
    if (c.text) out.push({ tool: c.tool, origin: "output", where: `output of ${c.tool}`, text: c.text });
  if (snap.stderr) out.push({ origin: "stderr", where: "server stderr", text: snap.stderr });
  return out;
}

/**
 * Match patterns against the text as written, then against a normalised copy
 * (zero-width characters removed, homoglyphs folded) and against any base64/hex
 * blobs that decode to readable text, so simple obfuscation does not evade detection.
 */
function matchPatterns(surfaces: Surface[], patterns: Pattern[]): RuleHit[] {
  const hits: RuleHit[] = [];
  const seen = new Set<string>();
  for (const s of surfaces) {
    const normalized = normalizeText(s.text);
    const variants: { text: string; how: string }[] = [{ text: s.text, how: "" }];
    if (normalized !== s.text) variants.push({ text: normalized, how: " (after removing hidden characters / look-alike letters)" });
    for (const b of decodeBlobs(normalized)) variants.push({ text: b.decoded, how: ` (inside encoded text ${b.encoded.slice(0, 12)}…)` });
    for (const p of patterns) {
      for (const v of variants) {
        const m = p.re.exec(v.text);
        if (!m) continue;
        const key = `${s.tool ?? ""}|${s.where}|${p.id}`;
        if (seen.has(key)) break;
        seen.add(key);
        hits.push({
          tool: s.tool,
          message: `${s.where}: ${p.label}${v.how}.`,
          evidence: `"${snippet(v.text, m.index, m[0].length)}"`,
        });
        break;
      }
    }
  }
  return hits;
}

const hasAllowlistWords = /\b(allow-?list|allowed (commands?|directories|paths?|hosts?|domains?)|whitelist|restricted to|only (the )?(following|these)|sandbox(ed)?|within the (project|workspace|root)|inside the (project|workspace|root))\b/i;

function anyUnconstrainedString(tool: any, nameRe: RegExp): string | undefined {
  for (const [name, p] of Object.entries<any>(toolParams(tool))) {
    if (nameRe.test(name) && paramType(p) === "string" && !isConstrained(p) && !p.pattern) return name;
  }
  return undefined;
}

export const securityRules: Rule[] = [
  {
    id: "MCP-004",
    name: "Prompt injection indicator",
    category: "security",
    severity: "critical",
    group: "prompt_injection",
    description: "Server-provided text (tool descriptions, instructions, prompts, resources or tool output) contains phrasing that tries to override the model's instructions.",
    why: "Anything an MCP server returns is read by the model. Embedded instructions can hijack the agent, leak data or trigger unwanted tool calls.",
    recommendation: "Remove model-directed instructions from tool metadata and responses. Descriptions should say what a tool does, not tell the model how to behave. Treat tool output as untrusted data.",
    check({ snapshot }) {
      return matchPatterns(allSurfaces(snapshot, { includeNames: false }), PROMPT_INJECTION_PATTERNS);
    },
  },
  {
    id: "MCP-005",
    name: "Tool poisoning indicator",
    category: "security",
    severity: "critical",
    group: "tool_poisoning",
    description: "Tool metadata contains hidden or manipulative instructions: concealed tags, references to sensitive files, demands for side actions, exfiltration cues, tool shadowing, or invisible characters.",
    why: "Users usually see only a tool's name. Hidden text in the description or schema can silently steer the model into reading secrets or sending data elsewhere.",
    recommendation: "Keep tool descriptions short, factual and user-visible. Remove hidden tags, invisible characters and any text that references other tools, files or URLs. Pin and review tool definitions on every update.",
    check({ snapshot }) {
      const surfaces = allSurfaces(snapshot, { includeNames: false }).filter((s) => s.origin !== "output" && s.origin !== "stderr");
      const hits = matchPatterns(surfaces, TOOL_POISONING_PATTERNS);
      const seen = new Set<string>();
      for (const s of allSurfaces(snapshot, { includeNames: true })) {
        if (s.origin === "output" || s.origin === "stderr") continue;
        const m = HIDDEN_CHARS_RE.exec(s.text);
        if (!m) continue;
        const key = `${s.tool ?? ""}|${s.where}`;
        if (seen.has(key)) continue;
        seen.add(key);
        const cp = m[0].codePointAt(0)!.toString(16).toUpperCase().padStart(4, "0");
        hits.push({
          tool: s.tool,
          message: `${s.where}: contains invisible or direction-changing Unicode characters (U+${cp}).`,
          evidence: "These can hide instructions from human reviewers.",
        });
      }
      return hits;
    },
  },
  {
    id: "MCP-006",
    name: "Secret exposure",
    category: "security",
    severity: "high",
    group: "secret_exposure",
    description: "Text from the server (descriptions, schema defaults/examples, instructions, tool output or stderr) contains what looks like an API key, token, password or private key.",
    why: "Secrets published in metadata or logs are readable by every client, model provider and log collector that touches the server.",
    recommendation: "Revoke and rotate the exposed credential, remove it from the source, load secrets from environment variables or a secret manager at runtime, and never echo them in output or logs.",
    check({ snapshot }) {
      const hits: RuleHit[] = [];
      const seen = new Set<string>();
      for (const s of allSurfaces(snapshot, { includeNames: false })) {
        for (const p of SECRET_PATTERNS) {
          const m = p.re.exec(s.text);
          if (!m) continue;
          const key = `${s.tool ?? ""}|${s.where}|${p.label}`;
          if (seen.has(key)) continue;
          seen.add(key);
          hits.push({
            tool: s.tool,
            message: `${s.where}: possible ${p.label}.`,
            evidence: `matched ${redact(m[0])}`,
          });
        }
      }
      return hits;
    },
  },
  {
    id: "MCP-007",
    name: "Excessive permissions",
    category: "security",
    severity: "high",
    group: "dangerous_permissions",
    description: "A tool can modify databases, read credentials, or make requests to arbitrary URLs, or the server bundles many high-impact capabilities.",
    why: "The more a server can do, the more damage a confused or manipulated model can cause. Least privilege limits the blast radius.",
    recommendation: "Split high-impact tools into separate, opt-in servers, scope each one to the minimum resources it needs (specific tables, hosts, paths), and set annotations such as readOnlyHint/destructiveHint.",
    check({ snapshot }) {
      const hits: RuleHit[] = [];
      const bundle = new Map<Capability, string[]>();
      for (const tool of snapshot.tools) {
        const caps = classifyTool(tool);
        for (const c of caps) {
          if (["shell", "fs_write", "fs_delete", "db_write", "credentials"].includes(c.capability)) {
            bundle.set(c.capability, [...(bundle.get(c.capability) ?? []), tool.name]);
          }
        }
        const cred = hasCapability(caps, "credentials");
        if (cred)
          hits.push({ tool: tool.name, message: "Tool appears to read or handle credentials.", evidence: `matched ${cred.reason}` });
        const dbw = hasCapability(caps, "db_write");
        if (dbw && tool.annotations?.readOnlyHint !== true)
          hits.push({ tool: tool.name, message: "Tool can modify database contents.", evidence: `matched ${dbw.reason}` });
        const net = hasCapability(caps, "network");
        if (net) {
          const urlParam = anyUnconstrainedString(tool, /^(url|uri|endpoint|host|hostname|address|webhook)$/i);
          if (urlParam)
            hits.push({
              tool: tool.name,
              severity: "medium",
              message: `Tool makes network requests to a caller-supplied "${urlParam}" with no allowlist (SSRF / data-exfiltration risk).`,
              evidence: `matched ${net.reason}`,
            });
        }
      }
      if (bundle.size >= 3) {
        hits.push({
          message: `Server exposes ${bundle.size} distinct high-impact capabilities (${[...bundle.keys()].join(", ")}).`,
          evidence: [...bundle.entries()].map(([c, t]) => `${c}: ${t.slice(0, 3).join(", ")}${t.length > 3 ? "…" : ""}`).join(" · "),
        });
      }
      return hits;
    },
  },
  {
    id: "MCP-008",
    name: "Command injection risk",
    category: "security",
    severity: "high",
    group: "command_injection",
    description: "A tool appears to wrap a command-line program and accepts unconstrained string arguments that could reach a shell or subprocess.",
    why: "Values passed into a command line can inject extra arguments or shell metacharacters (`; rm -rf`, `$(...)`, `--flag`) when not validated or escaped.",
    recommendation: "Invoke programs with an argument array (no shell), validate inputs with `enum`/`pattern`, reject values starting with `-`, and avoid string concatenation into command lines.",
    check({ snapshot }) {
      const hits: RuleHit[] = [];
      const wraps = /\b(runs?|executes?|invokes?|spawns?|calls?|wraps?|shells? out)\b[^.]{0,40}\b(cli|command[- ]?line|command|binary|subprocess|git|docker|kubectl|ffmpeg|curl|ping|nslookup|grep|npm|pip|make|ssh|scp|tar|zip|shell)\b/i;
      const cliName = /\b(git|docker|kubectl|ffmpeg|ping|nslookup|traceroute|grep|npm|pip|make|ssh|scp|tar|zip|convert|nmap)\b/i;
      const argParams = /^(args?|arguments|flags|options|filename|file_?name|host|hostname|domain|ip|target|branch|repo|image|package|name|input|expression|path|pattern|ref|tag|remote|url)$/i;
      for (const tool of snapshot.tools) {
        const caps = classifyTool(tool);
        if (hasCapability(caps, "shell")) continue; // reported by MCP-012
        const spaced = tool.name.replace(/([a-z0-9])([A-Z])/g, "$1 $2").replace(/[_\-.]+/g, " ");
        const desc = tool.description ?? "";
        const paramText = Object.values<any>(toolParams(tool)).map((p) => p?.description ?? "").join(" ");
        const looksWrapped = wraps.test(desc) || cliName.test(spaced) || /\b(shell|command[- ]line|cli arguments?)\b/i.test(paramText);
        if (!looksWrapped) continue;
        const p = anyUnconstrainedString(tool, argParams);
        if (!p) continue;
        hits.push({
          tool: tool.name,
          message: `Tool appears to wrap a command-line program and passes an unconstrained "${p}" string to it.`,
          evidence: wraps.test(desc) ? `description: "${snippet(desc, desc.search(wraps), 40)}"` : `tool name "${tool.name}"`,
        });
      }
      return hits;
    },
  },
  {
    id: "MCP-011",
    name: "Dangerous filesystem operation",
    category: "security",
    severity: "high",
    group: "dangerous_permissions",
    description: "A tool can write, modify or delete files, especially with an unrestricted path parameter.",
    why: "Unscoped file writes allow overwriting configs, shell profiles or SSH keys; path traversal (`../`) can escape the intended directory.",
    recommendation: "Restrict operations to an allowed root directory, resolve and verify paths server-side, require confirmation for deletes, and annotate the tool with destructiveHint.",
    check({ snapshot }) {
      const hits: RuleHit[] = [];
      for (const tool of snapshot.tools) {
        const caps = classifyTool(tool);
        const del = hasCapability(caps, "fs_delete");
        const wr = hasCapability(caps, "fs_write");
        if (!del && !wr) continue;
        const pathParam = anyUnconstrainedString(tool, /^(path|file|filename|filepath|file_?path|dir|directory|dest|destination|target|source)$/i);
        const scoped = hasAllowlistWords.test(tool.description ?? "");
        const hit = (del ?? wr)!;
        hits.push({
          tool: tool.name,
          severity: pathParam && !scoped ? "high" : "medium",
          message: del
            ? `Tool can delete files${pathParam ? ` via an unrestricted "${pathParam}" parameter` : ""}.`
            : `Tool can write or modify files${pathParam ? ` via an unrestricted "${pathParam}" parameter` : ""}.`,
          evidence: `matched ${hit.reason}${scoped ? "; description mentions a scope restriction" : ""}`,
        });
      }
      return hits;
    },
  },
  {
    id: "MCP-012",
    name: "Dangerous shell operation",
    category: "security",
    severity: "critical",
    group: "dangerous_permissions",
    description: "A tool runs shell commands, scripts or arbitrary code.",
    why: "Shell execution gives anything that can influence the model (prompt injection, poisoned content) full control of the host with the server's privileges.",
    recommendation: "Avoid generic command execution. Expose narrow, purpose-built tools instead, or enforce an allowlist of commands and arguments, run in a sandbox/container with least privilege, and require human confirmation.",
    check({ snapshot }) {
      const hits: RuleHit[] = [];
      for (const tool of snapshot.tools) {
        const sh = hasCapability(classifyTool(tool), "shell");
        if (!sh) continue;
        const allow = hasAllowlistWords.test(tool.description ?? "");
        const free = anyUnconstrainedString(tool, /^(command|cmd|script|code|shell_?command|bash|powershell|args?|arguments)$/i);
        hits.push({
          tool: tool.name,
          severity: allow && !free ? "high" : "critical",
          message: free
            ? `Tool executes commands from an unconstrained "${free}" parameter with no allowlist.`
            : "Tool executes shell commands or code.",
          evidence: `matched ${sh.reason}`,
        });
      }
      return hits;
    },
  },
];
