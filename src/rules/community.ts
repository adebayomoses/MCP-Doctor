import { existsSync, readdirSync, readFileSync, statSync } from "node:fs";
import { extname, join, resolve } from "node:path";
import { pathToFileURL } from "node:url";
import { parse as parseYaml } from "yaml";
import { CATEGORIES, SEVERITY_ORDER, type Category, type ResolvedConfig, type Rule, type RuleHit, type Severity } from "../core/types.js";
import { normalizeText } from "../detectors/security/normalize.js";
import { snippet } from "../detectors/tools/text.js";
import { allSurfaces, type Surface } from "./security-rules.js";
import { registerRule, unregisterRule } from "./index.js";

/** Community rule IDs: a short namespace and a number, e.g. ACME-001. `MCP-` is reserved for built-in rules. */
export const COMMUNITY_ID = /^(?!MCP-)[A-Z][A-Z0-9]{1,9}-\d{3,}$/;

const APPLIES = ["tool_name", "tool_description", "parameter_description", "instructions", "resource", "prompt", "output"] as const;
type AppliesTo = (typeof APPLIES)[number];

function surfaceKind(s: Surface): AppliesTo | undefined {
  if (s.origin === "instructions") return "instructions";
  if (s.origin === "resource") return "resource";
  if (s.origin === "prompt") return "prompt";
  if (s.origin === "output") return "output";
  if (s.origin !== "tool") return undefined;
  if (s.where === "name") return "tool_name";
  if (s.where === "description") return "tool_description";
  if (/^param ".*" description$/.test(s.where) || /^input .*description$/.test(s.where)) return "parameter_description";
  return undefined;
}

/** Characters of each text we are willing to run community regexes against. */
const MAX_TEXT = 20_000;

function globToRegExp(g: string): RegExp {
  return new RegExp("^" + g.replace(/[.+^${}()|[\]\\]/g, "\\$&").replace(/\*/g, ".*").replace(/\?/g, ".") + "$", "i");
}

/**
 * Compile a user-supplied regex, refusing patterns likely to backtrack catastrophically. Community
 * rules run on every scanned text, so a hostile or careless pattern must not be able to hang a scan.
 */
const MAX_OPEN_ENDED = 4;

/** Number of unbounded repetitions (`*`, `+`, `{n,}`) outside escapes and character classes. */
export function countOpenEnded(source: string): number {
  const bare = source.replace(/\\./g, "x").replace(/\[(?:[^\]\\]|\\.)*\]/g, "x");
  return (bare.match(/[*+]|\{\d+,\}/g) ?? []).length;
}

export function compileSafeRegex(source: string, flags = "i", where = "pattern"): RegExp {
  if (typeof source !== "string" || !source.length) throw new Error(`${where}: pattern must be a non-empty string`);
  if (source.length > 300) throw new Error(`${where}: pattern is longer than 300 characters`);
  if (!/^[imsu]*$/.test(flags)) throw new Error(`${where}: flags may only contain i, m, s, u`);
  // A quantified group that itself contains a quantifier or an alternation, such as (a+)+, (a|aa)+ or (a?){30},
  // is the classic source of exponential backtracking. Refuse the whole family rather than try to judge each one.
  if (/\((?:\?:)?(?:[^()\\]|\\.)*[+*?{|](?:[^()\\]|\\.)*\)[+*{]/.test(source))
    throw new Error(`${where}: a repeated group that contains a quantifier or alternation (e.g. "(a+)+", "(a|b)*") can cause catastrophic backtracking; rewrite it without the outer repetition`);
  // Several open-ended repetitions in one pattern (e.g. ".*.*.*.*.*x") backtrack polynomially: the work grows like
  // n^k for k of them. Count them without running the pattern, so rejecting a bad one is instant on any machine.
  const openEnded = countOpenEnded(source);
  if (openEnded > MAX_OPEN_ENDED)
    throw new Error(`${where}: ${openEnded} open-ended repetitions (*, + or {n,}); at most ${MAX_OPEN_ENDED} are allowed because more can make matching extremely slow. Use bounded forms such as .{0,40}`);
  let re: RegExp;
  try {
    re = new RegExp(source, flags);
  } catch (e) {
    throw new Error(`${where}: invalid regular expression: ${(e as Error).message}`);
  }
  // Defence in depth: time what is left on small adversarial inputs, smallest first. With at most MAX_OPEN_ENDED
  // repetitions the cost at the largest size is bounded (about n^4 / 24 steps), so this cannot hang validation.
  for (const n of [16, 32, 64, 128]) {
    for (const probe of ["a".repeat(n) + "!", " ".repeat(n) + "!", "ab".repeat(n / 2) + "!"]) {
      const t = performance.now();
      re.test(probe);
      if (performance.now() - t > 30) throw new Error(`${where}: pattern is too slow on adversarial input (possible catastrophic backtracking)`);
    }
  }
  return re;
}

interface RawRule {
  id?: unknown; name?: unknown; category?: unknown; severity?: unknown;
  description?: unknown; why?: unknown; recommendation?: unknown;
  applies_to?: unknown; tools?: unknown; match?: { any?: unknown; none?: unknown; flags?: unknown };
}

const str = (v: unknown, field: string, where: string): string => {
  if (typeof v !== "string" || !v.trim()) throw new Error(`${where}: "${field}" is required and must be a non-empty string`);
  return v.trim();
};

/** Validate one declarative rule and turn it into a Rule. Throws a descriptive error if invalid. */
export function buildDeclarativeRule(raw: RawRule, file: string): Rule {
  const where = `${file}${typeof raw?.id === "string" ? ` (${raw.id})` : ""}`;
  if (!raw || typeof raw !== "object") throw new Error(`${where}: rule must be a mapping`);
  const id = str(raw.id, "id", where).toUpperCase();
  if (!COMMUNITY_ID.test(id)) throw new Error(`${where}: id "${id}" must look like ACME-001 (2-10 letters/digits, a dash, 3+ digits). The MCP- prefix is reserved for built-in rules.`);
  const severity = str(raw.severity, "severity", where) as Severity;
  if (!SEVERITY_ORDER.includes(severity)) throw new Error(`${where}: severity must be one of ${SEVERITY_ORDER.join(", ")}`);
  const category = (raw.category === undefined ? "security" : str(raw.category, "category", where)) as Category;
  if (!CATEGORIES.includes(category)) throw new Error(`${where}: category must be one of ${CATEGORIES.join(", ")}`);
  const name = str(raw.name, "name", where);
  // Documentation is mandatory so every shared rule explains itself.
  const description = str(raw.description, "description", where);
  const why = str(raw.why, "why", where);
  const recommendation = str(raw.recommendation, "recommendation", where);

  const applies: AppliesTo[] =
    raw.applies_to === undefined ? ["tool_description", "parameter_description"] : (Array.isArray(raw.applies_to) ? raw.applies_to : [raw.applies_to]) as AppliesTo[];
  for (const a of applies) if (!APPLIES.includes(a)) throw new Error(`${where}: applies_to "${String(a)}" is not valid (use: ${APPLIES.join(", ")})`);

  const flags = raw.match?.flags === undefined ? "i" : String(raw.match.flags);
  const anySrc = raw.match?.any;
  if (!Array.isArray(anySrc) || !anySrc.length || anySrc.length > 20) throw new Error(`${where}: match.any must be a list of 1-20 regular expressions`);
  const any = anySrc.map((p, i) => compileSafeRegex(String(p), flags, `${where} match.any[${i}]`));
  const noneSrc = raw.match?.none === undefined ? [] : raw.match.none;
  if (!Array.isArray(noneSrc) || noneSrc.length > 20) throw new Error(`${where}: match.none must be a list of up to 20 regular expressions`);
  const none = noneSrc.map((p, i) => compileSafeRegex(String(p), flags, `${where} match.none[${i}]`));
  const toolGlobs = raw.tools === undefined ? undefined : (Array.isArray(raw.tools) ? raw.tools : [raw.tools]).map((g) => globToRegExp(str(g, "tools[]", where)));

  return {
    id,
    name,
    category,
    severity,
    description,
    why,
    recommendation,
    check({ snapshot }) {
      const hits: RuleHit[] = [];
      const seen = new Set<string>();
      for (const s of allSurfaces(snapshot, { includeNames: true })) {
        const kind = surfaceKind(s);
        if (!kind || !applies.includes(kind)) continue;
        if (toolGlobs && !(s.tool && toolGlobs.some((g) => g.test(s.tool!)))) continue;
        const text = normalizeText(s.text).slice(0, MAX_TEXT);
        if (none.some((re) => re.test(text))) continue;
        for (const re of any) {
          const m = re.exec(text);
          if (!m) continue;
          const key = `${s.tool ?? ""}|${s.where}`;
          if (seen.has(key)) break;
          seen.add(key);
          hits.push({ tool: s.tool, message: `${s.where}: matches rule ${id}.`, evidence: `"${snippet(text, m.index, m[0].length)}"` });
          break;
        }
      }
      return hits;
    },
  };
}

function listFiles(path: string): string[] {
  const p = resolve(path);
  if (!existsSync(p)) throw new Error(`Community rules path not found: ${p}`);
  if (statSync(p).isFile()) return [p];
  return readdirSync(p)
    .filter((f) => /\.(ya?ml|json)$/i.test(f))
    .sort()
    .map((f) => join(p, f));
}

/** Load declarative rules from files or directories. Does not execute any code from the files. */
export function loadDeclarativeRules(paths: string[]): Rule[] {
  const rules: Rule[] = [];
  for (const path of paths) {
    for (const file of listFiles(path)) {
      let doc: any;
      try {
        const text = readFileSync(file, "utf8");
        doc = extname(file).toLowerCase() === ".json" ? JSON.parse(text) : parseYaml(text);
      } catch (e) {
        throw new Error(`Could not parse ${file}: ${(e as Error).message}`);
      }
      const list = Array.isArray(doc) ? doc : Array.isArray(doc?.rules) ? doc.rules : [doc];
      for (const raw of list) rules.push(buildDeclarativeRule(raw, file));
    }
  }
  const ids = new Set<string>();
  for (const r of rules) {
    if (ids.has(r.id)) throw new Error(`Duplicate community rule id ${r.id}`);
    ids.add(r.id);
  }
  return rules;
}

/** Load JavaScript plugin modules (default export: a Rule or an array of Rules). Runs their code: only call when the user opted in. */
export async function loadPluginRules(paths: string[]): Promise<Rule[]> {
  const rules: Rule[] = [];
  for (const path of paths) {
    const file = resolve(path);
    if (!existsSync(file)) throw new Error(`Plugin not found: ${file}`);
    const mod = await import(pathToFileURL(file).href);
    const exported = mod.default ?? mod.rules ?? mod.rule;
    for (const r of Array.isArray(exported) ? exported : [exported]) {
      if (!r || typeof r.check !== "function") throw new Error(`${file}: export a Rule object (or an array of them) with a check() function`);
      for (const f of ["id", "name", "category", "severity", "description", "why", "recommendation"])
        if (typeof r[f] !== "string" || !r[f]) throw new Error(`${file}: rule is missing "${f}"`);
      if (!COMMUNITY_ID.test(String(r.id))) throw new Error(`${file}: rule id "${r.id}" must look like ACME-001 (MCP- is reserved)`);
      rules.push(r as Rule);
    }
  }
  return rules;
}

const registered = new Set<string>();

/** Register external rules, replacing any this process registered earlier (so repeated loads are idempotent). */
export function registerExternalRules(rules: Rule[]): void {
  for (const id of registered) unregisterRule(id);
  registered.clear();
  for (const r of rules) {
    registerRule(r);
    registered.add(r.id);
  }
}

export interface CommunityOptions {
  allowPlugins?: boolean;
  /** Extra declarative rule paths from the command line. */
  rulePaths?: string[];
}

/** Load and register everything the config and CLI ask for. Returns what was loaded, for display. */
export async function applyCommunityRules(config: ResolvedConfig, o: CommunityOptions = {}): Promise<{ declarative: number; plugins: number; skippedPlugins: number }> {
  const declarative = loadDeclarativeRules([...config.communityRules, ...(o.rulePaths ?? [])]);
  let plugins: Rule[] = [];
  let skippedPlugins = 0;
  if (config.plugins.length) {
    if (o.allowPlugins) plugins = await loadPluginRules(config.plugins);
    else skippedPlugins = config.plugins.length;
  }
  if (declarative.length || plugins.length || skippedPlugins === 0) registerExternalRules([...declarative, ...plugins]);
  return { declarative: declarative.length, plugins: plugins.length, skippedPlugins };
}
