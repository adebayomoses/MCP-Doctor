import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { evaluate } from "../../src/core/detector.js";
import { allRules } from "../../src/rules/index.js";
import {
  applyCommunityRules,
  buildDeclarativeRule,
  compileSafeRegex,
  countOpenEnded,
  loadDeclarativeRules,
  loadPluginRules,
  registerExternalRules,
} from "../../src/rules/community.js";
import { cfg, makeSnapshot, tool } from "../fixtures/snapshot.js";

afterEach(() => registerExternalRules([]));

const base = {
  id: "ACME-101",
  name: "Test rule",
  severity: "medium",
  description: "d",
  why: "w",
  recommendation: "r",
  match: { any: ["\\bforbidden word\\b"] },
};
const tmp = () => mkdtempSync(join(tmpdir(), "mcpd-comm-"));

describe("declarative rule validation", () => {
  it("accepts a complete rule and defaults to security / tool + parameter descriptions", () => {
    const r = buildDeclarativeRule(base, "f.yml");
    expect(r).toMatchObject({ id: "ACME-101", category: "security", severity: "medium" });
  });
  it.each([
    ["built-in prefix", { id: "MCP-900" }, /reserved/],
    ["bad id", { id: "acme_1" }, /must look like/],
    ["bad severity", { severity: "urgent" }, /severity must be one of/],
    ["bad category", { category: "vibes" }, /category must be one of/],
    ["missing docs: why", { why: "" }, /"why" is required/],
    ["missing docs: recommendation", { recommendation: undefined }, /"recommendation" is required/],
    ["bad applies_to", { applies_to: ["everything"] }, /applies_to/],
    ["no patterns", { match: { any: [] } }, /match\.any/],
    ["invalid regex", { match: { any: ["(unclosed"] } }, /invalid regular expression/],
    ["bad flags", { match: { any: ["x"], flags: "g" } }, /flags may only contain/],
    ["too many patterns", { match: { any: Array.from({ length: 21 }, () => "x") } }, /1-20/],
    ["huge pattern", { match: { any: ["a".repeat(301)] } }, /300 characters/],
  ])("rejects: %s", (_n, over, msg) => {
    expect(() => buildDeclarativeRule({ ...base, ...over } as any, "f.yml")).toThrow(msg);
  });
});

describe("regex safety", () => {
  it.each(["(a+)+$", "(a|aa)+$", "(a?){30}a{30}", "(x*)*y", "(\\d+\\.)+", "(foo|bar)*baz"])("refuses nested/alternated repetition: %s", (p) => {
    expect(() => compileSafeRegex(p)).toThrow(/catastrophic/);
  });
  it("refuses polynomial blow-ups instantly, without running the pattern", () => {
    // Found on CI: validating this by timing it took 8 s on a slow runner. It must be rejected statically.
    for (const p of ["(.*)(.*)(.*)(.*)(.*)(.*)x", ".*.*.*.*.*x", "a+b+c+d+e+f+g", "\\w+\\s+\\w+\\s+\\w+\\s+x*"]) {
      const t = performance.now();
      expect(() => compileSafeRegex(p), p).toThrow(/open-ended repetitions/);
      expect(performance.now() - t, `${p} took too long to reject`).toBeLessThan(100);
    }
  });
  it("counts open-ended repetitions correctly, ignoring escapes and character classes", () => {
    expect(countOpenEnded("a*b+c{2,}")).toBe(3);
    expect(countOpenEnded("a{0,40}b{2,5}")).toBe(0);
    expect(countOpenEnded("\\*\\+[*+]x")).toBe(0);
    expect(countOpenEnded("^get_[a-z]+$")).toBe(1);
  });
  it("accepts a realistic pattern with the maximum allowed repetitions, and stays fast on it", () => {
    const p = "a.*b.*c.*d.*e"; // 4 open-ended repetitions: allowed
    const t = performance.now();
    expect(compileSafeRegex(p).source).toBe(p);
    expect(performance.now() - t).toBeLessThan(2000);
  });
  it.each(["\\bwithout (asking|confirmation)\\b", "ignore.{0,20}instructions", "^get_[a-z]+$", "(foo|bar)?baz", "\\d{3}-\\d{4}"])("accepts ordinary patterns: %s", (p) => {
    expect(compileSafeRegex(p).source).toBe(p);
  });
});

describe("running community rules", () => {
  const run = (tools: any[], rule: any, extra: any = {}) => {
    registerExternalRules([buildDeclarativeRule({ ...base, ...rule }, "f.yml")]);
    return evaluate(makeSnapshot({ tools, ...extra }), cfg()).result.findings.filter((f) => f.rule === "ACME-101");
  };
  it("fires with evidence, and findings carry the rule's own documentation", () => {
    const f = run([tool("t", { description: "This has a forbidden word inside." })], {});
    expect(f).toHaveLength(1);
    expect(f[0].evidence).toContain("forbidden word");
    expect(f[0]).toMatchObject({ severity: "medium", why: "w", recommendation: "r" });
  });
  it("respects applies_to", () => {
    const t = tool("t", { description: "clean", inputSchema: { type: "object", properties: { p: { type: "string", maxLength: 3, description: "forbidden word" } } } });
    expect(run([t], {})).toHaveLength(1); // default: also parameter descriptions
    expect(run([t], { applies_to: ["tool_description"] })).toHaveLength(0);
    expect(run([tool("t")], { applies_to: ["instructions"] }, { instructions: "a forbidden word" })).toHaveLength(1);
  });
  it("supports match.none exclusions and tools globs", () => {
    const d = tool("get_x", { description: "forbidden word but approved" });
    expect(run([d], { match: { any: ["forbidden word"], none: ["approved"] } })).toHaveLength(0);
    expect(run([tool("get_x", { description: "forbidden word" })], { tools: ["set_*"] })).toHaveLength(0);
    expect(run([tool("get_x", { description: "forbidden word" })], { tools: ["get_*"] })).toHaveLength(1);
  });
  it("still matches after obfuscation, like the built-in rules", () => {
    expect(run([tool("t", { description: "a for​bidden word" })], {})).toHaveLength(1);
  });
  it("can be re-levelled or disabled from config like any rule", () => {
    registerExternalRules([buildDeclarativeRule(base, "f.yml")]);
    const snap = makeSnapshot({ tools: [tool("t", { description: "forbidden word" })] });
    const hit = (c: any) => evaluate(snap, c).result.findings.filter((f) => f.rule === "ACME-101");
    expect(hit(cfg({ ruleOverrides: { "ACME-101": { severity: "critical" } } }))[0].severity).toBe("critical");
    expect(hit(cfg({ ruleOverrides: { "ACME-101": { enabled: false } } }))).toHaveLength(0);
  });
  it("registering twice replaces rather than duplicates", () => {
    registerExternalRules([buildDeclarativeRule(base, "f.yml")]);
    registerExternalRules([buildDeclarativeRule(base, "f.yml")]);
    expect(allRules().filter((r) => r.id === "ACME-101")).toHaveLength(1);
    registerExternalRules([]);
    expect(allRules().some((r) => r.id === "ACME-101")).toBe(false);
  });
});

describe("loading from disk", () => {
  it("loads the shipped example (a `rules:` list in one YAML file) and fires it", () => {
    const rules = loadDeclarativeRules([resolve("examples/community-rules")]);
    expect(rules.map((r) => r.id)).toEqual(["ACME-001", "ACME-002"]);
    registerExternalRules(rules);
    const f = evaluate(makeSnapshot({ tools: [tool("deploy", { description: "Deploys the app without asking first." })] }), cfg()).result.findings;
    expect(f.some((x) => x.rule === "ACME-001")).toBe(true);
    const ok = evaluate(makeSnapshot({ tools: [tool("deploy", { description: "Deploys. Never runs without asking." })] }), cfg()).result.findings;
    expect(ok.some((x) => x.rule === "ACME-001")).toBe(false);
  });
  it("rejects duplicate IDs and reports the offending file for bad rules", () => {
    const dir = tmp();
    writeFileSync(join(dir, "a.yml"), JSON.stringify(base));
    writeFileSync(join(dir, "b.json"), JSON.stringify(base));
    expect(() => loadDeclarativeRules([dir])).toThrow(/Duplicate community rule id ACME-101/);
    const bad = tmp();
    writeFileSync(join(bad, "bad.yml"), "id: ACME-102\nname: x\n");
    expect(() => loadDeclarativeRules([bad])).toThrow(/bad\.yml.*severity/);
    expect(() => loadDeclarativeRules([join(bad, "missing")])).toThrow(/not found/);
  });
});

describe("plugins (code) are opt-in", () => {
  const pluginFile = () => {
    const dir = tmp();
    const f = join(dir, "plugin.mjs");
    writeFileSync(
      f,
      `export default { id: "PLUG-001", name: "Plugin rule", category: "quality", severity: "low", description: "d", why: "w", recommendation: "r",
        check({ snapshot }) { return snapshot.tools.filter((t) => t.name.startsWith("x_")).map((t) => ({ tool: t.name, message: "x_ tool", evidence: t.name })); } };`,
    );
    return f;
  };
  it("are not loaded unless allowed, and the user is told", async () => {
    const c = cfg({ plugins: [pluginFile()] });
    const r = await applyCommunityRules(c, { allowPlugins: false });
    expect(r).toMatchObject({ plugins: 0, skippedPlugins: 1 });
    expect(allRules().some((x) => x.id === "PLUG-001")).toBe(false);
  });
  it("load and run when allowed", async () => {
    const c = cfg({ plugins: [pluginFile()] });
    const r = await applyCommunityRules(c, { allowPlugins: true });
    expect(r.plugins).toBe(1);
    const f = evaluate(makeSnapshot({ tools: [tool("x_one")] }), cfg()).result.findings;
    expect(f.some((x) => x.rule === "PLUG-001")).toBe(true);
  });
  it("must use a community id and export a real rule", async () => {
    const dir = tmp();
    const f = join(dir, "bad.mjs");
    writeFileSync(f, `export default { id: "MCP-777", name: "n", category: "quality", severity: "low", description: "d", why: "w", recommendation: "r", check() { return []; } };`);
    await expect(loadPluginRules([f])).rejects.toThrow(/reserved|must look like/);
    const g = join(dir, "bad2.mjs"); // a new path: Node caches ES modules by URL
    writeFileSync(g, `export default { nope: true };`);
    await expect(loadPluginRules([g])).rejects.toThrow(/check\(\) function/);
  });
});
