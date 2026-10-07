import { existsSync, mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { describe, expect, it } from "vitest";
import { buildBaseline, describeChange, diffBaseline, pinTool } from "../../src/core/pinning.js";
import { cfg, makeSnapshot, tool } from "../fixtures/snapshot.js";
import { runCli } from "../fixtures/run-cli.js";

const server = resolve("tests/fixtures/servers/rugpull-server.mjs");
const target = ["--", process.execPath, server];
const tmp = () => mkdtempSync(join(tmpdir(), "mcpd-pin-"));
const scan = (dir: string, phase: string, extra: string[] = []) =>
  JSON.parse(runCli(["scan", "--env", `MCPD_PHASE=${phase}`, "--format", "json", ...extra, ...target], { cwd: dir }).stdout);
const rules = (j: any) => j.findings.map((f: any) => f.rule);

describe("pinning primitives", () => {
  it("hashes are stable regardless of key order, and change with any visible field", () => {
    const a = tool("t", { inputSchema: { type: "object", properties: { x: { type: "string" }, y: { type: "number" } } } });
    const b = tool("t", { inputSchema: { properties: { y: { type: "number" }, x: { type: "string" } }, type: "object" } });
    expect(pinTool(a).hash).toBe(pinTool(b).hash);
    expect(pinTool(tool("t", { description: "other" })).hash).not.toBe(pinTool(tool("t")).hash);
    expect(pinTool(tool("t", { annotations: { readOnlyHint: true } })).hash).not.toBe(pinTool(tool("t")).hash);
  });
  it("diff reports added, removed and changed tools and instruction changes", () => {
    const base = buildBaseline(makeSnapshot({ tools: [tool("a"), tool("b")], instructions: "v1" }), "test");
    const now = makeSnapshot({ tools: [tool("a", { description: "changed text here" }), tool("c")], instructions: "v2" });
    const d = diffBaseline(base, now);
    expect(d.changed.map((c) => c.tool)).toEqual(["a"]);
    expect(d.changed[0]).toMatchObject({ description: true, schema: false, annotations: false });
    expect(d.added).toEqual(["c"]);
    expect(d.removed).toEqual(["b"]);
    expect(d.instructionsChanged).toBe(true);
  });
  it("describeChange points at where the text diverges", () => {
    expect(describeChange("Adds two numbers.", "Adds two numbers. <IMPORTANT>x</IMPORTANT>")).toContain("<IMPORTANT>");
  });
  it("MCP-032 is silent without a baseline", async () => {
    const { evaluate } = await import("../../src/core/detector.js");
    expect(evaluate(makeSnapshot({ tools: [tool("a")] }), cfg()).result.findings.map((f) => f.rule)).not.toContain("MCP-032");
  });
});

describe("rug-pull detection end to end", () => {
  it("pin writes a lockfile; an unchanged server stays clean", () => {
    const dir = tmp();
    const pin = runCli(["pin", "--env", "MCPD_PHASE=good", ...target], { cwd: dir });
    expect(pin.code, pin.stderr).toBe(0);
    expect(pin.stdout).toContain("Pinned 1 tool(s)");
    const lock = JSON.parse(readFileSync(join(dir, "mcp-detector.lock.json"), "utf8"));
    expect(lock.version).toBe(1);
    expect(Object.keys(lock.tools)).toEqual(["add_numbers"]);
    expect(rules(scan(dir, "good"))).not.toContain("MCP-032");
  }, 90_000);

  it("a swapped description is caught: MCP-032 plus the poisoning it introduced", () => {
    const dir = tmp();
    runCli(["pin", "--env", "MCPD_PHASE=good", ...target], { cwd: dir });
    const j = scan(dir, "evil");
    const changed = j.findings.find((f: any) => f.rule === "MCP-032" && f.tool === "add_numbers");
    expect(changed.severity).toBe("high");
    expect(changed.message).toContain("description");
    expect(changed.evidence).toContain("<IMPORTANT>");
    expect(rules(j)).toContain("MCP-005");
    // the newly added tool is reported as a capability expansion
    expect(j.findings.find((f: any) => f.rule === "MCP-032" && f.tool === "get_status").message).toContain("added");
  }, 90_000);

  it("a schema-only change is reported too", () => {
    const dir = tmp();
    runCli(["pin", "--env", "MCPD_PHASE=good", ...target], { cwd: dir });
    const f = scan(dir, "quiet").findings.find((f: any) => f.rule === "MCP-032");
    expect(f.message).toContain("input/output schema");
  }, 90_000);

  it("--fail-on high turns a rug pull into a failing build", () => {
    const dir = tmp();
    runCli(["pin", "--env", "MCPD_PHASE=good", ...target], { cwd: dir });
    const r = runCli(["scan", "--env", "MCPD_PHASE=evil", "--fail-on", "high", ...target], { cwd: dir });
    expect(r.code).toBe(1);
  }, 90_000);

  it("--no-baseline ignores the lockfile; --baseline selects another file", () => {
    const dir = tmp();
    runCli(["pin", "--env", "MCPD_PHASE=good", ...target], { cwd: dir });
    expect(rules(scan(dir, "evil", ["--no-baseline"]))).not.toContain("MCP-032");
    runCli(["pin", "--env", "MCPD_PHASE=good", "-o", "other.lock.json", ...target], { cwd: dir });
    expect(existsSync(join(dir, "other.lock.json"))).toBe(true);
    expect(rules(scan(dir, "evil", ["--baseline", "other.lock.json"]))).toContain("MCP-032");
  }, 120_000);

  it("re-pinning shows what changed and then accepts it", () => {
    const dir = tmp();
    runCli(["pin", "--env", "MCPD_PHASE=good", ...target], { cwd: dir });
    const again = runCli(["pin", "--env", "MCPD_PHASE=evil", ...target], { cwd: dir });
    expect(again.stdout).toContain("changed  add_numbers (description)");
    expect(again.stdout).toContain("+ added    get_status");
    expect(again.stdout).toContain("critical/high finding"); // warns before trusting a risky server
    expect(rules(scan(dir, "evil"))).not.toContain("MCP-032");
  }, 120_000);

  it("a corrupt baseline is a clear usage error", () => {
    const dir = tmp();
    writeFileSync(join(dir, "mcp-detector.lock.json"), "{ not json");
    const r = runCli(["scan", ...target], { cwd: dir });
    expect(r.code).toBe(2);
    expect(r.stderr).toContain("Could not read baseline");
  }, 60_000);
});
