import { resolve } from "node:path";
import { describe, expect, it } from "vitest";
import { evaluate, runScan } from "../../src/core/detector.js";
import { cfg, makeSnapshot, tool } from "../fixtures/snapshot.js";

const fixture = (n: string) => resolve("tests/fixtures/servers", n);
const stdio = (file: string, over: object = {}) => cfg({ server: { command: process.execPath, args: [file] }, ...over });
const rules = (r: { result: { findings: { rule: string }[] } }) => r.result.findings.map((f) => f.rule);

describe("misbehaving servers", () => {
  it("slow server: active mode measures latency, a hang, and error rate", async () => {
    const config = stdio(fixture("slow-server.mjs"), { active: true });
    config.thresholds.latency_ms = 300;
    config.thresholds.timeout_ms = 1500;
    const out = await runScan(config);
    const byTool = Object.fromEntries(out.snapshot.toolCalls.map((c) => [c.tool, c]));
    expect(byTool.get_fast.ok).toBe(true);
    expect(byTool.get_slow.durationMs).toBeGreaterThanOrEqual(600);
    expect(byTool.get_hang.timedOut).toBe(true);
    expect(byTool.get_error.ok).toBe(false);
    expect(rules(out)).toEqual(expect.arrayContaining(["MCP-009", "MCP-015", "MCP-023"]));
    expect(out.result.timings.timeoutRate).toBeCloseTo(0.25);
    expect(out.result.scores.performance).toBeLessThan(90);
  }, 30_000);

  it("passive mode never calls tools, even on a server with a hanging tool", async () => {
    const out = await runScan(stdio(fixture("slow-server.mjs")));
    expect(out.snapshot.toolCalls).toEqual([]);
    expect(out.result.timings.avgToolMs).toBeUndefined();
  }, 30_000);

  it("a server that crashes on start yields MCP-001 with its stderr as evidence", async () => {
    const out = await runScan(stdio(fixture("crash-server.mjs")));
    expect(out.result.status).toBe("failed");
    const f = out.result.findings.find((f) => f.rule === "MCP-001")!;
    expect(f.evidence).toContain("cannot bind to database");
  }, 30_000);

  it("a server that never answers initialize times out cleanly", async () => {
    const config = stdio(fixture("silent-server.mjs"));
    config.thresholds.connect_ms = 800;
    const t = Date.now();
    const out = await runScan(config);
    expect(Date.now() - t).toBeLessThan(10_000);
    expect(out.result.findings[0].rule).toBe("MCP-001");
    expect(out.result.findings[0].message).toMatch(/timed out/i);
  }, 30_000);

  it("a bogus protocol version yields MCP-002", async () => {
    const out = await runScan(stdio(fixture("badversion-server.mjs")));
    expect(rules(out)).toContain("MCP-002");
  }, 30_000);

  it("sensitive resources and empty declared capabilities", async () => {
    const out = await runScan(stdio(fixture("resources-server.mjs")));
    const sensitive = out.result.findings.filter((f) => f.rule === "MCP-030");
    expect(sensitive).toHaveLength(1);
    const text = JSON.stringify(sensitive[0]);
    expect(text).toContain(".ssh");
    expect(text).toContain(".env");
    expect(text).not.toContain("README");
    expect(rules(out)).toContain("MCP-027");
  }, 30_000);
});

describe("hygiene rules (snapshot level)", () => {
  const tools = (n: number) => Array.from({ length: n }, (_, i) => tool(`tool_${i}`));
  it("MCP-026 only above 40 tools", () => {
    expect(rules(evaluate(makeSnapshot({ tools: tools(40) }), cfg()))).not.toContain("MCP-026");
    expect(rules(evaluate(makeSnapshot({ tools: tools(41) }), cfg()))).toContain("MCP-026");
  });
  it("MCP-028 flags remote plain HTTP, not localhost or https", () => {
    const run = (url: string, headers?: Record<string, string>) => evaluate(makeSnapshot(), cfg({ server: { url, headers } }));
    expect(rules(run("http://example.com/mcp"))).toContain("MCP-028");
    const withAuth = run("http://example.com/mcp", { Authorization: "Bearer x" });
    expect(withAuth.result.findings.find((f) => f.rule === "MCP-028")!.severity).toBe("critical");
    expect(rules(run("http://localhost:3000/mcp"))).not.toContain("MCP-028");
    expect(rules(run("http://127.0.0.1:3000/mcp"))).not.toContain("MCP-028");
    expect(rules(run("https://example.com/mcp"))).not.toContain("MCP-028");
  });
  it("MCP-029 missing server identity", () => {
    expect(rules(evaluate(makeSnapshot({ serverInfo: { name: "x" } }), cfg()))).toContain("MCP-029");
    expect(rules(evaluate(makeSnapshot(), cfg()))).not.toContain("MCP-029");
  });
});
