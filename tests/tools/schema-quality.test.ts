import { describe, expect, it } from "vitest";
import { evaluate } from "../../src/core/detector.js";
import { cfg, makeSnapshot, tool } from "../fixtures/snapshot.js";

const ids = (r: ReturnType<typeof evaluate>) => r.result.findings.map((f) => f.rule);
const run = (tools: any[], extra: any = {}, c = cfg()) => evaluate(makeSnapshot({ tools, ...extra }), c);

describe("MCP-003 invalid tool schema", () => {
  it("flags a missing inputSchema", () => {
    expect(ids(run([{ name: "x", description: "A description long enough." }]))).toContain("MCP-003");
  });
  it("flags a non-object schema type", () => {
    expect(ids(run([tool("x", { inputSchema: { type: "string" } })]))).toContain("MCP-003");
  });
  it("flags an invalid JSON schema keyword value", () => {
    expect(ids(run([tool("x", { inputSchema: { type: "object", properties: { a: { type: "nope" } } } })]))).toContain("MCP-003");
  });
  it("flags required properties that are not defined", () => {
    const out = run([tool("x", { inputSchema: { type: "object", properties: { a: { type: "string" } }, required: ["b"] } })]);
    expect(ids(out)).toContain("MCP-003");
  });
  it("accepts a valid schema", () => {
    expect(ids(run([tool("x", { inputSchema: { type: "object", properties: { a: { type: "string", maxLength: 5, description: "d" } }, required: ["a"] } })]))).not.toContain("MCP-003");
  });
});

describe("MCP-010 weak validation", () => {
  it("flags untyped params and free-form path strings", () => {
    const out = run([tool("x", { inputSchema: { type: "object", properties: { path: { type: "string" }, v: {} }, required: ["path"] } })]);
    const f = out.result.findings.find((f) => f.rule === "MCP-010")!;
    expect(f.severity).toBe("medium");
    expect(f.evidence).toContain("path");
  });
  it("is quiet for constrained schemas", () => {
    const out = run([tool("x", { inputSchema: { type: "object", properties: { path: { type: "string", pattern: "^[a-z]+$" } }, required: ["path"] } })]);
    expect(ids(out)).not.toContain("MCP-010");
  });
});

describe("quality rules", () => {
  it("MCP-013 missing description and MCP-025 unclear description", () => {
    const out = run([tool("a", { description: undefined }), tool("b", { description: "b" })]);
    expect(ids(out)).toContain("MCP-013");
    expect(ids(out)).toContain("MCP-025");
  });
  it("MCP-014 duplicate tool names", () => {
    expect(ids(run([tool("dup"), tool("dup")]))).toContain("MCP-014");
  });
  it("MCP-021 mixed naming conventions and invalid characters", () => {
    expect(ids(run([tool("get_item"), tool("getOther")]))).toContain("MCP-021");
    expect(ids(run([tool("bad name!")]))).toContain("MCP-021");
  });
  it("MCP-020 parameters without descriptions", () => {
    const out = run([tool("x", { inputSchema: { type: "object", properties: { a: { type: "string", maxLength: 3 } }, required: ["a"] } })]);
    expect(ids(out)).toContain("MCP-020");
  });
});

describe("protocol and performance rules", () => {
  it("MCP-001 when not connected", () => {
    const out = evaluate(makeSnapshot({ connected: false, connectError: "spawn ENOENT" }), cfg());
    expect(ids(out)).toContain("MCP-001");
    expect(out.result.score).toBe(0);
  });
  it("MCP-002 on an unsupported version", () => {
    expect(ids(run([], { protocolVersion: "1999-01-01" }))).toContain("MCP-002");
    expect(ids(run([], { protocolVersion: "latest" }))).toContain("MCP-002");
  });
  it("MCP-016 / MCP-017 / MCP-018", () => {
    const out = run([], {
      ping: { ok: false, ms: 5, error: "nope" },
      unknownMethod: { rejected: false, timedOut: true },
      listErrors: { tools: "boom" },
    });
    expect(ids(out)).toEqual(expect.arrayContaining(["MCP-016", "MCP-017", "MCP-018"]));
  });
  it("MCP-015 high latency and MCP-009 timeouts in active mode", () => {
    const out = run([tool("slow")], {
      activeMode: true,
      toolCalls: [
        { tool: "slow", ok: true, timedOut: false, durationMs: 9000 },
        { tool: "hang", ok: false, timedOut: true, durationMs: 10000, error: "timed out" },
      ],
    });
    expect(ids(out)).toEqual(expect.arrayContaining(["MCP-015", "MCP-009", "MCP-023"]));
  });
  it("MCP-019 slow initialization", () => {
    expect(ids(run([], { timings: { connectMs: 4500 } }))).toContain("MCP-019");
  });
});

describe("configuration", () => {
  const poisoned = [tool("t", { description: "<IMPORTANT>do x</IMPORTANT>" })];
  it("disables a rule group", () => {
    const c = cfg();
    c.groups.tool_poisoning = false;
    expect(ids(run(poisoned, {}, c))).not.toContain("MCP-005");
  });
  it("disables and re-levels individual rules", () => {
    const c = cfg({ ruleOverrides: { "MCP-005": { severity: "low" } } });
    expect(run(poisoned, {}, c).result.findings.find((f) => f.rule === "MCP-005")!.severity).toBe("low");
    const d = cfg({ ruleOverrides: { "MCP-005": { enabled: false } } });
    expect(ids(run(poisoned, {}, d))).not.toContain("MCP-005");
  });
  it("ignores tools", () => {
    const c = cfg();
    c.ignore.tools = ["t"];
    expect(ids(run(poisoned, {}, c))).not.toContain("MCP-005");
  });
});

describe("false-positive guards (found by scanning real servers)", () => {
  it("does not treat a free-text 'query' tool as a database tool (MCP-009)", () => {
    const out = run([tool("simulate-research-query", { description: "Simulates a research query.", inputSchema: { type: "object", properties: { topic: { type: "string", maxLength: 50, description: "t" } }, required: ["topic"] } })]);
    expect(ids(out)).not.toContain("MCP-009");
  });
  it("does not flag schemas whose parameters are all optional (MCP-010)", () => {
    const out = run([tool("x", { inputSchema: { type: "object", properties: { a: { type: "string", maxLength: 3, description: "d" } } } })]);
    expect(ids(out)).not.toContain("MCP-010");
  });
  it("still treats an explicit SQL tool as a database tool", () => {
    const out = run([tool("run_sql", { description: "Executes a SQL statement.", inputSchema: { type: "object", properties: { sql: { type: "string" } }, required: ["sql"] } })]);
    expect(ids(out)).toContain("MCP-009");
  });
});
