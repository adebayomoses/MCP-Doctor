import { createServer, type Server as HttpServer } from "node:http";
import type { AddressInfo } from "node:net";
import { resolve } from "node:path";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";
import { CallToolRequestSchema, ListToolsRequestSchema } from "@modelcontextprotocol/sdk/types.js";
import { runScan } from "../../src/core/detector.js";
import { cfg } from "../fixtures/snapshot.js";

const example = (n: string) => resolve("examples", n, "server.mjs");
const stdio = (file: string, over: object = {}) =>
  cfg({ server: { command: process.execPath, args: [file] }, ...over });

describe("stdio integration", () => {
  it("scans the secure example cleanly", async () => {
    const { result } = await runScan(stdio(example("secure-server")));
    expect(result.status).toBe("connected");
    expect(result.counts.tools).toBe(2);
    expect(result.protocolVersion).toMatch(/^\d{4}-\d{2}-\d{2}$/);
    expect(result.findings).toEqual([]);
    expect(result.score).toBe(100);
  }, 30_000);

  it("finds the planted problems in the vulnerable example", async () => {
    const { result } = await runScan(stdio(example("vulnerable-server")));
    const rules = new Set(result.findings.map((f) => f.rule));
    for (const r of ["MCP-003", "MCP-004", "MCP-005", "MCP-006", "MCP-007", "MCP-008", "MCP-010", "MCP-011", "MCP-012", "MCP-014"])
      expect(rules, `expected ${r}`).toContain(r);
    expect(result.score).toBeLessThan(70);
    expect(result.summary.critical).toBeGreaterThan(0);
  }, 30_000);

  it("active mode only calls tools that look read-only", async () => {
    const { result, snapshot } = await runScan(stdio(example("vulnerable-server"), { active: true }));
    const called = snapshot.toolCalls.map((c) => c.tool);
    expect(called).not.toContain("execute_command");
    expect(called).not.toContain("filesystem_write");
    expect(snapshot.skippedCalls.map((s) => s.tool)).toContain("execute_command");
    expect(result.timings.avgToolMs).toBeDefined();
  }, 30_000);

  it("reports MCP-001 when the server cannot start", async () => {
    const { result } = await runScan(stdio(resolve("examples", "does-not-exist.mjs")));
    expect(result.status).toBe("failed");
    expect(result.findings.map((f) => f.rule)).toContain("MCP-001");
    expect(result.score).toBe(0);
  }, 30_000);
});

describe("http integration", () => {
  let http: HttpServer;
  let url: string;

  beforeAll(async () => {
    http = createServer(async (req, res) => {
      // Stateless: a fresh server + transport per request.
      const server = new Server({ name: "http-demo", version: "1.0.0" }, { capabilities: { tools: {} } });
      server.setRequestHandler(ListToolsRequestSchema, async () => ({
        tools: [
          {
            name: "echo",
            description: "Echoes a short message back to the caller.",
            inputSchema: { type: "object", properties: { msg: { type: "string", maxLength: 100, description: "Message." } }, required: ["msg"], additionalProperties: false },
            annotations: { readOnlyHint: true },
          },
        ],
      }));
      server.setRequestHandler(CallToolRequestSchema, async (r) => ({ content: [{ type: "text", text: String(r.params.arguments?.msg) }] }));
      const transport = new StreamableHTTPServerTransport({ sessionIdGenerator: undefined });
      res.on("close", () => { transport.close(); server.close(); });
      await server.connect(transport);
      await transport.handleRequest(req, res);
    });
    await new Promise<void>((r) => http.listen(0, "127.0.0.1", r));
    url = `http://127.0.0.1:${(http.address() as AddressInfo).port}/mcp`;
  });
  afterAll(() => new Promise<void>((r) => http.close(() => r())));

  it("connects over Streamable HTTP and scans cleanly", async () => {
    const { result, snapshot } = await runScan(cfg({ server: { url }, active: true }));
    expect(result.status).toBe("connected");
    expect(result.server?.name).toBe("http-demo");
    expect(result.counts.tools).toBe(1);
    expect(snapshot.toolCalls[0]?.ok).toBe(true);
    expect(result.findings.filter((f) => f.severity !== "info")).toEqual([]);
  }, 30_000);
});
