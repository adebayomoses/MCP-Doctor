import { spawn } from "node:child_process";
import { createServer, type Server } from "node:http";
import { existsSync, mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import type { AddressInfo } from "node:net";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { pathToFileURL } from "node:url";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { runBatch } from "../../src/batch/runner.js";
import { cfg } from "../fixtures/snapshot.js";
import { example, runCli } from "../fixtures/run-cli.js";

const tmp = () => mkdtempSync(join(tmpdir(), "mcpd-p4e-"));
const node = process.execPath;
const secure = example("secure-server");
const vulnerable = example("vulnerable-server");

function serversFile(dir: string, extra: Record<string, unknown> = {}) {
  const f = join(dir, "servers.json");
  writeFileSync(
    f,
    JSON.stringify({
      mcpServers: {
        secure: { command: node, args: [secure] },
        vulnerable: { command: node, args: [vulnerable, "--token=supersecret-value-123"] },
        broken: { command: node, args: [join(dir, "nope.mjs")] },
        ...extra,
      },
    }),
  );
  return f;
}

describe("batch runner", () => {
  let locked: Server;
  let lockedUrl: string;
  const userAgents: string[] = [];
  beforeAll(async () => {
    locked = createServer((req, res) => {
      userAgents.push(String(req.headers["user-agent"]));
      res.writeHead(401, { "content-type": "application/json", "www-authenticate": 'Bearer realm="x"' }).end('{"error":"unauthorized"}');
    });
    await new Promise<void>((r) => locked.listen(0, "127.0.0.1", r));
    lockedUrl = `http://127.0.0.1:${(locked.address() as AddressInfo).port}/mcp`;
  });
  afterAll(() => new Promise<void>((r) => locked.close(() => r())));

  it("classifies each server: scanned, failed, or needs authentication (not scored as broken)", async () => {
    const batch = await runBatch(
      [
        { name: "ok", source: "t", server: { command: node, args: [secure] } },
        { name: "dead", source: "t", server: { command: node, args: ["no-such.mjs"] } },
        { name: "locked", source: "t", server: { url: lockedUrl } },
      ],
      { base: cfg(), origin: "test", concurrency: 3 },
    );
    const by = Object.fromEntries(batch.entries.map((e) => [e.name, e]));
    expect(by.ok.status).toBe("scanned");
    expect(by.dead.status).toBe("failed");
    expect(by.locked.status).toBe("auth_required");
    expect(by.locked.note).toMatch(/--header/);
    expect(batch.summary).toMatchObject({ total: 3, scanned: 1, failed: 1, authRequired: 1 });
    expect(batch.entries.map((e) => e.name)).toEqual(["ok", "dead", "locked"]); // input order is preserved
  }, 60_000);

  it("identifies itself to remote servers with a User-Agent, which a user header can override", async () => {
    userAgents.length = 0;
    const run = (headers?: Record<string, string>) =>
      runBatch([{ name: "l", source: "t", server: { url: lockedUrl, headers } }], { base: cfg(), origin: "t" });
    await run();
    expect(userAgents.length).toBeGreaterThan(0);
    expect(userAgents.every((u) => /^mcp-detector\/\d+\.\d+\.\d+/.test(u))).toBe(true);
    userAgents.length = 0;
    await run({ "user-agent": "custom-agent/9" });
    expect(userAgents.every((u) => u === "custom-agent/9")).toBe(true);
  }, 60_000);

  it("forcePassive never calls tools even if the config asks for active mode", async () => {
    const batch = await runBatch([{ name: "v", source: "t", server: { command: node, args: [secure] } }], {
      base: cfg({ active: true }),
      origin: "test",
      forcePassive: true,
    });
    expect(batch.entries[0].result?.timings.avgToolMs).toBeUndefined();
    const active = await runBatch([{ name: "v", source: "t", server: { command: node, args: [secure] } }], { base: cfg({ active: true }), origin: "test" });
    expect(active.entries[0].result?.timings.avgToolMs).toBeDefined();
  }, 60_000);

  it("reports progress and stores redacted targets", async () => {
    const seen: string[] = [];
    const batch = await runBatch([{ name: "t", source: "t", server: { command: node, args: [secure, "--token=abcdef123456789"] } }], {
      base: cfg(),
      origin: "x",
      onProgress: (d, t, e) => seen.push(`${d}/${t}:${e.status}`),
    });
    expect(seen).toEqual(["1/1:scanned"]);
    expect(batch.entries[0].target).not.toContain("abcdef123456789");
    expect(JSON.stringify(batch)).not.toContain("abcdef123456789");
  }, 60_000);
});

describe("CLI: scan-all, history, badge, site", () => {
  const dir = tmp();
  const file = serversFile(dir);

  it("scan-all scans a servers file, writes a batch, builds a site, and never leaks the token", () => {
    const r = runCli(["scan-all", file, "--site", "board", "--format", "json"], { cwd: dir });
    expect(r.code, r.stderr).toBe(0);
    const j = JSON.parse(r.stdout);
    expect(j.kind).toBe("batch");
    expect(j.summary).toMatchObject({ total: 3, scanned: 2, failed: 1 });
    expect(existsSync(join(dir, ".mcp-detector", "batch", "latest.json"))).toBe(true);
    expect(existsSync(join(dir, "board", "index.html"))).toBe(true);
    expect(existsSync(join(dir, "board", "servers", "secure.html"))).toBe(true);
    expect(existsSync(join(dir, "board", "badges", "vulnerable.svg"))).toBe(true);
    for (const f of ["board/data.json", "board/index.html", ".mcp-detector/batch/latest.json", "board/servers/vulnerable.html"])
      expect(readFileSync(join(dir, f), "utf8")).not.toContain("supersecret-value-123");
  }, 120_000);

  it("scan-all --dry-run lists targets without starting anything, with secrets redacted", () => {
    const r = runCli(["scan-all", file, "--dry-run"], { cwd: tmp() });
    expect(r.code).toBe(0);
    expect(r.stdout).toContain("3 server(s) would be scanned");
    expect(r.stdout).not.toContain("supersecret-value-123");
  }, 60_000);

  it("scan-all --fail-on high exits 1 when any server has such findings", () => {
    expect(runCli(["scan-all", file, "--fail-on", "high", "--format", "json"], { cwd: tmp() }).code).toBe(1);
    const only = join(tmp(), "ok.json");
    writeFileSync(only, JSON.stringify({ mcpServers: { secure: { command: node, args: [secure] } } }));
    expect(runCli(["scan-all", only, "--fail-on", "high", "--format", "json"], { cwd: tmp() }).code).toBe(0);
  }, 120_000);

  it("requires exactly one source", () => {
    const r = runCli(["scan-all", file, "--clients"], { cwd: tmp() });
    expect(r.code).toBe(2);
    expect(r.stderr).toContain("exactly one source");
    expect(runCli(["scan-all"], { cwd: tmp() }).code).toBe(2);
  }, 60_000);

  it("history lists targets, and shows what changed between two runs", () => {
    const d = tmp();
    const scan = () => runCli(["scan", "--format", "json", "--", node, secure], { cwd: d });
    scan();
    scan();
    const list = runCli(["history", "--json"], { cwd: d });
    const items = JSON.parse(list.stdout);
    expect(items).toHaveLength(1);
    expect(items[0].runs).toBe(2);
    const one = JSON.parse(runCli(["history", items[0].key, "--json"], { cwd: d }).stdout);
    expect(one.runs).toHaveLength(2);
    expect(one.diff.scoreDelta).toBe(0);
    expect(runCli(["history", "nomatch"], { cwd: d }).code).toBe(2);
    expect(runCli(["scan", "--no-history", "--format", "json", "--", node, vulnerable], { cwd: d }).code).toBe(0);
    expect(JSON.parse(runCli(["history", "--json"], { cwd: d }).stdout)).toHaveLength(1); // --no-history was honoured
  }, 120_000);

  it("badge writes an SVG or shields JSON from a saved result", () => {
    const d = tmp();
    runCli(["scan", "--format", "json", "--", node, secure], { cwd: d });
    const svg = runCli(["badge", "-o", "b.svg"], { cwd: d });
    expect(svg.code).toBe(0);
    expect(readFileSync(join(d, "b.svg"), "utf8")).toContain("100/100");
    expect(JSON.parse(runCli(["badge", "--json", "--category", "security"], { cwd: d }).stdout)).toMatchObject({ label: "mcp security", message: "100/100" });
    expect(runCli(["badge", "--category", "vibes"], { cwd: d }).code).toBe(2);
    expect(runCli(["badge", "missing.json"], { cwd: d }).code).toBe(2);
  }, 120_000);

  it("scan --format html produces a script-free report", () => {
    const d = tmp();
    const r = runCli(["scan", "--format", "html", "--", node, vulnerable], { cwd: d });
    expect(r.stdout.startsWith("<!doctype html>")).toBe(true);
    expect(r.stdout).not.toMatch(/<script/i);
    expect(r.stdout).toContain("MCP-012");
  }, 60_000);

  it("site builds from the scan history when there is no batch", () => {
    const d = tmp();
    runCli(["scan", "--format", "json", "--", node, secure], { cwd: d });
    const r = runCli(["site", "-o", "out"], { cwd: d });
    expect(r.code, r.stderr).toBe(0);
    expect(existsSync(join(d, "out", "index.html"))).toBe(true);
    expect(runCli(["site"], { cwd: tmp() }).stderr).toContain("No scan data found");
  }, 60_000);
});

describe("CLI: dashboard", () => {
  it("serves the scoreboard on localhost only, read-only, and refuses path traversal", async () => {
    const d = tmp();
    runCli(["scan-all", serversFile(d), "--format", "json"], { cwd: d });
    const tsx = pathToFileURL(resolve("node_modules/tsx/dist/esm/index.mjs")).href;
    const child = spawn(node, ["--import", tsx, resolve("src/cli/index.ts"), "dashboard", "--port", "0"], { cwd: d, env: { ...process.env, NO_COLOR: "1" } });
    try {
      const url = await new Promise<string>((ok, fail) => {
        let out = "";
        const t = setTimeout(() => fail(new Error("dashboard did not start: " + out)), 30_000);
        child.stdout.on("data", (c) => {
          out += c;
          const m = /http:\/\/127\.0\.0\.1:(\d+)\//.exec(out);
          if (m) {
            clearTimeout(t);
            ok(m[0]);
          }
        });
        child.on("exit", () => fail(new Error("dashboard exited: " + out)));
      });
      const index = await fetch(url);
      expect(index.status).toBe(200);
      expect(index.headers.get("x-content-type-options")).toBe("nosniff");
      const html = await index.text();
      expect(html).toContain("secure");
      expect(html).toContain("Not scored");
      expect((await fetch(url + "servers/secure.html")).status).toBe(200);
      expect((await fetch(url + "badges/secure.svg")).headers.get("content-type")).toContain("image/svg+xml");
      expect((await fetch(url + "data.json")).status).toBe(200);
      expect((await fetch(url + "nope.html")).status).toBe(404);
      expect((await fetch(url, { method: "POST" })).status).toBe(405);
      // traversal attempts (raw requests, since fetch normalises ../)
      for (const p of ["/..%2f..%2fpackage.json", "/%2e%2e/%2e%2e/package.json", "/servers/..%5c..%5c..%5cpackage.json"]) {
        const res = await fetch(url.replace(/\/$/, "") + p);
        expect([403, 404]).toContain(res.status);
        expect(await res.text()).not.toContain('"name"');
      }
    } finally {
      child.kill();
    }
  }, 90_000);
});

describe("CLI: community rules", () => {
  it("--rules loads declarative rules; config community_rules works too", () => {
    const d = tmp();
    writeFileSync(
      join(d, "rule.yml"),
      "id: ACME-201\nname: Mentions adds\nseverity: low\ncategory: quality\ndescription: d\nwhy: w\nrecommendation: r\nmatch:\n  any: ['adds two numbers']\n",
    );
    const viaFlag = JSON.parse(runCli(["scan", "--format", "json", "--rules", "rule.yml", "--", node, secure], { cwd: d }).stdout);
    expect(viaFlag.findings.some((f: any) => f.rule === "ACME-201")).toBe(true);
    writeFileSync(join(d, "mcp-detector.yml"), `community_rules: [./rule.yml]\nrules:\n  ACME-201: high\n`);
    const viaConfig = JSON.parse(runCli(["scan", "--format", "json", "--", node, secure], { cwd: d }).stdout);
    expect(viaConfig.findings.find((f: any) => f.rule === "ACME-201").severity).toBe("high");
  }, 120_000);

  it("an invalid community rule is a clear usage error naming the file", () => {
    const d = tmp();
    writeFileSync(join(d, "bad.yml"), "id: MCP-001\nname: x\nseverity: low\ndescription: d\nwhy: w\nrecommendation: r\nmatch: { any: ['x'] }\n");
    const r = runCli(["scan", "--rules", "bad.yml", "--", node, secure], { cwd: d });
    expect(r.code).toBe(2);
    expect(r.stderr).toMatch(/bad\.yml.*reserved/);
  }, 60_000);

  it("plugins listed in a config do NOT run unless --allow-plugins is given", () => {
    const d = tmp();
    const marker = join(d, "plugin-ran.txt");
    writeFileSync(
      join(d, "plugin.mjs"),
      `import { writeFileSync } from "node:fs";\nwriteFileSync(${JSON.stringify(marker)}, "ran");\nexport default { id: "PLUG-009", name: "p", category: "quality", severity: "low", description: "d", why: "w", recommendation: "r", check: () => [] };`,
    );
    writeFileSync(join(d, "mcp-detector.yml"), "plugins: [./plugin.mjs]\n");
    const without = runCli(["scan", "--format", "json", "--", node, secure], { cwd: d });
    expect(without.code).toBe(0);
    expect(without.stderr).toContain("NOT loaded");
    expect(existsSync(marker)).toBe(false);
    const withFlag = runCli(["scan", "--allow-plugins", "--format", "json", "--", node, secure], { cwd: d });
    expect(withFlag.code, withFlag.stderr).toBe(0);
    expect(existsSync(marker)).toBe(true);
  }, 120_000);
});
