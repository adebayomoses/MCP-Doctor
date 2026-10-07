import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { loadConfig } from "../../src/config/config-loader.js";
import { categoryScores, gradeFor, overallScore } from "../../src/core/health-score.js";
import { splitCommand } from "../../src/cli/shared.js";
import { exceedsThreshold } from "../../src/reporting/severity.js";
import type { Finding } from "../../src/core/types.js";

const f = (rule: string, severity: Finding["severity"], category: Finding["category"] = "security"): Finding => ({
  rule, name: rule, severity, category, message: "m", why: "w", recommendation: "r",
});

describe("health score", () => {
  it("is 100 with no findings and maps to grades", () => {
    expect(overallScore(categoryScores([]))).toBe(100);
    expect(gradeFor(95)).toBe("Excellent");
    expect(gradeFor(85)).toBe("Good");
    expect(gradeFor(75)).toBe("Fair");
    expect(gradeFor(55)).toBe("Poor");
    expect(gradeFor(10)).toBe("Critical");
  });
  it("penalises by severity and only the touched category", () => {
    const s = categoryScores([f("MCP-005", "critical")]);
    expect(s.security).toBe(70);
    expect(s.protocol).toBe(100);
  });
  it("caps repeated hits of one rule so a single noisy rule cannot zero a category", () => {
    const many = Array.from({ length: 40 }, () => f("MCP-020", "low", "quality"));
    expect(categoryScores(many).quality).toBeGreaterThan(85);
  });
  it("never goes below 0", () => {
    const s = categoryScores(["MCP-004", "MCP-005", "MCP-006", "MCP-012"].map((r) => f(r, "critical")));
    expect(s.security).toBe(0);
  });
});

describe("fail-on threshold", () => {
  it("compares severities by rank", () => {
    expect(exceedsThreshold([f("a", "medium")], "high")).toBe(false);
    expect(exceedsThreshold([f("a", "high")], "high")).toBe(true);
    expect(exceedsThreshold([f("a", "critical")], "high")).toBe(true);
    expect(exceedsThreshold([f("a", "critical")], "none")).toBe(false);
  });
});

describe("config loader", () => {
  const write = (yaml: string) => {
    const dir = mkdtempSync(join(tmpdir(), "mcpd-"));
    writeFileSync(join(dir, "mcp-detector.yml"), yaml);
    return dir;
  };
  it("loads the spec's example config", () => {
    const dir = write(`severity:\n  fail_on: high\nrules:\n  prompt_injection: true\n  performance: false\nthresholds:\n  latency_ms: 3000\n  timeout_ms: 10000\n`);
    const { config, file } = loadConfig(undefined, dir);
    expect(file).toBeTruthy();
    expect(config.severity.fail_on).toBe("high");
    expect(config.groups.performance).toBe(false);
    expect(config.thresholds.timeout_ms).toBe(10000);
  });
  it("supports per-rule overrides, server block and active allow/deny", () => {
    const dir = write(`server:\n  command: node\n  args: [a.js]\nrules:\n  MCP-024: off\n  MCP-010: low\nactive:\n  allow: [x]\n  deny: [y]\n`);
    const { config } = loadConfig(undefined, dir);
    expect(config.server).toMatchObject({ command: "node", args: ["a.js"] });
    expect(config.ruleOverrides["MCP-024"]).toEqual({ enabled: false });
    expect(config.ruleOverrides["MCP-010"]).toEqual({ severity: "low" });
    expect(config.active).toBe(true);
    expect(config.activeAllow).toEqual(["x"]);
    expect(config.activeDeny).toEqual(["y"]);
  });
  it("rejects invalid severities with a helpful message", () => {
    const dir = write(`severity:\n  fail_on: severe\n`);
    expect(() => loadConfig(undefined, dir)).toThrow(/Invalid severity "severe"/);
  });
  it("returns defaults when there is no config file", () => {
    const { config, file } = loadConfig(undefined, mkdtempSync(join(tmpdir(), "mcpd-")));
    expect(file).toBeUndefined();
    expect(config.severity.fail_on).toBe("none");
  });
});

describe("splitCommand", () => {
  it("handles quotes", () => {
    expect(splitCommand(`npx -y "my server" 'a b'`)).toEqual(["npx", "-y", "my server", "a b"]);
  });
});
