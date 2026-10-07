import { spawnSync } from "node:child_process";
import { chmodSync, existsSync, mkdirSync, mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { pathToFileURL } from "node:url";
import { describe, expect, it } from "vitest";
import { parse } from "yaml";
import { example } from "../fixtures/run-cli.js";

// Prefer Git Bash on Windows (plain `bash` there may be WSL, which cannot see these paths).
const GIT_BASH = "C:\\Program Files\\Git\\bin\\bash.exe";
const BASH = process.platform === "win32" && existsSync(GIT_BASH) ? GIT_BASH : "bash";
const hasBash = spawnSync(BASH, ["-c", "true"]).status === 0;
const fwd = (p: string) => p.replace(/\\/g, "/");

const action = parse(readFileSync("github-action/action.yml", "utf8"));
const scanStep = action.runs.steps.find((s: any) => s.id === "scan");

/** Run the action's `scan` step script locally, with `npx mcp-detector@x` mapped to this checkout. */
function runActionStep(inputs: Record<string, string>) {
  const dir = mkdtempSync(join(tmpdir(), "mcpd-action-"));
  const shim = join(dir, "bin");
  const tsx = pathToFileURL(resolve("node_modules/tsx/dist/esm/index.mjs")).href;
  const cli = fwd(resolve("src/cli/index.ts"));
  // `npx --yes mcp-detector@<version> <args>`  ->  run the CLI from source with <args>
  mkdirSync(shim);
  writeFileSync(join(shim, "npx"), `#!/usr/bin/env bash\nshift 2\nexec "${fwd(process.execPath)}" --import "${tsx}" "${cli}" "$@"\n`);
  chmodSync(join(shim, "npx"), 0o755);
  writeFileSync(join(dir, "script.sh"), scanStep.run);
  const summary = join(dir, "summary.md");
  const output = join(dir, "output.txt");
  writeFileSync(summary, "");
  writeFileSync(output, "");

  const r = spawnSync(BASH, ["-eo", "pipefail", fwd(join(dir, "script.sh"))], {
    cwd: dir,
    encoding: "utf8",
    timeout: 90_000,
    env: {
      ...process.env,
      NO_COLOR: "1",
      PATH: `${fwd(shim)}${process.platform === "win32" ? ";" : ":"}${process.env.PATH}`,
      RUNNER_TEMP: fwd(dir),
      GITHUB_STEP_SUMMARY: fwd(summary),
      GITHUB_OUTPUT: fwd(output),
      SERVER_COMMAND: "",
      SERVER_URL: "",
      CONFIG: "",
      FAIL_ON: "high",
      ACTIVE: "false",
      VERSION: "latest",
      ...inputs,
    },
  });
  const outputs = Object.fromEntries(
    readFileSync(output, "utf8").split("\n").filter(Boolean).map((l) => [l.slice(0, l.indexOf("=")), l.slice(l.indexOf("=") + 1)]),
  );
  return { code: r.status, stdout: r.stdout, stderr: r.stderr, summary: readFileSync(summary, "utf8"), outputs, dir };
}

const cmd = (name: string) => `"${fwd(process.execPath)}" "${fwd(example(name))}"`;

describe.skipIf(!hasBash)("GitHub Action scan step", () => {
  it("passes on a clean server and exposes score outputs + job summary", () => {
    const r = runActionStep({ SERVER_COMMAND: cmd("secure-server") });
    expect(r.code, r.stderr).toBe(0);
    expect(r.outputs.score).toBe("100");
    expect(r.outputs.findings).toBe("0");
    expect(existsSync(r.outputs["report-path"])).toBe(true);
    expect(r.summary).toContain("# MCP Detector Report");
    expect(r.summary).toContain("Score: 100/100");
  }, 120_000);

  it("fails the job on findings at or above fail-on, but still writes the report", () => {
    const r = runActionStep({ SERVER_COMMAND: cmd("vulnerable-server"), FAIL_ON: "high" });
    expect(r.code).toBe(1);
    expect(Number(r.outputs.score)).toBeLessThan(70);
    expect(r.summary).toContain("MCP-012");
    expect(r.stdout).toContain("::error title=MCP Detector failed::");
  }, 120_000);

  it("fail-on: none never fails", () => {
    const r = runActionStep({ SERVER_COMMAND: cmd("vulnerable-server"), FAIL_ON: "none" });
    expect(r.code, r.stderr).toBe(0);
  }, 120_000);

  it("does not execute shell metacharacters smuggled into inputs", () => {
    const marker = join(mkdtempSync(join(tmpdir(), "mcpd-inj-")), "pwned");
    const r = runActionStep({ SERVER_COMMAND: `node x; touch "${fwd(marker)}"; $(touch "${fwd(marker)}")`, FAIL_ON: "none" });
    expect(existsSync(marker)).toBe(false);
    expect(r.code).toBe(1); // server could not start: the scan fails instead of running the payload
  }, 120_000);
});
