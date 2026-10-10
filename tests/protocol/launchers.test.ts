import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";

/**
 * The double-click launchers are the front door for non-technical people, and they break silently if a
 * line ending is wrong (a .bat with LF endings can mis-handle `goto` labels; a .command with CRLF fails to run).
 * .gitattributes pins the endings; these tests make sure it keeps working on every platform CI checks out on.
 */
const bat = readFileSync("start-app.bat");
const command = readFileSync("start-app.command");
const text = (b: Buffer) => b.toString("utf8");

describe("start-app.bat (Windows)", () => {
  it("uses CRLF line endings throughout", () => {
    const lf = (text(bat).match(/\n/g) ?? []).length;
    const crlf = (text(bat).match(/\r\n/g) ?? []).length;
    expect(lf).toBeGreaterThan(20);
    expect(crlf).toBe(lf);
  });
  it("checks for Node.js and its version before doing anything, and explains how to fix it", () => {
    const t = text(bat);
    expect(t).toContain("where node");
    expect(t).toMatch(/a>22\|\|\(a===22&&b>=12\)/);
    expect(t).toContain("nodejs.org");
    expect(t).toContain("pause"); // the window must not vanish before the person can read the message
  });
  it("only touches its own folder: npm install, npm run build, then the app", () => {
    const t = text(bat);
    expect(t).toContain('cd /d "%~dp0"');
    expect(t).toContain("npm install");
    expect(t).toContain("npm run build");
    expect(t).toContain("dist\\cli\\index.js ui");
    expect(t).not.toMatch(/\b(del|rmdir|rd|format|reg|setx|netsh)\b/i);
  });
});

describe("start-app.command (macOS / Linux)", () => {
  it("uses LF line endings and a bash shebang", () => {
    expect(text(command)).not.toContain("\r");
    expect(text(command).startsWith("#!/bin/bash\n")).toBe(true);
  });
  it("has the same safety checks and only touches its own folder", () => {
    const t = text(command);
    expect(t).toContain('cd "$(dirname "$0")"');
    expect(t).toContain("command -v node");
    expect(t).toContain("a>22||(a===22&&b>=12)");
    expect(t).toContain("npm install");
    expect(t).toContain("npm run build");
    expect(t).toContain("dist/cli/index.js ui");
    expect(t).not.toMatch(/\b(sudo|rm -rf|chmod|curl|wget)\b/);
  });
});

describe(".gitattributes", () => {
  it("pins the line endings these files need", () => {
    const t = readFileSync(".gitattributes", "utf8");
    expect(t).toMatch(/\*\.bat\s+text\s+eol=crlf/);
    expect(t).toMatch(/\*\.command\s+text\s+eol=lf/);
  });
});
