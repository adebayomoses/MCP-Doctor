#!/usr/bin/env node
import { Command } from "commander";
import { VERSION } from "../version.js";
import { scanCommand } from "./commands/scan.js";
import { inspectCommand } from "./commands/inspect.js";
import { testCommand } from "./commands/test.js";
import { reportCommand } from "./commands/report.js";
import { rulesCommand } from "./commands/rules.js";
import { initCommand } from "./commands/init.js";
import { pinCommand } from "./commands/pin.js";
import { scanAllCommand } from "./commands/scan-all.js";
import { historyCommand } from "./commands/history.js";
import { badgeCommand } from "./commands/badge.js";
import { siteCommand, dashboardCommand } from "./commands/site.js";
import { uiCommand } from "./commands/ui.js";
import { demoCommand } from "./commands/demo.js";
import { welcome } from "./welcome.js";

const program = new Command();
program
  .name("mcp-detector")
  .description("Security, reliability, and quality scanner for Model Context Protocol (MCP) servers.")
  .version(VERSION)
  .showHelpAfterError()
  .addHelpText(
    "after",
    `
Examples:
  mcp-detector scan -- npx -y @modelcontextprotocol/server-everything
  mcp-detector scan https://example.com/mcp --header "Authorization: Bearer $TOKEN"
  mcp-detector scan --format json --fail-on high
  mcp-detector inspect -- node ./build/index.js
  mcp-detector rules MCP-005

Exit codes: 0 ok · 1 findings at/above --fail-on, or the server could not be reached · 2 usage or internal error`,
  );

program.addCommand(uiCommand());
program.addCommand(demoCommand());
program.addCommand(scanCommand());
program.addCommand(inspectCommand());
program.addCommand(testCommand());
program.addCommand(reportCommand());
program.addCommand(rulesCommand());
program.addCommand(pinCommand());
program.addCommand(scanAllCommand());
program.addCommand(historyCommand());
program.addCommand(badgeCommand());
program.addCommand(siteCommand());
program.addCommand(dashboardCommand());
program.addCommand(initCommand());

async function main() {
  let argv = process.argv;
  // A first-time user who just types `mcp-detector` in a terminal gets a short menu instead of a wall of help.
  // Scripts and CI (no TTY) keep the normal behaviour.
  if (argv.length <= 2 && process.stdin.isTTY && process.stdout.isTTY) {
    const next = await welcome();
    if (next) argv = [...argv, ...next];
    else argv = [...argv, "--help"];
  }
  await program.parseAsync(argv);
}

main().catch((err: Error) => {
  process.stderr.write(`error: ${err.message}\n`);
  process.exit(2);
});
