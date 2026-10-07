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

program.addCommand(scanCommand());
program.addCommand(inspectCommand());
program.addCommand(testCommand());
program.addCommand(reportCommand());
program.addCommand(rulesCommand());
program.addCommand(pinCommand());
program.addCommand(initCommand());

program.parseAsync(process.argv).catch((err: Error) => {
  process.stderr.write(`error: ${err.message}\n`);
  process.exit(2);
});
