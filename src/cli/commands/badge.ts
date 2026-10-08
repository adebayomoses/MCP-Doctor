import { existsSync, readFileSync } from "node:fs";
import { Command } from "commander";
import type { Category, ScanResult } from "../../core/types.js";
import { CATEGORIES } from "../../core/types.js";
import { renderBadge, shieldsEndpoint } from "../../reporting/badge.js";
import { LAST_SCAN_PATH, writeOutput } from "../shared.js";

export function badgeCommand(): Command {
  return new Command("badge")
    .description("Create a score badge (SVG, or a shields.io endpoint JSON) from a scan result")
    .argument("[file]", "JSON result from `scan --format json`", LAST_SCAN_PATH)
    .option("-o, --output <file>", "write to a file (default: stdout)")
    .option("--json", "emit shields.io endpoint JSON instead of SVG")
    .option("--category <name>", `badge a single category: ${CATEGORIES.join(" | ")}`)
    .option("--label <text>", "left-hand label")
    .action((file: string, opts: { output?: string; json?: boolean; category?: string; label?: string }) => {
      if (!existsSync(file)) throw new Error(`No scan result at ${file}. Run \`mcp-detector scan\` first.`);
      let r: ScanResult;
      try {
        r = JSON.parse(readFileSync(file, "utf8"));
      } catch (e) {
        throw new Error(`Could not read ${file}: ${(e as Error).message}`);
      }
      if (r?.tool !== "mcp-detector" || typeof r.score !== "number") throw new Error(`${file} is not an MCP Detector result.`);
      if (opts.category && !(CATEGORIES as string[]).includes(opts.category))
        throw new Error(`Unknown category "${opts.category}". Use one of: ${CATEGORIES.join(", ")}.`);
      const o = { label: opts.label, category: opts.category as Category | undefined };
      writeOutput(opts.json ? JSON.stringify(shieldsEndpoint(r, o), null, 2) : renderBadge(r, o).trimEnd(), opts.output);
    });
}
