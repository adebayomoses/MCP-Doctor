import pc from "picocolors";
import { Command } from "commander";
import { defaultConfig } from "../../config/default-config.js";
import { demoServerSpec } from "../../core/demo.js";
import { runScan } from "../../core/detector.js";
import { renderReport } from "../../reporting/report-generator.js";
import { saveHistory } from "../../store/history.js";

export function demoCommand(): Command {
  return new Command("demo")
    .description("Scan a built-in example server so you can see what a report looks like (touches nothing on your computer)")
    .option("--secure", "scan the well-built example instead of the deliberately unsafe one")
    .option("--verbose", "include explanations and fixes for each finding")
    .option("--no-color", "disable colored output")
    .action(async (opts: { secure?: boolean; verbose?: boolean; color?: boolean }) => {
      const c = pc.createColors(opts.color !== false && pc.isColorSupported);
      const which = opts.secure ? "secure" : "vulnerable";
      process.stdout.write(
        `${c.bold("Demo:")} scanning a built-in ${opts.secure ? "well-built" : "deliberately unsafe"} example server.\n${c.dim("This is a tiny test server shipped with MCP Detector; nothing on your computer is read or changed.")}\n\n`,
      );
      const { result } = await runScan({ ...defaultConfig(), server: demoServerSpec(which) });
      saveHistory(result);
      process.stdout.write(renderReport(result, "terminal", { color: opts.color !== false && pc.isColorSupported, verbose: opts.verbose }) + "\n\n");
      process.stdout.write(
        [
          c.bold("What next?"),
          `  • Read the fix for every finding:  ${c.cyan("mcp-detector demo --verbose")}`,
          `  • See the report in your browser:  ${c.cyan("mcp-detector ui")}`,
          `  • Scan your own server:            ${c.cyan("mcp-detector scan -- <the command that starts it>")}`,
          opts.secure ? "" : `  • See a clean report:               ${c.cyan("mcp-detector demo --secure")}`,
          "",
        ]
          .filter((l) => l !== "")
          .join("\n") + "\n",
      );
    });
}
