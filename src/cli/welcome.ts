import { createInterface } from "node:readline/promises";
import pc from "picocolors";
import { discoverClientServers } from "../batch/sources.js";
import { describeTarget } from "../transport/connect.js";

/**
 * First-run menu, shown only when `mcp-detector` is run with no arguments in an interactive terminal.
 * Returns the argv to run next (without the node/script prefix), or undefined to just show help.
 */
export async function welcome(input = process.stdin, output = process.stdout): Promise<string[] | undefined> {
  const c = pc.createColors(pc.isColorSupported);
  const rl = createInterface({ input, output });
  const ask = async (q: string) => (await rl.question(q)).trim();
  try {
    output.write(
      [
        "",
        `${c.bold("MCP Detector")}  ${c.dim("checks MCP servers for security, reliability and quality problems")}`,
        "",
        "What would you like to do?",
        `  ${c.bold("1)")} Open the web app ${c.dim("(recommended: paste a server, click Scan)")}`,
        `  ${c.bold("2)")} See a demo scan here in the terminal ${c.dim("(safe, takes a few seconds)")}`,
        `  ${c.bold("3)")} Scan the MCP servers I already use ${c.dim("(Claude Desktop, Cursor, VS Code, …)")}`,
        `  ${c.bold("4)")} Show all commands`,
        "",
      ].join("\n") + "\n",
    );
    const choice = (await ask("Choose 1-4 [1]: ")) || "1";
    if (choice === "1") return ["ui"];
    if (choice === "2") return ["demo"];
    if (choice === "4") return undefined;
    if (choice === "3") {
      const found = discoverClientServers();
      if (!found.specs.length) {
        output.write("\nNo MCP apps with configured servers were found on this computer.\nTry the demo (option 2) or scan a server yourself:\n  mcp-detector scan -- <the command that starts your server>\n\n");
        return undefined;
      }
      output.write(`\nFound ${found.specs.length} server(s):\n`);
      for (const s of found.specs) output.write(`  • ${s.name} ${c.dim(`(${s.source})`)}  ${c.dim(describeTarget(s.server).slice(0, 80))}\n`);
      output.write(`\n${c.yellow("Scanning starts these programs on your computer, exactly as those apps start them.")}\n`);
      const yes = (await ask("Scan them now? [y/N]: ")).toLowerCase();
      return yes === "y" || yes === "yes" ? ["scan-all", "--clients"] : undefined;
    }
    output.write(`\nPlease type 1, 2, 3 or 4.\n`);
    return undefined;
  } finally {
    rl.close();
  }
}
