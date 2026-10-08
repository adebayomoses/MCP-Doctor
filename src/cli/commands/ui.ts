import pc from "picocolors";
import { Command } from "commander";
import { startUiServer } from "../../ui/server.js";

export function uiCommand(): Command {
  return new Command("ui")
    .description("Open the web app: paste a server, click Scan, read the report (runs on your computer, localhost only)")
    .option("-p, --port <n>", "port to listen on (default: a free one)")
    .option("--no-open", "do not open the browser automatically")
    .option("--no-color", "disable colored output")
    .action(async (opts: { port?: string; open?: boolean; color?: boolean }) => {
      const c = pc.createColors(opts.color !== false && pc.isColorSupported);
      let port: number | undefined;
      if (opts.port !== undefined) {
        port = Number(opts.port);
        if (!Number.isInteger(port) || port < 0 || port > 65535) throw new Error(`Invalid --port "${opts.port}".`);
      }
      const ui = await startUiServer({ port, open: opts.open !== false });
      process.stdout.write(
        [
          "",
          `${c.green("✓")} ${c.bold("MCP Detector is running")}`,
          "",
          `  Open this link in your browser${opts.open !== false ? " (it should open by itself)" : ""}:`,
          `  ${c.cyan(ui.url)}`,
          "",
          c.dim("  • The link contains a private key, so only this browser tab can use the app."),
          c.dim("  • It only listens on your own computer (127.0.0.1); nothing is reachable from the network."),
          c.dim("  • Scans never call a server's tools unless you tick the box that says so."),
          "",
          `  Keep this window open. Press ${c.bold("Ctrl+C")} to stop.`,
          "",
        ].join("\n"),
      );
      await new Promise<void>((done) => {
        const stop = () => void ui.close().then(done);
        process.once("SIGINT", stop);
        process.once("SIGTERM", stop);
      });
    });
}
