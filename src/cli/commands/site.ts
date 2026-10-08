import { createReadStream, existsSync, statSync } from "node:fs";
import { createServer } from "node:http";
import { extname, join, normalize, resolve, sep } from "node:path";
import pc from "picocolors";
import { Command } from "commander";
import { loadBatchOrHistory } from "../../batch/load.js";
import { buildSite } from "../../reporting/site.js";
import { DATA_DIR } from "../../store/history.js";

const TYPES: Record<string, string> = {
  ".html": "text/html; charset=utf-8",
  ".svg": "image/svg+xml",
  ".json": "application/json; charset=utf-8",
};

export function siteCommand(): Command {
  return new Command("site")
    .description("Build a static scoreboard website (index, one page and badge per server, data.json) from scan results")
    .argument("[batchFile]", "batch result from `scan-all` (default: the latest batch, else the scan history)")
    .option("-o, --output <dir>", "output directory", "mcp-detector-site")
    .option("--title <text>", "page title")
    .action((file: string | undefined, opts: { output: string; title?: string }) => {
      const batch = loadBatchOrHistory(file);
      const built = buildSite(batch, opts.output, { title: opts.title });
      process.stdout.write(`${pc.green("✓")} Wrote ${built.files.length} files (${built.servers} scored server(s)) to ${built.dir}\nOpen ${join(built.dir, "index.html")} or host the folder on any static host (e.g. GitHub Pages).\n`);
    });
}

export function dashboardCommand(): Command {
  return new Command("dashboard")
    .description("Serve the scoreboard locally (read-only, 127.0.0.1) so you can browse scores, findings and trends")
    .argument("[batchFile]", "batch result to show (default: latest batch, else scan history)")
    .option("-p, --port <n>", "port", "4173")
    .option("--title <text>", "page title")
    .action(async (file: string | undefined, opts: { port: string; title?: string }) => {
      const port = Number(opts.port);
      if (!Number.isInteger(port) || port < 0 || port > 65535) throw new Error(`Invalid --port "${opts.port}".`);
      const dir = resolve(DATA_DIR, "site");
      const build = () => buildSite(loadBatchOrHistory(file), dir, { title: opts.title ?? "MCP Detector dashboard" });
      build();
      const server = createServer((req, res) => {
        if (req.method !== "GET" && req.method !== "HEAD") {
          res.writeHead(405).end();
          return;
        }
        let rel: string;
        try {
          rel = decodeURIComponent(new URL(req.url ?? "/", "http://localhost").pathname);
        } catch {
          res.writeHead(400).end();
          return;
        }
        if (rel === "/") {
          try {
            build(); // refresh on every visit to the index, so new scans show up
          } catch {
            /* keep serving the previous build */
          }
          rel = "/index.html";
        }
        const target = normalize(join(dir, rel));
        if (target !== dir && !target.startsWith(dir + sep)) {
          res.writeHead(403).end();
          return;
        }
        if (!existsSync(target) || !statSync(target).isFile() || !TYPES[extname(target)]) {
          res.writeHead(404, { "content-type": "text/plain" }).end("Not found");
          return;
        }
        res.writeHead(200, { "content-type": TYPES[extname(target)], "x-content-type-options": "nosniff", "cache-control": "no-store", "referrer-policy": "no-referrer" });
        if (req.method === "HEAD") res.end();
        else createReadStream(target).pipe(res);
      });
      await new Promise<void>((ok, fail) => {
        server.once("error", fail);
        server.listen(port, "127.0.0.1", ok);
      });
      const addr = server.address();
      const p = typeof addr === "object" && addr ? addr.port : port;
      process.stdout.write(`${pc.green("✓")} Dashboard running at http://127.0.0.1:${p}/  (Ctrl+C to stop)\n`);
      await new Promise<void>((done) => {
        process.once("SIGINT", () => server.close(() => done()));
        process.once("SIGTERM", () => server.close(() => done()));
      });
    });
}
