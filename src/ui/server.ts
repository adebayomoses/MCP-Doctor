import { spawn } from "node:child_process";
import { randomBytes, timingSafeEqual } from "node:crypto";
import { createServer, type IncomingMessage, type Server, type ServerResponse } from "node:http";
import type { AddressInfo } from "node:net";
import { discoverClientServers, type DiscoveredClients } from "../batch/sources.js";
import type { ServerSpec } from "../batch/types.js";
import { splitCommand } from "../cli/shared.js";
import { demoServerSpec } from "../core/demo.js";
import type { ResolvedConfig } from "../core/types.js";
import { redactTarget } from "../detectors/security/redact-target.js";
import { describeTarget } from "../transport/connect.js";
import { renderHtmlReport } from "../reporting/html.js";
import { listTargets } from "../store/history.js";
import { VERSION } from "../version.js";
import { JobManager, TooManyJobsError, type Runner } from "./jobs.js";
import { renderUiPage, uiCsp } from "./page.js";

export interface UiServerOptions {
  /** 0 picks a free port. */
  port?: number;
  /** Open the default browser at the access link. */
  open?: boolean;
  /** Where scan history lives (defaults to the current directory). */
  cwd?: string;
  /** Injection points for tests. */
  discover?: () => DiscoveredClients;
  runner?: Runner;
  maxRunning?: number;
}

export interface UiServer {
  /** Link to open, including the private access key in the fragment. */
  url: string;
  port: number;
  token: string;
  jobs: JobManager;
  close(): Promise<void>;
}

const MAX_BODY = 64 * 1024;

class HttpError extends Error {
  constructor(public status: number, message: string) {
    super(message);
  }
}

const json = (res: ServerResponse, status: number, body: unknown) => {
  res.writeHead(status, {
    "content-type": "application/json; charset=utf-8",
    "cache-control": "no-store",
    "x-content-type-options": "nosniff",
  });
  res.end(JSON.stringify(body));
};

function readJson(req: IncomingMessage): Promise<any> {
  return new Promise((resolve, reject) => {
    let size = 0;
    let tooBig = false;
    const chunks: Buffer[] = [];
    req.on("data", (c: Buffer) => {
      if (tooBig) return; // keep draining but stop buffering: the 413 reply closes the connection
      size += c.length;
      if (size > MAX_BODY) {
        tooBig = true;
        chunks.length = 0;
        reject(new HttpError(413, "Request is too large."));
        return;
      }
      chunks.push(c);
    });
    req.on("end", () => {
      if (tooBig) return;
      try {
        resolve(JSON.parse(Buffer.concat(chunks).toString("utf8") || "{}"));
      } catch {
        reject(new HttpError(400, "Request body is not valid JSON."));
      }
    });
    req.on("error", reject);
  });
}

const str = (v: unknown, field: string, max = 2000): string => {
  if (typeof v !== "string" || !v.trim()) throw new HttpError(400, `"${field}" is required.`);
  if (v.length > max) throw new HttpError(400, `"${field}" is too long.`);
  if (/[\r\n\0]/.test(v)) throw new HttpError(400, `"${field}" must be a single line.`);
  return v.trim();
};

export async function startUiServer(o: UiServerOptions = {}): Promise<UiServer> {
  const token = randomBytes(24).toString("hex");
  const tokenBuf = Buffer.from(token);
  const jobs = new JobManager({ cwd: o.cwd, runner: o.runner, maxRunning: o.maxRunning });
  const discover = o.discover ?? (() => discoverClientServers());
  let clientSpecs: ServerSpec[] = [];
  const allowedHosts = new Set<string>();
  const allowedOrigins = new Set<string>();

  const refreshClients = () => {
    try {
      clientSpecs = discover().specs;
    } catch {
      clientSpecs = [];
    }
    return clientSpecs;
  };

  function authorized(req: IncomingMessage): boolean {
    const given = req.headers["x-mcpd-token"];
    if (typeof given !== "string") return false;
    const g = Buffer.from(given);
    return g.length === tokenBuf.length && timingSafeEqual(g, tokenBuf);
  }

  /** Build the server for a scan request. Throws HttpError for anything invalid or unconfirmed. */
  function serverFor(body: any): { label: string; server: NonNullable<ResolvedConfig["server"]>; active: boolean } {
    const active = body.active === true;
    switch (body.kind) {
      case "demo": {
        if (body.name !== "vulnerable" && body.name !== "secure") throw new HttpError(400, "Unknown demo.");
        return { label: `Demo: ${body.name === "secure" ? "well-built" : "unsafe"} example server`, server: demoServerSpec(body.name), active: false };
      }
      case "command": {
        if (body.confirm !== true) throw new HttpError(400, "Please tick the box confirming you want this program started on your computer.");
        const line = str(body.command, "command");
        const argv = splitCommand(line);
        if (!argv.length) throw new HttpError(400, "Enter a command.");
        return { label: redactTarget(line), server: { command: argv[0], args: argv.slice(1) }, active };
      }
      case "url": {
        const raw = str(body.url, "url");
        let u: URL;
        try {
          u = new URL(raw);
        } catch {
          throw new HttpError(400, "That does not look like a valid web address.");
        }
        if (u.protocol !== "http:" && u.protocol !== "https:") throw new HttpError(400, "Only http:// and https:// addresses are supported.");
        const headers: Record<string, string> = {};
        const entries = Object.entries(body.headers ?? {});
        if (entries.length > 10) throw new HttpError(400, "Too many headers.");
        for (const [k, v] of entries) {
          if (!/^[A-Za-z0-9-]{1,64}$/.test(k)) throw new HttpError(400, `Invalid header name "${k.slice(0, 40)}".`);
          if (typeof v !== "string" || v.length > 2000 || /[\r\n\0]/.test(v)) throw new HttpError(400, `Invalid value for header "${k}".`);
          headers[k] = v;
        }
        return { label: redactTarget(raw), server: { url: raw, headers: Object.keys(headers).length ? headers : undefined }, active: false };
      }
      case "client": {
        if (body.confirm !== true) throw new HttpError(400, "Please tick the box confirming you want these programs started on your computer.");
        const id = body.id;
        if (!Number.isInteger(id) || id < 0 || id >= clientSpecs.length) throw new HttpError(400, "Unknown server. Reload the page and try again.");
        const spec = clientSpecs[id];
        return { label: spec.name, server: spec.server, active: false };
      }
      default:
        throw new HttpError(400, "Unknown kind of scan.");
    }
  }

  async function handleApi(req: IncomingMessage, res: ServerResponse, path: string) {
    if (req.method === "GET" && path === "/api/state") {
      return json(res, 200, {
        version: VERSION,
        // Names and redacted command lines only: environment variables and headers never leave the server.
        clients: refreshClients().map((s, id) => ({ id, name: s.name, source: s.source, target: describeTarget(s.server) })),
      });
    }
    if (req.method === "GET" && path === "/api/history") {
      return json(res, 200, {
        items: listTargets(o.cwd).map((t) => ({ key: t.key, name: t.name, target: t.target, score: t.latest.result.score, at: t.latest.at })),
      });
    }
    const hist = /^\/api\/history\/([a-f0-9]{12})$/.exec(path);
    if (req.method === "GET" && hist) {
      const t = listTargets(o.cwd).find((x) => x.key === hist[1]);
      if (!t) throw new HttpError(404, "No such scan.");
      return json(res, 200, { id: `h${t.key}`, status: "done", label: t.name ?? t.target, result: t.latest.result, html: renderHtmlReport(t.latest.result) });
    }
    if (req.method === "POST" && path === "/api/scan") {
      if (!/^application\/json\b/i.test(String(req.headers["content-type"] ?? ""))) throw new HttpError(415, "Send JSON.");
      if (!clientSpecs.length) refreshClients();
      const body = await readJson(req);
      const { label, server, active } = serverFor(body ?? {});
      try {
        return json(res, 202, { id: jobs.start(label, server, { active }) });
      } catch (e) {
        if (e instanceof TooManyJobsError) throw new HttpError(429, e.message);
        throw e;
      }
    }
    const job = /^\/api\/scan\/([a-f0-9]{16})$/.exec(path);
    if (req.method === "GET" && job) {
      const v = jobs.get(job[1]);
      if (!v) throw new HttpError(404, "No such scan (it may have expired).");
      return json(res, 200, v);
    }
    throw new HttpError(404, "Not found.");
  }

  const server: Server = createServer(async (req, res) => {
    try {
      // 1. Only ever answer requests addressed to us (defeats DNS rebinding).
      if (!allowedHosts.has(String(req.headers.host ?? "").toLowerCase())) throw new HttpError(403, "Unexpected host.");
      if (req.method !== "GET" && req.method !== "POST") throw new HttpError(405, "Method not allowed.");
      const path = new URL(req.url ?? "/", "http://localhost").pathname;

      if (path.startsWith("/api/")) {
        // 2. Cross-site requests are refused outright, then the access key is required.
        const origin = req.headers.origin;
        if (typeof origin === "string" && !allowedOrigins.has(origin.toLowerCase())) throw new HttpError(403, "Cross-site request refused.");
        const site = req.headers["sec-fetch-site"];
        if (typeof site === "string" && site !== "same-origin" && site !== "none") throw new HttpError(403, "Cross-site request refused.");
        if (!authorized(req)) throw new HttpError(401, "Missing or wrong access key. Open the link printed by `mcp-detector ui`.");
        return await handleApi(req, res, path);
      }

      if (req.method === "GET" && path === "/") {
        const nonce = randomBytes(16).toString("base64");
        res.writeHead(200, {
          "content-type": "text/html; charset=utf-8",
          "content-security-policy": uiCsp(nonce),
          "cache-control": "no-store",
          "x-content-type-options": "nosniff",
          "x-frame-options": "DENY",
          "referrer-policy": "no-referrer",
          "permissions-policy": "camera=(), microphone=(), geolocation=()",
        });
        return void res.end(renderUiPage(nonce));
      }
      if (path === "/favicon.ico") return void res.writeHead(204).end();
      throw new HttpError(404, "Not found.");
    } catch (e) {
      const status = e instanceof HttpError ? e.status : 500;
      if (status === 413) {
        // Answer, then drop the connection so an oversized upload is not read to the end.
        res.setHeader("connection", "close");
        res.on("finish", () => req.destroy());
      }
      if (!res.headersSent) json(res, status, { error: e instanceof HttpError ? e.message : "Internal error." });
      else res.end();
    }
  });

  await new Promise<void>((ok, fail) => {
    server.once("error", (e: NodeJS.ErrnoException) =>
      fail(e.code === "EADDRINUSE" ? new Error(`Port ${o.port} is already in use. Pick another with --port, or omit it to choose a free one.`) : e),
    );
    server.listen(o.port ?? 0, "127.0.0.1", ok);
  });
  const port = (server.address() as AddressInfo).port;
  for (const h of ["127.0.0.1", "localhost", "[::1]"]) {
    allowedHosts.add(`${h}:${port}`);
    allowedOrigins.add(`http://${h}:${port}`);
  }
  refreshClients();

  const url = `http://127.0.0.1:${port}/#token=${token}`;
  if (o.open) openBrowser(url);
  return {
    url,
    port,
    token,
    jobs,
    close: () =>
      new Promise<void>((ok) => {
        server.close(() => ok());
        server.closeAllConnections();
      }),
  };
}

/** Best effort: failing to open a browser must never stop the server. */
export function openBrowser(url: string): void {
  try {
    const [cmd, args] =
      process.platform === "win32" ? ["cmd", ["/c", "start", '""', url]] : process.platform === "darwin" ? ["open", [url]] : ["xdg-open", [url]];
    const child = spawn(cmd, args as string[], { stdio: "ignore", detached: true, windowsVerbatimArguments: process.platform === "win32" });
    child.on("error", () => {});
    child.unref();
  } catch {
    /* ignore */
  }
}
