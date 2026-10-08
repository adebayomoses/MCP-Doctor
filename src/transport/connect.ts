import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StdioClientTransport, getDefaultEnvironment } from "@modelcontextprotocol/sdk/client/stdio.js";
import { StreamableHTTPClientTransport } from "@modelcontextprotocol/sdk/client/streamableHttp.js";
import { SSEClientTransport } from "@modelcontextprotocol/sdk/client/sse.js";
import type { Transport } from "@modelcontextprotocol/sdk/shared/transport.js";
import type { ResolvedConfig } from "../core/types.js";
import { redactTarget } from "../detectors/security/redact-target.js";
import { VERSION } from "../version.js";

export interface Connection {
  client: Client;
  transport: Transport;
  describe: string;
  connectMs: number;
  /** Protocol version negotiated during initialize. */
  protocolVersion?: string;
  close(): Promise<void>;
}

function withTimeout<T>(p: Promise<T>, ms: number, label: string): Promise<T> {
  let t: NodeJS.Timeout;
  const timeout = new Promise<never>((_, rej) => {
    t = setTimeout(() => rej(new Error(`${label} timed out after ${ms} ms`)), ms);
  });
  return Promise.race([p, timeout]).finally(() => clearTimeout(t));
}

export function describeTarget(server: NonNullable<ResolvedConfig["server"]>): string {
  const raw = server.url ?? [server.command, ...(server.args ?? [])].filter(Boolean).join(" ");
  return redactTarget(raw);
}

/** Record the negotiated protocol version on the transport (the SDK only exposes it via this hook). */
function track<T extends Transport>(t: T): T {
  const orig = t.setProtocolVersion?.bind(t);
  t.setProtocolVersion = (v: string) => {
    (t as any).__negotiated = v;
    orig?.(v);
  };
  return t;
}

function makeClient() {
  return new Client({ name: "mcp-detector", version: "0.1.0" }, { capabilities: {} });
}

/**
 * Connect to a server over stdio, Streamable HTTP, or legacy SSE.
 * The SDK's `connect()` performs the initialize handshake; `connectMs` therefore
 * covers transport start-up + initialization.
 */
export async function connect(
  server: NonNullable<ResolvedConfig["server"]>,
  timeoutMs: number,
  onStderr?: (chunk: string) => void,
): Promise<Connection> {
  const describe = describeTarget(server);

  if (server.url) {
    const url = new URL(server.url);
    // Identify ourselves to server operators; a user-supplied header of the same name wins.
    const requestInit = { headers: { "user-agent": `mcp-detector/${VERSION}`, ...(server.headers ?? {}) } };
    const kind = server.transport ?? "http";
    if (kind === "sse") {
      const client = makeClient();
      const transport = track(new SSEClientTransport(url, { requestInit }));
      const start = performance.now();
      await withTimeout(client.connect(transport), timeoutMs, "Connection");
      return wrap(client, transport, describe, performance.now() - start);
    }
    // Try Streamable HTTP first, then fall back to legacy SSE.
    const client = makeClient();
    const transport = track(new StreamableHTTPClientTransport(url, { requestInit }));
    const start = performance.now();
    try {
      await withTimeout(client.connect(transport), timeoutMs, "Connection");
      return wrap(client, transport, describe, performance.now() - start);
    } catch (httpErr) {
      await transport.close().catch(() => {});
      if (server.transport === "http") throw httpErr;
      const client2 = makeClient();
      const sse = track(new SSEClientTransport(url, { requestInit }));
      const start2 = performance.now();
      try {
        await withTimeout(client2.connect(sse), timeoutMs, "Connection");
        return wrap(client2, sse, describe + " (sse)", performance.now() - start2);
      } catch {
        throw httpErr;
      }
    }
  }

  if (!server.command) throw new Error("No server specified. Provide a command, a --url, or a `server:` block in mcp-detector.yml.");
  const client = makeClient();
  const transport = track(new StdioClientTransport({
    command: server.command,
    args: server.args ?? [],
    env: { ...getDefaultEnvironment(), ...(server.env ?? {}) },
    cwd: server.cwd,
    stderr: "pipe",
  }));
  const err = (transport as any).stderr;
  if (err && onStderr) err.on("data", (c: Buffer) => onStderr(c.toString()));
  const start = performance.now();
  try {
    await withTimeout(client.connect(transport), timeoutMs, "Connection");
  } catch (e) {
    await transport.close().catch(() => {});
    throw e;
  }
  return wrap(client, transport, describe, performance.now() - start);
}

function wrap(client: Client, transport: Transport, describe: string, connectMs: number): Connection {
  return {
    get protocolVersion() {
      return (transport as any).__negotiated as string | undefined;
    },
    client,
    transport,
    describe,
    connectMs,
    close: async () => {
      await client.close().catch(() => {});
    },
  };
}
