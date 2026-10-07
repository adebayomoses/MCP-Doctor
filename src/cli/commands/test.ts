import pc from "picocolors";
import { Command } from "commander";
import { collectSnapshot } from "../../core/scanner.js";
import { addTargetOptions, resolveConfig, type CommonOptions } from "../shared.js";

interface Check {
  name: string;
  status: "pass" | "fail" | "warn" | "skip";
  detail?: string;
}

export function testCommand(): Command {
  const cmd = new Command("test")
    .description("Run connectivity and functional tests (handshake, ping, discovery and, with --active, read-only tool calls)")
    .argument("[server...]", "server command (after `--`) or an http(s) URL")
    .option("--active", "also call tools that look read-only")
    .option("--no-color", "disable colored output");
  addTargetOptions(cmd);
  cmd.action(async (server: string[], opts: CommonOptions) => {
    const { config } = resolveConfig(server, opts);
    const c = pc.createColors(opts.color !== false && pc.isColorSupported);
    const s = await collectSnapshot(config);
    const checks: Check[] = [];
    const add = (name: string, ok: boolean | undefined, detail?: string, warn = false) =>
      checks.push({ name, status: ok === undefined ? "skip" : ok ? "pass" : warn ? "warn" : "fail", detail });

    add("Connection + initialization", s.connected, s.connected ? `${s.timings.connectMs} ms` : s.connectError);
    if (s.connected) {
      add("Protocol version", !!s.protocolVersion, s.protocolVersion);
      add("Server info", !!s.serverInfo?.name, s.serverInfo ? `${s.serverInfo.name} ${s.serverInfo.version ?? ""}` : "missing serverInfo", true);
      add("Capabilities declared", Object.keys(s.capabilities ?? {}).length > 0, Object.keys(s.capabilities ?? {}).join(", ") || "none", true);
      add("Ping", s.ping?.ok, s.ping ? (s.ping.ok ? `${s.ping.ms} ms` : s.ping.error) : undefined);
      add("Unknown method returns an error", s.unknownMethod?.rejected, s.unknownMethod?.timedOut ? "timed out" : undefined, true);
      for (const kind of ["tools", "resources", "prompts"] as const) {
        if (!s.capabilities?.[kind]) continue;
        const err = s.listErrors[kind];
        add(`${kind}/list`, !err, err ?? `${s[kind].length} found`);
      }
      add("Tool names unique", new Set(s.toolNames).size === s.toolNames.length);
      add("Tools have input schemas", s.tools.every((t) => t.inputSchema && typeof t.inputSchema === "object"), undefined);
      if (s.activeMode) {
        for (const call of s.toolCalls) add(`call ${call.tool}`, call.ok, call.ok ? `${call.durationMs} ms` : call.error?.slice(0, 120));
        if (!s.toolCalls.length) add("Tool calls", undefined, "no tools were safe to call");
      }
    }

    for (const k of checks) {
      const mark = { pass: c.green("✓"), fail: c.red("✗"), warn: c.yellow("⚠"), skip: c.dim("–") }[k.status];
      process.stdout.write(`${mark} ${k.name}${k.detail ? c.dim(`  ${k.detail}`) : ""}\n`);
    }
    const failed = checks.filter((k) => k.status === "fail").length;
    const warned = checks.filter((k) => k.status === "warn").length;
    process.stdout.write(`\n${checks.length - failed - warned} passed, ${warned} warnings, ${failed} failed\n`);
    if (failed) process.exitCode = 1;
  });
  return cmd;
}
