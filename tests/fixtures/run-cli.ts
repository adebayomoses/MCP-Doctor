import { spawnSync } from "node:child_process";
import { resolve } from "node:path";
import { pathToFileURL } from "node:url";

const ROOT = resolve(".");
const TSX = pathToFileURL(resolve("node_modules/tsx/dist/esm/index.mjs")).href;
const CLI = resolve("src/cli/index.ts");

export const example = (name: string) => resolve("examples", name, "server.mjs");

/** Run the CLI from source in `cwd` and capture its output and exit code. */
export function runCli(args: string[], opts: { cwd?: string; env?: NodeJS.ProcessEnv } = {}) {
  const r = spawnSync(process.execPath, ["--import", TSX, CLI, ...args], {
    cwd: opts.cwd ?? ROOT,
    encoding: "utf8",
    env: { ...process.env, NO_COLOR: "1", ...opts.env },
    timeout: 60_000,
  });
  return { code: r.status ?? -1, stdout: r.stdout ?? "", stderr: r.stderr ?? "" };
}
