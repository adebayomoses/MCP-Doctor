import { existsSync } from "node:fs";
import { fileURLToPath } from "node:url";
import type { ResolvedConfig } from "./types.js";

export type DemoName = "vulnerable" | "secure";

/**
 * The bundled demo servers live in `demo/` at the package root. This file is at src/core or dist/core,
 * so the same relative path works both in the repository and in an installed package.
 */
export function demoServerPath(name: DemoName): string {
  const p = fileURLToPath(new URL(`../../demo/${name}-server.mjs`, import.meta.url));
  if (!existsSync(p)) throw new Error(`The bundled demo server is missing (${p}). Reinstall mcp-detector.`);
  return p;
}

export function demoServerSpec(name: DemoName): NonNullable<ResolvedConfig["server"]> {
  return { command: process.execPath, args: [demoServerPath(name)] };
}
