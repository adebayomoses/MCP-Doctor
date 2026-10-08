import { mkdirSync, writeFileSync } from "node:fs";
import { join, resolve } from "node:path";
import type { BatchResult } from "../batch/types.js";
import { readTargetHistory } from "../store/history.js";
import { renderBadge } from "./badge.js";
import { renderSiteIndex, renderSiteServerPage, slugify, type SiteEntry } from "./html.js";

export interface SiteOptions {
  title?: string;
  /** Where to look up per-target score history for trend lines. */
  cwd?: string;
}

export interface SiteBuild {
  dir: string;
  files: string[];
  servers: number;
}

/**
 * Build a static scoreboard from a batch result: index.html, one page and one badge per scored
 * server, and data.json. It is plain files (no scripts, no backend), so it can be hosted anywhere,
 * e.g. GitHub Pages.
 */
export function buildSite(batch: BatchResult, outDir: string, opts: SiteOptions = {}): SiteBuild {
  const dir = resolve(outDir);
  mkdirSync(join(dir, "servers"), { recursive: true });
  mkdirSync(join(dir, "badges"), { recursive: true });
  const taken = new Set<string>();
  const files: string[] = [];
  const write = (rel: string, content: string) => {
    writeFileSync(join(dir, rel), content, "utf8");
    files.push(rel);
  };

  const items: SiteEntry[] = batch.entries.map((entry) => ({
    entry,
    slug: slugify(entry.name, taken),
    history: entry.result ? readTargetHistory(entry.result.target, opts.cwd).map((h) => h.result.score).slice(-20) : [],
  }));

  for (const it of items) {
    if (it.entry.status !== "scanned" || !it.entry.result) continue;
    write(`servers/${it.slug}.html`, renderSiteServerPage(it));
    write(`badges/${it.slug}.svg`, renderBadge(it.entry.result));
  }
  write("index.html", renderSiteIndex(batch, items, { title: opts.title }));
  write(
    "data.json",
    JSON.stringify(
      {
        ...batch,
        entries: batch.entries.map((e, i) => ({ ...e, slug: items[i].slug })),
      },
      null,
      2,
    ) + "\n",
  );
  return { dir, files, servers: items.filter((i) => i.entry.status === "scanned").length };
}
