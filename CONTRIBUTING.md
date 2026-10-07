# Contributing to MCP Detector

Thanks for helping. The project aims to stay **small, reliable and transparent**: few false positives, clear evidence, actionable fixes.

## Setup

```bash
git clone <your fork>
cd mcp-detector
npm install
npm test            # unit + integration tests
npm run typecheck
npm run dev -- scan -- node examples/vulnerable-server/server.mjs
```

## Adding a detection rule

A rule is a plain object (see `src/rules/*.ts`):

```ts
import type { Rule } from "../core/types.js";

export const myRule: Rule = {
  id: "MCP-033",                // next free ID; IDs are stable forever
  name: "Short name",
  category: "security",         // protocol | security | tools | schema | performance | quality
  severity: "high",             // default; users can override in config
  group: "dangerous_permissions", // optional config toggle
  description: "What it detects.",
  why: "Why it matters.",
  recommendation: "How to fix it.",
  check({ snapshot, config }) {
    // snapshot = everything we learned about the server; return one hit per problem.
    return snapshot.tools
      .filter((t) => /* your condition */ false)
      .map((t) => ({ tool: t.name, message: "…", evidence: "the text that matched" }));
  },
};
```

1. Add it to the relevant file in `src/rules/` (and the array that file exports). `src/rules/index.ts` registers it.
2. **Always return `evidence`** (the matched text, redacted if it is a secret) so a false positive can be investigated.
3. Rules must be pure functions of the snapshot: no network, no file access, no tool calls.
4. Add tests: at least one case that must fire and one near-miss that must not (`tests/`).
5. Run `npm run docs:rules` to regenerate `docs/rules.md` (CI fails if it is stale).

Rule IDs are never reused or renumbered; deprecate a rule instead of deleting it.

### Detection philosophy

- Prefer **indicators** with evidence over verdicts. Say "tool appears to…", not "tool is vulnerable".
- Precision beats recall for severity `high`/`critical`; those fail CI builds.
- Be passive by default. Nothing that calls a tool may run without `--active`.
- Never print a full secret.

## Other contributions

Test cases (`tests/`, `examples/`), transport adapters (`src/transport/`), output formats (`src/reporting/`), docs and integrations are all welcome.

## Pull requests

- Keep PRs focused; include tests and a CHANGELOG line.
- `npm run typecheck && npm test` must pass.
- By contributing you agree your work is licensed under the MIT license.
