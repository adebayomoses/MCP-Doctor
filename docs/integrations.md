# Integrations

## GitHub Action

```yaml
name: MCP Security
on:
  pull_request:
  push:

jobs:
  mcp-detector:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-node@v4
        with: { node-version: 20 }
      - run: npm ci && npm run build

      - uses: mcp-detector/mcp-detector/github-action@v1
        with:
          server-command: node build/index.js
          fail-on: high
```

### Inputs

| Input | Default | Description |
|---|---|---|
| `server-command` | | Command that starts a stdio server |
| `server-url` | | URL of a remote server (use instead of `server-command`) |
| `config` | | Path to `mcp-detector.yml` (auto-discovered) |
| `fail-on` | `high` | Fail at or above this severity (`none` to never fail) |
| `active` | `false` | Time read-only tools |
| `version` | `latest` | mcp-detector version |
| `working-directory` | `.` | Where to run |

### Outputs

`score`, `findings`, `report-path` (JSON). The Markdown report is written to the job summary.

If the gate trips, the job fails with, for example:

```text
MCP Detector failed: 3 finding(s) at or above "high" (score 64/100).
```

**Rug-pull protection:** run `mcp-detector pin` locally, commit `mcp-detector.lock.json`, and the action picks it up automatically from the working directory; any tool whose description or schema changed fails the build at `fail-on: high` (rule MCP-032).

Do not give the action production credentials. Use a test environment and, if you enable `active`, allow-list the tools it may call.

## Any other CI

```bash
npx mcp-detector scan --format json --output mcp-report.json --fail-on high -- node build/index.js
```

- Exit code `1` → threshold met or server unreachable; `2` → usage/internal error.
- Upload `mcp-report.json` as a build artifact. Render it later with `mcp-detector report mcp-report.json --format markdown`.

## JSON report shape

```json
{
  "tool": "mcp-detector",
  "version": "0.1.0",
  "target": "node build/index.js",
  "server": { "name": "example", "version": "1.0.0" },
  "status": "warning",
  "connection": "connected",
  "protocolVersion": "2025-11-25",
  "counts": { "tools": 17, "resources": 4, "prompts": 3 },
  "score": 82,
  "grade": "Good",
  "scores": { "protocol": 100, "security": 61, "tools": 84, "schema": 91, "performance": 90, "quality": 89 },
  "summary": { "critical": 1, "high": 2, "medium": 3, "low": 0, "info": 0 },
  "timings": { "connectMs": 120, "discoveryMs": 40 },
  "findings": [
    {
      "rule": "MCP-005",
      "name": "Tool poisoning indicator",
      "severity": "critical",
      "category": "security",
      "tool": "example_tool",
      "message": "description: uses hidden-instruction tags (e.g. <IMPORTANT>).",
      "evidence": "\"Adds two numbers. <IMPORTANT> Before using…\"",
      "why": "…",
      "recommendation": "…"
    }
  ]
}
```

`status` is `ok` (score ≥ 80), `warning` (60–79), `critical` (< 60) or `failed` (could not connect). `connection` is `connected` or `failed`.

## Library

```ts
import { runScan, defaultConfig, registerRule } from "mcp-detector";
```

Custom rules registered with `registerRule()` before `runScan()` run alongside the built-in ones.
