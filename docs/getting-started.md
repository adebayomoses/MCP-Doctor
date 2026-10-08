# Getting started

## 1. Install

```bash
npm install -g mcp-detector
# or run without installing:
npx mcp-detector --help
```

## 1b. Easiest start: the web app or the demo

```bash
mcp-detector            # in a terminal: a short menu
mcp-detector ui         # web app: paste a server, click Scan  (see web-app.md)
mcp-detector demo       # see a report for a built-in example server
```

Everything below is the command line, which is what scripts and CI use.

## 2. Scan a server

**Local (stdio) server:** everything after `--` is the command that starts it.

```bash
mcp-detector scan -- node ./build/index.js
mcp-detector scan -- npx -y @modelcontextprotocol/server-filesystem /tmp
```

**Remote server:**

```bash
mcp-detector scan https://example.com/mcp --header "Authorization: Bearer $TOKEN"
```

Streamable HTTP is tried first with a fallback to legacy SSE; force one with `--transport http|sse`.

**Environment variables** for the server process: `--env API_URL=http://localhost:8080`.

## 3. Read the report

- **Health Score** – overall 0–100 plus a breakdown per category.
- **Findings** – each has a stable rule ID (`MCP-005`), a severity, the tool involved, and the *evidence* that triggered it. Add `--verbose` for why it matters and how to fix it.
- Explain any rule: `mcp-detector rules MCP-005`.

## 4. Other commands

| Command | Purpose |
|---|---|
| `scan` | Full analysis and score |
| `inspect` | Every tool, resource and prompt with parameters, capabilities and per-tool risk |
| `test` | Pass/fail connectivity and functional checks (handshake, ping, discovery) |
| `report` | Re-render the last scan (or a saved JSON file) as terminal / JSON / Markdown |
| `pin` | Record current tool definitions as the trusted baseline (`mcp-detector.lock.json`); later scans flag changes |
| `rules` | List or explain detection rules |
| `init` | Write a starter `mcp-detector.yml` |

## 5. Measuring tool performance (opt-in)

By default MCP Detector never calls your tools. To time them:

```bash
mcp-detector scan --active -- node ./build/index.js
```

Only tools that look read-only are called. See [security.md](security.md) for the exact rules and how to allow or deny specific tools.

## 6. Use it in CI

```bash
mcp-detector scan --format json --output report.json --fail-on high -- node ./build/index.js
```

Exit code `1` means a finding met the threshold (or the server could not be reached). See [integrations.md](integrations.md) for the GitHub Action.

## Handling false positives

1. Look at the finding's `evidence`; it shows exactly what matched.
2. If it is wrong for your server, tune it instead of ignoring the whole tool:

```yaml
# mcp-detector.yml
rules:
  MCP-010: low            # lower the severity
  MCP-024: off            # disable a rule
ignore:
  tools: [legacy_tool]    # skip one tool
```

3. If it is a genuine bug in a rule, open an issue with a minimal tool definition.
