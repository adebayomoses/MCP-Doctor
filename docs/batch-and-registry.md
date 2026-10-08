# Batch scanning, history, badges and the scoreboard

## `scan-all`: many servers at once

```bash
mcp-detector scan-all servers.json          # a servers file
mcp-detector scan-all --clients             # everything configured in your MCP clients
mcp-detector scan-all --registry --limit 25 # remote servers from the official registry
```

Choose exactly one source. Useful flags: `--concurrency <n>` (default 2, max 8), `--delay <ms>`, `--dry-run` (list targets and exit), `--fail-on <severity>`, `--format terminal|json|markdown`, `-o <file>`, `--site <dir>` (also build the scoreboard), `--rules <path>` (community rules).

Results are saved to `.mcp-detector/batch/` (`latest.json` and a timestamped copy) and each scored server is added to its history.

Each server ends up as one of:

| Status | Meaning |
|---|---|
| scanned | connected and scored |
| auth_required | the server answered 401/403 or "missing token". It is **not scored** (that is not a defect in the server). Scan it on its own with `--header` to include it |
| failed | could not start or connect (the reason is shown) |

### Servers file

Any of these shapes, JSON or YAML:

```json
{ "mcpServers": { "files": { "command": "npx", "args": ["-y", "@modelcontextprotocol/server-filesystem", "."] },
                  "remote": { "url": "https://example.com/mcp", "headers": { "Authorization": "Bearer ${env:TOKEN}" } } } }
```

A `servers` map or list (VS Code style, with `type: "http" | "sse"`) and a bare list of `{ name, command, args }` also work. `${env:NAME}` and `${NAME}` are expanded from your environment; entries with `disabled: true` are skipped.

### `--clients`

Reads the configs of Claude Desktop, Cursor, VS Code, Windsurf and Claude Code (user-level, plus `./.mcp.json`, `./.cursor/mcp.json` and `./.vscode/mcp.json` in the current directory). A server configured in several clients is scanned once. The files that were read are printed.

**This starts your local (stdio) servers**, exactly as your clients start them. Use `--dry-run` first to see the list.

### `--registry`

Lists servers from the [official MCP registry](https://registry.modelcontextprotocol.io) (`--registry-url` to use another instance, `--search` to filter), keeps the newest version of each, and scans **remote HTTP/SSE servers only**.

Deliberately not scanned, and reported as skipped with the reason:

- **Package-based servers** (npm, PyPI, Docker). Scanning them would download and run third-party code on your machine.
- Remotes whose URL needs template variables, and deprecated or deleted entries.

Registry scans are always **passive**: the scanner connects, lists tools, resources and prompts, and never calls a tool, even if you pass `--active`. It sends a `User-Agent: mcp-detector` header and waits 500 ms between scans by default. Be considerate with large `--limit` values; these are other people's servers.

## History

Every `scan` and every scored `scan-all` entry is recorded in `.mcp-detector/history/` (last 50 runs per target; `--no-history` to skip).

```bash
mcp-detector history                 # all scanned targets: latest score, trend, number of runs
mcp-detector history my-server       # runs, plus new / resolved findings since the previous scan
```

A target is matched by key, server name, or part of the command or URL.

## Badges

```bash
mcp-detector scan --format json -- node build/index.js
mcp-detector badge -o badge.svg               # from the last scan
mcp-detector badge --category security        # a single category
mcp-detector badge --json                     # shields.io endpoint JSON
```

```markdown
![mcp-detector](badge.svg)
```

A badge shows a score, for example `mcp-detector | 94/100`, never "safe" or "verified": the score is an engineering signal, not a certification. Unreachable servers get a grey `unreachable` badge.

## HTML report

`mcp-detector scan --format html -o report.html` (or `report --format html`) writes one self-contained file: score ring, category bars, expandable findings with evidence and fixes. It contains **no scripts**, a restrictive Content-Security-Policy, and every piece of server-supplied text is HTML-escaped, so a hostile server cannot run code in the browser of whoever opens the report.

## Scoreboard site and dashboard

```bash
mcp-detector scan-all --registry --limit 50 --site public/   # scan and build in one go
mcp-detector site -o public/                                 # build from the latest batch (or the scan history)
mcp-detector dashboard                                       # serve it on http://127.0.0.1:4173
```

The site is plain static files, so it can be hosted anywhere (GitHub Pages, S3, any web server):

```text
index.html            ranked table, trends, summary, "not scored" list, how-to-read note
servers/<slug>.html   full report per server
badges/<slug>.svg     one badge per server
data.json             everything, machine readable
```

`dashboard` serves the same site on `127.0.0.1` only. It is read-only (GET/HEAD), refuses path traversal, rebuilds when you reload the index (so new scans appear), and has no backend or write access.

### Publishing a scoreboard responsibly

If you publish scores for servers you do not own:

- Say what the score is. The generated index already states that scores come from heuristic, passive scans and are not certifications.
- Keep false positives in mind. Findings are indicators; link to a server's own page so people can see the evidence.
- Give maintainers a way to contest a result or ask for a rescan.
- Do not scan servers that ask not to be scanned.

## Secrets in stored data

Targets (command lines and URLs) often contain tokens. Before anything is written to a report, history file, batch file or site, secrets are redacted: `--token=…`/`--api-key …` style flags, `?access_token=` query parameters, `user:password@` URL credentials, `Bearer …`, and known key formats. Check your own servers file before sharing it, since that is your input and is not rewritten.
