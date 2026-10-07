# Configuration

MCP Detector reads `mcp-detector.yml` (also `.yaml` or `.mcp-detector.yml`) from the working directory, or the file given with `--config`. Create a starter file with `mcp-detector init`.

**Precedence:** command-line flags > positional target (`scan -- cmd`) > config file.

## Reference

```yaml
# Which server to scan (stdio OR http)
server:
  command: node
  args: ["build/index.js"]
  env: { LOG_LEVEL: warn }
  cwd: ./
  # --- or ---
  # url: https://example.com/mcp
  # transport: http            # http | sse (default: try http, fall back to sse)
  # headers: { Authorization: "Bearer abc" }

baseline: mcp-detector.lock.json   # optional; auto-discovered in the working directory if present

severity:
  fail_on: high                # none | info | low | medium | high | critical

rules:
  # Group toggles (true/false)
  prompt_injection: true       # MCP-004
  tool_poisoning: true         # MCP-005
  secret_exposure: true        # MCP-006
  dangerous_permissions: true  # MCP-007, 011, 012, 028, 030
  network_risk: true           # MCP-031
  rug_pull: true               # MCP-032 (only active when a baseline exists)
  command_injection: true      # MCP-008
  performance: true            # MCP-009, 015, 019, 023
  protocol: true               # MCP-001, 002, 016, 017, 018, 027, 029
  schema: true                 # MCP-003, 010
  quality: true                # MCP-013, 014, 020, 021, 022, 024, 025, 026
  # Per-rule overrides: off | info | low | medium | high | critical
  MCP-024: off
  MCP-010: low

thresholds:
  latency_ms: 3000             # slower tool calls / discovery raise MCP-015 / MCP-019
  timeout_ms: 10000            # per-request timeout
  connect_ms: 30000            # maximum time to start and initialize (npx may need to download)
  max_timeout_rate: 0.05       # above this fraction of timed-out calls raises MCP-023

active:                        # or simply `active: true`
  enabled: true
  allow: [render_report]       # always call these (even with side-effect-looking names)
  deny: [get_secrets]          # never call these

ignore:
  rules: [MCP-022]             # same as `MCP-022: off`
  tools: [legacy_tool]         # skip every finding on these tools
```

Rule IDs are case-insensitive. A per-rule `off` wins over a group toggle; a per-rule severity wins over the rule's default and over per-hit severities.

## CLI flags that mirror config

| Flag | Config |
|---|---|
| `--fail-on <sev>` | `severity.fail_on` |
| `--active` | `active` |
| `--timeout <ms>` | `thresholds.timeout_ms` |
| `--latency <ms>` | `thresholds.latency_ms` |
| `--disable MCP-024 …` | `rules.MCP-024: off` |
| `--url`, `--command`, `--arg`, `--env`, `--header`, `--transport` | `server.*` |

## Environment

`NO_COLOR` or `--no-color` disables color. Colors are also off when writing to a file with `--output`.
